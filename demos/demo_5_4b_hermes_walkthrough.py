"""Phase 5.4b live walk-through — drive a real LLM ask through the hub.

Boots the hub in-process with a temp workspace + TestClient, spawns a
``kind=hermes`` agent via the supervisor, fishes the issued cap_token off
disk (the spawn response only returns the token_id), and POSTs a real
prompt through the A2A proxy. Prints DeepSeek's reply.

Run: python demos/demo_5_4b_hermes_walkthrough.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

# H-1b 修复 (5.4b R2): 路径不再钉死在源码里。环境变量未设时
# 退到本机默认路径，其他用户/CI 改 NTH_HERMES_REPO 一处即可。
# R-5 顺手清理：删掉 urllib.request 的死 import（确实没用上）。
# R-6 自审撤回 (5.4b R2 → R3): 我原以为 ``sys.path.insert(0,
# hermes_path)`` 是死代码（本进程不 import run_agent），实测删了
# 直接 ModuleNotFoundError —— nth_dao/__init__.py 启动时
# ``from team_layer import ...``，单跑 ``python demos/foo.py`` 时
# sys.path[0] = demos/，team_layer/ 找不着。老版本能跑是因为
# hermes-team-agent 仓库里碰巧也有一份 team_layer 的镜像，被
# sys.path.insert 顺带激活。这是隐式依赖；正经做法是让本仓库
# 自己的 team_layer/ 来供给：main() 里加 ``REPO_ROOT`` 到 sys.path,
# 用我们自己的 team_layer，不再寄生 hermes 的镜像。教训同 L-2：
# reasoning ≠ verification，删 "看起来无用" 的代码前先跑一次。
DEFAULT_HERMES_REPO = r"C:/Users/TonyWU/Desktop/hermes-team-agent"


def main() -> int:
    # Windows 默认 stdout 是 cp936；中文响应会被替成 ? 显示不出来。
    # 强制走 UTF-8 让 print 的中文在终端里可读。
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — Python < 3.7 兼容
        pass
    # 让本仓库自己的 team_layer/ 可被 import (见顶部注释)。
    # __file__ = .../nth-team-layer/demos/demo_5_4b_...py
    # → parent.parent = .../nth-team-layer (repo root)
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))

    # PYTHONPATH 才是关键：supervisor 用 sys.executable 把 dummy_agent
    # 拉起来跑子进程，子进程才是真正 ``import run_agent`` 的地方,
    # PYTHONPATH 会被子进程继承。本进程不直接 import run_agent，但
    # 子进程要，所以把 hermes-team-agent 仓库塞 PYTHONPATH 里。
    # D-1 修复 (5.4b R3): 错误消息别再把 Tony 的本机路径推到非 Tony
    # 用户脸上 —— 他们看到 "C:/Users/TonyWU/..." 会一脸懵。改成
    # actionable hint 先讲，path 作为调试信息放后面，并标注那是
    # dev box fallback。
    hermes_repo = os.environ.get("NTH_HERMES_REPO", DEFAULT_HERMES_REPO)
    if not Path(hermes_repo).exists():
        print(
            "[setup] FAIL — hermes-agent 仓库不可用。请把环境变量 "
            "NTH_HERMES_REPO 设成你机器上 hermes-agent 仓库根目录的路径。\n"
            f"        (tried {hermes_repo!r} —— 这是 dev box 的 fallback "
            "默认值)"
        )
        return 1
    existing = os.environ.get("PYTHONPATH", "")
    os.environ["PYTHONPATH"] = (
        hermes_repo + (os.pathsep + existing if existing else "")
    )

    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    # R-2 修复 (5.4b R2): Windows 下 supervisor 子进程退出有个尾巴 ——
    # /stop 返回后子进程不一定立刻松开 workspace 里的句柄（cap_token.json
    # / identity.json）。with-block 离开时 rmtree 撞上还在锁的文件会
    # 抛 PermissionError，结果是 "walk-through 跑通了但进程非零退出"。
    # ignore_cleanup_errors 让 rmtree best-effort 删，删不掉的就留在
    # %TEMP% 让 OS 后面清。Py 3.10+ 才有，老版本就静默走老行为。
    cleanup_kwargs: dict = {"prefix": "nth-walkthrough-"}
    if sys.version_info >= (3, 10):
        cleanup_kwargs["ignore_cleanup_errors"] = True
    with tempfile.TemporaryDirectory(**cleanup_kwargs) as tmp_dir:
        workspace = Path(tmp_dir)
        print(f"[setup] workspace = {workspace}")

        # require_console_auth=False so we can drive without juggling
        # the per-workspace console token.
        app = create_app(workspace=workspace, require_console_auth=False)
        client = TestClient(app)

        print("[step 1] POST /api/v2/agents/spawn (kind=hermes) ...")
        t0 = time.time()
        # ask 方法在 child A2A 端要求 ``a2a:message_send`` 这个 cap;
        # spawn 默认只发 nth:receipt_sign，得显式申请。
        r = client.post(
            "/api/v2/agents/spawn",
            json={
                "kind": "hermes",
                "label": "hermes-demo",
                "capabilities": ["a2a:message_send"],
            },
        )
        print(f"  status={r.status_code} elapsed={time.time()-t0:.1f}s")
        if r.status_code != 201:
            print(f"  body={r.text[:500]}")
            return 1
        spawn = r.json()
        agent_id = spawn["agent_id"]
        did = spawn["did"]
        cap_token_id = spawn["cap_token_id"]
        a2a_port = spawn.get("a2a_port")
        print(f"  agent_id={agent_id}")
        print(f"  did={did}")
        print(f"  cap_token_id={cap_token_id}")
        print(f"  a2a_port={a2a_port}")

        # spawn 只返回 token_id；完整签名 token 落盘在
        # <workspace>/team_cap_tokens/<token_id>.json 里。
        print("[step 2] read cap_token JSON from disk ...")
        cap_token_path = workspace / "team_cap_tokens" / f"{cap_token_id}.json"
        if not cap_token_path.exists():
            print(f"  FAIL cap_token file not found at {cap_token_path}")
            return 1
        cap_token = json.loads(cap_token_path.read_text(encoding="utf-8"))
        print(f"  capabilities={cap_token.get('capabilities')}")
        print(f"  exp={cap_token.get('expires_at')}")

        # 子端期望的是 ``Authorization: CapToken <base64url(canonical_json)>``,
        # 不是 Bearer + 裸 JSON。复用 cap_token 模块本身的 encoder 以免
        # 自己拼字节出错。
        from nth_dao.cap_token import encode_authorization_header
        encoded = encode_authorization_header(cap_token)

        prompt = "请用一句话告诉我今天是2026年6月12日，仅回复这一句中文，不要任何前缀或解释。"

        # 子端要先把自己的 --cap-token-file 读进来，才会知道自己的
        # issuer_did，然后才能校验入境请求。轮询默认 1s 一次，2~3s
        # 内应该完成。retry-with-backoff 比一次性 sleep(3) 更稳:
        # 既不会等过头，子端慢一点也能等到。
        #
        # R-4 注意 (5.4b R2，D-2 修复 R3 挪到循环外): TestClient 跑的
        # 是进程内 ASGI，``timeout=`` 这个参数会被 starlette/httpx 的
        # TestClient 路径吃掉但不当 wall-clock 用 —— 真挂的话这里
        # 会一直阻塞而不是抛 ReadTimeout。保留这个参数纯属占位说明
        # 我们 *期望* 的语义；真要 hard cap，得用 uvicorn 起真服务
        # + httpx.Client。本 demo 容忍这个限制。
        print(f"[step 3] POST /api/v2/agents/{did[:20]}.../a2a/ask ...")
        ask_deadline = time.time() + 10.0
        r = None
        t0 = time.time()
        while time.time() < ask_deadline:
            r = client.post(
                f"/api/v2/agents/{did}/a2a/ask",
                headers={"Authorization": f"CapToken {encoded}"},
                json={"prompt": prompt},
                timeout=180.0,
            )
            if r.status_code == 401 and "not-yet-authorized" in r.text:
                time.sleep(0.5)
                continue
            break
        elapsed = time.time() - t0
        print(f"  status={r.status_code} elapsed={elapsed:.1f}s")
        if r.status_code != 200:
            print(f"  body={r.text[:800]}")
            return 1
        print(f"  raw body    = {r.text[:1200]}")
        ask = r.json()
        # 不同包装下找到真实响应：直接键 vs result.* 嵌套。
        inner = ask.get("result") if isinstance(ask, dict) else None
        if isinstance(inner, dict):
            backend = inner.get("backend")
            response_text = inner.get("response")
            print(f"  result.backend  = {backend}")
            print(f"  result.model    = {inner.get('model')}")
            print(f"  result.response = {response_text!r}")
        else:
            backend = ask.get("backend")
            response_text = ask.get("response")
            print(f"  backend     = {backend}")
            print(f"  model       = {ask.get('model')}")
            print(f"  response    = {response_text!r}")

        # D-3 修复 (5.4b R3): 把验证放到 stop 之前，叙事顺序变成
        # "捕获 → 验证 → 清理 → 报结果"。同时保证不管验证成功还是
        # 失败都会 stop，避免失败路径把 child 进程留着。
        # R-7 修复 (5.4b R2): 200 + empty response 也是失败 —— 比如
        # hub 把 child 的回包丢了、或者 backend 走了 silent-empty 路径
        # 都会落到这里。显式断言非空字符串，让 demo 别假装成功。
        ok_walkthrough = (
            isinstance(response_text, str)
            and response_text.strip() != ""
            and backend == "hermes"
        )

        print("[step 4] stop agent ...")
        r = client.post(f"/api/v2/agents/{agent_id}/stop")
        print(f"  status={r.status_code}")

        if not ok_walkthrough:
            print(
                "[result] FAIL — got 200 but response 为空或 backend 不是 "
                "hermes; 走查 hub proxy / dummy_agent A2A handler / "
                "_HermesAskBackend 看是哪一层把内容丢了。"
            )
            return 1
        print("[result] OK — hermes → DeepSeek 真实 round-trip 通过。")
        return 0


if __name__ == "__main__":
    sys.exit(main())
