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
import urllib.request
from pathlib import Path


def main() -> int:
    # Windows 默认 stdout 是 cp936；中文响应会被替成 ? 显示不出来。
    # 强制走 UTF-8 让 print 的中文在终端里可读。
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — Python < 3.7 兼容
        pass
    # 把 hermes-team-agent 包加进 import path:
    #   • sys.path 是给本进程的（用不上，本进程不直接 import run_agent）。
    #   • PYTHONPATH 才是关键 —— supervisor 用 sys.executable 把
    #     dummy_agent 拉起来跑子进程，子进程才是真正 import run_agent
    #     的地方。PYTHONPATH 会被子进程继承。
    hermes_path = r"C:/Users/TonyWU/Desktop/hermes-team-agent"
    sys.path.insert(0, hermes_path)
    existing = os.environ.get("PYTHONPATH", "")
    os.environ["PYTHONPATH"] = (
        hermes_path + (os.pathsep + existing if existing else "")
    )

    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    with tempfile.TemporaryDirectory(prefix="nth-walkthrough-") as tmp_dir:
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
            print(f"  result.backend  = {inner.get('backend')}")
            print(f"  result.model    = {inner.get('model')}")
            print(f"  result.response = {inner.get('response')!r}")
        else:
            print(f"  backend     = {ask.get('backend')}")
            print(f"  model       = {ask.get('model')}")
            print(f"  response    = {ask.get('response')!r}")

        print("[step 4] stop agent ...")
        r = client.post(f"/api/v2/agents/{agent_id}/stop")
        print(f"  status={r.status_code}")

        return 0


if __name__ == "__main__":
    sys.exit(main())
