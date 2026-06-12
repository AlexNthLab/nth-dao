"""Phase 6c walk-through — per-token model scope demonstration.

Spawns three mock-backed agents under different ``scope_model_allowlist``
policies and exercises ``/a2a/ask`` against each to show the 6b gate's
behavior end-to-end:

  Agent A: scope = None (pre-6b shape, "defer to backend")
           — any model override flows through to the backend;
             the BACKEND'S MODEL_ALLOWLIST (6a) is the only gate.
             Mock backend has no 6a gate, so any override "passes".

  Agent B: scope = []  (tightest possible — token forbids all overrides)
           — model override of ANY value gets 403 from the 6b handler.
           — request WITHOUT params['model'] proceeds normally (the
             empty scope only blocks the override path; default-model
             path is NOT restricted — see I-2 note in
             ``token_allows_model`` docstring).

  Agent C: scope = ["safe-name"]
           — params['model'] == 'safe-name' passes 6b → backend (mock).
           — params['model'] == 'evil-opus' gets 403 from 6b.

We use the mock backend (not hermes) on purpose: mock doesn't enforce
its own MODEL_ALLOWLIST inside ``ask()``, so it isolates the 6b layer
and the test isn't conflated with 6a's per-backend policy.

Run: python demos/demo_6c_scope_walkthrough.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional


def main() -> int:
    # Windows 默认 stdout = cp936；中文跑不出来。
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass

    # 让本仓库自己的 team_layer/ 可 import (5.4b R3 教训 — 这一行
    # 不能删，nth_dao/__init__.py 启动时要 ``from team_layer import``)。
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))

    from fastapi.testclient import TestClient
    from nth_dao.cap_token import encode_authorization_header
    from nth_dao.web import create_app

    cleanup_kwargs: dict = {"prefix": "nth-6c-walk-"}
    if sys.version_info >= (3, 10):
        cleanup_kwargs["ignore_cleanup_errors"] = True

    failures: list[str] = []

    with tempfile.TemporaryDirectory(**cleanup_kwargs) as tmp_dir:
        workspace = Path(tmp_dir)
        print(f"[setup] workspace = {workspace}")
        app = create_app(workspace=workspace, require_console_auth=False)
        client = TestClient(app)

        spawned_agent_ids: list[str] = []

        def spawn(label: str, scope: Optional[list]) -> tuple[str, str]:
            """Spawn a mock agent. Returns (did, CapToken-encoded auth)."""
            body: dict = {
                "kind": "mock", "label": label,
                "capabilities": ["a2a:message_send"],
            }
            if scope is not None:
                body["scope_model_allowlist"] = scope
            r = client.post("/api/v2/agents/spawn", json=body)
            assert r.status_code == 201, r.text
            spawn_data = r.json()
            # Record the agent_id at spawn time so cleanup doesn't have
            # to re-derive it from the listing (whose schema doesn't
            # expose agent_id by design — only DID + capabilities).
            spawned_agent_ids.append(spawn_data["agent_id"])
            cap_token_id = spawn_data["cap_token_id"]
            cap_token_path = (
                workspace / "team_cap_tokens" / f"{cap_token_id}.json"
            )
            cap_token = json.loads(cap_token_path.read_text(encoding="utf-8"))
            return spawn_data["did"], encode_authorization_header(cap_token)

        def ask(
            did: str, auth: str,
            *, model: Optional[str] = None,
        ) -> tuple[int, dict]:
            payload: dict = {"prompt": "ping"}
            if model is not None:
                payload["model"] = model
            r = client.post(
                f"/api/v2/agents/{did}/a2a/ask",
                headers={"Authorization": f"CapToken {auth}"},
                json=payload, timeout=30.0,
            )
            return r.status_code, r.json()

        def expect(
            label: str, got_status: int, got_body: dict,
            *,
            want_status: int, want_code: Optional[str] = None,
        ) -> None:
            ok = got_status == want_status
            if want_code is not None:
                err_code = (
                    got_body.get("error", {}).get("code")
                    if isinstance(got_body, dict) else None
                )
                ok = ok and (err_code == want_code)
            marker = "[OK]  " if ok else "[FAIL]"
            print(f"  {marker} {label}: status={got_status}")
            if want_code is not None:
                print(f"         expected error.code={want_code!r}, got "
                      f"{got_body.get('error', {}).get('code')!r}")
            if want_status == 200:
                resp = got_body.get("result", {}).get("response", "")
                print(f"         response = {resp!r}")
            if not ok:
                failures.append(label)

        # ── Agent A — no scope (pre-6b shape) ───────────────────────
        print("\n[step A] spawn mock agent with scope=None (legacy shape)")
        did_a, auth_a = spawn("no-scope", None)

        # 子端要先 poll cap_token 文件。轮询默认 1s 一次，几次 retry。
        import time
        for _ in range(20):
            status, body = ask(did_a, auth_a)  # no model override
            if not (status == 401 and "not-yet-authorized" in str(body)):
                break
            time.sleep(0.3)

        expect(
            "A1: no model override, no scope → 200",
            status, body, want_status=200,
        )
        status, body = ask(did_a, auth_a, model="evil-opus")
        expect(
            "A2: model override, no scope → 200 (defer to backend; "
            "mock has no 6a gate)",
            status, body, want_status=200,
        )

        # ── Agent B — empty scope (forbid all overrides) ───────────
        print("\n[step B] spawn mock agent with scope=[] (forbid overrides)")
        did_b, auth_b = spawn("empty-scope", [])

        for _ in range(20):
            status, body = ask(did_b, auth_b)
            if not (status == 401 and "not-yet-authorized" in str(body)):
                break
            time.sleep(0.3)

        expect(
            "B1: no model override, scope=[] → 200 "
            "(default-path NOT restricted by empty scope, see I-2)",
            status, body, want_status=200,
        )
        status, body = ask(did_b, auth_b, model="claude-opus-4-8")
        expect(
            "B2: model='claude-opus-4-8', scope=[] → 403 "
            "model-not-in-token-scope",
            status, body,
            want_status=403, want_code="model-not-in-token-scope",
        )

        # ── Agent C — scoped list ───────────────────────────────────
        print("\n[step C] spawn mock agent with scope=['safe-model-name']")
        did_c, auth_c = spawn("scoped", ["safe-model-name"])

        for _ in range(20):
            status, body = ask(did_c, auth_c, model="safe-model-name")
            if not (status == 401 and "not-yet-authorized" in str(body)):
                break
            time.sleep(0.3)

        expect(
            "C1: model='safe-model-name', scope=['safe-model-name'] → 200",
            status, body, want_status=200,
        )
        status, body = ask(did_c, auth_c, model="evil-opus")
        expect(
            "C2: model='evil-opus', scope=['safe-model-name'] → 403 "
            "(off-list)",
            status, body,
            want_status=403, want_code="model-not-in-token-scope",
        )

        # ── Layer demonstration: 6b + 6a together ─────────────────
        # Agent C requests "safe-model-name" — passes 6b (in scope).
        # But mock doesn't enforce 6a, so the request goes through.
        # To prove 6a still applies under 6b, we need a backend that
        # has its own MODEL_ALLOWLIST. Hermes is the most accessible
        # demo target locally; without ANTHROPIC_API_KEY codex needs
        # OAuth. Skip the hermes leg here — it's covered by 5.4b's
        # walkthrough (which exercises hermes default path) plus
        # the 6B-11 unit test (which exercises the intersection
        # without a live LLM round-trip).

        # ── Cleanup: stop the agents we spawned ───────────────────
        for agent_id in spawned_agent_ids:
            client.post(f"/api/v2/agents/{agent_id}/stop")

    print()
    if failures:
        print(f"[result] FAIL — {len(failures)} expectation(s) missed:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("[result] OK — Phase 6b per-token scope gate "
          "behaves as designed across all 6 probes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
