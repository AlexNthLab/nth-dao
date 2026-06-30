"""Live Hermes walk-through through the NTH DAO hub.

This demo starts the web hub in-process with a temporary workspace, spawns a
``kind=hermes`` supervised agent, reads the issued cap_token from disk, and
sends one real A2A ``ask`` request through the hub proxy.

This is intentionally opt-in because it can call a real model provider. Set
``NTH_HERMES_REPO`` to the local hermes-agent repository root before running:

    NTH_HERMES_REPO=/path/to/hermes-agent python demos/demo_5_4b_hermes_walkthrough.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_HERMES_REPO = ""


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass

    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))

    hermes_repo = os.environ.get("NTH_HERMES_REPO", DEFAULT_HERMES_REPO).strip()
    if not hermes_repo or not Path(hermes_repo).exists():
        print(
            "[setup] FAIL — set NTH_HERMES_REPO to the hermes-agent "
            "repository root before running this live walkthrough."
        )
        return 1

    existing = os.environ.get("PYTHONPATH", "")
    os.environ["PYTHONPATH"] = hermes_repo + (os.pathsep + existing if existing else "")

    from fastapi.testclient import TestClient
    from nth_dao.cap_token import encode_authorization_header
    from nth_dao.web import create_app

    cleanup_kwargs: dict = {"prefix": "nth-walkthrough-"}
    if sys.version_info >= (3, 10):
        cleanup_kwargs["ignore_cleanup_errors"] = True

    with tempfile.TemporaryDirectory(**cleanup_kwargs) as tmp_dir:
        workspace = Path(tmp_dir)
        print("[setup] temporary workspace created")

        app = create_app(workspace=workspace, require_console_auth=False)
        client = TestClient(app)

        print("[step 1] spawn Hermes agent")
        t0 = time.time()
        resp = client.post(
            "/api/v2/agents/spawn",
            json={
                "kind": "hermes",
                "label": "hermes-demo",
                "capabilities": ["a2a:message_send"],
                "persist": False,
            },
        )
        print(f"  status={resp.status_code} elapsed={time.time() - t0:.1f}s")
        if resp.status_code != 201:
            print(f"  body={resp.text[:500]}")
            return 1

        spawn = resp.json()
        agent_id = spawn["agent_id"]
        did = spawn["did"]
        cap_token_id = spawn["cap_token_id"]
        print(f"  did={did}")
        print(f"  cap_token_id={cap_token_id}")
        print(f"  a2a_port={spawn.get('a2a_port')}")

        print("[step 2] read issued cap_token")
        cap_token_path = workspace / "team_cap_tokens" / f"{cap_token_id}.json"
        if not cap_token_path.exists():
            print("  FAIL cap_token file was not written")
            return 1
        cap_token = json.loads(cap_token_path.read_text(encoding="utf-8"))
        encoded = encode_authorization_header(cap_token)

        prompt = "Reply with exactly one short sentence confirming Hermes is reachable."
        print("[step 3] A2A ask through hub proxy")
        deadline = time.time() + 10.0
        ask_resp = None
        t0 = time.time()
        while time.time() < deadline:
            ask_resp = client.post(
                f"/api/v2/agents/{did}/a2a/ask",
                headers={"Authorization": f"CapToken {encoded}"},
                json={"prompt": prompt},
                timeout=180.0,
            )
            if ask_resp.status_code == 401 and "not-yet-authorized" in ask_resp.text:
                time.sleep(0.5)
                continue
            break

        if ask_resp is None:
            print("  FAIL ask was not attempted")
            return 1
        print(f"  status={ask_resp.status_code} elapsed={time.time() - t0:.1f}s")
        if ask_resp.status_code != 200:
            print(f"  body={ask_resp.text[:800]}")
            return 1

        data = ask_resp.json()
        inner = data.get("result") if isinstance(data, dict) else None
        payload = inner if isinstance(inner, dict) else data
        backend = payload.get("backend") if isinstance(payload, dict) else None
        response_text = payload.get("response") if isinstance(payload, dict) else None
        print(f"  backend={backend}")
        print(f"  response={response_text!r}")

        print("[step 4] stop agent")
        stop = client.post(f"/api/v2/agents/{agent_id}/stop")
        print(f"  status={stop.status_code}")

        if not isinstance(response_text, str) or not response_text.strip() or backend != "hermes":
            print("[result] FAIL — Hermes response was empty or routed through the wrong backend.")
            return 1
        print("[result] OK — Hermes round-trip succeeded.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
