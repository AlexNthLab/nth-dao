"""Hostile and conforming subprocess RPC worker modes for tests only."""

from __future__ import annotations

import json
import os
import sys
import time


PROTOCOL = "nth-dao-plugin-rpc"
VERSION = 1


def read_document():
    line = sys.stdin.buffer.readline()
    if not line:
        raise EOFError
    return json.loads(line)


def write_document(value):
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "normal"
    if mode == "handshake-hang":
        time.sleep(30)
        return
    hello = read_document()
    ready = dict(hello)
    ready["type"] = "ready"
    if mode == "bad-ready":
        ready["nonce"] = "0" * 32
    write_document(ready)

    if mode == "flood":
        for index in range(16):
            write_document({"unexpected": index})
    if mode == "single-unsolicited":
        write_document({"unexpected": 1})

    while True:
        request = read_document()
        if request.get("type") == "shutdown":
            write_document(
                {
                    "protocol": PROTOCOL,
                    "version": VERSION,
                    "type": "stopped",
                    "request_id": request["request_id"],
                }
            )
            return
        if mode == "hang":
            time.sleep(30)
            return
        if mode == "crash":
            os._exit(7)
        if mode == "stderr-secret":
            sys.stderr.write("secret-token-must-not-surface\n")
            sys.stderr.flush()
            os._exit(9)
        if mode == "stderr-flood":
            sys.stderr.write("x" * (128 * 1024))
            sys.stderr.flush()
            time.sleep(30)
            return
        if mode == "oversize":
            sys.stdout.buffer.write(b"x" * (3 * 1024 * 1024) + b"\n")
            sys.stdout.buffer.flush()
            continue
        if mode == "malformed":
            sys.stdout.buffer.write(b"{broken-json\n")
            sys.stdout.buffer.flush()
            continue
        if mode == "noncanonical":
            value = {
                "protocol": PROTOCOL,
                "version": VERSION,
                "type": "result",
                "invocation_id": request["invocation_id"],
                "ok": True,
                "output": {"value": request["payload"]["value"]},
            }
            sys.stdout.write(json.dumps(value) + "\n")
            sys.stdout.flush()
            continue
        invocation_id = request["invocation_id"]
        if mode == "wrong-id":
            invocation_id = "f" * 32
        if mode == "remote-error":
            write_document(
                {
                    "protocol": PROTOCOL,
                    "version": VERSION,
                    "type": "result",
                    "invocation_id": invocation_id,
                    "ok": False,
                    "error": {
                        "code": "not-ready",
                        "message": "worker is warming up",
                        "retryable": True,
                    },
                }
            )
            continue
        if mode == "invalid-output":
            write_document(
                {
                    "protocol": PROTOCOL,
                    "version": VERSION,
                    "type": "result",
                    "invocation_id": invocation_id,
                    "ok": True,
                    "output": {"value": 7},
                }
            )
            continue
        value = request["payload"]["value"]
        if mode == "environment":
            value = (
                os.environ.get("EXPLICIT_VALUE", "missing")
                + "|"
                + ("leaked" if os.environ.get("NTH_SECRET_SHOULD_NOT_LEAK") else "clean")
            )
        write_document(
            {
                "protocol": PROTOCOL,
                "version": VERSION,
                "type": "result",
                "invocation_id": invocation_id,
                "ok": True,
                "output": {"value": value},
            }
        )


if __name__ == "__main__":
    main()
