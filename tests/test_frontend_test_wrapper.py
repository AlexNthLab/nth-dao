"""The frontend test wrapper must retain deterministic defaults with filters."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "frontend" / "scripts" / "run-vitest.ps1"


def _invoke_wrapper(tmp_path: Path, *arguments: str) -> str:
    powershell = shutil.which("powershell")
    if powershell is None or os.name != "nt":
        pytest.skip("PowerShell wrapper test requires Windows PowerShell")
    fake_node = tmp_path / "fake-node.cmd"
    fake_node.write_text("@echo off\r\necho %*\r\n", encoding="ascii")
    env = {**os.environ, "NTH_DAO_NODE": str(fake_node)}
    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            *arguments,
        ],
        cwd=str(ROOT / "frontend"),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def test_wrapper_keeps_defaults_when_run_flag_is_supplied(tmp_path) -> None:
    output = _invoke_wrapper(tmp_path, "--run")
    assert "--run" in output
    assert "--environment jsdom" in output
    assert "--fileParallelism=false" in output


def test_wrapper_allows_explicit_environment_and_parallelism(tmp_path) -> None:
    output = _invoke_wrapper(
        tmp_path,
        "--run",
        "--environment",
        "node",
        "--fileParallelism=true",
    )
    assert "--environment node" in output
    assert "--fileParallelism=true" in output
    assert "--environment jsdom" not in output
    assert "--fileParallelism=false" not in output
