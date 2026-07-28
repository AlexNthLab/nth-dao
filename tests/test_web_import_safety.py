"""Importing the web package must not mutate the operator workspace."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


def test_import_nth_dao_web_has_no_workspace_side_effect(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    env["USERPROFILE"] = str(tmp_path)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import pathlib; import nth_dao.web; "
                "p=pathlib.Path.home()/'.nth-dao'; "
                "raise SystemExit(1 if p.exists() else 0)"
            ),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
