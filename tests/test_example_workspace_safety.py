"""Executable examples must never clean a user's repository workspace."""

from __future__ import annotations

import ast
import importlib
import tempfile
from pathlib import Path

from examples.demo_workspace import new_demo_workspace


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = (
    "evo_demo.py",
    "blackboard_demo.py",
    "sync_demo.py",
    "nth_demo.py",
    "real_world_demo.py",
    "multi_backend_demo.py",
    "integration_demo.py",
)
_DESTRUCTIVE_CALLS = {"rmtree", "unlink", "remove", "removedirs"}


def test_demo_workspace_is_unique_uncreated_and_outside_repository() -> None:
    first = new_demo_workspace("safety-check")
    second = new_demo_workspace("safety-check")

    assert first != second
    assert first.parent == Path(tempfile.gettempdir()).resolve()
    assert not first.exists()
    assert ROOT.resolve() not in first.parents


def test_executable_examples_have_no_destructive_file_operations() -> None:
    for filename in EXAMPLES:
        path = ROOT / "examples" / filename
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert not calls.intersection(_DESTRUCTIVE_CALLS), filename


def test_executable_examples_use_the_nth_dao_public_facade() -> None:
    for filename in EXAMPLES:
        path = ROOT / "examples" / filename
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        legacy_imports = [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and isinstance(node.module, str)
            and node.module.startswith("team_layer")
        ]
        assert legacy_imports == [], f"{filename}: {legacy_imports}"


def test_executable_examples_are_importable_as_modules() -> None:
    for filename in EXAMPLES:
        module_name = f"examples.{Path(filename).stem}"
        importlib.import_module(module_name)
