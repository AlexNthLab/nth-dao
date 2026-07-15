import importlib
import pathlib
import tomllib

import nth_dao
from setuptools import find_packages


def test_nth_dao_is_the_only_public_package_name():
    pyproject = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    assert data["project"]["name"] == "nth-dao"
    package_find = data["tool"]["setuptools"]["packages"]["find"]
    assert package_find["include"] == ["nth_dao*", "team_layer*"]
    assert "nth_team_layer*" not in package_find["include"]


def test_package_discovery_covers_every_importable_project_package():
    root = pathlib.Path(__file__).resolve().parents[1]
    discovered = set(find_packages(where=root))
    expected = {
        ".".join(path.relative_to(root).parent.parts)
        for path in root.glob("**/__init__.py")
        if path.parts[len(root.parts)] in {"nth_dao", "team_layer"}
    }

    assert discovered == expected


def test_package_data_excludes_stale_nested_build_metadata():
    pyproject = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    package_data = data["tool"]["setuptools"]["package-data"]

    assert "*.toml" not in package_data["nth_dao"]
    assert data["tool"]["setuptools"]["include-package-data"] is False


def test_nth_dao_import_path_exports_current_api():
    assert nth_dao.attach
    assert nth_dao.GroupManager
    assert nth_dao.TeamRole


def test_nth_dao_submodule_imports_work():
    membership = importlib.import_module("nth_dao.membership")
    orchestration = importlib.import_module("nth_dao.orchestration")

    assert membership.TeamRole.OWNER == nth_dao.TeamRole.OWNER
    assert orchestration.Mission
