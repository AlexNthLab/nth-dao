from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_publish_workflow_has_release_quality_gates():
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )

    required = (
        "python tools/release_gate.py",
        "python -m pytest -q",
        "npm ci",
        "npm run test:raw -- --fileParallelism=false",
        "npm run build:raw",
        "python -m twine check dist/*",
        "python tools/release_gate.py --dist dist/*",
        "Smoke-test wheel in a clean environment",
    )
    for command in required:
        assert command in workflow


def test_publish_workflow_uses_current_project_urls_only():
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )

    assert "nth-team-layer" not in workflow
    assert "https://test.pypi.org/project/nth-dao/" in workflow
    assert "https://pypi.org/project/nth-dao/" in workflow


def test_publish_workflow_is_ascii_without_mojibake():
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )

    assert all(ord(character) < 128 for character in workflow)
