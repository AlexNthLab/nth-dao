"""Tests for examples/nth_telegram_bot.py lazy-init contract.

The bot module must be importable without TELEGRAM_BOT_TOKEN or
DEEPSEEK_API_KEY set, so that:
    - pytest can collect tests in the examples/ tree
    - static analyzers (mypy, ruff) can parse the file
    - tooling like docs-generation can introspect handlers

`_validate_env()` is only called from main(). `get_llm()` is only
called from handlers when DeepSeek is actually needed.

Lazy-init pattern originally proposed by @andy1868 in PR #7.
"""

from __future__ import annotations

import importlib
import builtins
import asyncio
import sys
import types
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    """Strip all telegram/DeepSeek env vars AND redirect ``~/.hermes/.env``
    away from the dev box so the bot's `_load_dotenv` at import time
    can't undo monkeypatch's work.
    """
    for key in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_ALLOWED_USERS",
                "DEEPSEEK_API_KEY", "KEDELAW_BOT_TOKEN", "KEDELAW_ALLOWED_USERS"):
        monkeypatch.delenv(key, raising=False)
    # Point Path.home() at a clean tmp dir so ~/.hermes/.env doesn't exist.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    # Always resolve the module from this checkout. A contributor may have
    # another nth_telegram_bot.py on sys.path; importing that file would make
    # this suite environment-dependent and could execute untrusted code.
    monkeypatch.syspath_prepend(str(EXAMPLES_DIR))
    # Force a fresh import every time, so _load_dotenv re-runs against the
    # redirected HOME and the lazy `_validate_env` is the only source of truth.
    missing = object()
    previous = sys.modules.pop("nth_telegram_bot", missing)
    try:
        yield
    finally:
        sys.modules.pop("nth_telegram_bot", None)
        if previous is not missing:
            sys.modules["nth_telegram_bot"] = previous


def _import_bot():
    return importlib.import_module("nth_telegram_bot")


def test_module_imports_without_env_vars(clean_env):
    """Import must not raise: no SystemExit, no RuntimeError, no print."""
    mod = _import_bot()
    assert hasattr(mod, "_validate_env")
    assert hasattr(mod, "get_llm")
    assert hasattr(mod, "get_runtime")
    assert hasattr(mod, "main")


def test_validate_env_raises_with_clear_message(clean_env):
    mod = _import_bot()
    with pytest.raises(RuntimeError) as excinfo:
        mod._validate_env()
    msg = str(excinfo.value)
    assert "TELEGRAM_BOT_TOKEN" in msg
    assert "DEEPSEEK_API_KEY" in msg
    assert "TELEGRAM_ALLOWED_USERS" in msg
    assert "~/.hermes/.env" in msg


def test_validate_env_passes_when_vars_present(monkeypatch, clean_env):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "123")
    mod = _import_bot()
    mod._validate_env()  # must not raise


def test_validate_env_allows_explicit_open_mode(monkeypatch, clean_env):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setenv("TELEGRAM_ALLOW_OPEN", "1")
    mod = _import_bot()
    mod._validate_env()


def test_get_llm_lazy_errors_without_key(clean_env):
    mod = _import_bot()
    # Reset singleton between tests
    mod._LLM = None
    with pytest.raises(RuntimeError, match="DEEPSEEK_API_KEY"):
        mod.get_llm()


def test_get_llm_reports_missing_openai_package(monkeypatch, clean_env):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    mod = _import_bot()
    mod._LLM = None
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "openai":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match="openai package"):
        mod.get_llm()


def test_get_llm_caches_client(monkeypatch, clean_env):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    fake_openai = types.ModuleType("openai")

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    fake_openai.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    mod = _import_bot()
    mod._LLM = None
    client1 = mod.get_llm()
    client2 = mod.get_llm()
    assert client1 is client2


def test_no_module_level_side_effects(clean_env):
    """Smoke test: importing the module twice must not double-initialize."""
    mod1 = _import_bot()
    mod2 = _import_bot()
    assert mod1 is mod2
    # Singletons untouched by import alone
    assert mod1._TEAM is None
    assert mod1._LLM is None


def test_authorized_only_blocks_unconfigured_allowlist(clean_env):
    mod = _import_bot()
    calls = []

    async def handler(update, context):
        calls.append("called")

    class Message:
        def __init__(self):
            self.replies = []
            self.text = "/start"

        async def reply_text(self, text, **_kwargs):
            self.replies.append(text)

    class User:
        id = 123
        first_name = "Alice"

    class Update:
        effective_user = User()

        def __init__(self):
            self.message = Message()

    update = Update()
    asyncio.run(mod.authorized_only(handler)(update, object()))
    assert calls == []
    assert "locked" in update.message.replies[0]


def test_authorized_only_allows_configured_user(monkeypatch, clean_env):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "123")
    mod = _import_bot()
    calls = []

    async def handler(update, context):
        calls.append("called")

    class Message:
        text = "/start"

        async def reply_text(self, text, **_kwargs):
            raise AssertionError(text)

    class User:
        id = 123
        first_name = "Alice"

    class Update:
        effective_user = User()
        message = Message()

    asyncio.run(mod.authorized_only(handler)(Update(), object()))
    assert calls == ["called"]


def test_no_mojibake_in_telegram_bot_source():
    source = (EXAMPLES_DIR / "nth_telegram_bot.py").read_text(encoding="utf-8")
    mojibake_tokens = [chr(0x9225), chr(0x9239), chr(0x6522), chr(0x6EBE), chr(0x65BA)]
    assert not any(token in source for token in mojibake_tokens)
