from __future__ import annotations

from types import SimpleNamespace

import pytest

from nth_dao.trade_rules.dispute_statement_dispatch import (
    TradeDisputeStatementDispatchStore,
)
from nth_dao.trade_rules.execution_dispatch import _is_linklike as execution_linklike
from nth_dao.trade_rules.receipt_review_dispatch import (
    _is_linklike as review_linklike,
)
from nth_dao.util import path_security


class _Candidate:
    def is_symlink(self) -> bool:
        return False

    def is_junction(self) -> bool:
        return False


_CHECKS = (
    path_security.path_is_linklike,
    TradeDisputeStatementDispatchStore._is_linklike,
    execution_linklike,
    review_linklike,
)


@pytest.mark.parametrize("check", _CHECKS)
def test_linklike_check_treats_a_vanished_sqlite_sidecar_as_absent(
    monkeypatch,
    check,
):
    monkeypatch.setattr(path_security.os, "name", "nt")
    monkeypatch.setattr(
        path_security.os,
        "lstat",
        lambda _path: (_ for _ in ()).throw(FileNotFoundError()),
    )

    assert check(_Candidate()) is False


def test_linklike_check_does_not_hide_permission_failures(monkeypatch):
    monkeypatch.setattr(path_security.os, "name", "nt")
    monkeypatch.setattr(
        path_security.os,
        "lstat",
        lambda _path: (_ for _ in ()).throw(PermissionError("denied")),
    )

    with pytest.raises(PermissionError, match="denied"):
        path_security.path_is_linklike(_Candidate())


def test_linklike_check_still_rejects_windows_reparse_points(monkeypatch):
    monkeypatch.setattr(path_security.os, "name", "nt")
    monkeypatch.setattr(
        path_security.os,
        "lstat",
        lambda _path: SimpleNamespace(st_file_attributes=0x400),
    )

    assert path_security.path_is_linklike(_Candidate()) is True
