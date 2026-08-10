"""Fold a verified Spine event stream into materialized views."""
from __future__ import annotations

from typing import Iterable

from nth_dao.spine.event import SpineEvent


class Projection:
    """Base class for incrementally materializing an event stream."""

    def apply(self, event: SpineEvent) -> None:
        raise NotImplementedError

    def reset(self) -> None:
        """Clear internal state before replay; stateless by default."""


def replay(events: Iterable[SpineEvent], *projections: Projection) -> None:
    """Feed ordered, already verified events to each projection."""
    for ev in events:
        for p in projections:
            p.apply(ev)
