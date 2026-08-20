"""Host-owned verification and persistence boundary for peer candidates."""

from __future__ import annotations

import hmac
import time
from pathlib import Path
from typing import Any, Optional

from nth_dao.did_key import is_did_key
from nth_dao.discovery.federation_registry import LearnedPeerStore
from nth_dao.plugins.federation_trust import (
    FederationTrustKernel,
    VerifiedFederationIdentity,
)


class FederationPeerAdmission:
    """Keep identity verification and core peer storage outside providers."""

    def __init__(self, workspace: Path, *, trust_kernel: Any = None) -> None:
        self.workspace = Path(workspace).resolve()
        self._trust_kernel = (
            FederationTrustKernel() if trust_kernel is None else trust_kernel
        )
        if not callable(
            getattr(self._trust_kernel, "verify_public_hint_identity", None)
        ):
            raise TypeError("trust_kernel must verify public federation hints")
        self._peer_store = LearnedPeerStore(self.workspace)

    def verify_candidate(
        self,
        peer_url: str,
        *,
        expected_did: str = "",
        timeout_seconds: float,
    ) -> Optional[VerifiedFederationIdentity]:
        if expected_did and (
            not isinstance(expected_did, str) or not is_did_key(expected_did)
        ):
            raise ValueError("expected peer DID is invalid")
        verified = self._trust_kernel.verify_public_hint_identity(
            peer_url,
            timeout_seconds=timeout_seconds,
        )
        if verified is None:
            return None
        if expected_did and not hmac.compare_digest(
            verified.endpoint.did, expected_did,
        ):
            return None
        return verified

    def persist_verified(self, verified: VerifiedFederationIdentity) -> None:
        if not isinstance(verified, VerifiedFederationIdentity):
            raise TypeError("verified federation identity is required")
        endpoint = verified.endpoint
        if endpoint.network_scope != "public":
            raise ValueError("registry admission requires a public peer binding")
        endpoint.require_current(int(time.time() * 1000))
        self._peer_store.upsert_verified(
            endpoint.url,
            verified.learned_metadata(),
            resolved_ip=endpoint.resolved_ip,
        )


__all__ = ["FederationPeerAdmission"]
