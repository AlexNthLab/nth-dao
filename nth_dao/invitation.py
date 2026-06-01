"""Invitation tokens — bootstrap trust with one scan / link / paste.

Problem this solves:
    To join a NTH DAO team you currently need (a) the team's `team.json`
    out-of-band, (b) the team's join_token for `JoinPolicy.TOKEN`, AND
    (c) the team owner's pubkey to verify subsequent signed state. That's
    3 separate pieces. Bad UX.

Solution:
    `Invitation` packages all of them into one self-contained, URL-safe
    string that fits inside a QR code:

        nthdao+invite://<base64-payload>

    Payload (JSON, base64url):
        {
            "team_id":      "<short id>",
            "team_name":    "...",
            "owner_pubkey": "<hex>",   # for verifying signed team.json
            "join_token":   "...",     # for JoinPolicy.TOKEN; "" if not needed
            "ws_url":       "ws://192.168.1.5:9876",   # optional bootstrap peer
            "psk":          "...",     # optional LAN discovery psk
            "issued_at":    "<iso>",
            "expires_at":   "<iso>",
            "issuer":       "<owner agent_id>",
            "sig":          "<hex>"    # owner signs the payload-sans-sig
        }

Usage:
    # On the owner's machine:
    inv = nth.Invitation.mint(
        team_config=team.membership.load_config(),
        owner_identity=alice,
        ws_url="ws://192.168.1.5:9876",
        ttl_days=7,
    )
    url = inv.to_url()              # nthdao+invite://AAAAB3Nz...
    png_bytes = inv.to_qr_png()     # optional, requires `qrcode` extra

    # On the joiner's machine:
    inv = nth.Invitation.from_url(url)
    inv.verify_signature()          # raises if signature is invalid
    team = nth.attach(
        agent_id="bob",
        workspace="./team",
        join_token=inv.join_token,   # bypasses TOKEN policy
    )
    # Optionally pin the owner_pubkey so subsequent signed team.json verifies:
    # (handled automatically by attach when the invitation pins it)

QR support is optional: `pip install nth-dao[ux]` installs `qrcode[pil]`.
Without it, `to_qr_png()` raises ImportError and you can still use `to_url()`.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from .identity import (
    AgentIdentity,
    _NACL_AVAILABLE,
    _VerifyKey,
    canonical_json,
)

logger = logging.getLogger("nth_dao.invitation")


INVITE_URL_SCHEME = "nthdao+invite://"
DEFAULT_INVITE_TTL_DAYS = 7
MAX_INVITE_BYTES = 2048  # leaves room for QR error correction


class InvitationError(Exception):
    """Generic invitation-validation error."""


@dataclass
class Invitation:
    """A signed packet that lets a new agent bootstrap trust in a team."""

    team_id: str
    team_name: str
    owner_pubkey: str
    issuer: str
    issued_at: str = field(default_factory=lambda: datetime.now().isoformat())
    expires_at: str = ""
    join_token: str = ""
    ws_url: str = ""
    psk: str = ""
    sig: str = ""

    # ── lifecycle / serde ──

    def signable_dict(self) -> dict:
        d = asdict(self)
        d.pop("sig", None)
        return d

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Invitation":
        return cls(
            team_id=data.get("team_id", ""),
            team_name=data.get("team_name", ""),
            owner_pubkey=data.get("owner_pubkey", ""),
            issuer=data.get("issuer", ""),
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at", ""),
            join_token=data.get("join_token", ""),
            ws_url=data.get("ws_url", ""),
            psk=data.get("psk", ""),
            sig=data.get("sig", ""),
        )

    # ── verification ──

    @property
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            return datetime.fromisoformat(self.expires_at) < datetime.now()
        except ValueError:
            return True

    def verify_signature(self) -> bool:
        """Verify the invitation was signed by `owner_pubkey`."""
        if not (_NACL_AVAILABLE and _VerifyKey and self.sig and self.owner_pubkey):
            return False
        try:
            payload = canonical_json(self.signable_dict())
            _VerifyKey(bytes.fromhex(self.owner_pubkey)).verify(
                payload, bytes.fromhex(self.sig),
            )
            return True
        except Exception:
            return False

    def validate(self) -> None:
        """Raise InvitationError on any problem; otherwise return None."""
        if not self.team_id or not self.owner_pubkey:
            raise InvitationError("invitation missing team_id or owner_pubkey")
        if self.is_expired:
            raise InvitationError(f"invitation expired at {self.expires_at}")
        if not self.verify_signature():
            raise InvitationError("invitation signature does not verify")

    # ── URL encoding ──

    def to_url(self) -> str:
        """Encode as URL-safe `nthdao+invite://...` string."""
        raw = json.dumps(
            self.to_dict(), separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        if len(raw) > MAX_INVITE_BYTES:
            raise InvitationError(
                f"invitation payload too large ({len(raw)} bytes > "
                f"{MAX_INVITE_BYTES}); strip ws_url or psk if needed"
            )
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        return f"{INVITE_URL_SCHEME}{encoded}"

    @classmethod
    def from_url(cls, url: str) -> "Invitation":
        if not url.startswith(INVITE_URL_SCHEME):
            raise InvitationError(
                f"not a nthdao invitation URL (must start with {INVITE_URL_SCHEME})"
            )
        body = url[len(INVITE_URL_SCHEME):]
        # Re-pad base64
        padding = "=" * (-len(body) % 4)
        try:
            raw = base64.urlsafe_b64decode(body + padding)
        except (ValueError, TypeError) as e:
            raise InvitationError(f"invalid base64: {e}") from e
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise InvitationError(f"invalid invitation JSON: {e}") from e
        if not isinstance(data, dict):
            raise InvitationError("invitation payload is not a dict")
        return cls.from_dict(data)

    # ── QR ──

    def to_qr_png(self) -> bytes:
        """Render the invitation URL as a PNG QR code.

        Requires `pip install nth-dao[ux]` (qrcode + pillow).
        """
        try:
            import qrcode  # type: ignore
        except ImportError as e:
            raise ImportError(
                "to_qr_png() requires the [ux] extra: "
                "pip install nth-dao[ux] (installs qrcode + pillow)"
            ) from e
        url = self.to_url()
        img = qrcode.make(url, box_size=8, border=2)
        # Write PNG bytes to memory
        import io
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    def to_qr_terminal(self) -> str:
        """ASCII QR code suitable for printing to a terminal (no PIL needed).

        Uses qrcode's built-in print_ascii; still requires `qrcode` lib but
        not pillow.
        """
        try:
            import qrcode  # type: ignore
        except ImportError as e:
            raise ImportError(
                "to_qr_terminal() requires `pip install qrcode` "
                "(or the [ux] extra)"
            ) from e
        import io
        q = qrcode.QRCode(border=2)
        q.add_data(self.to_url())
        q.make(fit=True)
        out = io.StringIO()
        q.print_ascii(out=out, tty=False, invert=False)
        return out.getvalue()

    # ── mint ──

    @classmethod
    def mint(
        cls,
        team_config: Any,                  # TeamConfig — typed loosely to avoid cycle
        owner_identity: AgentIdentity,
        ws_url: str = "",
        psk: str = "",
        ttl_days: int = DEFAULT_INVITE_TTL_DAYS,
    ) -> "Invitation":
        """Owner creates a signed invitation snapshot from current team config.

        Raises:
            ValueError: owner_identity can't sign, or owner_pubkey on
                        team_config doesn't match owner_identity (you can't
                        mint invitations for a team you don't own).
        """
        if not owner_identity.can_sign:
            raise ValueError("mint() requires a signing-capable identity")
        cfg_owner_pubkey = getattr(team_config, "owner_pubkey", "")
        if cfg_owner_pubkey and cfg_owner_pubkey != owner_identity.pubkey_hex:
            raise ValueError(
                "owner_identity pubkey does not match team_config.owner_pubkey "
                "— only the legitimate owner can mint invitations"
            )

        inv = cls(
            team_id=getattr(team_config, "team_id", ""),
            team_name=getattr(team_config, "team_name", ""),
            owner_pubkey=owner_identity.pubkey_hex,
            issuer=str(owner_identity.agent_id),
            issued_at=datetime.now().isoformat(),
            expires_at=(datetime.now() + timedelta(days=ttl_days)).isoformat(),
            join_token=getattr(team_config, "join_token", "") or "",
            ws_url=ws_url,
            psk=psk,
        )
        inv.sig = owner_identity.sign_json(inv.signable_dict())
        return inv
