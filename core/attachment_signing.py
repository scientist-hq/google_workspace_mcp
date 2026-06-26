"""Signed capability URLs for streaming attachment downloads (Design A).

Neither the Gmail nor the Drive API exposes a native public/signed download URL —
the bytes only come back from an authenticated API call carrying the user's OAuth
token. That leaves two unappealing default behaviours for a remote MCP server:

  * stateless mode returns the attachment as base64 *through the model* — slow and
    enormously token-hungry; and
  * non-stateless mode writes the file to local disk and serves it from an
    unauthenticated ``/attachments/{file_id}`` route — incompatible with a
    stateless, multi-replica hosted deployment, and a per-user authz gap.

Design A threads the needle: the tool hands the client a short-lived **signed URL**
whose token encodes the attachment reference, its owner, and an expiry. The
``/attachments/signed/{token}`` route verifies the signature, recovers the owner's
credentials, fetches the bytes from Google on demand, and streams them straight to
the client. Nothing is base64-encoded into the model and nothing is written to
disk; the signature *is* the per-user authorization.

The signing key defaults to the OAuth client secret so the feature works with no
extra configuration in the single-profile PoC, but a dedicated
``WORKSPACE_MCP_ATTACHMENT_SIGNING_KEY`` should be set for any real deployment.
"""

import os
import time
from typing import Optional

import jwt

_ALG = "HS256"
# Lifetime of a signed URL. The cached credential record (attachment_cred_cache)
# is given the same TTL so creds never outlive the link that needs them.
ATTACHMENT_URL_TTL_SECONDS = 900  # 15 minutes
_DEFAULT_TTL_SECONDS = ATTACHMENT_URL_TTL_SECONDS


def signed_attachment_urls_enabled() -> bool:
    """True when the tool should return signed streaming URLs instead of base64/disk."""
    return os.getenv("WORKSPACE_MCP_SIGNED_ATTACHMENT_URLS", "false").lower() == "true"


def _signing_key() -> str:
    """Resolve the HMAC signing key.

    Prefer a dedicated key; fall back to the OAuth client secret so the PoC works
    out of the box (the secret is already a high-entropy shared secret unique to
    the profile, and never leaves the server).
    """
    key = os.getenv("WORKSPACE_MCP_ATTACHMENT_SIGNING_KEY") or os.getenv(
        "GOOGLE_OAUTH_CLIENT_SECRET"
    )
    if not key:
        raise RuntimeError(
            "No signing key available for attachment URLs. Set "
            "WORKSPACE_MCP_ATTACHMENT_SIGNING_KEY (or GOOGLE_OAUTH_CLIENT_SECRET)."
        )
    return key


def mint_attachment_token(
    *,
    source: str,
    message_id: str,
    attachment_id: str,
    user_email: str,
    filename: Optional[str] = None,
    mime_type: Optional[str] = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
) -> str:
    """Sign a capability token referencing a single attachment for a single owner.

    Args:
        source: Origin of the attachment (currently ``"gmail"``).
        message_id: Gmail message id the attachment belongs to.
        attachment_id: Ephemeral Gmail attachment id.
        user_email: Owner whose credentials the route must use to fetch the bytes.
        filename: Resolved attachment filename, signed in so the route can name the
            download without re-resolving the (ephemeral) attachment id.
        mime_type: Resolved MIME type, signed in for the same reason.
        ttl_seconds: Lifetime of the URL.
    """
    now = int(time.time())
    payload = {
        "src": source,
        "mid": message_id,
        "aid": attachment_id,
        "sub": user_email,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    if filename:
        payload["fn"] = filename
    if mime_type:
        payload["mt"] = mime_type
    return jwt.encode(payload, _signing_key(), algorithm=_ALG)


def verify_attachment_token(token: str) -> Optional[dict]:
    """Verify and decode a capability token. Returns the claims, or None if invalid.

    Signature mismatch, expiry, and malformed tokens all return None — the route
    treats any None as a 403.
    """
    try:
        return jwt.decode(token, _signing_key(), algorithms=[_ALG])
    except Exception:
        return None


def get_signed_attachment_url(token: str) -> str:
    """Build the absolute ``/attachments/signed/{token}`` URL for a minted token.

    Mirrors ``attachment_storage.get_attachment_url`` so both routes resolve the
    same externally reachable base (reverse-proxy aware).
    """
    from core.config import WORKSPACE_MCP_PORT, WORKSPACE_MCP_BASE_URI

    external_url = os.getenv("WORKSPACE_EXTERNAL_URL")
    if external_url:
        base_url = external_url.rstrip("/")
    else:
        base_url = f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}"

    return f"{base_url}/attachments/signed/{token}"
