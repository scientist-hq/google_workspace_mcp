"""Per-source fetchers for signed download URLs (Design A).

The ``/attachments/signed`` route is source-agnostic: it verifies the token,
recovers the owner's Google credentials, then hands the claims off to the fetcher
registered for ``claims["src"]``. Each fetcher turns the source-specific claims +
credentials into ``(bytes, filename, mime_type)``; the route streams the result.

Adding a new download source = add a fetcher and register it. Nothing else in the
route changes.
"""

import asyncio
import base64
import binascii
import io
import logging
from typing import Awaitable, Callable, Optional, Tuple

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

logger = logging.getLogger(__name__)

# (bytes, filename, mime_type)
FetchResult = Tuple[bytes, str, str]


class SignedDownloadError(Exception):
    """Raised when a fetcher cannot produce the bytes (maps to a 502 in the route)."""


async def _fetch_gmail(claims: dict, credentials: Credentials) -> FetchResult:
    """Fetch a Gmail attachment by message + attachment id.

    Gmail attachment ids are ephemeral and rotate between fetches, so the filename
    is resolved here (after the bytes are in hand) by matching the message payload
    on byte size — the stable key, matching the download tool's own fallback.
    """
    from gmail.gmail_tools import _extract_attachments

    message_id = claims.get("mid")
    attachment_id = claims.get("aid")
    if not (message_id and attachment_id):
        raise SignedDownloadError("Gmail token missing mid/aid")

    gmail = build("gmail", "v1", credentials=credentials)
    try:
        attachment = await asyncio.to_thread(
            gmail.users()
            .messages()
            .attachments()
            .get(userId="me", messageId=message_id, id=attachment_id)
            .execute
        )
    except Exception as exc:
        raise SignedDownloadError(f"Gmail attachment fetch failed: {exc}") from exc

    data = attachment.get("data", "")
    if not data:
        raise SignedDownloadError("Gmail attachment has no content")

    # Gmail returns URL-safe base64; pad before decoding.
    try:
        raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (binascii.Error, ValueError) as exc:
        raise SignedDownloadError(f"Gmail attachment decode failed: {exc}") from exc

    filename = claims.get("fn") or "attachment"
    media_type = claims.get("mt") or "application/octet-stream"
    if not claims.get("fn"):
        try:
            meta = await asyncio.to_thread(
                gmail.users()
                .messages()
                .get(
                    userId="me",
                    id=message_id,
                    format="full",
                    fields="payload(parts(filename,mimeType,body(attachmentId,size)),body(attachmentId,size),filename,mimeType)",
                )
                .execute
            )
            atts = _extract_attachments(meta.get("payload", {}))

            chosen = None
            for att in atts:  # exact id first (covers the not-yet-rotated case)
                if att.get("attachmentId") == attachment_id:
                    chosen = att
                    break
            if chosen is None:  # else the attachment whose size matches the bytes
                size_matches = [
                    att
                    for att in atts
                    if att.get("size") and abs(att["size"] - len(raw)) < 100
                ]
                if len(size_matches) == 1:
                    chosen = size_matches[0]
            if chosen is None and len(atts) == 1:  # else the only attachment
                chosen = atts[0]

            if chosen:
                filename = chosen.get("filename") or filename
                media_type = chosen.get("mimeType") or media_type
        except Exception:
            logger.debug("Could not resolve Gmail filename; using defaults")

    return raw, filename, media_type


async def _fetch_drive(claims: dict, credentials: Credentials) -> FetchResult:
    """Fetch a Drive file by id, exporting native Google files when ``emt`` is set.

    Drive file ids are stable, so filename/MIME are resolved at mint time and
    signed into the token (``fn``/``mt``); this fetcher just streams the bytes.
    """
    file_id = claims.get("fid")
    if not file_id:
        raise SignedDownloadError("Drive token missing fid")
    export_mime = claims.get("emt")  # set only for native Google file exports

    drive = build("drive", "v3", credentials=credentials)
    request_obj = (
        drive.files().export_media(fileId=file_id, mimeType=export_mime)
        if export_mime
        else drive.files().get_media(fileId=file_id)
    )

    buffer = io.BytesIO()
    downloader = MediaIoBaseDownload(buffer, request_obj)
    try:
        done = False
        while not done:
            _status, done = await asyncio.to_thread(downloader.next_chunk)
    except Exception as exc:
        raise SignedDownloadError(f"Drive download failed: {exc}") from exc

    filename = claims.get("fn") or "download"
    media_type = claims.get("mt") or export_mime or "application/octet-stream"
    return buffer.getvalue(), filename, media_type


_FETCHERS: dict[str, Callable[[dict, Credentials], Awaitable[FetchResult]]] = {
    "gmail": _fetch_gmail,
    "drive": _fetch_drive,
}


def get_fetcher(source: str) -> Optional[Callable[[dict, Credentials], Awaitable[FetchResult]]]:
    """Return the fetcher for a token source, or None if unsupported."""
    return _FETCHERS.get(source)
