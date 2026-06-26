"""Tests for signed attachment capability tokens (Design A).

The token is the per-user authorization for the /attachments/signed route, so the
security-relevant properties are: a valid token round-trips, a tampered or
wrong-key token is rejected, and an expired token is rejected.
"""

import time

import jwt
import pytest

from core import attachment_signing as sign


@pytest.fixture(autouse=True)
def _signing_key(monkeypatch):
    monkeypatch.setenv("WORKSPACE_MCP_ATTACHMENT_SIGNING_KEY", "test-signing-key")
    yield


class TestEnabledFlag:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("WORKSPACE_MCP_SIGNED_ATTACHMENT_URLS", raising=False)
        assert sign.signed_attachment_urls_enabled() is False

    def test_enabled_when_true(self, monkeypatch):
        monkeypatch.setenv("WORKSPACE_MCP_SIGNED_ATTACHMENT_URLS", "true")
        assert sign.signed_attachment_urls_enabled() is True


class TestRoundTrip:
    def test_valid_token_round_trips(self):
        token = sign.mint_attachment_token(
            source="gmail",
            message_id="msg1",
            attachment_id="att1",
            user_email="user@example.com",
        )
        claims = sign.verify_attachment_token(token)
        assert claims is not None
        assert claims["src"] == "gmail"
        assert claims["mid"] == "msg1"
        assert claims["aid"] == "att1"
        assert claims["sub"] == "user@example.com"

    def test_tampered_token_is_rejected(self):
        token = sign.mint_attachment_token(
            source="gmail",
            message_id="msg1",
            attachment_id="att1",
            user_email="user@example.com",
        )
        assert sign.verify_attachment_token(token + "x") is None

    def test_wrong_key_is_rejected(self, monkeypatch):
        token = sign.mint_attachment_token(
            source="gmail",
            message_id="msg1",
            attachment_id="att1",
            user_email="user@example.com",
        )
        monkeypatch.setenv("WORKSPACE_MCP_ATTACHMENT_SIGNING_KEY", "different-key")
        assert sign.verify_attachment_token(token) is None

    def test_expired_token_is_rejected(self):
        token = sign.mint_attachment_token(
            source="gmail",
            message_id="msg1",
            attachment_id="att1",
            user_email="user@example.com",
            ttl_seconds=-1,
        )
        assert sign.verify_attachment_token(token) is None

    def test_malformed_token_is_rejected(self):
        assert sign.verify_attachment_token("not.a.jwt") is None


class TestSigningKeyFallback:
    def test_falls_back_to_client_secret(self, monkeypatch):
        monkeypatch.delenv("WORKSPACE_MCP_ATTACHMENT_SIGNING_KEY", raising=False)
        monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "client-secret")
        token = sign.mint_attachment_token(
            source="gmail",
            message_id="m",
            attachment_id="a",
            user_email="u@example.com",
        )
        # Verifiable with the same fallback key.
        assert sign.verify_attachment_token(token) is not None
        # And the payload is signed with that secret, not the dedicated key.
        assert jwt.decode(token, "client-secret", algorithms=["HS256"])["sub"] == (
            "u@example.com"
        )

    def test_raises_when_no_key_available(self, monkeypatch):
        monkeypatch.delenv("WORKSPACE_MCP_ATTACHMENT_SIGNING_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_SECRET", raising=False)
        with pytest.raises(RuntimeError):
            sign.mint_attachment_token(
                source="gmail",
                message_id="m",
                attachment_id="a",
                user_email="u@example.com",
            )


class TestUrlBuilder:
    def test_uses_external_url_when_set(self, monkeypatch):
        monkeypatch.setenv("WORKSPACE_EXTERNAL_URL", "https://gw.example.com/")
        url = sign.get_signed_attachment_url("TOK")
        assert url == "https://gw.example.com/attachments/signed/TOK"
