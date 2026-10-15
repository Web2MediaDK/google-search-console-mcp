import asyncio
import base64
import hashlib
import json
import secrets
from unittest.mock import MagicMock, patch
import urllib.parse

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from gsc_auth_store import FirestoreGoogleTokenStore, InMemoryGoogleTokenStore
from gsc_web_server import GSC_TOOL_NAMES, create_gsc_server, make_user_gsc_service
from spike_server import GoogleAuthResult, Settings


class FakeSnapshot:
    def __init__(self, value):
        self._value = value
        self.exists = value is not None

    def to_dict(self):
        return self._value


class FakeDocument:
    def __init__(self, data, key):
        self.data = data
        self.key = key

    def set(self, value):
        self.data[self.key] = value

    def get(self):
        return FakeSnapshot(self.data.get(self.key))

    def delete(self):
        self.data.pop(self.key, None)


class FakeCollection:
    def __init__(self):
        self.data = {}

    def document(self, key):
        return FakeDocument(self.data, key)


class FakeFirestore:
    def __init__(self):
        self.collections = {}

    def collection(self, name):
        return self.collections.setdefault(name, FakeCollection())


def test_firestore_token_store_encrypts_and_isolates_users():
    db = FakeFirestore()
    store = FirestoreGoogleTokenStore(client=db, key=Fernet.generate_key().decode())
    store.save("anna@example.com", "anna-refresh")
    store.save("ben@example.com", "ben-refresh")

    stored_values = [v["google_refresh_token_encrypted"] for v in db.collection("gsc_user_tokens").data.values()]
    assert "anna-refresh" not in stored_values
    assert "ben-refresh" not in stored_values
    assert store.get("ANNA@example.com") == "anna-refresh"
    assert store.get("ben@example.com") == "ben-refresh"
    assert store.get("carol@example.com") is None

    store.delete("anna@example.com")
    assert store.get("anna@example.com") is None
    assert store.get("ben@example.com") == "ben-refresh"

    # OAuth secrets are case-sensitive even though email addresses are normalized.
    store.put_state("access", "TokenAbC", {"owner": "anna"})
    store.put_state("access", "tokenabc", {"owner": "ben"})
    assert store.get_state("access", "TokenAbC") == {"owner": "anna"}
    assert store.get_state("access", "tokenabc") == {"owner": "ben"}


def test_user_services_use_only_the_calling_users_refresh_token():
    store = InMemoryGoogleTokenStore()
    store.save("anna@example.com", "anna-refresh")
    store.save("ben@example.com", "ben-refresh")
    settings = Settings("https://gsc.example", "client-id", "client-secret", "example.com")
    credentials = []

    class FakeCredentials:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.refresh_token = kwargs["refresh_token"]
            self.valid = False
            credentials.append(kwargs)

        def refresh(self, request):
            self.valid = True

    with patch("gsc_web_server.GoogleCredentials", FakeCredentials), patch(
        "gsc_web_server.build", side_effect=lambda *args, **kwargs: kwargs["credentials"]
    ):
        anna = make_user_gsc_service("anna@example.com", store, settings)
        ben = make_user_gsc_service("ben@example.com", store, settings)

    assert anna.kwargs["refresh_token"] == "anna-refresh"
    assert ben.kwargs["refresh_token"] == "ben-refresh"
    assert anna is not ben


def test_missing_user_token_fails_closed():
    settings = Settings("https://gsc.example", "client-id", "client-secret", "example.com")
    with pytest.raises(PermissionError, match="No stored Search Console authorization"):
        make_user_gsc_service("nobody@example.com", InMemoryGoogleTokenStore(), settings)


def test_combined_server_exposes_expected_gsc_tools_only():
    settings = Settings("https://gsc.example", "client-id", "client-secret", "example.com")
    server, _ = create_gsc_server(settings, InMemoryGoogleTokenStore(), exchange=lambda *_: {})
    actual_names = {tool.name for tool in server._tool_manager.list_tools()}
    assert actual_names == set(GSC_TOOL_NAMES)
    assert "whoami" not in actual_names


def test_google_token_delete_route_requires_a_valid_mcp_token():
    settings = Settings("https://gsc.example", "client-id", "client-secret", "example.com")
    store = InMemoryGoogleTokenStore()
    server, _ = create_gsc_server(settings, store, exchange=lambda *_: {})
    with TestClient(server.streamable_http_app(), base_url="https://gsc.example") as client:
        response = client.delete("/account/google-token")
    assert response.status_code == 401


def test_user_can_revoke_and_delete_their_google_token():
    settings = Settings("https://gsc.example", "client-id", "client-secret", "example.com")
    store = InMemoryGoogleTokenStore()
    store.save("anna@example.com", "anna-google-refresh")
    server, provider = create_gsc_server(settings, store, exchange=lambda *_: {})
    oauth = asyncio.run(provider._issue("chat-client", ["mcp"], "anna@example.com", settings.base_url + "/mcp"))

    class FakeResponse:
        status_code = 200

    class FakeAsyncClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, *args, **kwargs):
            assert kwargs["data"]["token"] == "anna-google-refresh"
            return FakeResponse()

    with patch("gsc_web_server.httpx.AsyncClient", return_value=FakeAsyncClient()):
        with TestClient(server.streamable_http_app(), base_url="https://gsc.example") as client:
            response = client.delete(
                "/account/google-token",
                headers={"Authorization": "Bearer " + oauth.access_token},
            )

    assert response.status_code == 204
    assert store.get("anna@example.com") is None


def test_authenticated_gsc_tool_uses_the_signed_in_users_credentials():
    settings = Settings("http://localhost:8080", "client-id", "client-secret", "example.com")
    store = InMemoryGoogleTokenStore()

    async def exchange(_settings, _code):
        return GoogleAuthResult(
            claims={"email": "Anna@example.com", "email_verified": True, "hd": "example.com"},
            refresh_token="anna-google-refresh",
        )

    service = MagicMock()
    service.sites().list().execute.return_value = {
        "siteEntry": [{"siteUrl": "https://anna.example/", "permissionLevel": "siteOwner"}]
    }
    with patch("gsc_web_server.make_user_gsc_service", return_value=service) as make_service:
        server, _ = create_gsc_server(settings, store, exchange=exchange)
        with TestClient(server.streamable_http_app(), base_url=settings.base_url) as client:
            registration = client.post(
                "/register",
                json={
                    "redirect_uris": ["https://chat.example/callback"],
                    "client_name": "test",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            client_id = registration.json()["client_id"]
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            auth = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "https://chat.example/callback",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "test-state",
                    "scope": "mcp",
                },
                follow_redirects=False,
            )
            google_state = urllib.parse.parse_qs(urllib.parse.urlparse(auth.headers["location"]).query)["state"][0]
            callback = client.get(
                "/oauth/google/callback",
                params={"state": google_state, "code": "google-code"},
                follow_redirects=False,
            )
            code = urllib.parse.parse_qs(urllib.parse.urlparse(callback.headers["location"]).query)["code"][0]
            oauth = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "https://chat.example/callback",
                    "client_id": client_id,
                    "code_verifier": verifier,
                },
            )
            assert oauth.status_code == 200, oauth.text
            result = client.post(
                "/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + oauth.json()["access_token"],
                },
                content=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "list_properties", "arguments": {}},
                    }
                ),
            )

    assert result.status_code == 200, result.text
    assert "https://anna.example/" in result.text
    make_service.assert_called_once_with("anna@example.com", store, settings)
