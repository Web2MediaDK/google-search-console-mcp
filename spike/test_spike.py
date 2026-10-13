import base64
import hashlib
import json
import secrets
import urllib.parse

import pytest
from starlette.testclient import TestClient

from spike_server import Settings, create_server

SETTINGS = Settings(base_url="http://localhost:8080", google_client_id="gid", google_client_secret="gsecret", allowed_domain="example.com")
REDIRECT = "https://chat.example/callback"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def make_app(claims):
    async def fake_exchange(settings, code):
        return claims
    mcp, provider = create_server(SETTINGS, fake_exchange)
    return mcp.streamable_http_app(), provider


GOOD = {"email": "Anna@Example.com", "email_verified": True, "hd": "example.com"}


@pytest.fixture
def client():
    app, _ = make_app(GOOD)
    with TestClient(app, base_url="http://localhost:8080") as c:
        yield c


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def register(c):
    r = c.post("/register", json={"redirect_uris": [REDIRECT], "client_name": "test", "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "token_endpoint_auth_method": "none"})
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def start_login(c, client_id, challenge):
    r = c.get("/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "code_challenge": challenge, "code_challenge_method": "S256", "state": "xyz", "scope": "mcp"}, follow_redirects=False)
    assert r.status_code == 302, r.text
    assert r.headers["location"].startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    return urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["location"]).query)["state"][0]


def full_login(c):
    client_id = register(c)
    verifier, challenge = pkce()
    state = start_login(c, client_id, challenge)
    cb = c.get("/oauth/google/callback", params={"state": state, "code": "google-code"}, follow_redirects=False)
    assert cb.status_code == 302, cb.text
    q = urllib.parse.parse_qs(urllib.parse.urlparse(cb.headers["location"]).query)
    assert cb.headers["location"].startswith(REDIRECT) and q["state"] == ["xyz"]
    tok = c.post("/token", data={"grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": REDIRECT, "client_id": client_id, "code_verifier": verifier})
    return client_id, tok


def rpc(c, token, method, params=None):
    headers = dict(MCP_HEADERS)
    if token:
        headers["Authorization"] = "Bearer " + token
    return c.post("/mcp", headers=headers, content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}))


def test_no_token_gets_401_with_metadata_pointer(client):
    r = rpc(client, None, "tools/list")
    assert r.status_code == 401
    assert "resource_metadata" in r.headers["www-authenticate"]


def test_discovery_documents(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["registration_endpoint"].endswith("/register")
    assert "S256" in meta["code_challenge_methods_supported"]
    pointer = rpc(client, None, "tools/list").headers["www-authenticate"].split('resource_metadata="')[1].split('"')[0]
    assert client.get(urllib.parse.urlparse(pointer).path).json()["resource"].endswith("/mcp")


def test_full_login_then_tool_call_returns_email(client):
    _, tok = full_login(client)
    assert tok.status_code == 200, tok.text
    access = tok.json()["access_token"]
    listed = rpc(client, access, "tools/list").json()["result"]["tools"]
    assert [t["name"] for t in listed] == ["whoami"]
    assert listed[0]["annotations"]["readOnlyHint"] is True
    call = rpc(client, access, "tools/call", {"name": "whoami", "arguments": {}}).json()
    assert "anna@example.com" in call["result"]["content"][0]["text"]


def test_wrong_domain_is_refused_and_no_code_issued():
    app, provider = make_app({"email": "x@gmail.com", "email_verified": True, "hd": "gmail.com"})
    with TestClient(app, base_url="http://localhost:8080") as c:
        client_id = register(c)
        _, challenge = pkce()
        state = start_login(c, client_id, challenge)
        cb = c.get("/oauth/google/callback", params={"state": state, "code": "x"}, follow_redirects=False)
        assert cb.status_code == 403
        assert provider.codes == {}


def test_unverified_email_is_refused():
    app, _ = make_app({"email": "a@example.com", "email_verified": False, "hd": "example.com"})
    with TestClient(app, base_url="http://localhost:8080") as c:
        state = start_login(c, register(c), pkce()[1])
        assert c.get("/oauth/google/callback", params={"state": state, "code": "x"}, follow_redirects=False).status_code == 403


def test_state_can_only_be_used_once(client):
    client_id = register(client)
    state = start_login(client, client_id, pkce()[1])
    assert client.get("/oauth/google/callback", params={"state": state, "code": "x"}, follow_redirects=False).status_code == 302
    assert client.get("/oauth/google/callback", params={"state": state, "code": "x"}, follow_redirects=False).status_code == 403


def test_wrong_pkce_verifier_is_rejected(client):
    client_id = register(client)
    _, challenge = pkce()
    state = start_login(client, client_id, challenge)
    cb = client.get("/oauth/google/callback", params={"state": state, "code": "x"}, follow_redirects=False)
    code = urllib.parse.parse_qs(urllib.parse.urlparse(cb.headers["location"]).query)["code"][0]
    r = client.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": client_id, "code_verifier": "wrong" * 10})
    assert r.status_code == 400


def test_refresh_rotates_and_old_token_dies(client):
    client_id, tok = full_login(client)
    refresh = tok.json()["refresh_token"]
    new = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": refresh, "client_id": client_id})
    assert new.status_code == 200, new.text
    assert rpc(client, new.json()["access_token"], "tools/list").status_code == 200
    again = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": refresh, "client_id": client_id})
    assert again.status_code == 400
