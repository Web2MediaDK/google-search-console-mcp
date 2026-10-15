"""Authentication spike: a remote MCP server that signs people in with Google.

One dummy tool (whoami) returns the signed-in email. There is no Search Console
code here on purpose: the point is to prove that ChatGPT and nao can sign in to
this server, and that only company Google accounts get through.

Flow: the MCP client (ChatGPT/nao) talks OAuth to THIS server. This server sends
the user to Google to sign in, checks the account's domain, then hands the MCP
client its own short-lived token. State is kept in memory, so run exactly one
instance (min = max = 1) while this is a spike.
"""
import asyncio
import html
import logging
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass

import httpx
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

log = logging.getLogger("gsc-mcp-spike")

CALLBACK_PATH = "/oauth/google/callback"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_SCOPES = "openid email https://www.googleapis.com/auth/webmasters.readonly"
SCOPE = "mcp"
CODE_TTL = 300
PENDING_TTL = 600
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 24 * 3600


class LoginError(Exception):
    """A sign-in attempt was refused. The message is safe to show the user."""


@dataclass(frozen=True)
class Settings:
    base_url: str  # public https address of this service, no trailing slash
    google_client_id: str
    google_client_secret: str
    allowed_domain: str  # e.g. yourcompany.com

    @classmethod
    def from_env(cls) -> "Settings":
        missing = [k for k in ("PUBLIC_BASE_URL", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "ALLOWED_DOMAIN") if not os.environ.get(k)]
        if missing:
            raise RuntimeError("Missing environment variables: " + ", ".join(missing))
        return cls(
            base_url=os.environ["PUBLIC_BASE_URL"].rstrip("/"),
            google_client_id=os.environ["GOOGLE_CLIENT_ID"],
            google_client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
            allowed_domain=os.environ["ALLOWED_DOMAIN"].lower().lstrip("@"),
        )


async def exchange_google_code(settings: Settings, code: str) -> dict:
    """Trade Google's one-time code for the user's verified identity claims."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.base_url + CALLBACK_PATH,
                "grant_type": "authorization_code",
            },
        )
    resp.raise_for_status()
    raw = resp.json()["id_token"]
    return await asyncio.to_thread(
        google_id_token.verify_oauth2_token, raw, google_requests.Request(), settings.google_client_id
    )


class GoogleBackedProvider:
    """OAuth server for MCP clients. Identity comes from Google; tokens are our own."""

    def __init__(self, settings: Settings, exchange=exchange_google_code):
        self.s = settings
        self._exchange = exchange
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.pending: dict[str, tuple[str, AuthorizationParams, float]] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.access: dict[str, AccessToken] = {}
        self.refresh: dict[str, RefreshToken] = {}

    # --- client registration (ChatGPT / nao register themselves) ---
    async def get_client(self, client_id: str):
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info

    # --- step 1: send the user to Google ---
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        state = secrets.token_urlsafe(24)
        self.pending[state] = (client.client_id, params, time.time() + PENDING_TTL)
        query = {
            "client_id": self.s.google_client_id,
            "redirect_uri": self.s.base_url + CALLBACK_PATH,
            "response_type": "code",
            "scope": GOOGLE_SCOPES,
            "state": state,
            "hd": self.s.allowed_domain,  # only a hint; the real check is in complete_login
        }
        return GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(query)

    # --- step 2: Google sends the user back; check who they are ---
    async def complete_login(self, state: str, google_code: str) -> str:
        entry = self.pending.pop(state, None)  # pop = a state can only be used once
        if entry is None or entry[2] < time.time():
            raise LoginError("This sign-in attempt is unknown or has expired. Please start again.")
        client_id, params, _ = entry
        claims = await self._exchange(self.s, google_code)
        email = str(claims.get("email", "")).lower()
        domain = self.s.allowed_domain
        log.warning(
            "Google identity check: email_domain=%r hd=%r email_verified=%r allowed_domain=%r",
            email.rsplit("@", 1)[-1] if "@" in email else "",
            str(claims.get("hd", "")).lower(),
            claims.get("email_verified"),
            domain,
        )

        if not (claims.get("email_verified") and claims.get("hd", "").lower() == domain and email.endswith("@" + domain)):
            log.warning("Refused sign-in for a non-company account")
            raise LoginError(f"Only {domain} accounts can sign in.")
        code = secrets.token_urlsafe(32)
        self.codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or [SCOPE],
            expires_at=time.time() + CODE_TTL,
            client_id=client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource or self.s.base_url + "/mcp",  # bind every token to this server
            subject=email,
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    # --- step 3: the MCP client trades our code for tokens ---
    async def load_authorization_code(self, client, authorization_code: str):
        code = self.codes.get(authorization_code)
        if code and code.client_id == client.client_id and code.expires_at > time.time():
            return code
        return None

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        self.codes.pop(authorization_code.code, None)
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.subject, authorization_code.resource)

    def _issue(self, client_id, scopes, subject, resource) -> OAuthToken:
        now = int(time.time())
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.access[access] = AccessToken(token=access, client_id=client_id, scopes=scopes, expires_at=now + ACCESS_TTL, resource=resource, subject=subject)
        self.refresh[refresh] = RefreshToken(token=refresh, client_id=client_id, scopes=scopes, expires_at=now + REFRESH_TTL, resource=resource, subject=subject)
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL, scope=" ".join(scopes), refresh_token=refresh)

    async def load_refresh_token(self, client, refresh_token: str):
        token = self.refresh.get(refresh_token)
        if token and token.client_id == client.client_id and (token.expires_at or 0) > time.time():
            return token
        return None

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        self.refresh.pop(refresh_token.token, None)  # rotate: the old refresh token dies
        return self._issue(client.client_id, scopes or refresh_token.scopes, refresh_token.subject, refresh_token.resource)

    # --- step 4: every MCP request is checked here ---
    async def load_access_token(self, token: str):
        found = self.access.get(token)
        if found and (found.expires_at or 0) > time.time():
            return found
        self.access.pop(token, None)
        return None

    async def revoke_token(self, token) -> None:
        self.access.pop(token.token, None)
        self.refresh.pop(token.token, None)


def _page(message: str) -> str:
    return f"<!doctype html><meta charset=utf-8><title>Sign-in</title><p style='font-family:sans-serif;margin:3em auto;max-width:30em'>{html.escape(message)}</p>"


def create_server(settings: Settings, exchange=exchange_google_code):
    provider = GoogleBackedProvider(settings, exchange)
    mcp = FastMCP(
        "gsc-mcp-spike",
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=settings.base_url,
            resource_server_url=settings.base_url + "/mcp",
            required_scopes=[SCOPE],
            validate_token_resource=True,
            client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]),
            revocation_options=RevocationOptions(enabled=True),
        ),
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        stateless_http=True,  # no per-session memory, so any request can hit any instance
        json_response=True,
    )

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> Response:
        return PlainTextResponse("ok")

    @mcp.custom_route(CALLBACK_PATH, methods=["GET"])
    async def google_callback(request: Request) -> Response:
        if "error" in request.query_params:
            return HTMLResponse(_page("Sign-in was cancelled or refused by Google."), status_code=400)
        state, code = request.query_params.get("state"), request.query_params.get("code")
        if not state or not code:
            return HTMLResponse(_page("Missing sign-in details."), status_code=400)
        try:
            return RedirectResponse(await provider.complete_login(state, code), status_code=302)
        except LoginError as err:
            return HTMLResponse(_page(str(err)), status_code=403)
        except Exception:
            log.exception("Sign-in failed")
            return HTMLResponse(_page("Sign-in failed. Please try again."), status_code=502)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def whoami() -> str:
        """Return the Google account the caller signed in with."""
        token = get_access_token()
        return f"Signed in as {token.subject}" if token and token.subject else "Not signed in"

    return mcp, provider


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_server(Settings.from_env())[0].run(transport="streamable-http")
