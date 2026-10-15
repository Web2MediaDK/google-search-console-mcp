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
            google_client_id=os.environ["GOOGLE_CLIENT_ID"].strip(),
            google_client_secret=os.environ["GOOGLE_CLIENT_SECRET"].strip(),
            allowed_domain=os.environ["ALLOWED_DOMAIN"].lower().lstrip("@"),
        )


@dataclass(frozen=True)
class GoogleAuthResult:
    """Verified Google identity plus the refresh token, when Google returns one."""

    claims: dict
    refresh_token: str | None


async def exchange_google_code(settings: Settings, code: str) -> GoogleAuthResult:
    """Exchange Google's one-time code and verify the returned identity."""
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
    token_response = resp.json()
    raw = token_response["id_token"]
    claims = await asyncio.to_thread(
        google_id_token.verify_oauth2_token, raw, google_requests.Request(), settings.google_client_id
    )
    return GoogleAuthResult(claims=claims, refresh_token=token_response.get("refresh_token"))


class GoogleBackedProvider:
    """OAuth server for MCP clients. Identity comes from Google; tokens are our own."""

    def __init__(self, settings: Settings, exchange=exchange_google_code, token_store=None):
        self.s = settings
        self._exchange = exchange
        self.token_store = token_store
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.pending: dict[str, tuple[str, AuthorizationParams, float]] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.access: dict[str, AccessToken] = {}
        self.refresh: dict[str, RefreshToken] = {}

    @property
    def _has_persistent_state(self) -> bool:
        return self.token_store is not None and hasattr(self.token_store, "put_state")

    # --- client registration (ChatGPT / nao register themselves) ---
    async def get_client(self, client_id: str):
        if self._has_persistent_state:
            value = await asyncio.to_thread(self.token_store.get_state, "clients", client_id)
            return OAuthClientInformationFull.model_validate(value) if value else None
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if self._has_persistent_state:
            await asyncio.to_thread(
                self.token_store.put_state,
                "clients",
                client_info.client_id,
                client_info.model_dump(mode="json"),
            )
            return
        self.clients[client_info.client_id] = client_info

    # --- step 1: send the user to Google ---
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        state = secrets.token_urlsafe(24)
        expires_at = time.time() + PENDING_TTL
        if self._has_persistent_state:
            await asyncio.to_thread(
                self.token_store.put_state,
                "pending",
                state,
                {
                    "client_id": client.client_id,
                    "params": params.model_dump(mode="json"),
                    "expires_at": expires_at,
                },
            )
        else:
            self.pending[state] = (client.client_id, params, expires_at)
        query = {
            "client_id": self.s.google_client_id,
            "redirect_uri": self.s.base_url + CALLBACK_PATH,
            "response_type": "code",
            "scope": GOOGLE_SCOPES,
            "state": state,
            "hd": self.s.allowed_domain,  # only a hint; the real check is in complete_login
            "access_type": "offline",
            "prompt": "consent",
        }
        return GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(query)

    # --- step 2: Google sends the user back; check who they are ---
    async def complete_login(self, state: str, google_code: str) -> str:
        if self._has_persistent_state:
            entry = await asyncio.to_thread(self.token_store.pop_state, "pending", state)
            if entry:
                params = AuthorizationParams.model_validate(entry["params"])
                client_id, expires_at = entry["client_id"], entry["expires_at"]
            else:
                client_id, params, expires_at = None, None, 0
        else:
            entry = self.pending.pop(state, None)  # pop = a state can only be used once
            if entry:
                client_id, params, expires_at = entry
            else:
                client_id, params, expires_at = None, None, 0
        if entry is None or expires_at < time.time():
            raise LoginError("This sign-in attempt is unknown or has expired. Please start again.")
        login = await self._exchange(self.s, google_code)
        # Keep plain-dict fakes supported, and use duck typing because deployments
        # may load this module through the ``spike`` package namespace.
        if isinstance(login, dict):
            claims, google_refresh_token = login, None
        else:
            claims = login.claims
            google_refresh_token = login.refresh_token
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

        # A missing refresh token is normal on later Google authorizations. Keep
        # the previously stored token; on first authorization, fail clearly if
        # Google did not grant offline access.
        if self.token_store is not None:
            if google_refresh_token:
                await asyncio.to_thread(self.token_store.save, email, google_refresh_token)
            else:
                existing = await asyncio.to_thread(self.token_store.get, email)
                if not existing:
                    raise LoginError(
                        "Google did not provide offline access. Please restart sign-in "
                        "and approve the requested access."
                    )
        code = secrets.token_urlsafe(32)
        authorization_code = AuthorizationCode(
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
        if self._has_persistent_state:
            await asyncio.to_thread(
                self.token_store.put_state,
                "codes",
                code,
                authorization_code.model_dump(mode="json"),
            )
        else:
            self.codes[code] = authorization_code
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    # --- step 3: the MCP client trades our code for tokens ---
    async def load_authorization_code(self, client, authorization_code: str):
        if self._has_persistent_state:
            # Consume in one Firestore transaction to prevent code replay.
            value = await asyncio.to_thread(self.token_store.pop_state, "codes", authorization_code)
            code = AuthorizationCode.model_validate(value) if value else None
            if code and code.client_id == client.client_id and code.expires_at > time.time():
                return code
            return None
        code = self.codes.get(authorization_code)
        if code and code.client_id == client.client_id and code.expires_at > time.time():
            return code
        return None

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        if not self._has_persistent_state:
            self.codes.pop(authorization_code.code, None)
        return await self._issue(client.client_id, authorization_code.scopes, authorization_code.subject, authorization_code.resource)

    async def _issue(self, client_id, scopes, subject, resource) -> OAuthToken:
        now = int(time.time())
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        access_record = AccessToken(token=access, client_id=client_id, scopes=scopes, expires_at=now + ACCESS_TTL, resource=resource, subject=subject)
        refresh_record = RefreshToken(token=refresh, client_id=client_id, scopes=scopes, expires_at=now + REFRESH_TTL, resource=resource, subject=subject)
        if self._has_persistent_state:
            await asyncio.gather(
                asyncio.to_thread(self.token_store.put_state, "access", access, access_record.model_dump(mode="json")),
                asyncio.to_thread(self.token_store.put_state, "refresh", refresh, refresh_record.model_dump(mode="json")),
            )
        else:
            self.access[access] = access_record
            self.refresh[refresh] = refresh_record
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL, scope=" ".join(scopes), refresh_token=refresh)

    async def load_refresh_token(self, client, refresh_token: str):
        if self._has_persistent_state:
            # Consume the old refresh token atomically; exchange creates its replacement.
            value = await asyncio.to_thread(self.token_store.pop_state, "refresh", refresh_token)
            token = RefreshToken.model_validate(value) if value else None
            if token and token.client_id == client.client_id and (token.expires_at or 0) > time.time():
                return token
            return None
        token = self.refresh.get(refresh_token)
        if token and token.client_id == client.client_id and (token.expires_at or 0) > time.time():
            return token
        return None

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        if not self._has_persistent_state:
            self.refresh.pop(refresh_token.token, None)  # rotate: the old refresh token dies
        return await self._issue(client.client_id, scopes or refresh_token.scopes, refresh_token.subject, refresh_token.resource)

    # --- step 4: every MCP request is checked here ---
    async def load_access_token(self, token: str):
        if self._has_persistent_state:
            value = await asyncio.to_thread(self.token_store.get_state, "access", token)
            found = AccessToken.model_validate(value) if value else None
            if found and (found.expires_at or 0) > time.time():
                return found
            if found:
                await asyncio.to_thread(self.token_store.delete_state, "access", token)
            return None
        found = self.access.get(token)
        if found and (found.expires_at or 0) > time.time():
            return found
        self.access.pop(token, None)
        return None

    async def revoke_token(self, token) -> None:
        if self._has_persistent_state:
            await asyncio.gather(
                asyncio.to_thread(self.token_store.delete_state, "access", token.token),
                asyncio.to_thread(self.token_store.delete_state, "refresh", token.token),
            )
        else:
            self.access.pop(token.token, None)
            self.refresh.pop(token.token, None)


def _page(message: str) -> str:
    return f"<!doctype html><meta charset=utf-8><title>Sign-in</title><p style='font-family:sans-serif;margin:3em auto;max-width:30em'>{html.escape(message)}</p>"


def create_server(
    settings: Settings,
    exchange=exchange_google_code,
    *,
    token_store=None,
    server_name: str = "gsc-mcp-spike",
    include_whoami: bool = True,
):
    provider = GoogleBackedProvider(settings, exchange, token_store=token_store)
    mcp = FastMCP(
        server_name,
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

    @mcp.custom_route("/health", methods=["GET"])
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

    if include_whoami:
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        async def whoami() -> str:
            """Return the Google account the caller signed in with."""
            token = get_access_token()
            return f"Signed in as {token.subject}" if token and token.subject else "Not signed in"

    return mcp, provider


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_server(Settings.from_env())[0].run(transport="streamable-http")
