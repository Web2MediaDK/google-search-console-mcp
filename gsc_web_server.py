"""Authenticated Streamable HTTP server combining Google sign-in and GSC tools."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from functools import wraps
from datetime import datetime, timezone

import httpx
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials as GoogleCredentials
from googleapiclient.discovery import build
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import gsc_server
from gsc_auth_store import FirestoreGoogleTokenStore, GoogleTokenStore
from spike.spike_server import Settings, create_server

log = logging.getLogger("gsc-mcp")
_CREDENTIALS_CACHE: dict[str, GoogleCredentials] = {}
_CREDENTIALS_CACHE_LOCK = threading.RLock()

GSC_TOOL_NAMES = (
    "get_capabilities",
    "list_properties",
    "get_search_analytics",
    "get_site_details",
    "get_sitemaps",
    "inspect_url_enhanced",
    "batch_url_inspection",
    "check_indexing_issues",
    "get_performance_overview",
    "get_advanced_search_analytics",
    "compare_search_periods",
    "get_search_by_page_query",
    "list_sitemaps_enhanced",
    "get_sitemap_details",
)


def make_user_gsc_service(email: str, token_store: GoogleTokenStore, settings: Settings):
    """Build a GSC API client using only the named user's Google refresh token."""
    refresh_token = token_store.get(email)
    if not refresh_token:
        raise PermissionError(
            "No stored Search Console authorization for this account. Sign in again and grant access."
        )

    email = email.strip().lower()
    with _CREDENTIALS_CACHE_LOCK:
        credentials = _CREDENTIALS_CACHE.get(email)
        if credentials is None or credentials.refresh_token != refresh_token:
            credentials = GoogleCredentials(
                token=None,
                refresh_token=refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=settings.google_client_id,
                client_secret=settings.google_client_secret,
                scopes=gsc_server.SCOPES,
            )
            _CREDENTIALS_CACHE[email] = credentials
        if not credentials.valid:
            try:
                credentials.refresh(GoogleRequest())
            except Exception:
                _CREDENTIALS_CACHE.pop(email, None)
                raise
            # Google normally keeps refresh tokens stable, but save a replacement
            # if its token endpoint rotates one.
            if credentials.refresh_token and credentials.refresh_token != refresh_token:
                token_store.save(email, credentials.refresh_token)
    return build("searchconsole", "v1", credentials=credentials, cache_discovery=False)


def clear_user_credentials(email: str) -> None:
    """Clear the per-process access-token cache after a user's token is deleted."""
    with _CREDENTIALS_CACHE_LOCK:
        _CREDENTIALS_CACHE.pop(email.strip().lower(), None)


def _audited_tool(function):
    """Log caller, tool, property, and time without logging tokens or results."""
    @wraps(function)
    async def wrapped(*args, **kwargs):
        token = get_access_token()
        email = token.subject if token and token.subject else "unknown"
        property_name = kwargs.get("site_url", "")
        log.info(
            "gsc_tool_call time=%s user=%s tool=%s property=%s",
            datetime.now(timezone.utc).isoformat(),
            email,
            function.__name__,
            property_name,
        )
        return await function(*args, **kwargs)
    return wrapped


def create_gsc_server(
    settings: Settings | None = None,
    token_store: GoogleTokenStore | None = None,
    *,
    exchange=None,
):
    """Create the authenticated remote MCP server with all read-only GSC tools."""
    settings = settings or Settings.from_env()
    token_store = token_store or FirestoreGoogleTokenStore()

    def service_for_current_user():
        token = get_access_token()
        if token is None or not token.subject:
            raise PermissionError("An authenticated company account is required")
        email = token.subject.strip().lower()
        service = make_user_gsc_service(email, token_store, settings)
        # Record identity and tool/property in the tool wrapper separately when
        # tool-level audit logging is added; never log tokens or API response data.
        return service

    gsc_server.configure_remote_service_factory(service_for_current_user)

    mcp, provider = create_server(
        settings,
        **({"exchange": exchange} if exchange is not None else {}),
        token_store=token_store,
        server_name="Google Search Console",
        include_whoami=False,
    )

    @mcp.custom_route("/account/google-token", methods=["DELETE"])
    async def delete_own_google_token(request: Request) -> Response:
        """Let the authenticated user revoke and delete their stored GSC grant."""
        authorization = request.headers.get("authorization", "")
        scheme, _, bearer = authorization.partition(" ")
        token = await provider.load_access_token(bearer) if scheme.lower() == "bearer" and bearer else None
        expected_resource = settings.base_url + "/mcp"
        if not token or token.resource != expected_resource or not token.subject:
            return JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        email = token.subject.strip().lower()
        refresh_token = await asyncio.to_thread(token_store.get, email)
        if refresh_token:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.post(
                        "https://oauth2.googleapis.com/revoke",
                        data={"token": refresh_token},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                # Google returns 400 when the grant was already revoked/invalid.
                if response.status_code >= 500:
                    return JSONResponse({"error": "Google revocation is temporarily unavailable"}, status_code=502)
                if response.status_code not in (200, 400):
                    return JSONResponse({"error": "Google revocation failed"}, status_code=502)
            except httpx.HTTPError:
                return JSONResponse({"error": "Google revocation is temporarily unavailable"}, status_code=502)

        await asyncio.to_thread(token_store.delete, email)
        clear_user_credentials(email)
        return Response(status_code=204)

    for name in GSC_TOOL_NAMES:
        mcp.add_tool(
            _audited_tool(getattr(gsc_server, name)),
            name=name,
            annotations=ToolAnnotations(readOnlyHint=True),
        )
    return mcp, provider


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    server, _ = create_gsc_server()
    server.run(transport="streamable-http")


if __name__ == "__main__":
    main()
