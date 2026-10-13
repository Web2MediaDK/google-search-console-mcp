# Authentication spike

A small remote MCP server that signs people in with Google and has one dummy tool,
`whoami`. It proves that ChatGPT and nao can sign in to the server and that only
company Google accounts get through. There is no Search Console code in here.

## Settings (environment variables)

| Name | Meaning |
| --- | --- |
| `PUBLIC_BASE_URL` | Public https address of this service, no trailing slash |
| `GOOGLE_CLIENT_ID` | Client ID of the Web OAuth client |
| `GOOGLE_CLIENT_SECRET` | Client secret of the Web OAuth client (use Secret Manager) |
| `ALLOWED_DOMAIN` | Company email domain, for example `yourcompany.com` |
| `PORT` | Set by Cloud Run; defaults to 8080 |

The Web OAuth client needs `PUBLIC_BASE_URL/oauth/google/callback` as an authorized redirect URI.

## Tests

```
pip install -r requirements.txt pytest
python -m pytest -q test_spike.py
```

The tests replace Google with a fake, so they check this server's own behaviour:
401 without a token, discovery documents, the full sign-in flow, wrong-domain and
unverified accounts refused, one-time state, PKCE, and refresh-token rotation.

## Known gaps (on purpose, for Part E)

- All state (registered clients, codes, tokens) is in memory. Run exactly one instance
  (min = max = 1). A restart signs everyone out and clients must register again.
- Any MCP client can register itself. Add a consent page before real use.
- Google tokens are not stored yet, so there is no Search Console access.
- The sign-in state is not tied to the browser that started it.
- No rate limiting, and no Host/Origin checks yet.
