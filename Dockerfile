FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app

# Copy dependency files first for layer caching.
COPY pyproject.toml README.md ./
RUN uv sync --no-cache --no-install-project

# The authenticated HTTP entry point combines the sign-in provider and GSC tools.
COPY gsc_server.py gsc_web_server.py gsc_auth_store.py ./
COPY spike/spike_server.py ./spike/spike_server.py

# Cloud Run supplies PORT (normally 8080); the MCP server reads it.
CMD ["uv", "run", "--no-sync", "python", "gsc_web_server.py"]
