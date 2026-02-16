FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium23 libsodium-dev \
    ca-certificates \
    curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

# Install keripy (vendored)
COPY keripy /srv/keripy
RUN pip install --no-cache-dir /srv/keripy

# Install common package
COPY common /srv/common
RUN pip install --no-cache-dir /srv/common

# Install keri-agent service
COPY services/keri-agent/pyproject.toml /srv/pyproject.toml
COPY services/keri-agent/app /srv/app
RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir .

# Copy config (will be overridden by volume mount in docker-compose)
COPY services/keri-agent/config /srv/config

# Data volume for LMDB persistence
VOLUME /data/vvp-keri-agent

# Environment
ENV PYTHONUNBUFFERED=1
ENV VVP_WITNESS_CONFIG=/srv/config/witnesses.json

# Health check — uses /livez (liveness probe, always 200)
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8002/livez || exit 1

EXPOSE 8002
CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8002"]
