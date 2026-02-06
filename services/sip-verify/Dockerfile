# VVP SIP Verify Service Dockerfile
# Sprint 44: SIP redirect-based verification service

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy common package first (for caching)
COPY common/ /app/common/

# Install common package
RUN pip install --no-cache-dir -e /app/common

# Copy service code
COPY services/sip-verify/ /app/services/sip-verify/

# Install service dependencies
RUN pip install --no-cache-dir -e /app/services/sip-verify

# Environment variables
ENV VVP_SIP_VERIFY_HOST=0.0.0.0
ENV VVP_SIP_VERIFY_PORT=5061
ENV VVP_LOG_LEVEL=INFO

# Expose SIP port
EXPOSE 5061/udp
EXPOSE 5061/tcp

# Health check (optional HTTP status server)
EXPOSE 8080

# Run the service
CMD ["python", "-m", "app.main"]
