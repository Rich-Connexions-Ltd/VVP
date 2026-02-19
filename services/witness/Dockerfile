# VVP Witness Docker Image (linux/amd64 — required by Azure Container Apps)
# Runs a single KERI witness with deterministic salt for consistent AIDs
#
# Environment Variables:
#   WITNESS_NAME  - Witness name: wan, wil, or wes (default: wan)
#   HTTP_PORT     - HTTP port for OOBI/REST API (default: 5642)
#   TCP_PORT      - TCP port for KERI protocol (default: 5632)
#
# Expected AIDs (from deterministic salts):
#   wan: BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
#   wil: BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM
#   wes: BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX
#
# Build:
#   docker build -t vvp-witness -f services/witness/Dockerfile .
#
# Run:
#   docker run -e WITNESS_NAME=wan -e HTTP_PORT=5642 -e TCP_PORT=5632 -p 5642:5642 vvp-witness
#
# Note: Built for linux/amd64 — required by Azure Container Apps

FROM --platform=linux/amd64 gleif/keri:1.2.10

# Copy the Python startup script
COPY services/witness/start-witness.py /app/start-witness.py

# Default environment for wan witness
ENV WITNESS_NAME=wan
ENV HTTP_PORT=5642
ENV TCP_PORT=5632

# Expose HTTP port (TCP port is for KERI protocol, exposed separately if needed)
EXPOSE 5642

# Run the Python startup script
ENTRYPOINT ["python3", "/app/start-witness.py"]
