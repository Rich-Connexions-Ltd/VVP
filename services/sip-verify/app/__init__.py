"""VVP SIP Verify Service.

Sprint 44: SIP redirect-based verification service that:
- Receives inbound SIP INVITEs containing VVP headers (RFC 8224 Identity, P-VVP-*)
- Parses headers and extracts PASSporT + VVP-Identity
- Calls VVP Verifier /verify-callee endpoint
- Returns SIP 302 with X-VVP-* headers for PBX to pass to WebRTC client
"""
