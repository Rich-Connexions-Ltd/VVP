# Support

## Reporting Issues

If you encounter a bug or unexpected behavior with the VVP verifier, please open an issue including:

1. **Steps to reproduce** -- Minimal PASSporT JWT or VVP-Identity header that triggers the issue.
2. **Expected behavior** -- What the spec says should happen (cite section number).
3. **Actual behavior** -- The error code, HTTP status, or SIP response you received.
4. **Environment** -- Python version, pysodium version, OS, Docker version (if applicable).
5. **Configuration** -- Any non-default environment variable settings.

## Specification References

The VVP verifier implements the **VVP Verifier Specification v1.5**. Key sections:

| Section | Topic |
|---------|-------|
| §3.2 | Claim status model (VALID / INVALID / INDETERMINATE) |
| §3.3A | Overall status derivation rules |
| §4.1 | Verify request and response format |
| §4.1A | VVP-Identity header format |
| §4.2 | Error codes and recoverability |
| §4.3 | Claim tree structure |
| §5.0 | EdDSA (Ed25519) signature mandate |
| §5.1 | Algorithm allow/forbid lists |
| §5.2A | iat drift limit (5 seconds, normative) |
| §5.2B | Token validity and expiry rules |
| §5.3 | CESR and base64url signature decoding |
| §5.4 | PASSporT-to-VVP-Identity binding validation |
| §5A | Verification result caching |

## Learning Resources

### KERI and ACDC

- [KERI Specification](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html) -- The Key Event Receipt Infrastructure protocol.
- [ACDC Specification](https://weboftrust.github.io/ietf-acdc/draft-ssmith-acdc.html) -- Authentic Chained Data Containers.
- [CESR Specification](https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html) -- Composable Event Streaming Representation.
- [vLEI Ecosystem](https://www.gleif.org/en/lei-solutions/gleif-s-digital-strategy/introducing-the-vlei) -- Verifiable Legal Entity Identifiers.

### PASSporT and STIR/SHAKEN

- [RFC 8225](https://tools.ietf.org/html/rfc8225) -- PASSporT: Personal Assertion Token.
- [RFC 8224](https://tools.ietf.org/html/rfc8224) -- Authenticated Identity Management in SIP.
- [RFC 8588](https://tools.ietf.org/html/rfc8588) -- STIR/SHAKEN framework.

### SIP

- [RFC 3261](https://tools.ietf.org/html/rfc3261) -- SIP: Session Initiation Protocol.

## Contact

- **Repository**: [GitHub](https://github.com/your-org/vvp-verifier)
- **Maintainer**: Rich Connexions Ltd.
- **Email**: support@richconnexions.com

## License

MIT License. Copyright (c) Rich Connexions Ltd. All rights reserved.
