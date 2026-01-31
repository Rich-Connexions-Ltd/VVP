"""Shared exception base classes.

Contains exception classes used by both verifier and issuer services:
- ACDCError hierarchy for credential errors
- Base parsing exceptions

This module is shared between verifier and issuer services.
"""


class VVPError(Exception):
    """Base exception for all VVP errors."""
    pass


# =============================================================================
# ACDC Exceptions
# =============================================================================

class ACDCError(VVPError):
    """Base exception for ACDC verification/issuance errors."""
    pass


class ACDCSAIDMismatch(ACDCError):
    """ACDC's self-addressing identifier doesn't match computed value.

    Maps to ErrorCode.ACDC_SAID_MISMATCH.
    """
    pass


class ACDCSignatureInvalid(ACDCError):
    """ACDC signature verification failed.

    Maps to ErrorCode.ACDC_PROOF_MISSING.
    """
    pass


class ACDCChainInvalid(ACDCError):
    """ACDC credential chain validation failed.

    This covers:
    - Edge target not found in dossier
    - Schema mismatch for credential type
    - Chain doesn't terminate at trusted root
    - Circular reference detected

    Maps to ErrorCode.DOSSIER_GRAPH_INVALID.
    """
    pass


class ACDCParseError(ACDCError):
    """Failed to parse ACDC structure.

    Maps to ErrorCode.DOSSIER_PARSE_FAILED.
    """
    pass


# =============================================================================
# KERI Exceptions
# =============================================================================

class KeriError(VVPError):
    """Base exception for KERI-related errors."""
    pass


class CESRFramingError(KeriError):
    """CESR stream framing error."""
    pass


class CESRMalformedError(KeriError):
    """CESR content is malformed."""
    pass


# =============================================================================
# Dossier Exceptions
# =============================================================================

class DossierError(VVPError):
    """Base exception for dossier errors."""
    pass


class DossierParseError(DossierError):
    """Failed to parse dossier structure."""
    pass
