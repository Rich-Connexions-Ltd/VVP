"""Shared SAID validation for VVP services.

KERI SAIDs use Blake3-256 with CESR encoding. The derivation code prefix
is 'E' followed by 43 Base64url characters (44 total).

Sprint 80: Extracted from per-service regex checks to a single shared utility.
"""
import re

# KERI SAID format: 'E' prefix (derivation code) + 43 Base64url chars
SAID_PATTERN = re.compile(r"^E[A-Za-z0-9_-]{43}$")


def is_valid_said(said: str) -> bool:
    """Check if a string is a valid KERI SAID format.

    Returns True if the SAID matches the expected pattern:
    - Starts with 'E' (KERI derivation code for Blake3-256)
    - Followed by exactly 43 Base64url characters
    - Total length: 44 characters
    """
    return bool(SAID_PATTERN.match(said))
