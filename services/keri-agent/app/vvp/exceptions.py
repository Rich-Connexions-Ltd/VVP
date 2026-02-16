"""VVP-specific exceptions for header and PASSporT creation."""


class VVPCreationError(Exception):
    """Base exception for VVP header/PASSporT creation errors."""

    pass


class IdentityNotAvailableError(VVPCreationError):
    """Issuer identity not found or not initialized."""

    pass


class InvalidPhoneNumberError(VVPCreationError):
    """Phone number not in E.164 format."""

    pass


class InvalidExpiryError(VVPCreationError):
    """Invalid expiry configuration."""

    pass
