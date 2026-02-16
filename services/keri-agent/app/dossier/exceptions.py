"""Dossier assembly exceptions."""


class DossierBuildError(Exception):
    """Raised when dossier assembly fails.

    Attributes:
        message: Human-readable error description
        credential_said: SAID of the credential that caused the error (if applicable)
    """

    def __init__(self, message: str, credential_said: str | None = None):
        self.message = message
        self.credential_said = credential_said
        super().__init__(message)

    def __str__(self) -> str:
        if self.credential_said:
            return f"{self.message} (credential: {self.credential_said})"
        return self.message
