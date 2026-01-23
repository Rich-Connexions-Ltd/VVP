"""Dossier-specific exceptions mapped to VVP error codes.

Per spec §6.1B:
- Fetch failures → INDETERMINATE (recoverable)
- Parse/structure failures → INVALID (non-recoverable)
"""

from app.vvp.api_models import ErrorCode


class DossierError(Exception):
    """Base exception for dossier operations.

    Carries an error code that maps to ErrorCode constants per §4.2A.
    """

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class FetchError(DossierError):
    """HTTP fetch failures.

    Maps to DOSSIER_FETCH_FAILED (recoverable → INDETERMINATE).
    Used when:
    - Network timeout
    - HTTP error status
    - Too many redirects
    - Response too large
    - Invalid content-type
    """

    def __init__(self, message: str = "Dossier fetch failed"):
        super().__init__(ErrorCode.DOSSIER_FETCH_FAILED, message)


class ParseError(DossierError):
    """JSON/structure parse failures.

    Maps to DOSSIER_PARSE_FAILED (non-recoverable → INVALID).
    Used when:
    - Invalid JSON
    - Missing required ACDC fields
    - Unexpected data types
    """

    def __init__(self, message: str = "Dossier parse failed"):
        super().__init__(ErrorCode.DOSSIER_PARSE_FAILED, message)


class GraphError(DossierError):
    """DAG structure invalid.

    Maps to DOSSIER_GRAPH_INVALID (non-recoverable → INVALID).
    Used when:
    - Cycle detected in DAG
    - No root node found
    - Multiple root nodes found
    - Duplicate SAIDs
    """

    def __init__(self, message: str = "Dossier graph invalid"):
        super().__init__(ErrorCode.DOSSIER_GRAPH_INVALID, message)
