"""OOBI URL construction helpers per §4.1B.

The VVP spec requires that `kid` and `evd` fields be OOBI URLs (not bare AIDs).
"""


def build_issuer_oobi(issuer_aid: str, witness_url: str) -> str:
    """Construct OOBI URL for issuer identity per §4.1B."""
    return f"{witness_url.rstrip('/')}/oobi/{issuer_aid}/controller"


def build_dossier_url(dossier_said: str, issuer_base_url: str) -> str:
    """Construct dossier URL for the evd field."""
    return f"{issuer_base_url.rstrip('/')}/dossier/{dossier_said}"
