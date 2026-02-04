"""Adapter module that imports parsing functions from verifier service.

This module provides stable import paths for CLI tools. All verifier
imports are centralized here with clear error messages if the verifier
package is not installed.

The verifier package must be installed for CLI tools to work:
    pip install -e services/verifier

Or install the full CLI bundle:
    pip install -e 'common[cli]'
"""

_INSTALL_MSG = """
VVP CLI requires the verifier package. Install with:
    pip install -e services/verifier

Or install the full CLI bundle:
    cd VVP && pip install -e services/verifier && pip install -e 'common[cli]'
"""

try:
    # JWT/PASSporT parsing
    from app.vvp.passport import (
        Passport,
        PassportHeader,
        PassportPayload,
        parse_passport,
        validate_passport_binding,
    )
    from app.vvp.header import (
        VVPIdentity,
        parse_vvp_identity,
    )

except ImportError as e:
    raise ImportError(f"{_INSTALL_MSG}\nOriginal error: {e}") from e

try:
    # CESR parsing
    from app.vvp.keri.cesr import (
        CESRMessage,
        CESRVersion,
        CountCode,
        WitnessReceipt,
        is_cesr_stream,
        parse_cesr_stream,
        parse_version_string,
    )
except ImportError as e:
    raise ImportError(f"{_INSTALL_MSG}\nOriginal error: {e}") from e

try:
    # SAID computation
    from app.vvp.keri.kel_parser import (
        compute_kel_event_said,
        compute_said_canonical,
        validate_event_said_canonical,
    )
    from app.vvp.acdc.parser import (
        compute_acdc_said,
        validate_acdc_said,
    )
    from app.vvp.acdc.schema_fetcher import (
        compute_schema_said,
    )
except ImportError as e:
    raise ImportError(f"{_INSTALL_MSG}\nOriginal error: {e}") from e

try:
    # ACDC parsing
    from app.vvp.acdc.parser import (
        ACDC,
        detect_acdc_variant,
        parse_acdc,
    )
except ImportError as e:
    raise ImportError(f"{_INSTALL_MSG}\nOriginal error: {e}") from e

try:
    # Dossier parsing and validation
    from app.vvp.dossier.parser import (
        parse_dossier,
    )
    from app.vvp.dossier.validator import (
        DossierDAG,
        DossierWarning,
        ToIPWarningCode,
        build_dag,
        detect_cycle,
        find_root,
        find_roots,
        validate_dag,
    )
    from app.vvp.dossier.fetch import (
        fetch_dossier,
    )
    from app.vvp.dossier import (
        ACDCNode,
    )
except ImportError as e:
    raise ImportError(f"{_INSTALL_MSG}\nOriginal error: {e}") from e

try:
    # Graph building
    from app.vvp.acdc.graph import (
        CredentialEdge,
        CredentialGraph,
        CredentialNode,
        CredentialStatus,
        ResolutionSource,
        build_credential_graph,
        credential_graph_to_dict,
    )
except ImportError as e:
    raise ImportError(f"{_INSTALL_MSG}\nOriginal error: {e}") from e

try:
    # KEL parsing
    from app.vvp.keri.kel_parser import (
        parse_kel_stream,
        validate_kel_chain,
    )
except ImportError as e:
    raise ImportError(f"{_INSTALL_MSG}\nOriginal error: {e}") from e


# Export all symbols
__all__ = [
    # JWT/PASSporT
    "Passport",
    "PassportHeader",
    "PassportPayload",
    "parse_passport",
    "validate_passport_binding",
    "VVPIdentity",
    "parse_vvp_identity",
    # CESR
    "CESRMessage",
    "CESRVersion",
    "CountCode",
    "WitnessReceipt",
    "is_cesr_stream",
    "parse_cesr_stream",
    "parse_version_string",
    # SAID
    "compute_kel_event_said",
    "compute_said_canonical",
    "validate_event_said_canonical",
    "compute_acdc_said",
    "validate_acdc_said",
    "compute_schema_said",
    # ACDC
    "ACDC",
    "detect_acdc_variant",
    "parse_acdc",
    # Dossier
    "ACDCNode",
    "DossierDAG",
    "DossierWarning",
    "ToIPWarningCode",
    "build_dag",
    "detect_cycle",
    "fetch_dossier",
    "find_root",
    "find_roots",
    "parse_dossier",
    "validate_dag",
    # Graph
    "CredentialEdge",
    "CredentialGraph",
    "CredentialNode",
    "CredentialStatus",
    "ResolutionSource",
    "build_credential_graph",
    "credential_graph_to_dict",
    # KEL
    "parse_kel_stream",
    "validate_kel_chain",
]
