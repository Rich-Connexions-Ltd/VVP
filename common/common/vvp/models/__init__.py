# VVP Models - Shared data models for ACDC, dossier, and KERI Agent types

from common.vvp.models.acdc import ACDC, ACDCChainResult
from common.vvp.models.dossier import (
    ACDCNode,
    DossierDAG,
    DossierWarning,
    EdgeOperator,
    EdgeValidationWarning,
    ToIPWarningCode,
)
from common.vvp.models.keri_agent import (
    AgentErrorResponse,
    AgentHealthResponse,
    AgentStatsResponse,
    BootstrapStatusResponse,
    BuildDossierRequest,
    CreateIdentityRequest,
    CreateRegistryRequest,
    CreateVVPAttestationRequest,
    CredentialResponse,
    DossierResponse,
    IdentityResponse,
    IssueCredentialRequest,
    RegistryResponse,
    RevokeCredentialRequest,
    RotateKeysRequest,
    RotationResponse,
    VVPAttestationResponse,
)

__all__ = [
    "ACDC",
    "ACDCChainResult",
    "ACDCNode",
    "DossierDAG",
    "DossierWarning",
    "EdgeOperator",
    "EdgeValidationWarning",
    "ToIPWarningCode",
    # KERI Agent DTOs (Sprint 68)
    "AgentErrorResponse",
    "AgentHealthResponse",
    "AgentStatsResponse",
    "BootstrapStatusResponse",
    "BuildDossierRequest",
    "CreateIdentityRequest",
    "CreateRegistryRequest",
    "CreateVVPAttestationRequest",
    "CredentialResponse",
    "DossierResponse",
    "IdentityResponse",
    "IssueCredentialRequest",
    "RegistryResponse",
    "RevokeCredentialRequest",
    "RotateKeysRequest",
    "RotationResponse",
    "VVPAttestationResponse",
]
