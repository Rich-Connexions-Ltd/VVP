"""Mock vLEI infrastructure for development and testing.

This module provides a mock GLEIF and QVI credential chain for development
and testing purposes. It creates:

1. mock-gleif identity - Simulates the GLEIF root authority
2. mock-gleif-registry - Registry for GLEIF-issued credentials
3. mock-qvi identity - Simulates a Qualified vLEI Issuer
4. mock-qvi-registry - Registry for QVI-issued credentials
5. QVI credential from mock-gleif to mock-qvi

When organizations are created, they receive Legal Entity credentials
from mock-qvi, establishing a valid (mock) credential chain.

IMPORTANT: This infrastructure is for development/testing only.
Production deployments should use real GLEIF and QVI credentials.

Sprint 68c: Migrated from direct app.keri.* access to KeriAgentClient.
MockVLEIManager is now a thin facade that delegates all KERI operations
to the KERI Agent via HTTP calls.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from app.config import MOCK_GLEIF_NAME, MOCK_GSMA_NAME, MOCK_QVI_NAME, MOCK_VLEI_ENABLED
from app.vetter.constants import GSMA_GOVERNANCE_SCHEMA_SAID, VETTER_CERT_SCHEMA_SAID

log = logging.getLogger(__name__)

# Schema SAIDs (from vLEI Ecosystem Governance Framework)
QVI_SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LEGAL_ENTITY_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"


@dataclass
class MockVLEIState:
    """State of mock vLEI infrastructure."""

    gleif_aid: str
    gleif_registry_key: str
    qvi_aid: str
    qvi_credential_said: str
    qvi_registry_key: str
    gsma_aid: str = ""
    gsma_registry_key: str = ""
    gsma_governance_said: str = ""  # Sprint 62: governance credential SAID
    gleif_org_id: str = ""  # Sprint 67: promoted Organization ID
    qvi_org_id: str = ""  # Sprint 67: promoted Organization ID
    gsma_org_id: str = ""  # Sprint 67: promoted Organization ID
    initialized: bool = True


# Module-level singleton
_mock_vlei_manager: Optional["MockVLEIManager"] = None


def get_mock_vlei_manager() -> "MockVLEIManager":
    """Get or create the mock vLEI manager singleton."""
    global _mock_vlei_manager
    if _mock_vlei_manager is None:
        _mock_vlei_manager = MockVLEIManager()
    return _mock_vlei_manager


def reset_mock_vlei_manager() -> None:
    """Reset the singleton (for testing)."""
    global _mock_vlei_manager
    _mock_vlei_manager = None


class MockVLEIManager:
    """Manages mock GLEIF and QVI identities for development/testing.

    Sprint 68c: Thin facade over KeriAgentClient. All KERI operations
    (identity creation, registry creation, credential issuance, witness
    publishing) are delegated to the KERI Agent. State is managed by
    TrustAnchorManager (DB-backed).
    """

    def __init__(self):
        self._state: Optional[MockVLEIState] = None

    @property
    def state(self) -> Optional[MockVLEIState]:
        """Get current mock vLEI state (None if not initialized).

        Delegates to get_mock_vlei_state() so all callers automatically
        get DB-backed state from TrustAnchorManager.
        """
        return self.get_mock_vlei_state()

    def get_mock_vlei_state(self) -> Optional[MockVLEIState]:
        """Get mock vLEI state via TrustAnchorManager (DB-backed)."""
        from app.org.trust_anchors import get_trust_anchor_manager
        return get_trust_anchor_manager().get_mock_vlei_state()

    @property
    def is_initialized(self) -> bool:
        """Check if mock vLEI infrastructure is initialized."""
        state = self.get_mock_vlei_state()
        return state is not None and state.initialized

    async def initialize(self) -> MockVLEIState:
        """Initialize mock GLEIF, QVI, and GSMA identities via KERI Agent.

        Delegates all KERI operations to the agent. The agent handles:
        - Creating/finding identities (GLEIF, QVI, GSMA)
        - Creating/finding registries
        - Issuing QVI + governance credentials
        - Publishing to witnesses

        After agent initialization, syncs state to the issuer DB via
        TrustAnchorManager and promotes trust anchors to Organizations.

        Returns:
            MockVLEIState with initialized infrastructure details

        Raises:
            RuntimeError: If mock vLEI is disabled via config
        """
        if not MOCK_VLEI_ENABLED:
            raise RuntimeError("Mock vLEI is disabled (VVP_MOCK_VLEI_ENABLED=false)")

        # Check for persisted state in database first
        persisted_state = self._load_persisted_state()
        if persisted_state:
            log.info("Restored mock vLEI state from database")
            self._state = persisted_state
            self._promote_trust_anchors()
            return self._state

        from app.keri_client import get_keri_client

        client = get_keri_client()

        log.info("Initializing mock vLEI infrastructure via KERI Agent...")
        status = await client.initialize_mock_vlei()

        # Sync agent state to issuer DB via TrustAnchorManager
        from app.org.trust_anchors import get_trust_anchor_manager
        tam = get_trust_anchor_manager()
        tam.sync_from_agent(status)

        self._state = tam.get_mock_vlei_state()
        log.info("Mock vLEI infrastructure initialized successfully")
        return self._state

    async def issue_le_credential(
        self,
        org_name: str,
        org_aid: str,
        pseudo_lei: str,
    ) -> str:
        """Issue a Legal Entity credential from mock-qvi to an organization.

        Args:
            org_name: Organization name
            org_aid: Organization's KERI AID
            pseudo_lei: Organization's pseudo-LEI

        Returns:
            SAID of the issued Legal Entity credential

        Raises:
            RuntimeError: If mock vLEI is not initialized
        """
        # Sprint 68b: Read state from TrustAnchorManager (DB-backed) instead
        # of self._state which requires startup initialize().
        state = self.get_mock_vlei_state()
        if state is None:
            raise RuntimeError(
                "Mock vLEI not initialized — KERI Agent bootstrap not yet complete"
            )

        from app.keri_client import get_keri_client
        from common.vvp.models.keri_agent import IssueCredentialRequest

        client = get_keri_client()

        # Legal Entity credential attributes per vLEI Governance Framework
        le_attributes = {
            "i": org_aid,  # Issuee AID
            "LEI": pseudo_lei,
        }

        # Edge to QVI credential for chain verification
        edges = {
            "qvi": {
                "n": state.qvi_credential_said,
                "s": QVI_SCHEMA_SAID,
            }
        }

        qvi_registry_name = f"{MOCK_QVI_NAME}-registry"
        req = IssueCredentialRequest(
            identity_name=MOCK_QVI_NAME,
            registry_name=qvi_registry_name,
            schema_said=LEGAL_ENTITY_SCHEMA_SAID,
            recipient_aid=org_aid,
            attributes=le_attributes,
            edges=edges,
        )
        cred = await client.issue_credential(req)

        log.info(f"Issued LE credential for {org_name}: {cred.said[:16]}...")
        return cred.said

    async def issue_vetter_certification(
        self,
        org_aid: str,
        ecc_targets: list[str],
        jurisdiction_targets: list[str],
        name: str,
        certification_expiry: Optional[str] = None,
    ) -> str:
        """Issue a VetterCertification credential from mock-gsma to an org.

        Sprint 62: Now includes 'issuer' edge pointing to the GSMA governance
        credential, establishing the trust chain.

        Args:
            org_aid: Organization's KERI AID (the certified vetter)
            ecc_targets: E.164 country codes
            jurisdiction_targets: ISO 3166-1 alpha-3 codes
            name: Vetter name
            certification_expiry: Optional expiry date (ISO 8601 UTC)

        Returns:
            SAID of the issued VetterCertification credential

        Raises:
            RuntimeError: If mock GSMA is not initialized
        """
        state = self.get_mock_vlei_state()
        if state is None or not state.gsma_aid:
            raise RuntimeError("Mock GSMA not initialized")

        from app.keri_client import get_keri_client
        from common.vvp.models.keri_agent import IssueCredentialRequest

        client = get_keri_client()

        # VetterCertification attributes
        attributes = {
            "i": org_aid,
            "ecc_targets": ecc_targets,
            "jurisdiction_targets": jurisdiction_targets,
            "name": name,
        }
        # NOTE: Expiry stored as "certificationExpiry" (camelCase) in ACDC attributes
        if certification_expiry:
            attributes["certificationExpiry"] = certification_expiry

        # Sprint 62: Add 'issuer' edge to GSMA governance credential
        edges = None
        if state.gsma_governance_said:
            edges = {
                "issuer": {
                    "n": state.gsma_governance_said,
                    "s": GSMA_GOVERNANCE_SCHEMA_SAID,
                    "o": "I2I",
                }
            }

        gsma_registry_name = f"{MOCK_GSMA_NAME}-registry"
        req = IssueCredentialRequest(
            identity_name=MOCK_GSMA_NAME,
            registry_name=gsma_registry_name,
            schema_said=VETTER_CERT_SCHEMA_SAID,
            recipient_aid=org_aid,
            attributes=attributes,
            edges=edges,
        )
        cred = await client.issue_credential(req)

        log.info(f"Issued VetterCertification for {name}: {cred.said[:16]}...")
        return cred.said

    def _promote_trust_anchors(self) -> None:
        """Promote trust-anchor identities to first-class Organization records.

        Sprint 68b: Delegates to TrustAnchorManager._promote_trust_anchors().
        Keeps self._state in sync with the trust anchor manager's state.
        """
        from app.org.trust_anchors import get_trust_anchor_manager

        tam = get_trust_anchor_manager()
        tam._state = self._state
        tam._promote_trust_anchors()
        # Sync back any org_id updates
        self._state = tam._state

    def _load_persisted_state(self) -> Optional[MockVLEIState]:
        """Load persisted mock vLEI state from database.

        Sprint 68b: Delegates to TrustAnchorManager.
        """
        from app.org.trust_anchors import get_trust_anchor_manager
        return get_trust_anchor_manager()._load_persisted_state()

    def _persist_state(self, state: MockVLEIState) -> None:
        """Persist mock vLEI state to database.

        Sprint 68b: Delegates to TrustAnchorManager.
        """
        from app.org.trust_anchors import get_trust_anchor_manager
        get_trust_anchor_manager()._persist_state(state)
