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
    """Get or create the mock vLEI manager singleton.

    Note: During Sprint 68b migration, callers should prefer
    get_trust_anchor_manager().get_mock_vlei_state() for state access.
    This accessor is kept for backwards compatibility with KERI-heavy
    methods (initialize, issue_le_credential, issue_vetter_certification)
    during the transition.
    """
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

    Creates a pseudo root-of-trust:
    - mock-gleif identity with registry
    - mock-qvi identity with QVI credential from mock-gleif

    Organizations created via the API receive Legal Entity credentials
    from mock-qvi, establishing a valid (mock) credential chain.
    """

    def __init__(self):
        self._state: Optional[MockVLEIState] = None

    @property
    def state(self) -> Optional[MockVLEIState]:
        """Get current mock vLEI state (None if not initialized).

        Sprint 68b: Delegates to get_mock_vlei_state() so all callers
        (including vetter/service.py) automatically get DB-backed state
        from TrustAnchorManager. Direct self._state access is deprecated.
        """
        return self.get_mock_vlei_state()

    def get_mock_vlei_state(self) -> Optional[MockVLEIState]:
        """Get mock vLEI state via TrustAnchorManager (DB-backed).

        Sprint 68b: Canonical read path. Uses TrustAnchorManager for
        DB persistence with in-memory cache fallback.
        """
        from app.org.trust_anchors import get_trust_anchor_manager
        return get_trust_anchor_manager().get_mock_vlei_state()

    @property
    def is_initialized(self) -> bool:
        """Check if mock vLEI infrastructure is initialized."""
        state = self.get_mock_vlei_state()
        return state is not None and state.initialized

    async def initialize(self) -> MockVLEIState:
        """Initialize mock GLEIF and QVI identities on startup.

        This method is idempotent - it checks for existing state in the
        database and KERI stores before creating new infrastructure.

        Returns:
            MockVLEIState with initialized infrastructure details

        Raises:
            RuntimeError: If mock vLEI is disabled via config
        """
        if not MOCK_VLEI_ENABLED:
            raise RuntimeError("Mock vLEI is disabled (VVP_MOCK_VLEI_ENABLED=false)")

        # Check for persisted state in database
        persisted_state = self._load_persisted_state()
        if persisted_state:
            log.info("Restored mock vLEI state from database")
            self._state = persisted_state
            # Sprint 61: Partial-state upgrade — if either GSMA field is empty,
            # bootstrap GSMA infrastructure on top of existing state
            if not self._state.gsma_aid or not self._state.gsma_registry_key:
                log.info("Pre-Sprint 61 state detected — bootstrapping GSMA infrastructure")
                try:
                    await self._bootstrap_gsma()
                except Exception as e:
                    log.error(
                        f"GSMA bootstrap failed (non-fatal): {e}. "
                        f"Vetter certification features will be unavailable."
                    )
            # Sprint 62: Partial-state upgrade — if governance credential is missing,
            # issue it on top of existing GSMA infrastructure
            if self._state.gsma_aid and not self._state.gsma_governance_said:
                log.info("Pre-Sprint 62 state detected — issuing GSMA governance credential")
                try:
                    await self._bootstrap_governance_credential()
                except Exception as e:
                    log.error(
                        f"GSMA governance bootstrap failed (non-fatal): {e}. "
                        f"Governance features will be unavailable."
                    )
            # Sprint 67: Promote trust anchors to first-class organizations
            # Runs on restored-state path to backfill pre-Sprint67 deployments
            self._promote_trust_anchors()
            return self._state

        # Import here to avoid circular imports
        from app.keri.identity import get_identity_manager
        from app.keri.registry import get_registry_manager
        from app.keri.issuer import get_credential_issuer

        identity_mgr = await get_identity_manager()
        registry_mgr = await get_registry_manager()
        issuer = await get_credential_issuer()

        log.info("Initializing mock vLEI infrastructure...")

        # 1. Create or get mock-gleif identity
        gleif_info = await identity_mgr.get_identity_by_name(MOCK_GLEIF_NAME)
        if gleif_info is None:
            gleif_info = await identity_mgr.create_identity(
                name=MOCK_GLEIF_NAME,
                transferable=True,
            )
            log.info(f"Created mock GLEIF identity: {gleif_info.aid[:16]}...")
        else:
            log.info(f"Found existing mock GLEIF identity: {gleif_info.aid[:16]}...")

        # 2. Create or get mock-gleif registry
        gleif_registry_name = f"{MOCK_GLEIF_NAME}-registry"
        gleif_registry = registry_mgr.regery.registryByName(gleif_registry_name)
        if gleif_registry is None:
            gleif_registry_info = await registry_mgr.create_registry(
                name=gleif_registry_name,
                issuer_aid=gleif_info.aid,
            )
            gleif_registry_key = gleif_registry_info.registry_key
            log.info(f"Created mock GLEIF registry: {gleif_registry_key[:16]}...")
        else:
            gleif_registry_key = gleif_registry.regk
            log.info(f"Found existing mock GLEIF registry: {gleif_registry_key[:16]}...")

        # 3. Create or get mock-qvi identity
        qvi_info = await identity_mgr.get_identity_by_name(MOCK_QVI_NAME)
        if qvi_info is None:
            qvi_info = await identity_mgr.create_identity(
                name=MOCK_QVI_NAME,
                transferable=True,
            )
            log.info(f"Created mock QVI identity: {qvi_info.aid[:16]}...")
        else:
            log.info(f"Found existing mock QVI identity: {qvi_info.aid[:16]}...")

        # 4. Create or get mock-qvi registry
        qvi_registry_name = f"{MOCK_QVI_NAME}-registry"
        qvi_registry = registry_mgr.regery.registryByName(qvi_registry_name)
        if qvi_registry is None:
            qvi_registry_info = await registry_mgr.create_registry(
                name=qvi_registry_name,
                issuer_aid=qvi_info.aid,
            )
            qvi_registry_key = qvi_registry_info.registry_key
            log.info(f"Created mock QVI registry: {qvi_registry_key[:16]}...")
        else:
            qvi_registry_key = qvi_registry.regk
            log.info(f"Found existing mock QVI registry: {qvi_registry_key[:16]}...")

        # 5. Publish all mock vLEI identities to witnesses for OOBI resolution
        try:
            from app.keri.witness import get_witness_publisher
            publisher = get_witness_publisher()
            for aid_info in [gleif_info, qvi_info]:
                kel_bytes = await identity_mgr.get_kel_bytes(aid_info.aid)
                pub = await publisher.publish_oobi(aid_info.aid, kel_bytes)
                log.info(f"Published {aid_info.name} to witnesses: "
                         f"{pub.success_count}/{pub.total_count}")
        except Exception as e:
            log.warning(f"Failed to publish mock vLEI identities to witnesses: {e}")

        # 6. Issue QVI credential from mock-gleif to mock-qvi (if not exists)
        qvi_cred_said = await self._get_or_issue_qvi_credential(
            issuer=issuer,
            gleif_registry_name=gleif_registry_name,
            qvi_aid=qvi_info.aid,
        )

        # 7. Create mock GSMA infrastructure (Sprint 61)
        gsma_aid, gsma_registry_key = await self._create_gsma_identity(
            identity_mgr, registry_mgr
        )

        # 8. Issue GSMA governance credential (Sprint 62)
        gsma_governance_said = await self._issue_governance_credential(
            issuer=issuer, gsma_aid=gsma_aid
        )

        # 9. Persist state to database
        self._state = MockVLEIState(
            gleif_aid=gleif_info.aid,
            gleif_registry_key=gleif_registry_key,
            qvi_aid=qvi_info.aid,
            qvi_credential_said=qvi_cred_said,
            qvi_registry_key=qvi_registry_key,
            gsma_aid=gsma_aid,
            gsma_registry_key=gsma_registry_key,
            gsma_governance_said=gsma_governance_said,
        )
        self._persist_state(self._state)

        # Sprint 67: Promote trust anchors to first-class organizations
        self._promote_trust_anchors()

        log.info("Mock vLEI infrastructure initialized successfully")
        return self._state

    async def _get_or_issue_qvi_credential(
        self,
        issuer,
        gleif_registry_name: str,
        qvi_aid: str,
    ) -> str:
        """Get existing QVI credential SAID or issue a new one.

        Args:
            issuer: CredentialIssuer instance
            gleif_registry_name: Name of the GLEIF registry
            qvi_aid: AID of the mock QVI

        Returns:
            SAID of the QVI credential
        """
        # Check if we already have a QVI credential for this QVI
        # We look for credentials in the registry that match the QVI schema
        # and have the QVI as recipient
        from app.keri.registry import get_registry_manager

        registry_mgr = await get_registry_manager()
        reger = registry_mgr.regery.reger

        # Scan issued credentials for existing QVI credential
        for said, creder in reger.creds.getItemIter():
            # Check if this is a QVI credential issued to our mock-qvi
            if hasattr(creder, "schema") and creder.schema == QVI_SCHEMA_SAID:
                # Check recipient
                attrib = creder.attrib if hasattr(creder, "attrib") else {}
                if attrib.get("i") == qvi_aid:
                    log.info(f"Found existing QVI credential: {creder.said[:16]}...")
                    return creder.said

        # No existing credential found, issue a new one
        log.info("Issuing new QVI credential from mock-gleif to mock-qvi...")

        # QVI credential attributes per vLEI Governance Framework
        qvi_attributes = {
            "i": qvi_aid,  # Issuee AID
            "LEI": "5493MOCK0QVI0000000",  # Pseudo-LEI for mock QVI
        }

        cred_info, _ = await issuer.issue_credential(
            registry_name=gleif_registry_name,
            schema_said=QVI_SCHEMA_SAID,
            attributes=qvi_attributes,
            recipient_aid=qvi_aid,
        )

        log.info(f"Issued QVI credential: {cred_info.said[:16]}...")
        return cred_info.said

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

        from app.keri.issuer import get_credential_issuer

        issuer = await get_credential_issuer()

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
        cred_info, _ = await issuer.issue_credential(
            registry_name=qvi_registry_name,
            schema_said=LEGAL_ENTITY_SCHEMA_SAID,
            attributes=le_attributes,
            recipient_aid=org_aid,
            edges=edges,
        )

        log.info(f"Issued LE credential for {org_name}: {cred_info.said[:16]}...")
        return cred_info.said

    async def _create_gsma_identity(self, identity_mgr, registry_mgr):
        """Create mock GSMA identity and registry.

        Returns:
            Tuple of (gsma_aid, gsma_registry_key)
        """
        # Create or get mock-gsma identity
        gsma_info = await identity_mgr.get_identity_by_name(MOCK_GSMA_NAME)
        if gsma_info is None:
            gsma_info = await identity_mgr.create_identity(
                name=MOCK_GSMA_NAME,
                transferable=True,
            )
            log.info(f"Created mock GSMA identity: {gsma_info.aid[:16]}...")
        else:
            log.info(f"Found existing mock GSMA identity: {gsma_info.aid[:16]}...")

        # Create or get mock-gsma registry
        gsma_registry_name = f"{MOCK_GSMA_NAME}-registry"
        gsma_registry = registry_mgr.regery.registryByName(gsma_registry_name)
        if gsma_registry is None:
            gsma_registry_info = await registry_mgr.create_registry(
                name=gsma_registry_name,
                issuer_aid=gsma_info.aid,
            )
            gsma_registry_key = gsma_registry_info.registry_key
            log.info(f"Created mock GSMA registry: {gsma_registry_key[:16]}...")
        else:
            gsma_registry_key = gsma_registry.regk
            log.info(f"Found existing mock GSMA registry: {gsma_registry_key[:16]}...")

        # Publish mock-gsma identity to witnesses
        try:
            from app.keri.witness import get_witness_publisher
            publisher = get_witness_publisher()
            kel_bytes = await identity_mgr.get_kel_bytes(gsma_info.aid)
            pub = await publisher.publish_oobi(gsma_info.aid, kel_bytes)
            log.info(f"Published mock GSMA to witnesses: "
                     f"{pub.success_count}/{pub.total_count}")
        except Exception as e:
            log.warning(f"Failed to publish mock GSMA identity to witnesses: {e}")

        return gsma_info.aid, gsma_registry_key

    async def _bootstrap_gsma(self) -> None:
        """Bootstrap GSMA infrastructure for pre-Sprint 61 state.

        Called when persisted state exists but GSMA fields are empty.
        Creates GSMA identity/registry and updates persisted state.
        """
        from app.keri.identity import get_identity_manager
        from app.keri.registry import get_registry_manager

        identity_mgr = await get_identity_manager()
        registry_mgr = await get_registry_manager()

        gsma_aid, gsma_registry_key = await self._create_gsma_identity(
            identity_mgr, registry_mgr
        )

        self._state.gsma_aid = gsma_aid
        self._state.gsma_registry_key = gsma_registry_key
        self._persist_state(self._state)
        log.info("GSMA infrastructure bootstrapped and state updated")

    async def _issue_governance_credential(
        self,
        issuer,
        gsma_aid: str,
    ) -> str:
        """Issue GSMA governance credential (self-issued by GSMA AID).

        Sprint 62: Creates a self-referencing governance credential that
        establishes GSMA as the vetter certification governance authority.

        Returns:
            SAID of the governance credential
        """
        from app.keri.registry import get_registry_manager

        # Check for existing governance credential in KERI store
        registry_mgr = await get_registry_manager()
        reger = registry_mgr.regery.reger
        for _said, creder in reger.creds.getItemIter():
            if hasattr(creder, "schema") and creder.schema == GSMA_GOVERNANCE_SCHEMA_SAID:
                attrib = creder.attrib if hasattr(creder, "attrib") else {}
                if attrib.get("i") == gsma_aid:
                    log.info(f"Found existing GSMA governance credential: {creder.said[:16]}...")
                    return creder.said

        log.info("Issuing GSMA governance credential (self-issued)...")
        gsma_registry_name = f"{MOCK_GSMA_NAME}-registry"
        governance_attributes = {
            "i": gsma_aid,
            "name": "GSMA",
            "role": "Vetter Governance Authority",
        }
        cred_info, _ = await issuer.issue_credential(
            registry_name=gsma_registry_name,
            schema_said=GSMA_GOVERNANCE_SCHEMA_SAID,
            attributes=governance_attributes,
            recipient_aid=gsma_aid,
        )
        log.info(f"Issued GSMA governance credential: {cred_info.said[:16]}...")
        return cred_info.said

    async def _bootstrap_governance_credential(self) -> None:
        """Bootstrap governance credential for pre-Sprint 62 state.

        Called when persisted state has GSMA AID but no governance credential.
        """
        from app.keri.issuer import get_credential_issuer

        issuer = await get_credential_issuer()
        gov_said = await self._issue_governance_credential(
            issuer=issuer, gsma_aid=self._state.gsma_aid
        )
        self._state.gsma_governance_said = gov_said
        self._persist_state(self._state)
        log.info("GSMA governance credential bootstrapped and state updated")

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
        if self._state is None or not self._state.gsma_aid:
            raise RuntimeError("Mock GSMA not initialized")

        from app.keri.issuer import get_credential_issuer

        issuer = await get_credential_issuer()

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
        if self._state.gsma_governance_said:
            edges = {
                "issuer": {
                    "n": self._state.gsma_governance_said,
                    "s": GSMA_GOVERNANCE_SCHEMA_SAID,
                    "o": "I2I",
                }
            }

        gsma_registry_name = f"{MOCK_GSMA_NAME}-registry"
        cred_info, _ = await issuer.issue_credential(
            registry_name=gsma_registry_name,
            schema_said=VETTER_CERT_SCHEMA_SAID,
            attributes=attributes,
            recipient_aid=org_aid,
            edges=edges,
        )

        log.info(f"Issued VetterCertification for {name}: {cred_info.said[:16]}...")
        return cred_info.said

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
