"""Mock vLEI infrastructure for KERI Agent.

KERI-only operations extracted from services/issuer/app/org/mock_vlei.py.
Creates mock GLEIF, QVI, and GSMA identities, registries, and trust chain
credentials. Does NOT interact with PostgreSQL — state is tracked in-memory
(LMDB persists the identities/registries/credentials natively).

Sprint 68: KERI Agent Service Extraction.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from app.config import (
    MOCK_GLEIF_NAME,
    MOCK_GSMA_NAME,
    MOCK_QVI_NAME,
    MOCK_VLEI_ENABLED,
    QVI_SCHEMA_SAID,
    LEGAL_ENTITY_SCHEMA_SAID,
)

log = logging.getLogger(__name__)

# Schema SAIDs for vetter certification (Sprint 61-62)
GSMA_GOVERNANCE_SCHEMA_SAID = "EIBowJmxx5hNWQlfXqGcbN0aP_RBuucMW6mle4tAN6TL"
VETTER_CERT_SCHEMA_SAID = "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H"


@dataclass
class MockVLEIState:
    """State of mock vLEI KERI infrastructure."""

    gleif_aid: str
    gleif_registry_key: str
    qvi_aid: str
    qvi_credential_said: str
    qvi_registry_key: str
    gsma_aid: str = ""
    gsma_registry_key: str = ""
    gsma_governance_said: str = ""
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
    """Manages mock GLEIF, QVI, and GSMA identities (KERI operations only).

    This is the agent-side complement to the issuer's MockVLEIManager.
    It handles all KERI/LMDB operations:
    - Creating identities and registries
    - Issuing trust chain credentials (QVI, LE, VetterCert, governance)
    - Publishing to witnesses

    It does NOT:
    - Write to PostgreSQL (Organization records)
    - Promote trust anchors
    - Persist state to DB (state is reconstructed from LMDB on restart)
    """

    def __init__(self):
        self._state: Optional[MockVLEIState] = None

    @property
    def state(self) -> Optional[MockVLEIState]:
        """Get current mock vLEI state (None if not initialized)."""
        return self._state

    @property
    def is_initialized(self) -> bool:
        """Check if mock vLEI infrastructure is initialized."""
        return self._state is not None and self._state.initialized

    async def initialize(self) -> MockVLEIState:
        """Initialize mock GLEIF and QVI identities.

        Idempotent — checks for existing identities/registries in LMDB
        before creating new ones.

        Returns:
            MockVLEIState with initialized infrastructure details
        """
        if not MOCK_VLEI_ENABLED:
            raise RuntimeError("Mock vLEI is disabled (VVP_MOCK_VLEI_ENABLED=false)")

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
                metadata={"type": "mock_gleif"},
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
                metadata={"type": "mock_qvi"},
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

        # 5. Publish all mock vLEI identities to witnesses
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

        # 6. Issue QVI credential from mock-gleif to mock-qvi
        qvi_cred_said = await self._get_or_issue_qvi_credential(
            issuer=issuer,
            gleif_registry_name=gleif_registry_name,
            qvi_aid=qvi_info.aid,
        )

        # 7. Create mock GSMA infrastructure
        gsma_aid, gsma_registry_key = await self._create_gsma_identity(
            identity_mgr, registry_mgr
        )

        # 8. Issue GSMA governance credential
        gsma_governance_said = await self._issue_governance_credential(
            issuer=issuer, gsma_aid=gsma_aid
        )

        # 9. Set state (in-memory only — LMDB persists the actual identities)
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

        log.info("Mock vLEI infrastructure initialized successfully")
        return self._state

    async def _get_or_issue_qvi_credential(
        self,
        issuer,
        gleif_registry_name: str,
        qvi_aid: str,
    ) -> str:
        """Get existing QVI credential SAID or issue a new one."""
        from app.keri.registry import get_registry_manager

        registry_mgr = await get_registry_manager()
        reger = registry_mgr.regery.reger

        # Scan for existing QVI credential
        for said, creder in reger.creds.getItemIter():
            if hasattr(creder, "schema") and creder.schema == QVI_SCHEMA_SAID:
                attrib = creder.attrib if hasattr(creder, "attrib") else {}
                if attrib.get("i") == qvi_aid:
                    log.info(f"Found existing QVI credential: {creder.said[:16]}...")
                    return creder.said

        log.info("Issuing new QVI credential from mock-gleif to mock-qvi...")

        qvi_attributes = {
            "i": qvi_aid,
            "LEI": "5493MOCK0QVI0000000",
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
        """Issue a Legal Entity credential from mock-qvi to an organization."""
        if self._state is None:
            raise RuntimeError("Mock vLEI not initialized")

        from app.keri.issuer import get_credential_issuer

        issuer = await get_credential_issuer()

        le_attributes = {
            "i": org_aid,
            "LEI": pseudo_lei,
        }

        edges = {
            "qvi": {
                "n": self._state.qvi_credential_said,
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
        """Create mock GSMA identity and registry."""
        gsma_info = await identity_mgr.get_identity_by_name(MOCK_GSMA_NAME)
        if gsma_info is None:
            gsma_info = await identity_mgr.create_identity(
                name=MOCK_GSMA_NAME,
                transferable=True,
                metadata={"type": "mock_gsma"},
            )
            log.info(f"Created mock GSMA identity: {gsma_info.aid[:16]}...")
        else:
            log.info(f"Found existing mock GSMA identity: {gsma_info.aid[:16]}...")

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

    async def _issue_governance_credential(
        self,
        issuer,
        gsma_aid: str,
    ) -> str:
        """Issue GSMA governance credential (self-issued)."""
        from app.keri.registry import get_registry_manager

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

    async def issue_vetter_certification(
        self,
        org_aid: str,
        ecc_targets: list[str],
        jurisdiction_targets: list[str],
        name: str,
        certification_expiry: Optional[str] = None,
    ) -> str:
        """Issue a VetterCertification credential from mock-gsma to an org."""
        if self._state is None or not self._state.gsma_aid:
            raise RuntimeError("Mock GSMA not initialized")

        from app.keri.issuer import get_credential_issuer

        issuer = await get_credential_issuer()

        attributes = {
            "i": org_aid,
            "ecc_targets": ecc_targets,
            "jurisdiction_targets": jurisdiction_targets,
            "name": name,
        }
        if certification_expiry:
            attributes["certificationExpiry"] = certification_expiry

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
