"""Trust anchor management for VVP Issuer.

Manages trust anchor Organization records in the issuer PostgreSQL database.
Reads bootstrap status from the KERI Agent (via BootstrapStatusResponse)
and creates/updates Organization records for GLEIF, QVI, GSMA.

Extracted from mock_vlei.py in Sprint 68b to separate DB-only operations
(issuer-side) from KERI operations (agent-side).
"""

import logging
import uuid
from typing import Optional

from common.vvp.models.keri_agent import BootstrapStatusResponse

from app.config import MOCK_GLEIF_NAME, MOCK_GSMA_NAME, MOCK_QVI_NAME
from app.db.models import MockVLEIState as MockVLEIStateModel, Organization, OrgType
from app.db.session import get_db_session
from app.org.mock_vlei import MockVLEIState

log = logging.getLogger(__name__)

# Module-level singleton
_trust_anchor_manager: Optional["TrustAnchorManager"] = None


def get_trust_anchor_manager() -> "TrustAnchorManager":
    """Get or create the TrustAnchorManager singleton."""
    global _trust_anchor_manager
    if _trust_anchor_manager is None:
        _trust_anchor_manager = TrustAnchorManager()
    return _trust_anchor_manager


def reset_trust_anchor_manager() -> None:
    """Reset the singleton (for testing)."""
    global _trust_anchor_manager
    _trust_anchor_manager = None


class TrustAnchorManager:
    """Manages trust anchor Organization records in the issuer DB.

    Reads bootstrap status from the KERI Agent (via BootstrapStatusResponse)
    and creates/updates Organization DB records for GLEIF, QVI, GSMA.

    State access: use get_mock_vlei_state() — returns MockVLEIState or None.
    Two-tier read: in-memory cache (fast) → DB fallback (durable).
    """

    def __init__(self):
        self._state: Optional[MockVLEIState] = None

    def get_mock_vlei_state(self) -> Optional[MockVLEIState]:
        """Get current mock vLEI state.

        Returns cached in-memory state if available, otherwise loads
        from PostgreSQL. Returns None if no state has been synced.
        """
        if self._state is not None:
            return self._state
        self._state = self._load_persisted_state()
        return self._state

    def sync_from_agent(self, status: BootstrapStatusResponse) -> None:
        """Sync trust anchor state from KERI Agent bootstrap status.

        Builds a MockVLEIState from the agent's BootstrapStatusResponse,
        persists it to PostgreSQL, and promotes trust anchors to
        first-class Organization records.

        Args:
            status: Bootstrap status from the KERI Agent
        """
        if not status.initialized:
            log.info("Agent not initialized — skipping trust anchor sync")
            return

        # Load existing state to preserve org_ids across syncs
        existing = self._load_persisted_state()

        self._state = MockVLEIState(
            gleif_aid=status.gleif_aid or "",
            gleif_registry_key=status.gleif_registry_key or "",
            qvi_aid=status.qvi_aid or "",
            qvi_credential_said=status.qvi_credential_said or "",
            qvi_registry_key=status.qvi_registry_key or "",
            gsma_aid=status.gsma_aid or "",
            gsma_registry_key=status.gsma_registry_key or "",
            gsma_governance_said=status.gsma_governance_said or "",
            # Preserve org_ids from existing state (DB-side concept)
            gleif_org_id=existing.gleif_org_id if existing else "",
            qvi_org_id=existing.qvi_org_id if existing else "",
            gsma_org_id=existing.gsma_org_id if existing else "",
        )

        self._persist_state(self._state)
        self._promote_trust_anchors()
        log.info("Trust anchors synced from KERI Agent")

    def _promote_trust_anchors(self) -> None:
        """Promote trust-anchor identities to first-class Organization records.

        Creates Organization DB records for GLEIF, QVI, and GSMA
        so they appear in the org list and can have admin users and credentials.

        Matching strategy:
        1. Check persisted org_id in MockVLEIState → load by ID
        2. Check if Organization with matching AID exists → update org_type
        3. Create new Organization (with name collision safety)

        Idempotent: safe to call on every sync.
        """
        if self._state is None:
            return

        from app.org.lei_generator import generate_pseudo_lei

        trust_anchors = [
            (MOCK_GLEIF_NAME, self._state.gleif_aid, self._state.gleif_registry_key,
             OrgType.ROOT_AUTHORITY, "gleif_org_id"),
            (MOCK_QVI_NAME, self._state.qvi_aid, self._state.qvi_registry_key,
             OrgType.QVI, "qvi_org_id"),
        ]
        if self._state.gsma_aid:
            trust_anchors.append(
                (MOCK_GSMA_NAME, self._state.gsma_aid, self._state.gsma_registry_key,
                 OrgType.VETTER_AUTHORITY, "gsma_org_id"),
            )

        state_changed = False
        try:
            with get_db_session() as db:
                for name, aid, registry_key, org_type, state_field in trust_anchors:
                    org = None
                    persisted_org_id = getattr(self._state, state_field, "")

                    # Strategy 1: Load by persisted org_id
                    if persisted_org_id:
                        org = db.query(Organization).filter(
                            Organization.id == persisted_org_id
                        ).first()
                        if org:
                            if org.org_type != org_type.value:
                                org.org_type = org_type.value
                                state_changed = True
                            log.debug(f"Trust anchor {name}: found by persisted org_id {persisted_org_id[:8]}...")
                            continue

                    # Strategy 2: Find by AID
                    if aid:
                        org = db.query(Organization).filter(
                            Organization.aid == aid
                        ).first()
                        if org:
                            if org.org_type != org_type.value:
                                org.org_type = org_type.value
                            setattr(self._state, state_field, org.id)
                            state_changed = True
                            log.info(f"Trust anchor {name}: matched by AID, org_id={org.id[:8]}...")
                            continue

                    # Strategy 3: Create new Organization
                    org_id = str(uuid.uuid4())
                    pseudo_lei = generate_pseudo_lei(name, org_id)

                    org_name = name
                    existing = db.query(Organization).filter(
                        Organization.name == org_name
                    ).first()
                    if existing:
                        org_name = f"{name}-ta-{aid[:8] if aid else org_id[:8]}"
                        log.warning(
                            f"Trust anchor name '{name}' already taken by org {existing.id[:8]}..., "
                            f"using '{org_name}' instead"
                        )

                    org = Organization(
                        id=org_id,
                        name=org_name,
                        pseudo_lei=pseudo_lei,
                        aid=aid,
                        registry_key=registry_key,
                        org_type=org_type.value,
                        enabled=True,
                    )
                    db.add(org)
                    setattr(self._state, state_field, org_id)
                    state_changed = True
                    log.info(f"Trust anchor {name}: created org {org_id[:8]}... (type={org_type.value})")

                db.flush()

            if state_changed:
                self._persist_state(self._state)
                log.info("Trust anchor promotion complete — state updated")
            else:
                log.debug("Trust anchor promotion: no changes needed")

        except Exception as e:
            log.error(f"Trust anchor promotion failed (non-fatal): {e}")

    def _load_persisted_state(self) -> Optional[MockVLEIState]:
        """Load persisted mock vLEI state from database."""
        try:
            with get_db_session() as db:
                state_record = db.query(MockVLEIStateModel).first()
                if state_record:
                    return MockVLEIState(
                        gleif_aid=state_record.gleif_aid,
                        gleif_registry_key=state_record.gleif_registry_key,
                        qvi_aid=state_record.qvi_aid,
                        qvi_credential_said=state_record.qvi_credential_said,
                        qvi_registry_key=state_record.qvi_registry_key,
                        gsma_aid=state_record.gsma_aid or "",
                        gsma_registry_key=state_record.gsma_registry_key or "",
                        gsma_governance_said=getattr(state_record, "gsma_governance_said", None) or "",
                        gleif_org_id=getattr(state_record, "gleif_org_id", None) or "",
                        qvi_org_id=getattr(state_record, "qvi_org_id", None) or "",
                        gsma_org_id=getattr(state_record, "gsma_org_id", None) or "",
                    )
        except Exception as e:
            log.debug(f"Could not load persisted mock vLEI state: {e}")
        return None

    def _persist_state(self, state: MockVLEIState) -> None:
        """Persist mock vLEI state to database."""
        try:
            with get_db_session() as db:
                db.query(MockVLEIStateModel).delete()
                state_record = MockVLEIStateModel(
                    gleif_aid=state.gleif_aid,
                    gleif_registry_key=state.gleif_registry_key,
                    qvi_aid=state.qvi_aid,
                    qvi_credential_said=state.qvi_credential_said,
                    qvi_registry_key=state.qvi_registry_key,
                    gsma_aid=state.gsma_aid or None,
                    gsma_registry_key=state.gsma_registry_key or None,
                    gsma_governance_said=state.gsma_governance_said or None,
                    gleif_org_id=state.gleif_org_id or None,
                    qvi_org_id=state.qvi_org_id or None,
                    gsma_org_id=state.gsma_org_id or None,
                )
                db.add(state_record)
                log.info("Persisted mock vLEI state to database")
        except Exception as e:
            log.warning(f"Could not persist mock vLEI state: {e}")
