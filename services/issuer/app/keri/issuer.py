"""KERI credential issuance for VVP Issuer.

Wraps keripy's proving.credential() and Registry.issue()/revoke() to provide
ACDC credential lifecycle management including issuance, revocation, and retrieval.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from keri import core
from keri.app import signing
from keri.core import coring, eventing, serdering
from keri.db import dbing
from keri.help import helping
from keri.vc import proving

from app.keri.identity import get_identity_manager
from app.keri.registry import get_registry_manager
from app.schema.store import has_embedded_schema

log = logging.getLogger(__name__)


@dataclass
class CredentialInfo:
    """Information about an issued credential."""

    said: str  # Credential SAID
    issuer_aid: str  # Issuing identity AID
    recipient_aid: Optional[str]  # Recipient AID (issuee)
    registry_key: str  # Registry key tracking this credential
    schema_said: str  # Schema SAID
    issuance_dt: str  # ISO8601 timestamp
    status: str  # "issued" | "revoked"
    revocation_dt: Optional[str]  # If revoked
    attributes: dict  # The 'a' section data
    edges: Optional[dict]  # Edge references
    rules: Optional[dict]  # Rules section


class CredentialIssuer:
    """Manages ACDC credential issuance and revocation.

    Wraps keripy's proving.credential() and Registry.issue()/revoke() to provide:
    - Credential creation with schema validation
    - TEL event generation and anchoring to KEL
    - Credential storage and retrieval
    - Revocation management

    The issuer shares Habery and Regery instances from identity and registry managers.
    """

    def __init__(self, temp: bool = False):
        """Initialize credential issuer.

        Args:
            temp: If True, use temporary storage (for testing).

        Note: Call initialize() to complete setup after construction.
        """
        self._lock = asyncio.Lock()
        self._initialized = False
        self._temp = temp

    async def initialize(self) -> None:
        """Initialize with access to registry and identity managers."""
        async with self._lock:
            if self._initialized:
                return

            # Ensure dependencies are initialized
            await get_identity_manager()
            await get_registry_manager()

            log.info("CredentialIssuer initialized")
            self._initialized = True

    async def close(self) -> None:
        """Release resources."""
        async with self._lock:
            if self._initialized:
                log.info("CredentialIssuer closed")
                self._initialized = False

    async def issue_credential(
        self,
        registry_name: str,
        schema_said: str,
        attributes: dict,
        recipient_aid: Optional[str] = None,
        edges: Optional[dict] = None,
        rules: Optional[dict] = None,
        private: bool = False,
    ) -> tuple[CredentialInfo, bytes]:
        """Issue a new ACDC credential.

        Args:
            registry_name: Name of the registry to track this credential
            schema_said: SAID of the schema for validation
            attributes: Credential attribute data (becomes 'a' section)
            recipient_aid: Optional targeted recipient AID
            edges: Optional edge references for chained credentials
            rules: Optional rules section
            private: If True, add privacy-preserving nonces

        Returns:
            Tuple of (CredentialInfo, credential_bytes with CESR attachments)

        Raises:
            ValueError: Schema not found, registry not found, or validation failed
        """
        async with self._lock:
            # 1. Validate schema exists
            if not has_embedded_schema(schema_said):
                raise ValueError(f"Schema not found: {schema_said}")

            # 2. Get registry and issuer hab
            registry_mgr = await get_registry_manager()
            registry = registry_mgr.regery.registryByName(registry_name)
            if registry is None:
                raise ValueError(f"Registry not found: {registry_name}")

            hab = registry.hab
            if hab is None:
                raise ValueError(f"Registry {registry_name} has no associated identity")

            # 3. Create ACDC via proving.credential()
            # Add timestamp to attributes if not present
            if "dt" not in attributes:
                attributes["dt"] = helping.nowIso8601()

            creder = proving.credential(
                schema=schema_said,
                issuer=hab.pre,
                data=attributes,
                recipient=recipient_aid,
                private=private,
                status=registry.regk,  # Registry key
                source=edges,
                rules=rules,
            )

            log.info(f"Created credential: {creder.said[:16]}... schema={schema_said[:16]}...")

            # 4. Create TEL issuance event
            dt = attributes.get("dt", helping.nowIso8601())
            iserder = registry.issue(said=creder.said, dt=dt)

            # 5. Create KEL anchor (interaction event with TEL seal)
            rseal = eventing.SealEvent(iserder.pre, iserder.snh, iserder.said)
            anc = hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])

            # 6. Anchor the TEL iss event and re-process it through the Tevery
            # This is required so the registry knows the credential has been issued
            reger = registry_mgr.regery.reger
            anc_seqner = coring.Seqner(sn=hab.kever.sn)
            anc_saider = coring.Saider(qb64=hab.kever.serder.said)

            # Store the anchor in the reger database
            registry.anchorMsg(
                pre=iserder.pre,  # Credential SAID (TEL event prefix)
                regd=iserder.said,
                seqner=anc_seqner,
                saider=anc_saider,
            )

            # Re-process the TEL iss event with the anchor reference
            registry_mgr.regery.tvy.processEvent(
                serder=iserder,
                seqner=anc_seqner,
                saider=anc_saider,
            )

            log.info(f"Created TEL iss event and KEL anchor for {creder.said[:16]}...")

            # 7. Store credential and anchor information
            prefixer = coring.Prefixer(qb64=iserder.pre)
            seqner = core.Number(num=iserder.sn, code=core.NumDex.Huge)
            saider = coring.Saider(qb64=iserder.said)

            reger.creds.put(keys=(creder.said,), val=creder)
            reger.cancs.pin(keys=(creder.said,), val=[prefixer, seqner, saider])

            log.info(f"Stored credential {creder.said[:16]}... in reger")

            # 7. Serialize credential with SealSourceTriples attachment
            acdc_bytes = signing.serialize(creder, prefixer, seqner, saider)

            # Build CredentialInfo
            cred_info = CredentialInfo(
                said=creder.said,
                issuer_aid=hab.pre,
                recipient_aid=recipient_aid,
                registry_key=registry.regk,
                schema_said=schema_said,
                issuance_dt=dt,
                status="issued",
                revocation_dt=None,
                attributes=dict(creder.attrib) if creder.attrib else attributes,
                edges=edges,
                rules=rules,
            )

            return cred_info, acdc_bytes

    async def get_anchor_ixn_bytes(self, credential_said: str) -> bytes:
        """Get the KEL interaction event that anchors the credential TEL.

        This is used for witness publishing - witnesses receipt the KEL ixn event,
        not the TEL event directly.

        The anchor is stored via registry.anchorMsg() during issuance/revocation,
        which writes to reger using dgKey(tel_prefix, tel_event_said).

        Args:
            credential_said: SAID of the credential

        Returns:
            CESR-encoded interaction event with signatures

        Raises:
            ValueError: If credential not found or anchor missing
        """
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            # Get credential to find registry
            creder = reger.creds.get(keys=(credential_said,))
            if creder is None:
                raise ValueError(f"Credential not found: {credential_said}")

            # Get registry
            regk = creder.sad.get("ri")
            if regk is None:
                raise ValueError(f"Credential {credential_said} has no registry")

            registry = registry_mgr.regery.regs.get(regk)
            if registry is None:
                raise ValueError(f"Registry not found: {regk}")

            # Get the issuer's hab
            hab = registry.hab
            if hab is None:
                raise ValueError(f"Registry {regk} has no associated hab")

            # Get the most recent TEL event (iss at sn=0, or rev at sn=1 if revoked)
            # First check if revoked (sn=1 exists)
            tel_sn = 0
            try:
                rev_dig = reger.getTel(key=dbing.snKey(credential_said, 1))
                if rev_dig is not None:
                    tel_sn = 1  # Use revocation event anchor
            except Exception:
                pass

            # Clone the TEL event to get its SAID
            try:
                tel_raw = reger.cloneTvtAt(credential_said, sn=tel_sn)
                tel_serder = serdering.SerderKERI(raw=tel_raw)
            except Exception as e:
                raise ValueError(f"Failed to get TEL event for credential {credential_said}: {e}")

            # Get the KEL anchor using dgKey(tel_prefix, tel_event_said)
            # This was stored via registry.anchorMsg() during issuance/revocation
            dgkey = dbing.dgKey(credential_said, tel_serder.said)
            couple = reger.getAnc(dgkey)
            if couple is None:
                raise ValueError(f"No KEL anchor found for credential {credential_said}")

            # Parse the anchor couple (seqner + saider for the KEL event)
            ancb = bytearray(couple)
            anc_seqner = coring.Seqner(qb64b=ancb, strip=True)
            anc_saider = coring.Saider(qb64b=ancb, strip=True)

            # Clone the KEL anchoring event
            identity_mgr = await get_identity_manager()
            hby = identity_mgr.habery

            msg = hby.db.cloneEvtMsg(pre=hab.pre.encode(), fn=anc_seqner.sn, dig=anc_saider.qb64b)
            if msg is None:
                raise ValueError(f"Failed to clone anchor ixn for credential {credential_said}")

            return bytes(msg)

    async def revoke_credential(self, credential_said: str) -> CredentialInfo:
        """Revoke an issued credential.

        Creates a TEL revocation event (rev) and updates credential status.

        Args:
            credential_said: SAID of credential to revoke

        Returns:
            Updated CredentialInfo with revocation details

        Raises:
            ValueError: Credential not found or already revoked
        """
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            # Get credential
            creder = reger.creds.get(keys=(credential_said,))
            if creder is None:
                raise ValueError(f"Credential not found: {credential_said}")

            # Get registry
            regk = creder.sad.get("ri")
            if regk is None:
                raise ValueError(f"Credential {credential_said} has no registry")

            registry = registry_mgr.regery.regs.get(regk)
            if registry is None:
                raise ValueError(f"Registry not found: {regk}")

            # Check if already revoked by checking TEL state
            try:
                tever = reger.tevers.get(credential_said)
                if tever is not None:
                    # Check the TEL sequence - if > 0, it's been revoked
                    tel_dig = reger.getTel(key=dbing.snKey(credential_said, 1))
                    if tel_dig is not None:
                        raise ValueError(f"Credential already revoked: {credential_said}")
            except KeyError:
                pass  # No tever yet, credential exists but not revoked

            hab = registry.hab
            if hab is None:
                raise ValueError(f"Registry {regk} has no associated hab")

            # Create revocation event
            dt = helping.nowIso8601()
            rserder = registry.revoke(said=credential_said, dt=dt)

            # Anchor to KEL
            rseal = eventing.SealEvent(rserder.pre, rserder.snh, rserder.said)
            anc = hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])

            # Anchor the TEL rev event and re-process it through the Tevery
            anc_seqner = coring.Seqner(sn=hab.kever.sn)
            anc_saider = coring.Saider(qb64=hab.kever.serder.said)

            # Store the anchor in the reger database
            registry.anchorMsg(
                pre=rserder.pre,  # Credential SAID (TEL event prefix)
                regd=rserder.said,
                seqner=anc_seqner,
                saider=anc_saider,
            )

            # Re-process the TEL rev event with the anchor reference
            registry_mgr.regery.tvy.processEvent(
                serder=rserder,
                seqner=anc_seqner,
                saider=anc_saider,
            )

            log.info(f"Created TEL rev event for {credential_said[:16]}...")

            # Build CredentialInfo
            schema_said = creder.sad.get("s", "")
            recipient_aid = creder.attrib.get("i") if creder.attrib else None

            # Get original issuance timestamp from TEL iss event
            try:
                iss_raw = reger.cloneTvtAt(credential_said, sn=0)
                iss_serder = serdering.SerderKERI(raw=iss_raw)
                issuance_dt = iss_serder.ked.get("dt", "")
            except Exception:
                issuance_dt = ""

            return CredentialInfo(
                said=credential_said,
                issuer_aid=hab.pre,
                recipient_aid=recipient_aid,
                registry_key=regk,
                schema_said=schema_said,
                issuance_dt=issuance_dt,
                status="revoked",
                revocation_dt=dt,
                attributes=dict(creder.attrib) if creder.attrib else {},
                edges=creder.sad.get("e"),
                rules=creder.sad.get("r"),
            )

    async def get_credential(self, credential_said: str) -> Optional[CredentialInfo]:
        """Get credential info by SAID.

        Args:
            credential_said: SAID of the credential

        Returns:
            CredentialInfo if found, None otherwise
        """
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            # Get credential
            creder = reger.creds.get(keys=(credential_said,))
            if creder is None:
                return None

            # Get registry info
            regk = creder.sad.get("ri", "")
            registry = registry_mgr.regery.regs.get(regk) if regk else None
            issuer_aid = registry.hab.pre if registry and registry.hab else ""

            # Check revocation status
            status = "issued"
            revocation_dt = None
            try:
                tel_dig = reger.getTel(key=dbing.snKey(credential_said, 1))
                if tel_dig is not None:
                    status = "revoked"
                    # Get revocation timestamp
                    rev_raw = reger.cloneTvtAt(credential_said, sn=1)
                    rev_serder = serdering.SerderKERI(raw=rev_raw)
                    revocation_dt = rev_serder.ked.get("dt")
            except Exception:
                pass

            # Get issuance timestamp
            issuance_dt = ""
            try:
                iss_raw = reger.cloneTvtAt(credential_said, sn=0)
                iss_serder = serdering.SerderKERI(raw=iss_raw)
                issuance_dt = iss_serder.ked.get("dt", "")
            except Exception:
                pass

            schema_said = creder.sad.get("s", "")
            recipient_aid = creder.attrib.get("i") if creder.attrib else None

            return CredentialInfo(
                said=credential_said,
                issuer_aid=issuer_aid,
                recipient_aid=recipient_aid,
                registry_key=regk,
                schema_said=schema_said,
                issuance_dt=issuance_dt,
                status=status,
                revocation_dt=revocation_dt,
                attributes=dict(creder.attrib) if creder.attrib else {},
                edges=creder.sad.get("e"),
                rules=creder.sad.get("r"),
            )

    async def get_credential_bytes(self, credential_said: str) -> Optional[bytes]:
        """Get CESR-encoded credential with SealSourceTriples attachment.

        This is the wire format suitable for dossier assembly.

        Args:
            credential_said: SAID of the credential

        Returns:
            CESR-encoded credential bytes if found, None otherwise
        """
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            try:
                creder, prefixer, seqner, saider = reger.cloneCred(said=credential_said)
                return signing.serialize(creder, prefixer, seqner, saider)
            except Exception:
                return None

    async def list_credentials(
        self,
        registry_key: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[CredentialInfo]:
        """List credentials with optional filtering.

        Args:
            registry_key: Filter by registry key
            status: Filter by status ("issued" or "revoked")

        Returns:
            List of CredentialInfo
        """
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            credentials = []

            # Iterate over all credentials in the database
            for keys, creder in reger.creds.getItemIter():
                cred_said = keys[0] if keys else creder.said

                # Get registry info
                regk = creder.sad.get("ri", "")

                # Filter by registry if specified
                if registry_key is not None and regk != registry_key:
                    continue

                registry = registry_mgr.regery.regs.get(regk) if regk else None
                issuer_aid = registry.hab.pre if registry and registry.hab else ""

                # Check revocation status
                cred_status = "issued"
                revocation_dt = None
                try:
                    tel_dig = reger.getTel(key=dbing.snKey(cred_said, 1))
                    if tel_dig is not None:
                        cred_status = "revoked"
                        rev_raw = reger.cloneTvtAt(cred_said, sn=1)
                        rev_serder = serdering.SerderKERI(raw=rev_raw)
                        revocation_dt = rev_serder.ked.get("dt")
                except Exception:
                    pass

                # Filter by status if specified
                if status is not None and cred_status != status:
                    continue

                # Get issuance timestamp
                issuance_dt = ""
                try:
                    iss_raw = reger.cloneTvtAt(cred_said, sn=0)
                    iss_serder = serdering.SerderKERI(raw=iss_raw)
                    issuance_dt = iss_serder.ked.get("dt", "")
                except Exception:
                    pass

                schema_said = creder.sad.get("s", "")
                recipient_aid = creder.attrib.get("i") if creder.attrib else None

                cred_info = CredentialInfo(
                    said=cred_said,
                    issuer_aid=issuer_aid,
                    recipient_aid=recipient_aid,
                    registry_key=regk,
                    schema_said=schema_said,
                    issuance_dt=issuance_dt,
                    status=cred_status,
                    revocation_dt=revocation_dt,
                    attributes=dict(creder.attrib) if creder.attrib else {},
                    edges=creder.sad.get("e"),
                    rules=creder.sad.get("r"),
                )
                credentials.append(cred_info)

            return credentials


# Module-level singleton
_credential_issuer: Optional[CredentialIssuer] = None


async def get_credential_issuer() -> CredentialIssuer:
    """Get or create the credential issuer singleton."""
    global _credential_issuer
    if _credential_issuer is None:
        _credential_issuer = CredentialIssuer()
        await _credential_issuer.initialize()
    return _credential_issuer


async def close_credential_issuer() -> None:
    """Close the credential issuer singleton."""
    global _credential_issuer
    if _credential_issuer is not None:
        await _credential_issuer.close()
        _credential_issuer = None


def reset_credential_issuer() -> None:
    """Reset the singleton without closing (for testing)."""
    global _credential_issuer
    _credential_issuer = None
