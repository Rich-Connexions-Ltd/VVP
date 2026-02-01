"""KERI identity management for VVP Issuer.

Wraps keripy's Habery to provide identity lifecycle management including
creation, persistence, key rotation, and OOBI URL generation.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from keri.app import habbing
from keri import core

from app.config import (
    WITNESS_AIDS,
    DEFAULT_KEY_COUNT,
    DEFAULT_KEY_THRESHOLD,
    DEFAULT_NEXT_KEY_COUNT,
    DEFAULT_NEXT_THRESHOLD,
)
from app.keri.persistence import get_persistence_manager
from app.keri.exceptions import (
    IdentityNotFoundError,
    NonTransferableIdentityError,
    InvalidRotationThresholdError,
)

log = logging.getLogger(__name__)


@dataclass
class IdentityInfo:
    """Information about a managed identity."""

    aid: str  # Autonomic Identifier (AID)
    name: str  # Human-readable alias
    created_at: str  # ISO8601 timestamp
    witness_count: int  # Number of witnesses
    key_count: int  # Number of signing keys
    sequence_number: int  # Current key event sequence
    transferable: bool  # Whether keys can rotate


@dataclass
class RotationResult:
    """Result of identity key rotation."""

    aid: str  # Autonomic Identifier (AID)
    name: str  # Human-readable alias
    previous_sequence_number: int  # Sequence number before rotation
    new_sequence_number: int  # Sequence number after rotation
    new_key_count: int  # Number of signing keys after rotation
    rotation_event_bytes: bytes  # CESR-encoded rotation event for witness publishing


class IssuerIdentityManager:
    """Manages KERI identities for the issuer service.

    Wraps keripy's Habery to provide:
    - Identity creation with witness configuration
    - OOBI URL generation
    - Persistence across restarts
    - Thread-safe operations

    The manager maintains a single Habery instance that can hold
    multiple Hab identities, each with its own AID.
    """

    def __init__(
        self,
        name: str = "vvp-issuer",
        base_dir: Optional[Path] = None,
        temp: bool = False,
    ):
        """Initialize identity manager.

        Args:
            name: Name for the Habery (used in storage paths)
            base_dir: Override base directory for persistence
            temp: If True, use temporary storage (testing)
        """
        self._name = name
        self._temp = temp
        self._persistence = get_persistence_manager()
        self._base_dir = base_dir or self._persistence.base_dir
        self._hby: Optional[habbing.Habery] = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize the Habery and load existing identities."""
        async with self._lock:
            if self._hby is not None:
                return

            # Generate salt for new Habery (will be stored in keystore)
            salt = core.Salter().qb64

            # Create Habery with persistence
            # base must be relative (empty string for no sub-hierarchy)
            # headDirPath sets the root directory for all keri data
            self._hby = habbing.Habery(
                name=self._name,
                base="",  # Relative path segment (empty = no sub-hierarchy)
                temp=self._temp,
                salt=salt,
                headDirPath=str(self._base_dir),  # Root directory for keri data
            )
            log.info(f"Habery initialized: {self._name} at {self._base_dir}")

            # Log existing identities
            for pre in self._hby.prefixes:
                hab = self._hby.habByPre(pre)
                if hab:
                    log.info(f"Loaded existing identity: {hab.name} ({pre[:16]}...)")

    async def close(self) -> None:
        """Close the Habery and release resources."""
        async with self._lock:
            if self._hby is not None:
                self._hby.close(clear=self._temp)
                self._hby = None
                log.info("Habery closed")

    @property
    def hby(self) -> habbing.Habery:
        """Get the Habery instance (raises if not initialized)."""
        if self._hby is None:
            raise RuntimeError("IssuerIdentityManager not initialized")
        return self._hby

    @property
    def habery(self) -> habbing.Habery:
        """Get the underlying Habery instance for registry use.

        This is the same as .hby but provides a clearer name for external
        components like CredentialRegistryManager that need access to the
        shared Habery instance.
        """
        return self.hby

    @property
    def temp(self) -> bool:
        """Whether using temporary storage (for testing)."""
        return self._temp

    async def create_identity(
        self,
        name: str,
        transferable: bool = True,
        icount: Optional[int] = None,
        isith: Optional[str] = None,
        ncount: Optional[int] = None,
        nsith: Optional[str] = None,
        witness_aids: Optional[list[str]] = None,
    ) -> IdentityInfo:
        """Create a new KERI identity.

        Args:
            name: Human-readable alias for the identity
            transferable: Whether keys can rotate (default True)
            icount: Inception key count (default from config)
            isith: Inception signing threshold (default from config)
            ncount: Next key count for rotation (default from config)
            nsith: Next signing threshold (default from config)
            witness_aids: List of witness AIDs (default from config)

        Returns:
            IdentityInfo with created identity details

        Raises:
            ValueError: If identity with name already exists
        """
        async with self._lock:
            # Check for existing
            if self.hby.habByName(name) is not None:
                raise ValueError(f"Identity '{name}' already exists")

            # Apply defaults
            icount = icount or DEFAULT_KEY_COUNT
            isith = isith or DEFAULT_KEY_THRESHOLD
            ncount = ncount or DEFAULT_NEXT_KEY_COUNT
            nsith = nsith or DEFAULT_NEXT_THRESHOLD
            wits = witness_aids or list(WITNESS_AIDS.values())
            toad = len(wits) if wits else 0

            # Create the Hab (identity)
            hab = self.hby.makeHab(
                name=name,
                transferable=transferable,
                icount=icount,
                isith=isith,
                ncount=ncount,
                nsith=nsith,
                wits=wits,
                toad=toad,
            )

            log.info(f"Created identity: {name} ({hab.pre[:16]}...)")

            return IdentityInfo(
                aid=hab.pre,
                name=name,
                created_at=datetime.now(timezone.utc).isoformat(),
                witness_count=len(wits),
                key_count=icount,
                sequence_number=hab.kever.sn if hab.kever else 0,
                transferable=transferable,
            )

    async def get_identity(self, aid: str) -> Optional[IdentityInfo]:
        """Get identity info by AID."""
        async with self._lock:
            hab = self.hby.habByPre(aid)
            if hab is None:
                return None

            return IdentityInfo(
                aid=hab.pre,
                name=hab.name,
                created_at="",  # Not stored in keripy
                witness_count=len(hab.kever.wits) if hab.kever else 0,
                key_count=len(hab.kever.verfers) if hab.kever else 0,
                sequence_number=hab.kever.sn if hab.kever else 0,
                transferable=hab.kever.transferable if hab.kever else True,
            )

    async def get_identity_by_name(self, name: str) -> Optional[IdentityInfo]:
        """Get identity info by name."""
        async with self._lock:
            hab = self.hby.habByName(name)
            if hab is None:
                return None

            return IdentityInfo(
                aid=hab.pre,
                name=hab.name,
                created_at="",
                witness_count=len(hab.kever.wits) if hab.kever else 0,
                key_count=len(hab.kever.verfers) if hab.kever else 0,
                sequence_number=hab.kever.sn if hab.kever else 0,
                transferable=hab.kever.transferable if hab.kever else True,
            )

    async def list_identities(self) -> list[IdentityInfo]:
        """List all managed identities."""
        async with self._lock:
            identities = []
            for pre in self.hby.prefixes:
                hab = self.hby.habByPre(pre)
                if hab:
                    info = IdentityInfo(
                        aid=hab.pre,
                        name=hab.name,
                        created_at="",
                        witness_count=len(hab.kever.wits) if hab.kever else 0,
                        key_count=len(hab.kever.verfers) if hab.kever else 0,
                        sequence_number=hab.kever.sn if hab.kever else 0,
                        transferable=hab.kever.transferable if hab.kever else True,
                    )
                    identities.append(info)
            return identities

    def get_oobi_url(self, aid: str, witness_url: str) -> str:
        """Construct OOBI URL for an identity.

        Args:
            aid: The AID to generate OOBI for
            witness_url: Base URL of witness to include in OOBI

        Returns:
            OOBI URL string
        """
        # Standard OOBI format: {witness_url}/oobi/{aid}/controller
        return f"{witness_url.rstrip('/')}/oobi/{aid}/controller"

    async def get_kel_bytes(self, aid: str) -> bytes:
        """Get the serialized KEL for an identity.

        Returns the inception event with attached signatures in CESR format,
        suitable for publishing to witnesses.

        Args:
            aid: The AID to get KEL for

        Returns:
            CESR-encoded inception event with signatures

        Raises:
            ValueError: If identity not found or no KEL available
        """
        async with self._lock:
            hab = self.hby.habByPre(aid)
            if hab is None:
                raise ValueError(f"Identity not found: {aid}")

            # Get the inception event (sn=0) from the database
            # cloneEvtMsg returns the event with all attached signatures
            pre = aid.encode() if isinstance(aid, str) else aid
            msg = bytearray()

            # Iterate over KEL events (for inception, just sn=0)
            for dig in self.hby.db.getKelIter(pre, sn=0):
                try:
                    evt_msg = self.hby.db.cloneEvtMsg(pre=pre, fn=0, dig=dig)
                    msg.extend(evt_msg)
                    break  # Only need inception event for initial publishing
                except Exception as e:
                    log.warning(f"Failed to clone event: {e}")
                    continue

            if not msg:
                raise ValueError(f"No KEL found for {aid}")

            return bytes(msg)

    def _validate_rotation_threshold(
        self, next_key_count: int, next_threshold: str
    ) -> None:
        """Validate next_key_count and next_threshold consistency.

        Args:
            next_key_count: Number of next keys to generate
            next_threshold: Signing threshold for next keys

        Raises:
            InvalidRotationThresholdError: If configuration is invalid
        """
        if next_key_count < 1:
            raise InvalidRotationThresholdError(
                f"next_key_count must be >= 1, got {next_key_count}"
            )

        # Simple numeric threshold validation
        try:
            threshold_int = int(next_threshold)
            if threshold_int < 1:
                raise InvalidRotationThresholdError(
                    f"next_threshold must be >= 1, got {next_threshold}"
                )
            if threshold_int > next_key_count:
                raise InvalidRotationThresholdError(
                    f"next_threshold ({next_threshold}) cannot exceed "
                    f"next_key_count ({next_key_count})"
                )
        except ValueError:
            # Weighted threshold format (e.g., "1/2,1/2") - defer to keripy validation
            pass

    async def rotate_identity(
        self,
        aid: str,
        next_key_count: Optional[int] = None,
        next_threshold: Optional[str] = None,
    ) -> RotationResult:
        """Rotate the keys for an identity.

        Promotes the current next keys to active signing keys and generates
        new next keys for future rotations.

        Args:
            aid: The AID of the identity to rotate
            next_key_count: Number of next keys to generate (for future rotation)
            next_threshold: Signing threshold for next keys

        Returns:
            RotationResult with rotation event bytes for witness publishing

        Raises:
            IdentityNotFoundError: If AID not found
            NonTransferableIdentityError: If identity is non-transferable
            InvalidRotationThresholdError: If threshold configuration is invalid
        """
        async with self._lock:
            hab = self.hby.habByPre(aid)
            if hab is None:
                raise IdentityNotFoundError(f"Identity not found: {aid}")

            # Check if identity is transferable
            if not hab.kever.transferable:
                raise NonTransferableIdentityError(
                    f"Cannot rotate non-transferable identity: {aid}"
                )

            # Validate threshold parameters if provided
            effective_ncount = next_key_count or DEFAULT_NEXT_KEY_COUNT
            effective_nsith = next_threshold or DEFAULT_NEXT_THRESHOLD
            self._validate_rotation_threshold(effective_ncount, effective_nsith)

            # Record previous state
            previous_sn = hab.kever.sn

            # Perform rotation - hab.rotate() returns the signed rotation event
            rotation_msg = hab.rotate(
                ncount=next_key_count,
                nsith=next_threshold,
            )

            # Verify rotation was successful
            new_sn = hab.kever.sn
            if new_sn != previous_sn + 1:
                raise RuntimeError(
                    f"Rotation failed: sequence number did not increment "
                    f"(expected {previous_sn + 1}, got {new_sn})"
                )

            log.info(
                f"Rotated identity: {hab.name} ({aid[:16]}...) "
                f"sn: {previous_sn} -> {new_sn}"
            )

            return RotationResult(
                aid=aid,
                name=hab.name,
                previous_sequence_number=previous_sn,
                new_sequence_number=new_sn,
                new_key_count=len(hab.kever.verfers),
                rotation_event_bytes=bytes(rotation_msg),
            )


# Module-level singleton
_identity_manager: Optional[IssuerIdentityManager] = None


async def get_identity_manager() -> IssuerIdentityManager:
    """Get or create the identity manager singleton."""
    global _identity_manager
    if _identity_manager is None:
        _identity_manager = IssuerIdentityManager()
        await _identity_manager.initialize()
    return _identity_manager


async def close_identity_manager() -> None:
    """Close the identity manager singleton."""
    global _identity_manager
    if _identity_manager is not None:
        await _identity_manager.close()
        _identity_manager = None


def reset_identity_manager() -> None:
    """Reset the singleton without closing (for testing)."""
    global _identity_manager
    _identity_manager = None
