"""ACDC (Authentic Chained Data Container) models.

Per KERI/ACDC spec and VVP §6.3.x credential types.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ACDC:
    """Parsed ACDC credential.

    ACDC structure per KERI spec:
    - v: Version string (e.g., "ACDC10JSON00...")
    - d: SAID (self-addressing identifier) - Blake3-256 hash
    - i: Issuer AID
    - s: Schema SAID
    - a: Attributes (credential data)
    - e: Edges (references to other credentials)
    - r: Rules (credential rules/policies)

    Attributes:
        version: ACDC version string from 'v' field.
        said: Self-addressing identifier from 'd' field.
        issuer_aid: Issuer's AID from 'i' field.
        schema_said: Schema SAID from 's' field.
        attributes: Credential attributes from 'a' field (dict for full, str for compact).
        edges: Credential chain edges from 'e' field.
        rules: Credential rules from 'r' field.
        raw: Original parsed dictionary for debugging.
        signature: Attached signature bytes (if parsed from CESR).
        variant: ACDC variant type ("full", "compact", "partial") per VVP §1.4.
    """
    version: str
    said: str
    issuer_aid: str
    schema_said: str
    attributes: Optional[Any] = None  # Dict for full, str (SAID) for compact
    edges: Optional[Dict[str, Any]] = None
    rules: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[bytes] = None
    variant: str = "full"  # "full", "compact", "partial" per VVP §1.4

    @property
    def credential_type(self) -> str:
        """Infer credential type from schema, edges, or attributes.

        For compact variants where attributes is a SAID string (not expanded),
        uses edge-based detection. For partial variants with placeholders,
        attempts best-effort detection from available fields.

        Returns:
            Credential type string (e.g., 'APE', 'DE', 'TNAlloc', 'LE', 'unknown').
        """
        # For compact variants, try edge-based detection first
        # (attributes may be SAID reference, not expanded dict)
        if self.variant == "compact" or not isinstance(self.attributes, dict):
            if self.edges:
                if "vetting" in self.edges or "le" in self.edges:
                    return "APE"  # Auth Phone Entity
                if "delegation" in self.edges:
                    return "DE"  # Delegate Entity
                # TNAlloc typically has JL/jurisdiction edge to parent
                if "jl" in self.edges or "jurisdiction" in self.edges:
                    return "TNAlloc"
            # Cannot determine type for compact without edges
            if self.variant == "compact":
                return "unknown"

        # Check for type in attributes (full or partial variants)
        if isinstance(self.attributes, dict):
            if "LEI" in self.attributes:
                return "LE"  # Legal Entity credential
            if "phone" in self.attributes or "tn" in self.attributes:
                return "TNAlloc"  # TN Allocation credential

        # Check edges for credential type hints (fallback)
        if self.edges:
            if "vetting" in self.edges or "le" in self.edges:
                return "APE"  # Auth Phone Entity
            if "delegation" in self.edges:
                return "DE"  # Delegate Entity

        return "unknown"

    @property
    def is_root_credential(self) -> bool:
        """Check if this credential has no parent edges.

        Root credentials (from GLEIF/QVI) have no edges or only
        self-references.
        """
        if not self.edges:
            return True
        # Check for empty edges or only metadata fields
        for key in self.edges:
            if key not in ('d', 'n'):  # Skip digest/nonce
                return False
        return True


@dataclass
class ACDCChainResult:
    """Result of ACDC chain validation.

    Attributes:
        chain: List of credentials from leaf to root.
        root_aid: The trusted root AID that anchored the chain.
        validated: Whether the chain was successfully validated.
        errors: List of any validation errors encountered.
        status: ClaimStatus for the chain (VALID, INVALID, INDETERMINATE).
            INDETERMINATE when compact/partial variants prevent full verification.
        has_variant_limitations: True if any ACDC in chain is compact/partial.
    """
    chain: List[ACDC] = field(default_factory=list)
    root_aid: Optional[str] = None
    validated: bool = False
    errors: List[str] = field(default_factory=list)
    status: Optional[str] = None  # ClaimStatus value: "VALID", "INVALID", "INDETERMINATE"
    has_variant_limitations: bool = False
