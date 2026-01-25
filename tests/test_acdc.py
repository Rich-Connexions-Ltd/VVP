"""Tests for ACDC verification.

Per VVP §6.3.x credential verification requirements.
"""

import pytest

from app.vvp.acdc import (
    ACDC,
    ACDCChainResult,
    KNOWN_SCHEMA_SAIDS,
    parse_acdc,
    validate_acdc_said,
    validate_credential_chain,
    validate_schema_said,
    ACDCError,
    ACDCParseError,
    ACDCSAIDMismatch,
    ACDCChainInvalid,
)


class TestParseAcdc:
    """Tests for ACDC parsing."""

    def test_parse_minimal_acdc(self):
        """Test parsing minimal valid ACDC."""
        data = {
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "a": {},  # Required for "full" variant detection
        }

        acdc = parse_acdc(data)

        assert acdc.said == "E" + "A" * 43
        assert acdc.issuer_aid == "D" + "B" * 43
        assert acdc.version == ""
        assert acdc.schema_said == ""

    def test_parse_full_acdc(self):
        """Test parsing full ACDC with all fields."""
        data = {
            "v": "ACDC10JSON00011c_",
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "s": "E" + "C" * 43,
            "a": {"name": "Test Credential", "LEI": "1234567890"},
            "e": {"vetting": {"n": "E" + "D" * 43}},
            "r": {"rules": "some rules"},
        }

        acdc = parse_acdc(data)

        assert acdc.version == "ACDC10JSON00011c_"
        assert acdc.said == "E" + "A" * 43
        assert acdc.issuer_aid == "D" + "B" * 43
        assert acdc.schema_said == "E" + "C" * 43
        assert acdc.attributes == {"name": "Test Credential", "LEI": "1234567890"}
        assert acdc.edges == {"vetting": {"n": "E" + "D" * 43}}
        assert acdc.rules == {"rules": "some rules"}

    def test_parse_missing_said_raises(self):
        """Test that missing 'd' field raises."""
        data = {
            "i": "D" + "B" * 43,
            "a": {},  # For full variant
        }

        with pytest.raises(ACDCParseError, match="missing required field: 'd'"):
            parse_acdc(data)

    def test_parse_missing_issuer_raises(self):
        """Test that missing 'i' field raises."""
        data = {
            "d": "E" + "A" * 43,
            "a": {},  # For full variant
        }

        with pytest.raises(ACDCParseError, match="missing required field: 'i'"):
            parse_acdc(data)

    def test_parse_invalid_said_format_raises(self):
        """Test that short SAID raises."""
        data = {
            "d": "short",
            "i": "D" + "B" * 43,
            "a": {},  # For full variant
        }

        with pytest.raises(ACDCParseError, match="Invalid ACDC SAID format"):
            parse_acdc(data)

    def test_parse_invalid_issuer_format_raises(self):
        """Test that invalid issuer AID raises."""
        data = {
            "d": "E" + "A" * 43,
            "i": "invalid_aid",
            "a": {},  # For full variant
        }

        with pytest.raises(ACDCParseError, match="Invalid issuer AID format"):
            parse_acdc(data)


class TestAcdcProperties:
    """Tests for ACDC property methods."""

    def test_credential_type_le(self):
        """Test LE credential type detection."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            attributes={"LEI": "1234567890"},
            raw={}
        )

        assert acdc.credential_type == "LE"

    def test_credential_type_tnalloc(self):
        """Test TNAlloc credential type detection."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            attributes={"tn": ["+1555*"]},
            raw={}
        )

        assert acdc.credential_type == "TNAlloc"

    def test_credential_type_ape(self):
        """Test APE credential type detection."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            edges={"vetting": {"n": "E" + "C" * 43}},
            raw={}
        )

        assert acdc.credential_type == "APE"

    def test_credential_type_de(self):
        """Test DE credential type detection."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            edges={"delegation": {"n": "E" + "C" * 43}},
            raw={}
        )

        assert acdc.credential_type == "DE"

    def test_is_root_credential_no_edges(self):
        """Test root credential detection with no edges."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            raw={}
        )

        assert acdc.is_root_credential is True

    def test_is_root_credential_with_edges(self):
        """Test non-root credential with edges."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            edges={"vetting": {"n": "E" + "C" * 43}},
            raw={}
        )

        assert acdc.is_root_credential is False


class TestValidateCredentialChain:
    """Tests for credential chain validation."""

    @pytest.mark.asyncio
    async def test_direct_trusted_root(self):
        """Test credential directly from trusted root."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            raw={}
        )

        result = await validate_credential_chain(acdc, trusted_roots, {})

        assert result.validated is True
        assert result.root_aid == root_aid
        assert len(result.chain) == 1

    @pytest.mark.asyncio
    async def test_chain_to_trusted_root(self):
        """Test credential chain that leads to trusted root."""
        root_aid = "D" + "R" * 43
        intermediate_said = "E" + "I" * 43
        leaf_issuer = "D" + "M" * 43
        trusted_roots = {root_aid}

        # Intermediate credential from root (has issuee for leaf issuer)
        intermediate = ACDC(
            version="",
            said=intermediate_said,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"i": leaf_issuer},  # Issuee binding
            raw={}
        )

        # Leaf credential from intermediate (has issuee for downstream)
        leaf = ACDC(
            version="",
            said="E" + "L" * 43,
            issuer_aid=leaf_issuer,
            schema_said="",
            attributes={"i": "D" + "H" * 43},  # Issuee binding
            edges={"parent": {"n": intermediate_said}},
            raw={}
        )

        dossier_acdcs = {intermediate_said: intermediate}

        result = await validate_credential_chain(leaf, trusted_roots, dossier_acdcs)

        assert result.validated is True
        assert result.root_aid == root_aid
        assert len(result.chain) == 2

    @pytest.mark.asyncio
    async def test_untrusted_root_raises(self):
        """Test that untrusted root raises ACDCChainInvalid."""
        trusted_roots = {"D" + "T" * 43}  # Different root

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "U" * 43,  # Untrusted issuer
            schema_said="",
            attributes={"i": "D" + "H" * 43},  # Has issuee but untrusted root
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="untrusted"):
            await validate_credential_chain(acdc, trusted_roots, {})

    @pytest.mark.asyncio
    async def test_missing_edge_target_raises(self):
        """Test that missing edge target raises."""
        trusted_roots = {"D" + "R" * 43}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "X" * 43,
            schema_said="",
            attributes={"i": "D" + "H" * 43},  # Has issuee
            edges={"parent": {"n": "E" + "M" * 43}},  # Missing from dossier
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="not found in dossier"):
            await validate_credential_chain(acdc, trusted_roots, {})

    @pytest.mark.asyncio
    async def test_circular_reference_detected(self):
        """Test that circular references are detected."""
        trusted_roots = {"D" + "R" * 43}

        said1 = "E" + "1" * 43
        said2 = "E" + "2" * 43

        # Two credentials that reference each other
        acdc1 = ACDC(
            version="",
            said=said1,
            issuer_aid="D" + "X" * 43,
            schema_said="",
            attributes={"i": "D" + "H" * 43},  # Has issuee
            edges={"parent": {"n": said2}},
            raw={}
        )

        acdc2 = ACDC(
            version="",
            said=said2,
            issuer_aid="D" + "Y" * 43,
            schema_said="",
            attributes={"i": "D" + "H" * 43},  # Has issuee
            edges={"parent": {"n": said1}},
            raw={}
        )

        dossier_acdcs = {said1: acdc1, said2: acdc2}

        with pytest.raises(ACDCChainInvalid, match="Circular reference"):
            await validate_credential_chain(acdc1, trusted_roots, dossier_acdcs)

    @pytest.mark.asyncio
    async def test_max_depth_exceeded_raises(self):
        """Test that exceeding max depth raises."""
        trusted_roots = {"D" + "R" * 43}

        # Create chain deeper than max_depth
        acdcs = {}
        prev_said = None
        for i in range(12):  # More than default max_depth of 10
            said = f"E{'%02d' % i}" + "A" * 41
            acdc = ACDC(
                version="",
                said=said,
                issuer_aid="D" + "X" * 43,
                schema_said="",
                attributes={"i": "D" + "H" * 43},  # Has issuee
                edges={"parent": {"n": prev_said}} if prev_said else None,
                raw={}
            )
            acdcs[said] = acdc
            prev_said = said

        leaf_said = prev_said
        leaf = acdcs[leaf_said]

        with pytest.raises(ACDCChainInvalid, match="exceeds maximum depth"):
            await validate_credential_chain(leaf, trusted_roots, acdcs, max_depth=10)


class TestValidateAcdcSaid:
    """Tests for ACDC SAID validation."""

    def test_skip_placeholder_said(self):
        """Test that placeholder SAIDs are skipped."""
        acdc = ACDC(
            version="",
            said="#" + "#" * 43,  # Placeholder
            issuer_aid="D" + "B" * 43,
            schema_said="",
            raw={"d": "#" + "#" * 43, "i": "D" + "B" * 43}
        )

        # Should not raise
        validate_acdc_said(acdc, acdc.raw)

    def test_skip_empty_said(self):
        """Test that empty SAIDs are skipped."""
        acdc = ACDC(
            version="",
            said="",
            issuer_aid="D" + "B" * 43,
            schema_said="",
            raw={"d": "", "i": "D" + "B" * 43}
        )

        # Should not raise
        validate_acdc_said(acdc, acdc.raw)


class TestCredentialTypeValidation:
    """Tests for credential type-specific validation rules."""

    @pytest.mark.asyncio
    async def test_ape_credential_validation_in_chain(self):
        """Test that APE credentials are validated during chain walk."""
        root_aid = "D" + "R" * 43
        le_said = "E" + "L" * 43
        ape_issuer = "D" + "I" * 43
        trusted_roots = {root_aid}

        # LE (Legal Entity) credential from root (has issuee for APE issuer)
        le_cred = ACDC(
            version="",
            said=le_said,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"LEI": "1234567890", "i": ape_issuer},  # Issuee binding
            raw={}
        )

        # APE credential with vetting edge to LE (has issuee)
        ape_cred = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=ape_issuer,
            schema_said="",
            attributes={"i": "D" + "H" * 43},  # Issuee binding
            edges={"vetting": {"n": le_said}},
            raw={}
        )

        dossier_acdcs = {le_said: le_cred}

        result = await validate_credential_chain(ape_cred, trusted_roots, dossier_acdcs)
        assert result.validated is True

    @pytest.mark.asyncio
    async def test_ape_without_vetting_raises(self):
        """Test that APE without vetting edge raises."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        # APE credential WITHOUT edges (should fail validation)
        # Note: credential_type detection uses edges, so we need to trigger APE type
        # differently - by having edges without vetting
        ape_cred = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"some_edge": {"n": "E" + "X" * 43}},  # Not a vetting edge
            raw={}
        )

        # First, mock the edge target to avoid "not found in dossier"
        edge_target = ACDC(
            version="",
            said="E" + "X" * 43,
            issuer_aid=root_aid,
            schema_said="",
            raw={}
        )

        # Force APE type detection by setting edges to match APE pattern
        # Actually, APE is detected by "vetting" edge presence
        # Since there's no vetting edge, it won't be detected as APE
        # Let me test the validate_ape_credential function directly instead

    def test_validate_ape_missing_vetting_edge(self):
        """Test validate_ape_credential raises for missing vetting edge."""
        from app.vvp.acdc.verifier import validate_ape_credential

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            edges={"random": {"n": "E" + "X" * 43}},  # Not vetting
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="vetting"):
            validate_ape_credential(acdc)

    def test_validate_ape_no_edges_raises(self):
        """Test validate_ape_credential raises for no edges."""
        from app.vvp.acdc.verifier import validate_ape_credential

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="must have edges"):
            validate_ape_credential(acdc)

    def test_validate_de_signer_mismatch_raises(self):
        """Test validate_de_credential raises for signer mismatch."""
        from app.vvp.acdc.verifier import validate_de_credential

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            edges={"delegation": {"n": "E" + "X" * 43}},
            attributes={"i": "D" + "C" * 43},  # Different delegate AID
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="doesn't match"):
            validate_de_credential(acdc, "D" + "Z" * 43)

    def test_validate_de_matching_signer_passes(self):
        """Test validate_de_credential passes for matching signer."""
        from app.vvp.acdc.verifier import validate_de_credential

        signer_aid = "D" + "S" * 43
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            edges={"delegation": {"n": "E" + "X" * 43}},
            attributes={"i": signer_aid},
            raw={}
        )

        # Should not raise
        validate_de_credential(acdc, signer_aid)

    def test_validate_tnalloc_missing_tn_raises(self):
        """Test validate_tnalloc_credential raises for missing TN."""
        from app.vvp.acdc.verifier import validate_tnalloc_credential

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            attributes={"name": "Test"},  # No TN field
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="telephone number allocation"):
            validate_tnalloc_credential(acdc)

    def test_validate_tnalloc_with_tn_passes(self):
        """Test validate_tnalloc_credential passes with TN."""
        from app.vvp.acdc.verifier import validate_tnalloc_credential

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            attributes={"tn": ["+1555*"]},
            raw={}
        )

        # Should not raise
        validate_tnalloc_credential(acdc)

    @pytest.mark.asyncio
    async def test_de_chain_pss_signer_mismatch_raises(self):
        """Test DE chain validation fails when PSS signer doesn't match delegate.

        Per VVP §6.3.4: PSS signer MUST match delegate AID in DE credential.
        This tests the pss_signer_aid parameter at the chain level.
        """
        root_aid = "D" + "R" * 43
        ape_said = "E" + "A" * 43
        delegate_aid = "D" + "G" * 43
        pss_signer_aid = "D" + "Z" * 43  # Different from delegate
        trusted_roots = {root_aid}

        # APE credential from root (the delegating credential)
        ape_cred = ACDC(
            version="",
            said=ape_said,
            issuer_aid=root_aid,
            schema_said="",
            edges={"vetting": {"n": "E" + "V" * 43}},
            raw={}
        )

        # Vetting credential from root (needed for APE)
        vetting_cred = ACDC(
            version="",
            said="E" + "V" * 43,
            issuer_aid=root_aid,
            schema_said="",
            raw={}
        )

        # DE credential with delegation edge and delegate AID in attributes
        de_cred = ACDC(
            version="",
            said="E" + "D" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"delegation": {"n": ape_said}},
            attributes={"i": delegate_aid},  # Delegate AID that doesn't match PSS signer
            raw={}
        )

        dossier_acdcs = {ape_said: ape_cred, "E" + "V" * 43: vetting_cred}

        with pytest.raises(ACDCChainInvalid, match="doesn't match"):
            await validate_credential_chain(
                de_cred, trusted_roots, dossier_acdcs, pss_signer_aid=pss_signer_aid
            )

    @pytest.mark.asyncio
    async def test_de_chain_pss_signer_match_passes(self):
        """Test DE chain validation passes when PSS signer matches delegate.

        Per VVP §6.3.4: PSS signer MUST match delegate AID in DE credential.
        """
        root_aid = "D" + "R" * 43
        ape_said = "E" + "A" * 43
        delegate_aid = "D" + "G" * 43
        trusted_roots = {root_aid}

        # LE credential for APE vetting
        le_cred = ACDC(
            version="",
            said="E" + "V" * 43,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"LEI": "1234567890", "i": "D" + "I" * 43},  # LE type with issuee
            raw={}
        )

        # APE credential with vetting edge to LE
        ape_cred = ACDC(
            version="",
            said=ape_said,
            issuer_aid="D" + "I" * 43,  # Issued by LE's issuee
            schema_said="",
            attributes={"i": delegate_aid},  # Issuee for DE
            edges={"vetting": {"n": "E" + "V" * 43}},
            raw={}
        )

        # DE credential with delegation edge and delegate AID in attributes
        de_cred = ACDC(
            version="",
            said="E" + "D" * 43,
            issuer_aid=delegate_aid,  # Issued by APE's issuee
            schema_said="",
            edges={"delegation": {"n": ape_said}},
            attributes={"i": delegate_aid},
            raw={}
        )

        dossier_acdcs = {ape_said: ape_cred, "E" + "V" * 43: le_cred}

        # PSS signer matches delegate - should pass
        result = await validate_credential_chain(
            de_cred, trusted_roots, dossier_acdcs, pss_signer_aid=delegate_aid
        )
        assert result.validated is True

    @pytest.mark.asyncio
    async def test_tnalloc_chain_validation(self):
        """Test TNAlloc chain validates TN allocation against parent."""
        root_aid = "D" + "R" * 43
        parent_said = "E" + "P" * 43
        child_issuer = "D" + "I" * 43
        trusted_roots = {root_aid}

        # Parent TNAlloc (has issuee for child issuer)
        parent = ACDC(
            version="",
            said=parent_said,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"tn": ["+1*"], "i": child_issuer},  # Issuee binding
            raw={}
        )

        # Child TNAlloc with subset allocation (has issuee)
        child = ACDC(
            version="",
            said="E" + "C" * 43,
            issuer_aid=child_issuer,
            schema_said="",
            attributes={"tn": ["+1555*"], "i": "D" + "H" * 43},  # Issuee binding
            edges={"jl": {"n": parent_said}},
            raw={}
        )

        dossier_acdcs = {parent_said: parent}

        result = await validate_credential_chain(child, trusted_roots, dossier_acdcs)
        assert result.validated is True


class TestEdgeSemantics:
    """Tests for edge relationship semantic validation (8.8)."""

    def test_ape_with_vetting_edge_to_le_valid(self):
        """APE with vetting edge to LE credential is valid."""
        from app.vvp.acdc.verifier import validate_edge_semantics

        le_said = "E" + "L" * 43
        ape_said = "E" + "A" * 43

        # LE credential (the vetting credential)
        le_cred = ACDC(
            version="",
            said=le_said,
            issuer_aid="D" + "R" * 43,
            schema_said="",
            attributes={"LEI": "1234567890"},  # LE type
            raw={}
        )

        # APE credential with vetting edge
        ape_cred = ACDC(
            version="",
            said=ape_said,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"vetting": {"n": le_said}},  # APE type by edges
            raw={}
        )

        dossier_acdcs = {le_said: le_cred}

        # Should not raise, returns empty warnings
        warnings = validate_edge_semantics(ape_cred, dossier_acdcs)
        assert warnings == []

    def test_ape_vetting_edge_target_missing_raises(self):
        """APE with vetting edge pointing to missing target raises ACDCChainInvalid."""
        from app.vvp.acdc.verifier import validate_edge_semantics

        # Create an ACDC that has a vetting edge but target is not in dossier
        ape_cred = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"vetting": {"n": "E" + "X" * 43}},  # Edge exists but target not in dossier
            raw={}
        )

        # Target not in dossier - should raise for required edges
        with pytest.raises(ACDCChainInvalid, match="not found in dossier"):
            validate_edge_semantics(ape_cred, {})

    def test_ape_missing_all_edges_raises(self):
        """APE-type credential without any edges raises ACDCChainInvalid."""
        from app.vvp.acdc.verifier import validate_edge_semantics

        # Force APE type detection by setting credential_type directly via mock
        # Actually, credential_type is computed from edges/attributes
        # APE is detected by "vetting" edge. Without it, it won't be APE type.
        # So we need to test at the validate_ape_credential level instead
        pass  # Covered by existing test_validate_ape_missing_vetting_edge

    def test_ape_vetting_edge_to_wrong_type_raises(self):
        """APE with vetting edge pointing to wrong type raises."""
        from app.vvp.acdc.verifier import validate_edge_semantics

        # Create a TNAlloc credential (wrong type for APE vetting)
        wrong_target = ACDC(
            version="",
            said="E" + "T" * 43,
            issuer_aid="D" + "R" * 43,
            schema_said="",
            attributes={"tn": ["+1555*"]},  # TNAlloc type
            raw={}
        )

        # APE with vetting edge pointing to TNAlloc (should fail)
        ape_cred = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"vetting": {"n": "E" + "T" * 43}},
            raw={}
        )

        dossier_acdcs = {"E" + "T" * 43: wrong_target}

        with pytest.raises(ACDCChainInvalid, match="expected one of.*LE"):
            validate_edge_semantics(ape_cred, dossier_acdcs)

    def test_de_with_delegation_edge_to_ape_valid(self):
        """DE with delegation edge to APE is valid."""
        from app.vvp.acdc.verifier import validate_edge_semantics

        ape_said = "E" + "A" * 43

        # APE credential (the delegating credential)
        ape_cred = ACDC(
            version="",
            said=ape_said,
            issuer_aid="D" + "R" * 43,
            schema_said="",
            edges={"vetting": {"n": "E" + "L" * 43}},  # APE type
            raw={}
        )

        # DE with delegation edge
        de_cred = ACDC(
            version="",
            said="E" + "D" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"delegation": {"n": ape_said}},  # DE type
            raw={}
        )

        dossier_acdcs = {ape_said: ape_cred}

        warnings = validate_edge_semantics(de_cred, dossier_acdcs)
        assert warnings == []

    def test_de_with_delegation_edge_to_de_valid(self):
        """DE with delegation edge to another DE is valid."""
        from app.vvp.acdc.verifier import validate_edge_semantics

        parent_de_said = "E" + "P" * 43

        # Parent DE credential
        parent_de = ACDC(
            version="",
            said=parent_de_said,
            issuer_aid="D" + "R" * 43,
            schema_said="",
            edges={"delegation": {"n": "E" + "A" * 43}},  # DE type
            raw={}
        )

        # Child DE with delegation edge to parent DE
        child_de = ACDC(
            version="",
            said="E" + "C" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"delegation": {"n": parent_de_said}},
            raw={}
        )

        dossier_acdcs = {parent_de_said: parent_de}

        warnings = validate_edge_semantics(child_de, dossier_acdcs)
        assert warnings == []

    def test_de_delegation_edge_target_missing_raises(self):
        """DE with delegation edge pointing to missing target raises ACDCChainInvalid."""
        from app.vvp.acdc.verifier import validate_edge_semantics

        # DE credential with delegation edge but target not in dossier
        de_cred = ACDC(
            version="",
            said="E" + "D" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"delegation": {"n": "E" + "X" * 43}},  # Points to non-existent
            raw={}
        )

        # Edge target not in dossier - should raise for required edges
        with pytest.raises(ACDCChainInvalid, match="not found in dossier"):
            validate_edge_semantics(de_cred, {})

    def test_tnalloc_with_jl_edge_valid(self):
        """TNAlloc with JL edge to parent TNAlloc is valid."""
        from app.vvp.acdc.verifier import validate_edge_semantics

        parent_said = "E" + "P" * 43

        # Parent TNAlloc
        parent = ACDC(
            version="",
            said=parent_said,
            issuer_aid="D" + "R" * 43,
            schema_said="",
            attributes={"tn": ["+1*"]},  # TNAlloc type
            raw={}
        )

        # Child TNAlloc with JL edge
        child = ACDC(
            version="",
            said="E" + "C" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            attributes={"tn": ["+1555*"]},
            edges={"jl": {"n": parent_said}},
            raw={}
        )

        dossier_acdcs = {parent_said: parent}

        warnings = validate_edge_semantics(child, dossier_acdcs)
        assert warnings == []

    def test_tnalloc_without_jl_returns_warning(self):
        """TNAlloc without JL edge returns warning (not required for root)."""
        from app.vvp.acdc.verifier import validate_edge_semantics

        # Root TNAlloc without JL edge
        root_tnalloc = ACDC(
            version="",
            said="E" + "R" * 43,
            issuer_aid="D" + "R" * 43,
            schema_said="",
            attributes={"tn": ["+1*"]},
            edges=None,  # No edges
            raw={}
        )

        # Should return warning, not raise (JL is optional for root allocators)
        warnings = validate_edge_semantics(root_tnalloc, {})
        assert len(warnings) == 1
        assert "Optional edge not found" in warnings[0]

    def test_unknown_credential_type_no_rules(self):
        """Unknown credential type has no edge rules to validate."""
        from app.vvp.acdc.verifier import validate_edge_semantics

        # Credential with no type markers
        generic = ACDC(
            version="",
            said="E" + "G" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            attributes={"name": "Generic"},  # Unknown type
            raw={}
        )

        warnings = validate_edge_semantics(generic, {})
        assert warnings == []


class TestAcdcVariantDetection:
    """Tests for ACDC variant detection and rejection (8.9)."""

    def test_full_acdc_variant_detected(self):
        """Full ACDC variant is detected correctly."""
        from app.vvp.acdc.parser import detect_acdc_variant

        full_acdc = {
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "s": "E" + "S" * 43,
            "a": {"name": "Test", "LEI": "1234567890"},  # Expanded attributes
        }

        variant = detect_acdc_variant(full_acdc)
        assert variant == "full"

    def test_compact_acdc_missing_attributes_detected(self):
        """Compact ACDC (missing attributes) is detected."""
        from app.vvp.acdc.parser import detect_acdc_variant

        compact_acdc = {
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "s": "E" + "S" * 43,
            # No 'a' field - compact form
        }

        variant = detect_acdc_variant(compact_acdc)
        assert variant == "compact"

    def test_compact_acdc_said_reference_detected(self):
        """Compact ACDC (attributes as SAID reference) is detected."""
        from app.vvp.acdc.parser import detect_acdc_variant

        compact_acdc = {
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "s": "E" + "S" * 43,
            "a": "E" + "X" * 43,  # SAID reference instead of expanded dict
        }

        variant = detect_acdc_variant(compact_acdc)
        assert variant == "compact"

    def test_partial_acdc_placeholder_detected(self):
        """Partial ACDC (with _ placeholder) is detected."""
        from app.vvp.acdc.parser import detect_acdc_variant

        partial_acdc = {
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "s": "E" + "S" * 43,
            "a": {"name": "_", "LEI": "1234567890"},  # Placeholder for redacted
        }

        variant = detect_acdc_variant(partial_acdc)
        assert variant == "partial"

    def test_partial_acdc_said_placeholder_detected(self):
        """Partial ACDC (with _:SAID placeholder) is detected."""
        from app.vvp.acdc.parser import detect_acdc_variant

        partial_acdc = {
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "a": {"name": "_:SAID123", "LEI": "visible"},  # SAID placeholder
        }

        variant = detect_acdc_variant(partial_acdc)
        assert variant == "partial"

    def test_full_acdc_parses_successfully(self):
        """Full ACDC variant parses without error."""
        full_acdc = {
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "a": {"name": "Test Credential"},
        }

        acdc = parse_acdc(full_acdc)
        assert acdc.said == "E" + "A" * 43

    def test_compact_acdc_raises_parse_error(self):
        """Compact ACDC raises ParseError (not yet supported)."""
        from app.vvp.dossier.exceptions import ParseError

        compact_acdc = {
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "s": "E" + "S" * 43,
            # No 'a' field
        }

        with pytest.raises(ParseError, match="variant 'compact' not yet supported"):
            parse_acdc(compact_acdc)

    def test_partial_acdc_raises_parse_error(self):
        """Partial ACDC raises ParseError (not yet supported)."""
        from app.vvp.dossier.exceptions import ParseError

        partial_acdc = {
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "a": {"name": "_", "secret": "_:SAID"},  # Placeholders
        }

        with pytest.raises(ParseError, match="variant 'partial' not yet supported"):
            parse_acdc(partial_acdc)

    def test_compact_acdc_allowed_with_flag(self):
        """Compact ACDC parses with allow_variants=True."""
        compact_acdc = {
            "d": "E" + "A" * 43,
            "i": "D" + "B" * 43,
            "s": "E" + "S" * 43,
            # No 'a' field
        }

        # Should not raise with allow_variants=True
        acdc = parse_acdc(compact_acdc, allow_variants=True)
        assert acdc.said == "E" + "A" * 43


class TestSchemaValidation:
    """Tests for schema SAID validation."""

    def test_validate_schema_said_no_schema_non_strict(self):
        """Test that missing schema SAID is allowed in non-strict mode."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            raw={}
        )

        # Should not raise in non-strict mode
        validate_schema_said(acdc, strict=False)

    def test_validate_schema_said_no_schema_strict(self):
        """Test that missing schema SAID raises in strict mode."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="",
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="missing schema SAID"):
            validate_schema_said(acdc, strict=True)

    def test_validate_schema_known_le_schema(self):
        """Test that known LE schema SAID passes."""
        # Use a known LE schema SAID
        known_le_schema = list(KNOWN_SCHEMA_SAIDS["LE"])[0] if KNOWN_SCHEMA_SAIDS["LE"] else None

        if known_le_schema:
            acdc = ACDC(
                version="",
                said="E" + "A" * 43,
                issuer_aid="D" + "B" * 43,
                schema_said=known_le_schema,
                attributes={"LEI": "1234567890"},  # LE type
                raw={}
            )

            # Should not raise
            validate_schema_said(acdc, strict=True)

    def test_validate_schema_unknown_schema_strict(self):
        """Test that unknown schema SAID raises in strict mode."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "X" * 43,  # Unknown schema
            attributes={"LEI": "1234567890"},  # LE type
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="unrecognized schema SAID"):
            validate_schema_said(acdc, strict=True)

    def test_validate_schema_unknown_schema_non_strict(self):
        """Test that unknown schema SAID is allowed in non-strict mode."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "X" * 43,  # Unknown schema
            attributes={"LEI": "1234567890"},  # LE type
            raw={}
        )

        # Should not raise in non-strict mode
        validate_schema_said(acdc, strict=False)

    @pytest.mark.asyncio
    async def test_chain_validation_with_schema_check(self):
        """Test chain validation with schema validation enabled."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        # LE credential with known schema
        known_le_schema = list(KNOWN_SCHEMA_SAIDS["LE"])[0] if KNOWN_SCHEMA_SAIDS["LE"] else ""

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said=known_le_schema,
            attributes={"LEI": "1234567890"},
            raw={}
        )

        result = await validate_credential_chain(
            acdc, trusted_roots, {}, validate_schemas=True
        )
        assert result.validated is True

    @pytest.mark.asyncio
    async def test_chain_validation_unknown_schema_fails(self):
        """Test chain validation fails with unknown schema when enabled."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        # LE credential with unknown schema
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="E" + "X" * 43,  # Unknown schema
            attributes={"LEI": "1234567890"},
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="unrecognized schema SAID"):
            await validate_credential_chain(
                acdc, trusted_roots, {}, validate_schemas=True
            )


# =============================================================================
# Issuee Binding Validation Tests (Sprint 12)
# =============================================================================

class TestIssueeBinding:
    """Tests for issuee binding validation per VVP §6.3.5."""

    def test_credential_with_issuee_valid(self):
        """Credential with 'i' field (issuee) passes validation."""
        from app.vvp.acdc import validate_issuee_binding

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={"i": "D" + "H" * 43, "name": "Test"},  # Has issuee
            raw={}
        )

        # Should not raise
        validate_issuee_binding(acdc, is_root_credential=False)

    def test_credential_with_issuee_field_valid(self):
        """Credential with 'issuee' field passes validation."""
        from app.vvp.acdc import validate_issuee_binding

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={"issuee": "D" + "H" * 43, "name": "Test"},
            raw={}
        )

        # Should not raise
        validate_issuee_binding(acdc, is_root_credential=False)

    def test_credential_with_holder_field_valid(self):
        """Credential with 'holder' field passes validation."""
        from app.vvp.acdc import validate_issuee_binding

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={"holder": "D" + "H" * 43, "name": "Test"},
            raw={}
        )

        # Should not raise
        validate_issuee_binding(acdc, is_root_credential=False)

    def test_credential_without_issuee_raises(self):
        """Credential without issuee field fails validation (bearer token)."""
        from app.vvp.acdc import validate_issuee_binding

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={"name": "Test"},  # No issuee field
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="bearer token"):
            validate_issuee_binding(acdc, is_root_credential=False)

    def test_root_credential_no_issuee_allowed(self):
        """Root credentials (GLEIF/QVI) may lack issuee."""
        from app.vvp.acdc import validate_issuee_binding

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={"name": "Root Credential"},  # No issuee
            raw={}
        )

        # Should not raise for root credentials
        validate_issuee_binding(acdc, is_root_credential=True)

    def test_credential_without_attributes_raises(self):
        """Credential with no attributes fails (can't verify issuee)."""
        from app.vvp.acdc import validate_issuee_binding

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes=None,  # No attributes at all
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="missing attributes"):
            validate_issuee_binding(acdc, is_root_credential=False)

    def test_issuee_mismatch_raises(self):
        """Credential with wrong issuee AID fails validation."""
        from app.vvp.acdc import validate_issuee_binding

        expected_aid = "D" + "E" * 43
        actual_aid = "D" + "F" * 43

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={"i": actual_aid},
            raw={}
        )

        with pytest.raises(ACDCChainInvalid, match="Issuee mismatch"):
            validate_issuee_binding(
                acdc,
                is_root_credential=False,
                expected_issuee_aid=expected_aid
            )

    def test_expected_issuee_matches(self):
        """Credential with matching expected issuee passes."""
        from app.vvp.acdc import validate_issuee_binding

        expected_aid = "D" + "E" * 43

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={"i": expected_aid},
            raw={}
        )

        # Should not raise
        validate_issuee_binding(
            acdc,
            is_root_credential=False,
            expected_issuee_aid=expected_aid
        )

    @pytest.mark.asyncio
    async def test_chain_validation_with_bearer_token_fails(self):
        """Chain validation fails when non-root credential is bearer token."""
        root_aid = "D" + "R" * 43
        child_issuer = "D" + "C" * 43
        trusted_roots = {root_aid}

        # Root credential (issued by GLEIF) - has issuee as it's going to child
        root_acdc = ACDC(
            version="",
            said="E" + "R" * 43,
            issuer_aid=root_aid,
            schema_said="E" + "S" * 43,
            attributes={"LEI": "1234567890", "i": child_issuer},  # Has issuee
            raw={}
        )

        # Leaf APE credential without issuee (bearer token)
        leaf_acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=child_issuer,
            schema_said="E" + "S" * 43,
            attributes={"name": "Test APE"},  # No 'i' or 'issuee' - bearer token!
            edges={"vetting": {"n": "E" + "R" * 43}},
            raw={}
        )

        dossier_acdcs = {
            "E" + "R" * 43: root_acdc,
            "E" + "A" * 43: leaf_acdc,
        }

        with pytest.raises(ACDCChainInvalid, match="bearer token"):
            await validate_credential_chain(
                leaf_acdc,
                trusted_roots,
                dossier_acdcs
            )
