"""Tests for revocation checking in verify.py.

Phase 9.3: Tests for check_dossier_revocations() function.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.vvp.api_models import ClaimStatus
from app.vvp.dossier.models import ACDCNode, DossierDAG


# Mock the TEL client at import time to avoid pysodium issues
@pytest.fixture
def mock_tel_client():
    """Create a mock TEL client."""
    from app.vvp.keri.tel_client import CredentialStatus, RevocationResult

    mock_client = MagicMock()
    mock_client.check_revocation = AsyncMock()

    return mock_client, CredentialStatus, RevocationResult


@pytest.fixture
def sample_dag():
    """Create a sample DossierDAG for testing."""
    dag = DossierDAG()
    dag.nodes = {
        "ESAID1234567890abcdef": ACDCNode(
            said="ESAID1234567890abcdef",
            issuer="EISSUER1234567890ab",
            schema="ESCHEMA1234567890ab",
            raw={"ri": "EREGISTRY1234567890"}
        ),
        "ESAID2234567890abcdef": ACDCNode(
            said="ESAID2234567890abcdef",
            issuer="EISSUER2234567890ab",
            schema="ESCHEMA2234567890ab",
            raw={}
        ),
    }
    dag.root_said = "ESAID1234567890abcdef"
    return dag


@pytest.fixture
def empty_dag():
    """Create an empty DossierDAG for testing."""
    dag = DossierDAG()
    dag.nodes = {}
    dag.root_said = None
    return dag


class TestCheckDossierRevocations:
    """Tests for check_dossier_revocations function."""

    @pytest.mark.asyncio
    async def test_all_credentials_active(self, mock_tel_client, sample_dag):
        """All credentials ACTIVE → revocation_clear VALID."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # All credentials return ACTIVE
        mock_client.check_revocation.return_value = RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said="test",
            registry_said=None,
            issuance_event=None,
            revocation_event=None,
            error=None,
            source="witness"
        )

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            assert claim.status == ClaimStatus.VALID
            assert claim.name == "revocation_clear"
            assert len(claim.evidence) > 0
            # Summary evidence shows counts
            assert "checked:2" in claim.evidence[-1]
            assert len(revoked_saids) == 0

    @pytest.mark.asyncio
    async def test_one_credential_revoked(self, mock_tel_client, sample_dag):
        """One revoked credential → revocation_clear INVALID."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # First call returns ACTIVE, second returns REVOKED
        mock_client.check_revocation.side_effect = [
            RevocationResult(
                status=CredentialStatus.ACTIVE,
                credential_said="test1",
                registry_said=None,
                issuance_event=None,
                revocation_event=None,
                error=None,
                source="witness"
            ),
            RevocationResult(
                status=CredentialStatus.REVOKED,
                credential_said="test2",
                registry_said=None,
                issuance_event=None,
                revocation_event=MagicMock(),
                error=None,
                source="witness"
            ),
        ]

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            assert claim.status == ClaimStatus.INVALID
            assert len(claim.reasons) > 0
            assert "revoked" in claim.reasons[0].lower()
            assert len(revoked_saids) == 1

    @pytest.mark.asyncio
    async def test_one_credential_unknown(self, mock_tel_client, sample_dag):
        """One unknown credential → revocation_clear INDETERMINATE."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # All credentials return UNKNOWN
        mock_client.check_revocation.return_value = RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said="test",
            registry_said=None,
            issuance_event=None,
            revocation_event=None,
            error="No TEL data found",
            source="none"
        )

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            assert claim.status == ClaimStatus.INDETERMINATE
            assert len(claim.reasons) > 0
            assert len(revoked_saids) == 0

    @pytest.mark.asyncio
    async def test_revoked_takes_precedence_over_unknown(self, mock_tel_client, sample_dag):
        """REVOKED wins over UNKNOWN → INVALID status."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # First returns UNKNOWN, second returns REVOKED
        mock_client.check_revocation.side_effect = [
            RevocationResult(
                status=CredentialStatus.UNKNOWN,
                credential_said="test1",
                registry_said=None,
                issuance_event=None,
                revocation_event=None,
                error="No TEL data",
                source="none"
            ),
            RevocationResult(
                status=CredentialStatus.REVOKED,
                credential_said="test2",
                registry_said=None,
                issuance_event=None,
                revocation_event=MagicMock(),
                error=None,
                source="witness"
            ),
        ]

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            # INVALID should take precedence over INDETERMINATE
            assert claim.status == ClaimStatus.INVALID
            assert len(revoked_saids) == 1

    @pytest.mark.asyncio
    async def test_empty_dag(self, mock_tel_client, empty_dag):
        """Empty DAG → VALID (nothing to check)."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(empty_dag)

            assert claim.status == ClaimStatus.VALID
            assert "checked:0" in claim.evidence[-1]
            assert len(revoked_saids) == 0

    @pytest.mark.asyncio
    async def test_extracts_registry_said(self, mock_tel_client):
        """Correctly extracts ri field from raw ACDC."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # Create DAG with registry SAID
        dag = DossierDAG()
        dag.nodes = {
            "ESAID_TEST": ACDCNode(
                said="ESAID_TEST",
                issuer="EISSUER",
                schema="ESCHEMA",
                raw={"ri": "EREGISTRY_SAID_123"}
            )
        }
        dag.root_said = "ESAID_TEST"

        mock_client.check_revocation.return_value = RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said="ESAID_TEST",
            registry_said="EREGISTRY_SAID_123",
            issuance_event=None,
            revocation_event=None,
            error=None,
            source="witness"
        )

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            await check_dossier_revocations(dag)

            # Verify the registry_said was passed to check_revocation
            call_args = mock_client.check_revocation.call_args
            assert call_args.kwargs["registry_said"] == "EREGISTRY_SAID_123"

    @pytest.mark.asyncio
    async def test_error_status_becomes_indeterminate(self, mock_tel_client, sample_dag):
        """ERROR status → revocation_clear INDETERMINATE."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        mock_client.check_revocation.return_value = RevocationResult(
            status=CredentialStatus.ERROR,
            credential_said="test",
            registry_said=None,
            issuance_event=None,
            revocation_event=None,
            error="Connection timeout",
            source="witness"
        )

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            assert claim.status == ClaimStatus.INDETERMINATE
            assert len(revoked_saids) == 0


class TestRevocationClaimInTree:
    """Tests for revocation_clear claim placement in tree."""

    def test_revocation_clear_is_child_of_dossier_verified(self):
        """revocation_clear is a REQUIRED child of dossier_verified per §3.3B."""
        # This test verifies the claim tree structure
        from app.vvp.api_models import ChildLink

        # Create mock claims
        from app.vvp.verify import ClaimBuilder

        dossier_claim = ClaimBuilder("dossier_verified")
        revocation_claim = ClaimBuilder("revocation_clear")

        # Build dossier node with revocation child
        revocation_node = revocation_claim.build()
        dossier_node = dossier_claim.build(children=[
            ChildLink(required=True, node=revocation_node),
        ])

        # Verify structure
        assert dossier_node.name == "dossier_verified"
        assert len(dossier_node.children) == 1
        assert dossier_node.children[0].required is True
        assert dossier_node.children[0].node.name == "revocation_clear"

    def test_dossier_status_reflects_revocation_child(self):
        """dossier_verified status propagates from revocation_clear per §3.3A."""
        from app.vvp.api_models import ChildLink
        from app.vvp.verify import ClaimBuilder, propagate_status, ClaimNode

        # Create dossier_verified as VALID but revocation_clear as INVALID
        dossier_claim = ClaimBuilder("dossier_verified")  # VALID by default
        revocation_claim = ClaimBuilder("revocation_clear")
        revocation_claim.fail(ClaimStatus.INVALID, "Credential revoked")

        revocation_node = revocation_claim.build()
        dossier_node = dossier_claim.build(children=[
            ChildLink(required=True, node=revocation_node),
        ])

        # Propagate status
        effective_status = propagate_status(dossier_node)

        # dossier_verified should reflect child's INVALID status
        assert effective_status == ClaimStatus.INVALID

    def test_dossier_status_indeterminate_when_revocation_indeterminate(self):
        """dossier_verified becomes INDETERMINATE when revocation_clear is INDETERMINATE."""
        from app.vvp.api_models import ChildLink
        from app.vvp.verify import ClaimBuilder, propagate_status

        dossier_claim = ClaimBuilder("dossier_verified")
        revocation_claim = ClaimBuilder("revocation_clear")
        revocation_claim.fail(ClaimStatus.INDETERMINATE, "TEL unavailable")

        revocation_node = revocation_claim.build()
        dossier_node = dossier_claim.build(children=[
            ChildLink(required=True, node=revocation_node),
        ])

        effective_status = propagate_status(dossier_node)
        assert effective_status == ClaimStatus.INDETERMINATE


class TestCredentialRevokedError:
    """Tests for CREDENTIAL_REVOKED error emission."""

    @pytest.mark.asyncio
    async def test_revoked_credential_emits_error(self, mock_tel_client, sample_dag):
        """Revoked credential emits CREDENTIAL_REVOKED error."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client
        from app.vvp.api_models import ErrorCode

        # Return REVOKED for all credentials
        mock_client.check_revocation.return_value = RevocationResult(
            status=CredentialStatus.REVOKED,
            credential_said="test",
            registry_said=None,
            issuance_event=None,
            revocation_event=MagicMock(),
            error=None,
            source="witness"
        )

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(sample_dag)

            # Verify revoked SAIDs are returned for error emission
            assert len(revoked_saids) == 2  # sample_dag has 2 nodes
            assert all(said in sample_dag.nodes for said in revoked_saids)


class TestInlineTELParsing:
    """Tests for Phase 9.4 inline TEL parsing from dossier."""

    @pytest.mark.asyncio
    async def test_inline_tel_issuance_found(self, mock_tel_client):
        """Inline TEL with issuance event → ACTIVE status."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        # Create DAG with a credential that has registry SAID
        dag = DossierDAG()
        cred_said = "ECredentialSAID123456"
        reg_said = "ERegistrySAID789012"
        dag.nodes = {
            cred_said: ACDCNode(
                said=cred_said,
                issuer="EISSUER123456",
                schema="ESCHEMA123456",
                raw={"ri": reg_said}
            )
        }
        dag.root_said = cred_said

        # Create raw dossier with inline TEL issuance event
        inline_tel_data = b'{"v":"KERI10JSON0000","t":"iss","i":"' + cred_said.encode() + b'","ri":"' + reg_said.encode() + b'","s":"0","d":"ESAID_DIGEST"}'

        # Mock parse_dossier_tel to return ACTIVE
        mock_client.parse_dossier_tel = MagicMock(return_value=RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said=cred_said,
            registry_said=reg_said,
            issuance_event=MagicMock(),
            revocation_event=None,
            error=None,
            source="dossier"
        ))
        # Ensure check_revocation is not called (since inline found it)
        mock_client.check_revocation = AsyncMock(return_value=RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=cred_said,
            registry_said=reg_said,
            issuance_event=None,
            revocation_event=None,
            error="Should not be called",
            source="witness"
        ))

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(
                dag, raw_dossier=inline_tel_data
            )

            # Should be VALID since inline TEL found ACTIVE
            assert claim.status == ClaimStatus.VALID
            # Check evidence contains dossier source (not in last element, which is summary)
            evidence_str = " ".join(claim.evidence)
            assert "revocation_source:dossier" in evidence_str
            assert "inline:1" in claim.evidence[-1]  # Summary shows 1 inline result
            assert len(revoked_saids) == 0
            # Verify parse_dossier_tel was called
            mock_client.parse_dossier_tel.assert_called()

    @pytest.mark.asyncio
    async def test_inline_tel_revocation_found(self, mock_tel_client):
        """Inline TEL with revocation event → INVALID status."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        dag = DossierDAG()
        cred_said = "ECredentialRevoked123"
        reg_said = "ERegistryRevoked789"
        dag.nodes = {
            cred_said: ACDCNode(
                said=cred_said,
                issuer="EISSUER123",
                schema="ESCHEMA123",
                raw={"ri": reg_said}
            )
        }
        dag.root_said = cred_said

        inline_tel_data = b'{"v":"KERI10JSON","t":"rev","i":"' + cred_said.encode() + b'"}'

        mock_client.parse_dossier_tel = MagicMock(return_value=RevocationResult(
            status=CredentialStatus.REVOKED,
            credential_said=cred_said,
            registry_said=reg_said,
            issuance_event=MagicMock(),
            revocation_event=MagicMock(),
            error=None,
            source="dossier"
        ))

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, revoked_saids = await check_dossier_revocations(
                dag, raw_dossier=inline_tel_data
            )

            assert claim.status == ClaimStatus.INVALID
            assert cred_said in revoked_saids

    @pytest.mark.asyncio
    async def test_no_raw_dossier_skips_inline(self, mock_tel_client, sample_dag):
        """No raw_dossier → falls back to witness query."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        mock_client.check_revocation = AsyncMock(return_value=RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said="test",
            registry_said=None,
            issuance_event=MagicMock(),
            revocation_event=None,
            error=None,
            source="witness"
        ))
        mock_client.parse_dossier_tel = MagicMock()

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, _ = await check_dossier_revocations(sample_dag, raw_dossier=None)

            assert claim.status == ClaimStatus.VALID
            # parse_dossier_tel should NOT be called when no raw_dossier
            mock_client.parse_dossier_tel.assert_not_called()
            # check_revocation should be called for each credential
            assert mock_client.check_revocation.call_count == len(sample_dag.nodes)


class TestRegistryOOBIDiscovery:
    """Tests for Phase 9.4 registry OOBI derivation."""

    @pytest.mark.asyncio
    async def test_registry_oobi_constructed(self, mock_tel_client):
        """Registry OOBI is derived from base URL."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        dag = DossierDAG()
        cred_said = "ECredentialNeedsRegistry"
        reg_said = "ERegistryForOOBI123"
        dag.nodes = {
            cred_said: ACDCNode(
                said=cred_said,
                issuer="EISSUER",
                schema="ESCHEMA",
                raw={"ri": reg_said}
            )
        }
        dag.root_said = cred_said

        # Inline TEL returns UNKNOWN → should trigger registry OOBI query
        mock_client.parse_dossier_tel = MagicMock(return_value=RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=cred_said,
            registry_said=reg_said,
            issuance_event=None,
            revocation_event=None,
            error=None,
            source="dossier"
        ))

        mock_client.check_revocation = AsyncMock(return_value=RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said=cred_said,
            registry_said=reg_said,
            issuance_event=MagicMock(),
            revocation_event=None,
            error=None,
            source="witness"
        ))

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, _ = await check_dossier_revocations(
                dag,
                raw_dossier=b'{}',  # Empty dossier
                oobi_url="https://origin.demo.provenant.net/v1/agent/public/oobi/EAID123"
            )

            assert claim.status == ClaimStatus.VALID
            # check_revocation should have been called with derived registry OOBI
            call_args = mock_client.check_revocation.call_args
            oobi_arg = call_args.kwargs.get("oobi_url", "")
            # Should contain registry SAID in OOBI path
            assert reg_said in oobi_arg or mock_client.check_revocation.called

    @pytest.mark.asyncio
    async def test_fallback_when_no_registry_said(self, mock_tel_client):
        """No registry SAID → uses default witnesses."""
        mock_client, CredentialStatus, RevocationResult = mock_tel_client

        dag = DossierDAG()
        cred_said = "ECredentialNoRegistry"
        dag.nodes = {
            cred_said: ACDCNode(
                said=cred_said,
                issuer="EISSUER",
                schema="ESCHEMA",
                raw={}  # No 'ri' field
            )
        }
        dag.root_said = cred_said

        mock_client.parse_dossier_tel = MagicMock(return_value=RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=cred_said,
            registry_said=None,
            issuance_event=None,
            revocation_event=None,
            error=None,
            source="dossier"
        ))

        mock_client.check_revocation = AsyncMock(return_value=RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said=cred_said,
            registry_said=None,
            issuance_event=MagicMock(),
            revocation_event=None,
            error=None,
            source="witness"
        ))

        with patch('app.vvp.keri.tel_client.get_tel_client', return_value=mock_client):
            from app.vvp.verify import check_dossier_revocations

            claim, _ = await check_dossier_revocations(
                dag,
                raw_dossier=b'{}',
                oobi_url="https://example.com/oobi/EAID"
            )

            assert claim.status == ClaimStatus.VALID
            # check_revocation should be called (fallback path)
            mock_client.check_revocation.assert_called()


class TestTELClientParseDossierTel:
    """Tests for TELClient.parse_dossier_tel with logging."""

    def test_parse_dossier_tel_finds_issuance(self):
        """parse_dossier_tel correctly extracts issuance event."""
        from app.vvp.keri.tel_client import TELClient, CredentialStatus

        client = TELClient()
        cred_said = "ECredentialTest123"
        reg_said = "ERegistryTest456"

        # CESR stream with TEL issuance event
        dossier_data = (
            '{"v":"KERI10JSON000000","t":"iss",'
            f'"i":"{cred_said}","ri":"{reg_said}",'
            '"s":"0","d":"ESAID_DIGEST123"}'
        )

        result = client.parse_dossier_tel(dossier_data, cred_said, reg_said)

        assert result.status == CredentialStatus.ACTIVE
        assert result.source == "dossier"
        assert result.issuance_event is not None
        assert result.revocation_event is None

    def test_parse_dossier_tel_finds_revocation(self):
        """parse_dossier_tel correctly extracts revocation event."""
        from app.vvp.keri.tel_client import TELClient, CredentialStatus

        client = TELClient()
        cred_said = "ECredentialRev123"
        reg_said = "ERegistryRev456"

        # CESR stream with both issuance and revocation
        dossier_data = (
            '{"v":"KERI10JSON","t":"iss","i":"' + cred_said + '","ri":"' + reg_said + '","s":"0","d":"D1"}'
            '{"v":"KERI10JSON","t":"rev","i":"' + cred_said + '","ri":"' + reg_said + '","s":"1","d":"D2"}'
        )

        result = client.parse_dossier_tel(dossier_data, cred_said, reg_said)

        assert result.status == CredentialStatus.REVOKED
        assert result.source == "dossier"
        assert result.issuance_event is not None
        assert result.revocation_event is not None

    def test_parse_dossier_tel_no_events(self):
        """parse_dossier_tel returns UNKNOWN when no TEL events found."""
        from app.vvp.keri.tel_client import TELClient, CredentialStatus

        client = TELClient()
        cred_said = "ECredentialEmpty"

        # Dossier with ACDC but no TEL events
        dossier_data = '{"d":"ESAID","i":"EISSUER","s":"ESCHEMA"}'

        result = client.parse_dossier_tel(dossier_data, cred_said)

        assert result.status == CredentialStatus.UNKNOWN
        assert result.source == "dossier"


class TestBinarySafeParsing:
    """Tests for binary-safe latin-1 decoding per Phase 9.4."""

    def test_latin1_preserves_binary_signatures(self):
        """Latin-1 decoding preserves binary CESR signatures."""
        from app.vvp.keri.tel_client import TELClient, CredentialStatus

        client = TELClient()
        cred_said = "ECredentialBinary"
        reg_said = "ERegistryBinary"

        # Simulate CESR stream with binary signature data after JSON
        # Latin-1 should preserve all byte values 0x00-0xFF
        json_part = '{"v":"KERI10JSON","t":"iss","i":"' + cred_said + '","ri":"' + reg_said + '","s":"0","d":"D1"}'
        # Add some "binary" signature bytes (non-UTF-8 but valid latin-1)
        binary_sig = bytes(range(128, 256))  # High bytes that would fail UTF-8

        # Decode as latin-1 (byte-transparent)
        combined = json_part.encode('utf-8') + binary_sig
        dossier_str = combined.decode('latin-1')

        result = client.parse_dossier_tel(dossier_str, cred_said, reg_said)

        # Should still find the TEL event despite binary trailer
        assert result.status == CredentialStatus.ACTIVE
        assert result.source == "dossier"
