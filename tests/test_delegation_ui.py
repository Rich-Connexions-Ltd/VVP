"""Sprint 25: Tests for Delegation Chain UI Visibility.

Tests for:
- DelegationNodeResponse and DelegationChainResponse models
- _build_delegation_response helper in verify.py
- build_delegation_chain_info function in credential_viewmodel.py
- Proper INVALID/INDETERMINATE status mapping
"""

import pytest
from typing import Dict, Optional
from dataclasses import dataclass, field

from app.vvp.api_models import (
    DelegationNodeResponse,
    DelegationChainResponse,
    VerifyResponse,
    ClaimStatus,
)
from app.vvp.ui.credential_viewmodel import (
    DelegationChainInfo,
    DelegationNode,
    IssuerIdentity,
    build_delegation_chain_info,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@dataclass
class MockDelegationChain:
    """Mock DelegationChain for testing _build_delegation_response."""
    delegates: list = field(default_factory=list)
    root_aid: Optional[str] = None
    valid: bool = False
    errors: list = field(default_factory=list)


# =============================================================================
# API Model Tests
# =============================================================================


class TestDelegationNodeResponse:
    """Tests for DelegationNodeResponse model."""

    def test_default_values(self):
        """Test default field values."""
        node = DelegationNodeResponse(
            aid="EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
            aid_short="EBfdlu8R27Fbx...",
        )
        assert node.display_name is None
        assert node.is_root is False
        assert node.authorization_status == "INDETERMINATE"

    def test_all_fields(self):
        """Test node with all fields populated."""
        node = DelegationNodeResponse(
            aid="EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
            aid_short="EBfdlu8R27Fbx...",
            display_name="GLEIF",
            is_root=True,
            authorization_status="VALID",
        )
        assert node.aid == "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        assert node.display_name == "GLEIF"
        assert node.is_root is True
        assert node.authorization_status == "VALID"


class TestDelegationChainResponse:
    """Tests for DelegationChainResponse model."""

    def test_default_values(self):
        """Test default field values."""
        chain = DelegationChainResponse()
        assert chain.chain == []
        assert chain.depth == 0
        assert chain.root_aid is None
        assert chain.is_valid is False
        assert chain.errors == []

    def test_full_chain(self):
        """Test chain with multiple nodes."""
        chain = DelegationChainResponse(
            chain=[
                DelegationNodeResponse(
                    aid="ELeaf123...",
                    aid_short="ELeaf123...",
                    authorization_status="VALID",
                ),
                DelegationNodeResponse(
                    aid="ERoot456...",
                    aid_short="ERoot456...",
                    is_root=True,
                    authorization_status="VALID",
                ),
            ],
            depth=1,
            root_aid="ERoot456...",
            is_valid=True,
        )
        assert len(chain.chain) == 2
        assert chain.depth == 1
        assert chain.is_valid is True
        assert chain.chain[1].is_root is True


class TestVerifyResponseDelegationFields:
    """Tests for delegation fields on VerifyResponse."""

    def test_delegation_chain_optional(self):
        """Test that delegation_chain defaults to None."""
        resp = VerifyResponse(
            request_id="test-123",
            overall_status=ClaimStatus.VALID,
        )
        assert resp.delegation_chain is None
        assert resp.signer_aid is None

    def test_delegation_chain_populated(self):
        """Test VerifyResponse with delegation chain."""
        chain = DelegationChainResponse(
            chain=[
                DelegationNodeResponse(
                    aid="ETest...",
                    aid_short="ETest...",
                )
            ],
            depth=1,
            is_valid=True,
        )
        resp = VerifyResponse(
            request_id="test-123",
            overall_status=ClaimStatus.VALID,
            delegation_chain=chain,
            signer_aid="ESigner...",
        )
        assert resp.delegation_chain is not None
        assert resp.delegation_chain.depth == 1
        assert resp.signer_aid == "ESigner..."


# =============================================================================
# _build_delegation_response Tests
# =============================================================================


class TestBuildDelegationResponse:
    """Tests for _build_delegation_response helper."""

    def test_valid_chain_valid_auth(self):
        """Test: chain.valid=True, auth_status=VALID → nodes get VALID."""
        from app.vvp.verify import _build_delegation_response

        chain = MockDelegationChain(
            delegates=["ELeaf...", "ERoot..."],
            root_aid="ERoot...",
            valid=True,
        )
        result = _build_delegation_response(chain, "VALID")

        assert result.is_valid is True
        assert len(result.chain) == 2
        assert all(node.authorization_status == "VALID" for node in result.chain)
        assert result.depth == 1

    def test_valid_chain_invalid_auth(self):
        """Test: chain.valid=True, auth_status=INVALID → nodes get INVALID."""
        from app.vvp.verify import _build_delegation_response

        chain = MockDelegationChain(
            delegates=["ELeaf...", "ERoot..."],
            root_aid="ERoot...",
            valid=True,
        )
        result = _build_delegation_response(chain, "INVALID")

        assert result.is_valid is False
        assert all(node.authorization_status == "INVALID" for node in result.chain)

    def test_valid_chain_indeterminate_auth(self):
        """Test: chain.valid=True, auth_status=INDETERMINATE → nodes get INDETERMINATE."""
        from app.vvp.verify import _build_delegation_response

        chain = MockDelegationChain(
            delegates=["ELeaf...", "ERoot..."],
            root_aid="ERoot...",
            valid=True,
        )
        result = _build_delegation_response(chain, "INDETERMINATE")

        assert result.is_valid is False
        assert all(node.authorization_status == "INDETERMINATE" for node in result.chain)

    def test_invalid_chain_any_auth(self):
        """Test: chain.valid=False → nodes get INVALID regardless of auth_status."""
        from app.vvp.verify import _build_delegation_response

        chain = MockDelegationChain(
            delegates=["ELeaf...", "ERoot..."],
            root_aid="ERoot...",
            valid=False,
            errors=["Cycle detected"],
        )

        # Even if auth says VALID, chain invalid means INVALID
        result = _build_delegation_response(chain, "VALID")
        assert result.is_valid is False
        assert all(node.authorization_status == "INVALID" for node in result.chain)
        assert "Cycle detected" in result.errors

    def test_root_node_marked(self):
        """Test that root node is correctly identified."""
        from app.vvp.verify import _build_delegation_response

        chain = MockDelegationChain(
            delegates=["ELeaf123...", "EMid456...", "ERoot789..."],
            root_aid="ERoot789...",
            valid=True,
        )
        result = _build_delegation_response(chain, "VALID")

        # Find the root node
        root_nodes = [n for n in result.chain if n.is_root]
        assert len(root_nodes) == 1
        assert "ERoot789" in root_nodes[0].aid

    def test_empty_chain(self):
        """Test handling of empty delegation chain."""
        from app.vvp.verify import _build_delegation_response

        chain = MockDelegationChain(
            delegates=[],
            root_aid=None,
            valid=True,
        )
        result = _build_delegation_response(chain, "VALID")

        assert result.chain == []
        assert result.depth == 0
        assert result.is_valid is True


# =============================================================================
# build_delegation_chain_info Tests
# =============================================================================


class TestBuildDelegationChainInfo:
    """Tests for build_delegation_chain_info function."""

    def test_none_input(self):
        """Test that None input returns None."""
        result = build_delegation_chain_info(None)
        assert result is None

    def test_empty_chain(self):
        """Test that empty chain returns None."""
        response = DelegationChainResponse(chain=[])
        result = build_delegation_chain_info(response)
        assert result is None

    def test_basic_conversion(self):
        """Test basic conversion from response to info."""
        response = DelegationChainResponse(
            chain=[
                DelegationNodeResponse(
                    aid="ELeaf...",
                    aid_short="ELeaf...",
                    authorization_status="VALID",
                ),
                DelegationNodeResponse(
                    aid="ERoot...",
                    aid_short="ERoot...",
                    is_root=True,
                    authorization_status="VALID",
                ),
            ],
            depth=1,
            root_aid="ERoot...",
            is_valid=True,
        )
        result = build_delegation_chain_info(response)

        assert result is not None
        assert isinstance(result, DelegationChainInfo)
        assert len(result.chain) == 2
        assert result.depth == 1
        assert result.is_valid is True

    def test_identity_resolution(self):
        """Test that issuer identities are resolved for display names."""
        response = DelegationChainResponse(
            chain=[
                DelegationNodeResponse(
                    aid="ELeaf123...",
                    aid_short="ELeaf123...",
                ),
                DelegationNodeResponse(
                    aid="ERoot456...",
                    aid_short="ERoot456...",
                    is_root=True,
                ),
            ],
            depth=1,
            root_aid="ERoot456...",
            is_valid=True,
        )

        identities = {
            "ELeaf123...": IssuerIdentity(
                aid="ELeaf123...",
                legal_name="Test QVI",
                lei="123456789012345678",
            ),
            "ERoot456...": IssuerIdentity(
                aid="ERoot456...",
                legal_name="GLEIF",
                lei="549300TRUWO2CD2G5692",
            ),
        }

        result = build_delegation_chain_info(response, identities)

        assert result is not None
        assert result.chain[0].display_name == "Test QVI"
        assert result.chain[1].display_name == "GLEIF"

    def test_partial_identity_resolution(self):
        """Test that missing identities don't break resolution."""
        response = DelegationChainResponse(
            chain=[
                DelegationNodeResponse(
                    aid="ELeaf123...",
                    aid_short="ELeaf123...",
                ),
                DelegationNodeResponse(
                    aid="ERoot456...",
                    aid_short="ERoot456...",
                    is_root=True,
                ),
            ],
            depth=1,
            root_aid="ERoot456...",
            is_valid=True,
        )

        # Only partial identity map
        identities = {
            "ERoot456...": IssuerIdentity(
                aid="ERoot456...",
                legal_name="GLEIF",
            ),
        }

        result = build_delegation_chain_info(response, identities)

        assert result is not None
        assert result.chain[0].display_name is None  # No identity found
        assert result.chain[1].display_name == "GLEIF"

    def test_errors_preserved(self):
        """Test that errors are passed through."""
        response = DelegationChainResponse(
            chain=[
                DelegationNodeResponse(
                    aid="ELeaf...",
                    aid_short="ELeaf...",
                ),
            ],
            depth=1,
            is_valid=False,
            errors=["Delegator KEL unavailable", "Authorization check failed"],
        )

        result = build_delegation_chain_info(response)

        assert result is not None
        assert len(result.errors) == 2
        assert "Delegator KEL unavailable" in result.errors


# =============================================================================
# Integration Tests
# =============================================================================


class TestDelegationUIIntegration:
    """Integration tests for delegation UI flow."""

    def test_full_ui_flow_valid_chain(self):
        """Test complete flow from delegation chain to UI info."""
        from app.vvp.verify import _build_delegation_response

        # Simulate backend delegation chain
        backend_chain = MockDelegationChain(
            delegates=["EDelegate...", "EIntermediate...", "EGLEIF..."],
            root_aid="EGLEIF...",
            valid=True,
        )

        # Build API response
        api_response = _build_delegation_response(backend_chain, "VALID")

        # Convert to UI info
        ui_info = build_delegation_chain_info(api_response)

        # Verify complete chain
        assert ui_info is not None
        assert ui_info.depth == 2
        assert ui_info.is_valid is True
        assert len(ui_info.chain) == 3
        assert ui_info.chain[2].is_root is True

    def test_full_ui_flow_failed_auth(self):
        """Test flow when authorization fails."""
        from app.vvp.verify import _build_delegation_response

        backend_chain = MockDelegationChain(
            delegates=["EDelegate...", "ERoot..."],
            root_aid="ERoot...",
            valid=True,  # Chain resolved but...
        )

        # Authorization failed (e.g., bad anchor signature)
        api_response = _build_delegation_response(backend_chain, "INVALID")

        ui_info = build_delegation_chain_info(api_response)

        assert ui_info is not None
        assert ui_info.is_valid is False
        # All nodes should show INVALID status
        assert all(n.authorization_status == "INVALID" for n in ui_info.chain)
