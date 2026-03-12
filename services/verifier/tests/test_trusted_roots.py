"""Tests for trusted root AID configuration.

Per VVP §5.1-7 - verifier MUST accept configured root of trust.
Sprint 83: TRUSTED_ROOT_AIDS constant replaced with _TrustedRootsStore.
Tests updated to use get_trusted_roots_current() and the store's snapshot.
"""

import os
import pytest


class TestTrustedRootsConfig:
    """Tests for trusted roots configuration (Sprint 83: now via _TrustedRootsStore)."""

    def test_default_gleif_root(self):
        """Test that default roots include GLEIF Root AID."""
        # Clear any env var
        os.environ.pop("VVP_TRUSTED_ROOT_AIDS", None)

        # Re-import to get fresh config
        import importlib
        from app.core import config
        importlib.reload(config)

        roots = config.get_trusted_roots_current()
        # GLEIF Root (production) from https://gleif.org/.well-known/keri/oobi/...
        assert "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2" in roots
        # NOTE: EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao is the QVI SCHEMA SAID,
        # not an issuer AID, so it should NOT be in trusted roots.
        assert "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao" not in roots
        assert len(roots) == 1

    def test_single_custom_root(self):
        """Test single custom root AID from env."""
        os.environ["VVP_TRUSTED_ROOT_AIDS"] = "DTestRoot1234567890123456789012345678901234"

        import importlib
        from app.core import config
        importlib.reload(config)

        roots = config.get_trusted_roots_current()
        assert "DTestRoot1234567890123456789012345678901234" in roots
        assert len(roots) == 1

        # Cleanup
        os.environ.pop("VVP_TRUSTED_ROOT_AIDS", None)

    def test_multiple_roots_comma_separated(self):
        """Test multiple roots from comma-separated env var."""
        os.environ["VVP_TRUSTED_ROOT_AIDS"] = "DRoot1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,DRoot2_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

        import importlib
        from app.core import config
        importlib.reload(config)

        roots = config.get_trusted_roots_current()
        assert "DRoot1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" in roots
        assert "DRoot2_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" in roots
        assert len(roots) == 2

        # Cleanup
        os.environ.pop("VVP_TRUSTED_ROOT_AIDS", None)

    def test_whitespace_trimmed(self):
        """Test that whitespace around AIDs is trimmed."""
        os.environ["VVP_TRUSTED_ROOT_AIDS"] = "  DRoot1_AAA  ,  DRoot2_BBB  "

        import importlib
        from app.core import config
        importlib.reload(config)

        roots = config.get_trusted_roots_current()
        assert "DRoot1_AAA" in roots
        assert "DRoot2_BBB" in roots
        assert "  DRoot1_AAA  " not in roots

        # Cleanup
        os.environ.pop("VVP_TRUSTED_ROOT_AIDS", None)

    def test_empty_entries_filtered(self):
        """Test that empty entries are filtered out."""
        os.environ["VVP_TRUSTED_ROOT_AIDS"] = "DRoot1_AAA,,DRoot2_BBB,,"

        import importlib
        from app.core import config
        importlib.reload(config)

        roots = config.get_trusted_roots_current()
        assert "" not in roots
        assert len(roots) == 2

        # Cleanup
        os.environ.pop("VVP_TRUSTED_ROOT_AIDS", None)

    def test_empty_env_uses_default(self):
        """Test that empty env var uses default."""
        os.environ["VVP_TRUSTED_ROOT_AIDS"] = ""

        import importlib
        from app.core import config
        importlib.reload(config)

        roots = config.get_trusted_roots_current()
        # Should fall back to GLEIF root AID
        assert "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2" in roots
        assert len(roots) == 1

        # Cleanup
        os.environ.pop("VVP_TRUSTED_ROOT_AIDS", None)

    def test_roots_is_frozenset(self):
        """Test that get_trusted_roots_current() returns a frozenset (immutable)."""
        from app.core import config

        roots = config.get_trusted_roots_current()
        assert isinstance(roots, frozenset)

    def test_store_snapshot_is_frozenset(self):
        """Test that _trusted_roots_store.snapshot() returns a frozenset."""
        import asyncio
        from app.core import config

        snap = asyncio.get_event_loop().run_until_complete(
            config._trusted_roots_store.snapshot()
        )
        assert isinstance(snap, frozenset)
