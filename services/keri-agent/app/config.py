"""KERI Agent configuration constants.

Agent-specific configuration for the standalone KERI Agent service.
Only includes settings relevant to KERI/LMDB operations — no database,
auth, sessions, OAuth, or UI configuration.

Sprint 68: KERI Agent Service Extraction.
"""
import json
import os
from pathlib import Path
from typing import Any


# =============================================================================
# PERSISTENCE CONFIGURATION
# =============================================================================

def _get_data_dir() -> Path:
    """Determine data directory based on environment.

    Sprint 69: LMDB is ephemeral. Default to /tmp for containers,
    ~/.vvp-issuer for local development convenience.

    Priority:
    1. VVP_KERI_AGENT_DATA_DIR env var (explicit override)
    2. ~/.vvp-issuer if it already exists (local development)
    3. /tmp/vvp-keri-agent (container default — ephemeral)
    """
    env_path = os.getenv("VVP_KERI_AGENT_DATA_DIR")
    if env_path:
        return Path(env_path)

    # Local development: use persistent dir if it already exists
    try:
        home_path = Path.home() / ".vvp-issuer"
        if home_path.exists():
            return home_path
    except (OSError, RuntimeError):
        pass

    # Container default: ephemeral storage (rebuilt from PG seeds on startup)
    return Path("/tmp/vvp-keri-agent")


DATA_DIR: Path = _get_data_dir()
KEYSTORE_DIR: Path = DATA_DIR / "keystores"
DATABASE_DIR: Path = DATA_DIR / "databases"


# =============================================================================
# MOCK vLEI CONFIGURATION
# =============================================================================

MOCK_VLEI_ENABLED: bool = os.getenv("VVP_MOCK_VLEI_ENABLED", "true").lower() == "true"
MOCK_GLEIF_NAME: str = os.getenv("VVP_MOCK_GLEIF_NAME", "mock-gleif")
MOCK_QVI_NAME: str = os.getenv("VVP_MOCK_QVI_NAME", "mock-qvi")
MOCK_GSMA_NAME: str = os.getenv("VVP_MOCK_GSMA_NAME", "mock-gsma")


# =============================================================================
# WITNESS CONFIGURATION
# =============================================================================

def _get_witness_config_path() -> str:
    """Get path to witness configuration file."""
    return os.getenv(
        "VVP_WITNESS_CONFIG",
        str(Path(__file__).parent.parent / "config" / "witnesses.json")
    )


def _load_witness_config() -> dict[str, Any]:
    """Load witness configuration from JSON file."""
    config_path = Path(_get_witness_config_path())
    if config_path.exists():
        try:
            return json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"iurls": [], "witness_aids": {}, "ports": {}}


WITNESS_CONFIG_PATH: str = _get_witness_config_path()
WITNESS_CONFIG: dict[str, Any] = _load_witness_config()
WITNESS_IURLS: list[str] = WITNESS_CONFIG.get("iurls", [])
WITNESS_AIDS: dict[str, str] = WITNESS_CONFIG.get("witness_aids", {})
WITNESS_PORTS: dict[str, dict[str, int]] = WITNESS_CONFIG.get("ports", {})
WITNESS_OOBI_BASE_URLS: list[str] = WITNESS_CONFIG.get("oobi_base_urls", [])

# Witness interaction settings
WITNESS_TIMEOUT_SECONDS: float = float(os.getenv("VVP_WITNESS_TIMEOUT", "10.0"))
WITNESS_RECEIPT_THRESHOLD: int = int(os.getenv("VVP_WITNESS_THRESHOLD", "2"))


# =============================================================================
# IDENTITY DEFAULTS
# =============================================================================

DEFAULT_KEY_COUNT: int = int(os.getenv("VVP_DEFAULT_KEY_COUNT", "1"))
DEFAULT_KEY_THRESHOLD: str = os.getenv("VVP_DEFAULT_KEY_THRESHOLD", "1")
DEFAULT_NEXT_KEY_COUNT: int = int(os.getenv("VVP_DEFAULT_NEXT_KEY_COUNT", "1"))
DEFAULT_NEXT_THRESHOLD: str = os.getenv("VVP_DEFAULT_NEXT_THRESHOLD", "1")


# =============================================================================
# VVP HEADER SETTINGS
# =============================================================================

# Base URL for the issuer service (used to construct dossier URLs in VVP headers)
VVP_ISSUER_BASE_URL: str = os.getenv("VVP_ISSUER_BASE_URL", "http://localhost:8001")


# =============================================================================
# AGENT OPERATIONAL SETTINGS
# =============================================================================

# =============================================================================
# DATABASE CONFIGURATION (Sprint 69: Seed Persistence)
# =============================================================================

DATABASE_URL: str = os.getenv(
    "VVP_KERI_AGENT_DATABASE_URL",
    f"sqlite:///{DATA_DIR}/keri_seeds.db"
)


SERVICE_PORT: int = int(os.getenv("VVP_KERI_AGENT_PORT", "8002"))

# Bearer token for inter-service authentication
# All endpoints except health probes require this token
AGENT_AUTH_TOKEN: str = os.getenv("VVP_KERI_AGENT_AUTH_TOKEN", "")

# Schema SAIDs (from vLEI Ecosystem Governance Framework)
QVI_SCHEMA_SAID: str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LEGAL_ENTITY_SCHEMA_SAID: str = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
