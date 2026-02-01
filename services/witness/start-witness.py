#!/usr/bin/env python3
"""
VVP Witness Startup Script

Initializes and runs a KERI witness with deterministic salt.
This ensures consistent AIDs across container restarts.

Environment Variables:
    WITNESS_NAME  - Witness name: wan, wil, or wes (default: wan)
    HTTP_PORT     - HTTP port for OOBI/REST API (default: 5642)
    TCP_PORT      - TCP port for KERI protocol (default: 5632)
    KERI_DB_PATH  - Path to KERI data directory (optional)

Expected AIDs (from deterministic salts):
    wan: BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
    wil: BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM
    wes: BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX
"""
import os
import sys
import logging

from keri.core import Salter
from keri.app import habbing, configing, directing, indirecting

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Deterministic salts for each witness (must be exactly 16 bytes)
WITNESS_SALTS = {
    "wan": b'wann-the-witness',
    "wil": b'will-the-witness',
    "wes": b'wess-the-witness',
}

# Expected AIDs from these salts
EXPECTED_AIDS = {
    "wan": "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
    "wil": "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
    "wes": "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
}


def main():
    # Read configuration from environment
    name = os.environ.get("WITNESS_NAME", "wan")
    http_port = int(os.environ.get("HTTP_PORT", "5642"))
    tcp_port = int(os.environ.get("TCP_PORT", "5632"))

    if name not in WITNESS_SALTS:
        logger.error(f"Unknown witness name: {name}")
        logger.error(f"Supported names: {', '.join(WITNESS_SALTS.keys())}")
        sys.exit(1)

    salt_raw = WITNESS_SALTS[name]
    salt_qb64 = Salter(raw=salt_raw).qb64
    expected_aid = EXPECTED_AIDS[name]

    logger.info("=== VVP Witness Startup ===")
    logger.info(f"Name: {name}")
    logger.info(f"HTTP Port: {http_port}")
    logger.info(f"TCP Port: {tcp_port}")
    logger.info(f"Salt (qb64): {salt_qb64}")
    logger.info(f"Expected AID: {expected_aid}")

    # Create Habery with deterministic salt
    # temp=False means persistent storage
    hby = habbing.Habery(name=name, salt=salt_qb64, temp=False)

    # Create HaberyDoer to manage the Habery lifecycle
    hby_doer = habbing.HaberyDoer(habery=hby)
    doers = [hby_doer]

    # Setup the witness using the standard KERI indirecting module
    # This creates the witness hab if it doesn't exist (with transferable=False)
    # and sets up all the necessary endpoints and handlers
    witness_doers = indirecting.setupWitness(
        alias=name,
        hby=hby,
        tcpPort=tcp_port,
        httpPort=http_port
    )
    doers.extend(witness_doers)

    # Get the witness hab and verify AID
    hab = hby.habByName(name=name)
    if hab is not None:
        actual_aid = hab.pre
        logger.info(f"Witness AID: {actual_aid}")
        if actual_aid != expected_aid:
            logger.warning(f"AID mismatch! Expected {expected_aid}, got {actual_aid}")
            logger.warning("This may indicate a salt encoding issue.")
    else:
        logger.info("Witness hab will be created on first request")

    logger.info("===============================")
    logger.info(f"Starting witness {name} on HTTP:{http_port} TCP:{tcp_port}...")

    # Run the witness controller (blocks until stopped)
    directing.runController(doers=doers, expire=0.0)

    logger.info(f"Witness {name} stopped.")


if __name__ == "__main__":
    main()
