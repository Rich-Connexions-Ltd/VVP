"""TEL (Transaction Event Log) query endpoint for the KERI Agent.

Internal-only endpoint providing CESR-encoded TEL events for credentials.
The Issuer service proxies this to provide the public TEL facade.

Sprint 80: TEL Publication to Witnesses.
"""
import asyncio
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from common.vvp.said_validation import is_valid_said
from app.keri.issuer import get_credential_issuer
from app.keri.registry import get_registry_manager

router = APIRouter(prefix="/tels", tags=["tel"])
log = logging.getLogger(__name__)


@router.get("/credential/{credential_said}")
async def get_credential_tel(credential_said: str):
    """Get CESR-encoded TEL events for a credential.

    Returns concatenated CESR: iss event (sn=0) + rev event (sn=1, if revoked).
    Content-Type: application/cesr.

    This is the canonical TEL query endpoint. The older
    GET /credentials/{said}/tel (Internal Only) returns iss-only for DossierBuilder.
    """
    if not is_valid_said(credential_said):
        raise HTTPException(status_code=400, detail="Invalid SAID format")

    await get_credential_issuer()  # Ensure KERI managers initialized
    registry_mgr = await get_registry_manager()
    reger = registry_mgr.regery.reger

    # Get iss event (sn=0) via asyncio.to_thread to avoid blocking
    try:
        iss_bytes = await asyncio.to_thread(
            _get_tel_event_bytes, reger, credential_said, 0
        )
    except Exception as e:
        log.warning(f"TEL lookup failed for {credential_said[:16]}...: {e}")
        raise HTTPException(status_code=404, detail="Credential TEL not found")

    if iss_bytes is None:
        raise HTTPException(status_code=404, detail="Credential TEL not found")

    # Get rev event (sn=1) if it exists
    try:
        rev_bytes = await asyncio.to_thread(
            _get_tel_event_bytes, reger, credential_said, 1
        )
    except Exception:
        rev_bytes = None

    # Concatenate iss + optional rev
    tel_bytes = iss_bytes
    if rev_bytes:
        tel_bytes = iss_bytes + rev_bytes

    return Response(
        content=tel_bytes,
        media_type="application/cesr",
        headers={"Cache-Control": "no-store"},
    )


def _get_tel_event_bytes(reger, credential_said: str, sn: int) -> bytes | None:
    """Read a TEL event from LMDB Reger (runs in thread pool)."""
    try:
        raw = reger.cloneTvtAt(credential_said, sn=sn)
        return bytes(raw) if raw else None
    except Exception:
        return None
