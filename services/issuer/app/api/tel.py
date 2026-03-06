"""TEL (Transaction Event Log) facade endpoint for the Issuer.

Public endpoint proxying TEL queries to the internal KERI Agent.
TEL data is public per KERI spec (like OOBI data) — no authentication required.

Sprint 80: TEL Publication to Witnesses.
"""
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from common.vvp.said_validation import is_valid_said
from app.keri_client import get_keri_client, KeriAgentUnavailableError

router = APIRouter(prefix="/tels", tags=["tel"])
log = logging.getLogger(__name__)


@router.get("/credential/{credential_said}")
async def get_credential_tel(credential_said: str):
    """Get CESR-encoded TEL events for a credential.

    Public endpoint — TEL data is public per KERI spec.
    Proxies to KERI Agent and returns raw CESR bytes unchanged.
    """
    if not is_valid_said(credential_said):
        raise HTTPException(status_code=400, detail="Invalid SAID format")

    client = get_keri_client()
    try:
        tel_bytes = await client.get_credential_tel_cesr(credential_said)
    except KeriAgentUnavailableError:
        raise HTTPException(
            status_code=503,
            detail="TEL source unavailable",
            headers={"Retry-After": "30"},
        )

    if tel_bytes is None:
        raise HTTPException(status_code=404, detail="Credential TEL not found")

    return Response(
        content=tel_bytes,
        media_type="application/cesr",
        headers={"Cache-Control": "no-store"},
    )
