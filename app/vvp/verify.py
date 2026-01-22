import uuid
from typing import Tuple
from .api_models import VerifyRequest, VerifyResponse, ClaimNode

def verify_vvp(req: VerifyRequest) -> Tuple[str, VerifyResponse]:
    request_id = str(uuid.uuid4())
    resp = VerifyResponse(
        request_id=request_id,
        passportStatus={"parsed": bool(req.identityHeader or req.passportJwt), "signature": "UNVERIFIED"},
        dossierGraphStatus={"retrieved": "UNVERIFIED", "graph_validated": "UNVERIFIED"},
        claimTree=ClaimNode(
            id="root",
            label="VVP Call",
            status="UNVERIFIED",
            reasons=["VERIFIER_NOT_YET_IMPLEMENTED"],
            children=[
                ClaimNode(id="passport", label="PASSporT (JWT)", status="UNVERIFIED"),
                ClaimNode(id="dossier", label="Dossier (evd)", status="UNVERIFIED"),
            ],
        ),
    )
    return request_id, resp
