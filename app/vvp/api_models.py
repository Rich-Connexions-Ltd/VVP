from pydantic import BaseModel
from typing import Any, Dict, List, Optional

class VerifyRequest(BaseModel):
    identityHeader: Optional[str] = None
    passportJwt: Optional[str] = None
    sipContext: Optional[Dict[str, Any]] = None
    policy: Optional[Dict[str, Any]] = None

class ClaimNode(BaseModel):
    id: str
    label: str
    status: str
    reasons: List[str] = []
    children: List["ClaimNode"] = []

ClaimNode.model_rebuild()

class VerifyResponse(BaseModel):
    request_id: str
    passportStatus: Dict[str, Any]
    dossierGraphStatus: Dict[str, Any]
    claimTree: ClaimNode
