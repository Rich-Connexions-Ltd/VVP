"""Credential management endpoints."""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from keri.kering import LikelyDuplicitousError, ValidationError

from app.api.models import (
    IssueCredentialRequest,
    IssueCredentialResponse,
    CredentialResponse,
    CredentialDetailResponse,
    CredentialListResponse,
    RevokeCredentialRequest,
    RevokeCredentialResponse,
    WitnessPublishResult,
)
from app.auth.api_key import Principal
from app.auth.roles import require_admin, require_operator, require_readonly
from app.audit import get_audit_logger
from app.config import WITNESS_IURLS
from app.keri.issuer import get_credential_issuer
from app.keri.witness import get_witness_publisher

log = logging.getLogger(__name__)
router = APIRouter(prefix="/credential", tags=["credential"])


@router.post("/issue", response_model=IssueCredentialResponse)
async def issue_credential(
    request: IssueCredentialRequest,
    http_request: Request,
    principal: Principal = require_operator,
) -> IssueCredentialResponse:
    """Issue a new ACDC credential.

    Creates a credential, generates TEL issuance event, and optionally
    publishes to witnesses.

    Requires: issuer:operator role
    """
    issuer = await get_credential_issuer()
    audit = get_audit_logger()

    try:
        # Issue the credential
        cred_info, acdc_bytes = await issuer.issue_credential(
            registry_name=request.registry_name,
            schema_said=request.schema_said,
            attributes=request.attributes,
            recipient_aid=request.recipient_aid,
            edges=request.edges,
            rules=request.rules,
            private=request.private,
        )

        # Publish anchoring IXN event to witnesses
        publish_results: list[WitnessPublishResult] | None = None
        if request.publish_to_witnesses and WITNESS_IURLS:
            try:
                ixn_bytes = await issuer.get_anchor_ixn_bytes(cred_info.said)
                publisher = get_witness_publisher()
                result = await publisher.publish_event(cred_info.issuer_aid, ixn_bytes)

                publish_results = [
                    WitnessPublishResult(
                        url=wr.url,
                        success=wr.success,
                        error=wr.error,
                    )
                    for wr in result.witnesses
                ]

                if not result.threshold_met:
                    log.warning(
                        f"Witness threshold not met for credential {cred_info.said[:16]}...: "
                        f"{result.success_count}/{result.total_count}"
                    )
            except Exception as e:
                log.error(f"Failed to publish anchor ixn to witnesses: {e}")
                # Don't fail credential issuance if witness publishing fails

        # Audit log the issuance
        audit.log_access(
            action="credential.issue",
            principal_id=principal.key_id,
            resource=cred_info.said,
            details={
                "registry_name": request.registry_name,
                "schema_said": request.schema_said,
                "recipient_aid": request.recipient_aid,
            },
            request=http_request,
        )

        return IssueCredentialResponse(
            credential=CredentialResponse(
                said=cred_info.said,
                issuer_aid=cred_info.issuer_aid,
                recipient_aid=cred_info.recipient_aid,
                registry_key=cred_info.registry_key,
                schema_said=cred_info.schema_said,
                issuance_dt=cred_info.issuance_dt,
                status=cred_info.status,
                revocation_dt=cred_info.revocation_dt,
            ),
            publish_results=publish_results,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.exception(f"Failed to issue credential: {e}")
        raise HTTPException(status_code=500, detail="Internal error issuing credential")


@router.get("", response_model=CredentialListResponse)
async def list_credentials(
    registry_key: Optional[str] = None,
    status: Optional[str] = None,
    principal: Principal = require_readonly,
) -> CredentialListResponse:
    """List issued credentials with optional filtering.

    Requires: issuer:readonly role
    """
    issuer = await get_credential_issuer()

    try:
        credentials = await issuer.list_credentials(
            registry_key=registry_key,
            status=status,
        )

        return CredentialListResponse(
            credentials=[
                CredentialResponse(
                    said=c.said,
                    issuer_aid=c.issuer_aid,
                    recipient_aid=c.recipient_aid,
                    registry_key=c.registry_key,
                    schema_said=c.schema_said,
                    issuance_dt=c.issuance_dt,
                    status=c.status,
                    revocation_dt=c.revocation_dt,
                )
                for c in credentials
            ],
            count=len(credentials),
        )
    except Exception as e:
        log.exception(f"Failed to list credentials: {e}")
        raise HTTPException(status_code=500, detail="Internal error listing credentials")


@router.get("/{said}", response_model=CredentialDetailResponse)
async def get_credential(
    said: str,
    principal: Principal = require_readonly,
) -> CredentialDetailResponse:
    """Get credential details by SAID.

    Requires: issuer:readonly role
    """
    issuer = await get_credential_issuer()

    try:
        cred_info = await issuer.get_credential(said)

        if cred_info is None:
            raise HTTPException(status_code=404, detail=f"Credential not found: {said}")

        return CredentialDetailResponse(
            said=cred_info.said,
            issuer_aid=cred_info.issuer_aid,
            recipient_aid=cred_info.recipient_aid,
            registry_key=cred_info.registry_key,
            schema_said=cred_info.schema_said,
            issuance_dt=cred_info.issuance_dt,
            status=cred_info.status,
            revocation_dt=cred_info.revocation_dt,
            attributes=cred_info.attributes,
            edges=cred_info.edges,
            rules=cred_info.rules,
        )
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to get credential {said}: {e}")
        raise HTTPException(status_code=500, detail="Internal error getting credential")


@router.post("/{said}/revoke", response_model=RevokeCredentialResponse)
async def revoke_credential(
    said: str,
    request: RevokeCredentialRequest,
    http_request: Request,
    principal: Principal = require_admin,
) -> RevokeCredentialResponse:
    """Revoke an issued credential.

    Creates TEL revocation event and updates credential status.

    Requires: issuer:admin role
    """
    issuer = await get_credential_issuer()
    audit = get_audit_logger()

    try:
        cred_info = await issuer.revoke_credential(said)

        # Publish anchoring IXN event to witnesses
        publish_results: list[WitnessPublishResult] | None = None
        if request.publish_to_witnesses and WITNESS_IURLS:
            try:
                ixn_bytes = await issuer.get_anchor_ixn_bytes(said)
                publisher = get_witness_publisher()
                result = await publisher.publish_event(cred_info.issuer_aid, ixn_bytes)

                publish_results = [
                    WitnessPublishResult(
                        url=wr.url,
                        success=wr.success,
                        error=wr.error,
                    )
                    for wr in result.witnesses
                ]

                if not result.threshold_met:
                    log.warning(
                        f"Witness threshold not met for credential revocation {said[:16]}...: "
                        f"{result.success_count}/{result.total_count}"
                    )
            except Exception as e:
                log.error(f"Failed to publish revocation anchor ixn to witnesses: {e}")
                # Don't fail revocation if witness publishing fails

        # Audit log the revocation
        audit.log_access(
            action="credential.revoke",
            principal_id=principal.key_id,
            resource=said,
            details={"reason": request.reason},
            request=http_request,
        )

        return RevokeCredentialResponse(
            credential=CredentialResponse(
                said=cred_info.said,
                issuer_aid=cred_info.issuer_aid,
                recipient_aid=cred_info.recipient_aid,
                registry_key=cred_info.registry_key,
                schema_said=cred_info.schema_said,
                issuance_dt=cred_info.issuance_dt,
                status=cred_info.status,
                revocation_dt=cred_info.revocation_dt,
            ),
            publish_results=publish_results,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except LikelyDuplicitousError:
        # Credential was already revoked - keripy sees the second rev as duplicate
        raise HTTPException(status_code=400, detail=f"Credential already revoked: {said}")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to revoke credential {said}: {e}")
        raise HTTPException(status_code=500, detail="Internal error revoking credential")
