# SPDX-License-Identifier: MIT
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.auth import current_user, require_role
from app.services import scope_service, store

router = APIRouter(prefix="/api/targets", tags=["scope"])


class TargetIn(BaseModel):
    target: str
    authorization_ref: str = ""


@router.get("")
def list_targets(user=Depends(current_user)):
    return {"targets": store.find("targets", org_id=user["org_id"])}


@router.post("")
def declare(body: TargetIn, user=Depends(require_role("admin", "analyst"))):
    t = scope_service.declare_target(user["org_id"], body.target,
                                     body.authorization_ref)
    return {
        "target_id": t["id"], "domain": t["domain"],
        "verify_token": t["verify_token"],
        "instructions": (
            f"Déposez le token '{t['verify_token']}' à "
            f"https://{t['domain']}/.well-known/ptaas-verify.txt puis appelez "
            f"POST /api/targets/{t['id']}/verify — ou fournissez une référence "
            "d'autorisation écrite à un admin."
        ),
    }


@router.post("/{target_id}/verify")
async def verify(target_id: str, user=Depends(current_user)):
    return await scope_service.verify_target(user["org_id"], target_id)


class ManualVerify(BaseModel):
    authorization_ref: str


@router.post("/{target_id}/admin-verify")
def admin_verify(target_id: str, body: ManualVerify,
                 user=Depends(require_role("admin"))):
    return scope_service.admin_verify(target_id, body.authorization_ref)
