from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.auth import current_user, require_role
from app.services import credits_service
from app.services.credits_service import PLANS, get_balance

router = APIRouter(prefix="/api/billing", tags=["billing"])


@router.get("/plans")
def plans():
    return {"plans": PLANS, "costs": credits_service.COSTS}


@router.get("/balance")
def balance(user=Depends(current_user)):
    return {"credits": get_balance(user["org_id"])}


class Recharge(BaseModel):
    credits: int


@router.post("/recharge")
def recharge(body: Recharge, user=Depends(require_role("admin"))):
    return {"credits": credits_service.recharge(user["org_id"], body.credits)}
