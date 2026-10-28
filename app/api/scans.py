# SPDX-License-Identifier: MIT
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.auth import current_user, require_role
from app.services import store, scope_service, scanner, credits_service
from app.services.report_service import build_report, llm_report

router = APIRouter(prefix="/api/scans", tags=["scans"])
_jobs = {}


class ScanIn(BaseModel):
    target: str
    deep: bool = False
    exploit: bool = False
    report: bool = True


async def _run(job_id: str, org_id: str, body: ScanIn):
    try:
        result = await scanner.run_scan(body.target, body.deep, body.exploit)
        result["report"] = (await llm_report(result) if body.report
                            else build_report(result))
        store.update("scans", job_id, {"status": "done", "result": result})
    except Exception as e:
        store.update("scans", job_id, {"status": "failed", "error": str(e)})
    _jobs.pop(job_id, None)


@router.post("")
async def launch(body: ScanIn, user=Depends(require_role("admin", "analyst"))):
    scope_service.assert_scannable(user["org_id"], body.target)
    kind = "exploit" if body.exploit else ("deep" if body.deep else "quick")
    if body.exploit and not credits_service.plan_allows(user["org_id"], "active_exploitation"):
        raise HTTPException(403, "L'exploitation active requiert le palier PME ou supérieur.")
    credits_service.consume(user["org_id"], kind)
    scan = store.insert("scans", {
        "org_id": user["org_id"], "target": body.target,
        "kind": kind, "status": "running", "by": user["email"],
    })
    import asyncio
    _jobs[scan["id"]] = asyncio.create_task(
        _run(scan["id"], user["org_id"], body))
    return {"scan_id": scan["id"], "status": "running",
            "credits_left": credits_service.get_balance(user["org_id"])}


@router.get("")
def list_scans(user=Depends(current_user)):
    return {"scans": store.find("scans", org_id=user["org_id"])}


@router.get("/{scan_id}")
def get_scan(scan_id: str, user=Depends(current_user)):
    s = store.get("scans", scan_id)
    if not s or s["org_id"] != user["org_id"]:
        raise HTTPException(404, "Scan introuvable")
    return s
