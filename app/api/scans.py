# SPDX-License-Identifier: MIT
import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.auth import current_user, require_role
from app.services import store, scope_service, scanner, credits_service
from app.services.report_service import build_report, llm_report, audience_view

router = APIRouter(prefix="/api/scans", tags=["scans"])
_jobs = {}


class ScanIn(BaseModel):
    target: str
    deep: bool = False
    exploit: bool = False
    report: bool = True
    mode: Optional[str] = None      # surcharge le mode de la cible
    audience: str = "developer"     # developer|ciso|auditor


async def _run(job_id: str, org_id: str, body: ScanIn, target_doc=None):
    try:
        result = await scanner.run_scan(body.target, body.deep, body.exploit)
        rep = (await llm_report(result) if body.report else build_report(result))
        result["report"] = rep
        result["report_views"] = {a: audience_view(rep, a)
                                for a in ("developer", "ciso", "auditor")}
        result["mode"] = body.mode or (target_doc or {}).get("mode", "black_box")
        result["asset_type"] = (target_doc or {}).get("asset_type", "web")
        store.update("scans", job_id, {"status": "done", "result": result})
        if target_doc:
            from datetime import datetime, timezone
            store.update("targets", target_doc["id"],
                         {"last_scan_at": datetime.now(timezone.utc).isoformat()})
    except Exception as e:
        store.update("scans", job_id, {"status": "failed", "error": str(e)})
    _jobs.pop(job_id, None)


async def _launch_scan(org_id: str, body: ScanIn, by: str, kind: str,
                 target_doc=None, retest_of: Optional[str] = None):
    credits_service.consume(org_id, kind)
    scan = store.insert("scans", {
        "org_id": org_id, "target": body.target,
        "kind": kind, "status": "running", "by": by,
        "mode": body.mode or (target_doc or {}).get("mode", "black_box"),
        "retest_of": retest_of,
    })
    _jobs[scan["id"]] = asyncio.create_task(
        _run(scan["id"], org_id, body, target_doc))
    return scan


@router.post("")
async def launch(body: ScanIn, user=Depends(require_role("admin", "analyst"))):
    target_doc = scope_service.assert_scannable(user["org_id"], body.target)
    kind = "exploit" if body.exploit else ("deep" if body.deep else "quick")
    if body.exploit and not credits_service.plan_allows(user["org_id"], "active_exploitation"):
        raise HTTPException(403, "L'exploitation active requiert le palier PME ou supérieur.")
    scan = await _launch_scan(user["org_id"], body, user["email"], kind, target_doc)
    return {"scan_id": scan["id"], "status": "running",
            "credits_left": credits_service.get_balance(user["org_id"])}


@router.post("/{scan_id}/retest")
async def retest(scan_id: str, user=Depends(require_role("admin", "analyst"))):
    """Relance le même test pour valider un correctif — réponse en minutes."""
    s = store.get("scans", scan_id)
    if not s or s["org_id"] != user["org_id"]:
        raise HTTPException(404, "Scan introuvable")
    if s["status"] != "done":
        raise HTTPException(409, "Le scan d'origine n'est pas terminé.")
    target_doc = scope_service.assert_scannable(user["org_id"], s["target"])
    body = ScanIn(target=s["target"], deep=s["kind"] != "quick",
                  exploit=s["kind"] == "exploit",
                  mode=s.get("mode"))
    scan = await _launch_scan(user["org_id"], body, user["email"], s["kind"],
                              target_doc, retest_of=scan_id)
    return {"scan_id": scan["id"], "retest_of": scan_id, "status": "running"}


@router.get("")
def list_scans(user=Depends(current_user)):
    return {"scans": store.find("scans", org_id=user["org_id"])}


@router.get("/{scan_id}")
def get_scan(scan_id: str, audience: Optional[str] = None,
             user=Depends(current_user)):
    s = store.get("scans", scan_id)
    if not s or s["org_id"] != user["org_id"]:
        raise HTTPException(404, "Scan introuvable")
    if audience and s.get("result", {}).get("report"):
        s = dict(s)
        s["result"] = dict(s["result"])
        s["result"]["report"] = audience_view(s["result"]["report"], audience)
    return s
