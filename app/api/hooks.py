# SPDX-License-Identifier: MIT
"""Webhook CI/CD : un événement de déploiement déclenche un scan ciblé
sur une cible vérifiée — ex: GitHub Actions / GitLab CI appellent
POST /api/hooks/deploy {"target_id": "...", "event": "merge", "ref": "main"}
avec le header Authorization: Bearer <token>.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.auth import current_user
from app.services import store
from app.api.scans import _launch_scan, ScanIn
from app.services import scope_service

router = APIRouter(prefix="/api/hooks", tags=["ci-cd"])


class DeployEvent(BaseModel):
    target_id: str
    event: str = "deploy"     # merge | deploy | pull_request
    ref: str = ""
    commit: str = ""


@router.post("/deploy")
async def deploy_hook(body: DeployEvent, user=Depends(current_user)):
    t = store.get("targets", body.target_id)
    if not t or t["org_id"] != user["org_id"]:
        raise HTTPException(404, "Cible introuvable")
    if not t.get("verified"):
        raise HTTPException(403, "Cible non vérifiée — aucun scan possible.")
    scan = await _launch_scan(
        user["org_id"],
        ScanIn(target=t["target"], deep=False, mode=t.get("mode")),
        f"webhook:{body.event}@{body.ref or '-'}",
        "quick", t,
    )
    return {
        "scan_id": scan["id"], "status": "running",
        "trigger": f"{body.event} sur {body.ref}",
        "note": "Le résultat peut bloquer le merge : GET /api/scans/{id} "
                "et vérifier report.risk_level.",
    }
