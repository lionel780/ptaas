# SPDX-License-Identifier: MIT
from fastapi import FastAPI

import asyncio
from datetime import datetime, timezone

from app.api import auth, targets, scans, billing, hooks, capabilities

app = FastAPI(
    title="PTaaS — Pentest as a Service",
    description=(
        "Plateforme de validation de sécurité continue : scans autorisés, "
        "preuve d'exploitabilité, rapports NIS2 / ISO 27001 / DORA.\n\n"
        "Toute cible doit être vérifiée (token /.well-known/ptaas-verify.txt "
        "ou autorisation écrite validée par un admin) avant le moindre scan."
    ),
)

app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(billing.router)
app.include_router(hooks.router)
app.include_router(capabilities.router)


async def _continuous_validation():
    """Validation continue : re-scanne les cibles vérifiées dont
    interval_hours est écoulé depuis last_scan_at."""
    from app.services import store
    from app.api.scans import _launch_scan, ScanIn
    while True:
        await asyncio.sleep(300)
        for t in store.all_docs("targets"):
            if not t.get("verified") or not t.get("interval_hours"):
                continue
            last = t.get("last_scan_at")
            due = True
            if last:
                try:
                    dt = datetime.fromisoformat(last)
                    due = (datetime.now(timezone.utc) - dt).total_seconds() \
                        >= t["interval_hours"] * 3600
                except ValueError:
                    due = True
            if due:
                try:
                    await _launch_scan(t["org_id"], ScanIn(target=t["target"],
                                                     mode=t.get("mode")),
                                 "scheduler", "quick", t)
                except Exception:
                    pass


@app.on_event("startup")
async def startup():
    asyncio.create_task(_continuous_validation())


@app.get("/api/health")
def health():
    return {"status": "ok"}
