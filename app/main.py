from fastapi import FastAPI

from app.api import auth, targets, scans, billing

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


@app.get("/api/health")
def health():
    return {"status": "ok"}
