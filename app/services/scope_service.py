# SPDX-License-Identifier: MIT
"""Gestion du scope autorisé — le « kill switch » recommandé :

Une cible ne peut être scannée que si elle est déclarée dans le scope de
l'organisation ET vérifiée : le client dépose un token à
/.well-known/ptaas-verify.txt sur le domaine, OU un admin confirme
manuellement une autorisation écrite (référence du document).
"""
import secrets
from typing import Dict, Any
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException

from app.services import store

VERIFY_PATH = "/.well-known/ptaas-verify.txt"


def _domain(url_or_domain: str) -> str:
    u = url_or_domain.strip().lower()
    if "://" in u:
        return urlparse(u).netloc.split(":")[0]
    return u.split("/")[0].split(":")[0]


def declare_target(org_id: str, target: str, authorization_ref: str = "") -> Dict[str, Any]:
    """Déclare une cible et génère son token de vérification."""
    token = "ptaas-" + secrets.token_hex(16)
    doc = store.insert("targets", {
        "org_id": org_id, "target": target, "domain": _domain(target),
        "verify_token": token, "verified": False,
        "authorization_ref": authorization_ref,  # ex: n° de contrat / mandat
    })
    return doc


async def verify_target(org_id: str, target_id: str) -> Dict[str, Any]:
    """Vérifie que le token est hébergé sur la cible."""
    t = store.get("targets", target_id)
    if not t or t["org_id"] != org_id:
        raise HTTPException(404, "Cible introuvable")
    url = f"https://{t['domain']}{VERIFY_PATH}"
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
            r = await c.get(url)
            if r.status_code != 200 or t["verify_token"] not in r.text:
                url = f"http://{t['domain']}{VERIFY_PATH}"
                r = await c.get(url)
                ok = r.status_code == 200 and t["verify_token"] in r.text
            else:
                ok = True
    except Exception:
        ok = False
    if ok:
        store.update("targets", target_id, {"verified": True, "verified_via": "token_file"})
    return {"verified": ok, "check_url": url}


def admin_verify(target_id: str, authorization_ref: str) -> Dict[str, Any]:
    """Vérification manuelle par un admin (autorisation écrite fournie)."""
    if not authorization_ref:
        raise HTTPException(400, "Référence d'autorisation écrite requise (contrat/mandat).")
    t = store.update("targets", target_id,
                     {"verified": True, "verified_via": "manual",
                      "authorization_ref": authorization_ref})
    if not t:
        raise HTTPException(404, "Cible introuvable")
    return t


def assert_scannable(org_id: str, target: str) -> Dict[str, Any]:
    """Bloque tout scan sur une cible non vérifiée."""
    dom = _domain(target)
    for t in store.find("targets", org_id=org_id):
        if t["verified"] and (t["domain"] == dom or dom.endswith("." + t["domain"])):
            return t
    raise HTTPException(
        403,
        "Cible hors du scope vérifié : déclarez-la (POST /api/targets), "
        "déposez le token à /.well-known/ptaas-verify.txt, puis "
        "POST /api/targets/{id}/verify — ou faites valider une autorisation "
        "écrite par un admin.",
    )
