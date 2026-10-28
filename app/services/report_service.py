"""Rapports de pentest prêts pour l'audit : sévérité, exploitabilité,
remédiation priorisée, mapping NIS2 / ISO 27001 / DORA.
LLM optionnel (OPENAI_*) ; sinon rapport structuré automatique.
"""
import json
from typing import Dict, Any, List

import httpx

from app.core.config import settings

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

COMPLIANCE_MAP = {
    "missing_header": {"nis2": "Art.21 mesures de gestion du risque",
                       "iso": "A.8.22 Segmentation / A.8.24 Chiffrement",
                       "dora": "Art.9 protection et prévention"},
    "dangerous_methods": {"nis2": "Art.21", "iso": "A.8.9 Gestion de la config",
                          "dora": "Art.9"},
    "sensitive_path": {"nis2": "Art.21", "iso": "A.8.15 Contrôle d'accès",
                       "dora": "Art.9/Art.10"},
    "no_tls": {"nis2": "Art.21 chiffrement", "iso": "A.8.24",
               "dora": "Art.9"},
    "weak_tls": {"nis2": "Art.21", "iso": "A.8.24", "dora": "Art.9"},
    "xss_reflected": {"nis2": "Art.21", "iso": "A.8.26 Sécurité applicative",
                      "dora": "Art.9"},
    "sqli_error": {"nis2": "Art.21", "iso": "A.8.26", "dora": "Art.9"},
    "sqli_confirmed": {"nis2": "Art.21", "iso": "A.8.26", "dora": "Art.9/12"},
    "info_disclosure": {"nis2": "Art.21", "iso": "A.8.9", "dora": "Art.9"},
    "nmap": {"nis2": "Art.21", "iso": "A.8.8 Gestion des vulnérabilités",
             "dora": "Art.9"},
}


def _by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    return {s: sum(1 for f in findings if f["severity"] == s)
            for s in SEVERITY_ORDER}


def _risk_level(counts: Dict[str, int]) -> str:
    if counts["critical"]:
        return "CRITIQUE"
    if counts["high"]:
        return "ÉLEVÉ"
    if counts["medium"]:
        return "MODÉRÉ"
    return "FAIBLE"


def build_report(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Rapport structuré prêt pour l'audit, même sans LLM."""
    findings = scan.get("findings", [])
    counts = _by_severity(findings)
    table = []
    for i, f in enumerate(findings, 1):
        comp = COMPLIANCE_MAP.get(f["type"], {})
        table.append({
            "n": i,
            "type": f["type"],
            "severite": f["severity"],
            "titre": f["title"],
            "cwe": f.get("cwe", "—"),
            "exploitabilite": f.get("exploitability",
                                    "prouvée" if f["type"] == "sqli_confirmed"
                                    else "à valider"),
            "nis2": comp.get("nis2", "—"),
            "iso27001": comp.get("iso", "—"),
            "dora": comp.get("dora", "—"),
            "detail": f.get("detail", ""),
        })
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    priorities = sorted(findings, key=lambda f: order.get(f["severity"], 9))
    return {
        "target": scan.get("target"),
        "risk_level": _risk_level(counts),
        "counts": counts,
        "executive_summary": (
            f"{len(findings)} vulnérabilités détectées sur {scan.get('target')} : "
            f"{counts['critical']} critiques, {counts['high']} hautes, "
            f"{counts['medium']} moyennes. Niveau de risque global : "
            f"{_risk_level(counts)}."
        ),
        "findings_table": table,
        "remediation_plan": [
            f"{i}. [{f['severity'].upper()}] {f['title']} — {f.get('detail', '')}"
            for i, f in enumerate(priorities[:10], 1)
        ],
        "compliance_note": (
            "Ce rapport couvre les exigences de gestion des vulnérabilités "
            "NIS2 (art. 21), ISO 27001 (A.8) et DORA (art. 9-12) : il peut être "
            "joint à un dossier d'audit."
        ),
    }


async def llm_report(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Version LLM si OPENAI_API_KEY est configurée, sinon rapport auto."""
    if not settings.openai_api_key:
        return build_report(scan)
    prompt = (
        "Tu es un pentester senior. Rédige un rapport de pentest en français "
        "en JSON strict avec les clés : executive_summary, risk_level, "
        "findings (liste: type, severite, titre, cwe, prerequis_exploitation, "
        "scenario_attaque, impact_metier, probabilite, remediation), "
        "remediation_plan, compliance_note (NIS2, ISO27001, DORA). "
        f"Données du scan : {json.dumps(scan)[:8000]}"
    )
    try:
        async with httpx.AsyncClient(timeout=120.0) as c:
            r = await c.post(
                f"{settings.openai_base_url}/chat/completions",
                headers={"Authorization": f"Bearer {settings.openai_api_key}"},
                json={"model": settings.openai_model,
                      "messages": [{"role": "user", "content": prompt}],
                      "response_format": {"type": "json_object"}},
            )
            text = r.json()["choices"][0]["message"]["content"]
            return json.loads(text)
    except Exception:
        return build_report(scan)
