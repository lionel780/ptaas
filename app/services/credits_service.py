"""Modèle par crédits : plans (startup/pme/enterprise) + consommation par scan.

1 crédit = 1 scan rapide ; scan profond = 3 crédits ; exploitation active = 5.
"""
from typing import Dict, Any

from fastapi import HTTPException

from app.services import store

PLANS = {
    "startup": {"price_eur": 300, "credits_month": 10, "deep_scan": True,
                "active_exploitation": False, "retests": True},
    "pme": {"price_eur": 2000, "credits_month": 50, "deep_scan": True,
            "active_exploitation": True, "compliance_reports": True},
    "enterprise": {"price_eur": None, "credits_month": -1, "deep_scan": True,
                   "active_exploitation": True, "compliance_reports": True,
                   "multi_users": True, "sla": True},
}

COSTS = {"quick": 1, "deep": 3, "exploit": 5}


def ensure_org(org_id: str, plan: str = "startup") -> Dict[str, Any]:
    org = store.get("orgs", org_id)
    if not org:
        org = store.insert("orgs", {
            "id": org_id, "plan": plan,
            "credits": PLANS[plan]["credits_month"],
        })
    return org


def get_balance(org_id: str) -> int:
    return ensure_org(org_id).get("credits", 0)


def consume(org_id: str, kind: str) -> int:
    """Débite les crédits d'un scan ; -1 = illimité."""
    org = ensure_org(org_id)
    plan = PLANS.get(org.get("plan", "startup"), PLANS["startup"])
    if plan["credits_month"] == -1:
        return -1
    cost = COSTS[kind]
    if org.get("credits", 0) < cost:
        raise HTTPException(
            402, f"Crédits insuffisants ({org.get('credits', 0)} restants, {cost} requis). "
                 "Passez au palier supérieur ou rechargez des crédits."
        )
    org = store.update("orgs", org_id, {"credits": org["credits"] - cost})
    return org["credits"]


def recharge(org_id: str, credits: int) -> int:
    org = ensure_org(org_id)
    org = store.update("orgs", org_id, {"credits": org.get("credits", 0) + credits})
    return org["credits"]


def plan_allows(org_id: str, feature: str) -> bool:
    org = ensure_org(org_id)
    return bool(PLANS.get(org.get("plan", "startup"), {}).get(feature))
