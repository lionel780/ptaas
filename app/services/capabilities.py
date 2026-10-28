# SPDX-License-Identifier: MIT
"""Catalogue des capacités de la plateforme : types d'assets, méthodologies,
modes de test et périmètre d'exclusion — affiché via GET /api/capabilities."""

ASSET_TYPES = {
    "web": {
        "label": "Application web",
        "references": ["OWASP Top 10", "OWASP WSTG"],
        "checks": "headers, TLS, méthodes, chemins sensibles, XSS, SQLi, logique d'accès",
    },
    "api": {
        "label": "API",
        "references": ["OWASP API Security Top 10"],
        "checks": "BOLA/IDOR, rate limiting, validation de schéma, auth",
    },
    "mobile": {
        "label": "Application mobile (iOS/Android)",
        "references": ["OWASP MASVS", "OWASP MASTG"],
        "checks": "stockage local, transport, code client",
    },
    "desktop": {
        "label": "Application de bureau",
        "references": ["OWASP ASVS"],
        "checks": "comms réseau, secrets en dur, DLL hijacking",
    },
    "network": {
        "label": "Infrastructure réseau",
        "references": ["PTES", "NIST SP 800-115"],
        "checks": "ports, services, SSL/TLS, segmentation",
    },
    "cloud": {
        "label": "Configuration cloud (AWS/GCP/Azure)",
        "references": ["CIS Benchmarks"],
        "checks": "IAM, ressources exposées, IaC",
    },
    "llm": {
        "label": "Application IA / LLM",
        "references": ["OWASP Top 10 LLM", "MITRE ATLAS"],
        "checks": "injection de prompt, fuite de données, agence excessive",
    },
}

METHODOLOGIES = [
    "OWASP WSTG", "OWASP MASTG", "OWASP API Security Top 10",
    "OWASP Top 10 LLM", "PTES", "NIST SP 800-115", "MITRE ATT&CK",
]

MODES = {
    "black_box": "Aucune information — simulation d'un attaquant externe",
    "grey_box": "Informations partielles — logique authentifiée testable",
    "white_box": "Accès au code et à l'architecture — revue en profondeur",
}

AUDIENCES = {
    "developer": "Détails techniques, PoC et étapes de reproduction",
    "ciso": "Niveau de risque, criticités, plan de remédiation, conformité",
    "auditor": "Mapping NIS2/ISO27001/DORA, preuves, horizon temporel",
}

EXCLUSIONS = [
    "Tests DoS/DDoS non contrôlés",
    "Audit de la sécurité intrinsèque des bibliothèques tierces",
    "Ingénierie sociale / phishing",
    "Accès physique aux locaux",
    "Cibles non vérifiées (voir ETHICS.md)",
]
