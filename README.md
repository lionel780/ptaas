# PTaaS — Pentest as a Service

Plateforme de validation de sécurité continue : scans autorisés, **preuve
d'exploitabilité**, rapports prêts pour l'audit (NIS2, ISO 27001, DORA).

## Démarrage

```bash
cd ptaas
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --port 8090
```

`.env` optionnel : `SECRET_KEY`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`,
`OPENAI_MODEL` (rapports IA).

## Flux

1. `POST /api/auth/register` — organisation + premier utilisateur (admin)
2. `POST /api/targets` — déclare une cible → token `ptaas-...`
3. Vérification : déposer le token à `/.well-known/ptaas-verify.txt` sur la
   cible puis `POST /api/targets/{id}/verify`, **ou** validation admin avec
   référence d'autorisation écrite (`/admin-verify`)
4. `POST /api/scans {"target","deep","exploit","report"}` — scan en tâche de fond
5. `GET /api/scans/{id}` — résultat + rapport de remédiation priorisé

## Modèle par crédits

| Palier | Prix indicatif | Crédits/mois | Exploitation active |
|---|---|---|---|
| startup | ~300 € | 10 | non |
| pme | ~2 000 € | 50 | oui |
| enterprise | sur devis | illimité | oui + multi-users + SLA |

Coûts : scan rapide = 1 crédit, profond = 3, exploitation (sqlmap) = 5.
`POST /api/billing/recharge` (admin) pour recharger.

## Garde-fou juridique

- **Aucun scan sur une cible non vérifiée** (`assert_scannable`) — le kill
  switch technique recommandé.
- Chaque cible conserve `authorization_ref` (n° de contrat / mandat écrit).
- À compléter avant tout client : CGU interdisant les scans non autorisés,
  clause de non-responsabilité, assurance RC Pro.

## Outils externes (deep/exploit)

Détectés automatiquement : `nmap`, `nikto`, `sqlmap`, `zap-baseline`.
