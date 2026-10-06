# Deploy: security.surf.saarland (SURF VPS2)

Prod-Betrieb des Security-Companion auf dem dedizierten VPS2 (178.105.200.25,
Ubuntu 26.04, 15 GB RAM). Stand 2026-08-14.

## Architektur-Abweichungen vom Dev-Setup

| Dev (Upstream) | Prod (dieses Overlay) |
|---|---|
| nginx published 80/443 mit Self-Signed-Cert | **Caddy** terminiert öffentliches TLS (ACME/LE), proxyt intern zu nginx (Self-Signed bleibt intern) |
| Bundled Keycloak (start-dev, H2) | **auth.surf.saarland**, Realm `surf-security` (Import via kcadm auf dem SURF-VPS-Keycloak; KC26: `surf_tenant_id` erst im User Profile deklarieren!) |
| 9200/5601/1514/9000/4317/9090/3000 öffentlich | **Keine** published Ports außer Caddy 80/443. Docker umgeht ufw — nicht-publishen ist der echte Schutz. |

## Deploy

```bash
cd /opt/soc && git pull
# .env pflegen (einmalig; NIE committen): Secrets frisch generieren,
# OIDC_ISSUER_URL/VITE_OIDC_ISSUER_URL/OIDC_JWKS_URI auf
# https://auth.surf.saarland/realms/surf-security, VITE_API_BASE=/api,
# FLEX/EMS/PAGERDUTY-Pflichtfelder: Platzhalter bis zur echten Anbindung
# (PLAYBOOK_DRY_RUN_DEFAULT=true lassen!).
./scripts/gen-dev-certs.sh              # interne nginx-Certs (einmalig)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

⚠ `VITE_*`-Variablen sind Build-Zeit: nach Änderung `... build frontend` nötig.
⚠ **Nach jedem Recreate von `backend` oder `frontend`: `... restart nginx`** — nginx
löst die `upstream`-Hostnamen nur beim Start auf; ein neuer Container = neue IP =
nginx-502 bei intaktem Backend (Caddy selbst dialt per Request, braucht keinen Restart).
⚠ Bootstrap (Realm/OpenSearch/MinIO/Sigma) greift nur auf leeren Volumes —
Fehlkonfiguration ⇒ `down -v` und neu.

## Verifikation

- `https://security.surf.saarland/healthz` → 200 (über Caddy+nginx)
- Login-Redirect zeigt auf auth.surf.saarland
- **Negativ-Checks** (müssen ALLE fehlschlagen): von extern Port 9200, 5601,
  9000, 9001, 3000, 9090, 4317, 1514 auf 178.105.200.25
- Seed + Regeln: `npm run seed` (siehe README) → Alerts nach ~60 s

## Später (Log-Shipper-Phase)

OpenSearch 9200 wird dann gezielt re-exponiert — nur für 178.104.103.16
(SURF-VPS), via zusätzlichem Overlay-Eintrag + ufw-Regel. Nicht vorher.

## SOC Phase 2b — WireGuard + Wazuh-Agent (2026-10-05)

- `wg-quick@wg0` (10.44.0.1/24, UDP 51820, ufw nur von 178.104.103.16) muss **vor** dem Stack
  laufen: `systemctl enable --now wg-quick@wg0`. Der Manager publisht 1514/1515 nur auf 10.44.0.1
  (`docker-compose.prod.yml`); solange die Adresse fehlt, startet Docker den Container neu.
- Nach `git pull`: `up -d --build --no-deps wazuh-manager vector` (agent.conf-Mount + Mirror),
  dann `agent_control -l` prüfen. Details: `docs/WAZUH_AGENT.md`.
