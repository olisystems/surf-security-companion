# SURF Security Companion

A KRITIS-grade Security Operations Centre (SOC) portal for the SURF energy-flexibility platform.
Centralised log visibility, 20 MITRE ATT&CK-mapped correlation rules (Sigma → Wazuh), case
management, safe-mode SOAR playbooks, NIS2/KRITIS/GDPR reporting, and cryptographic log
integrity (hourly signed Merkle rollups + WORM audit exports) — all behind Keycloak OIDC
with PKCE and WebAuthn/OTP MFA.

> **Version stamp:** July 2026 · **Status:** MVP (12-week scope) · See [COMPLIANCE.md](COMPLIANCE.md)
> for the NIS2 / KRITIS §8a / IEC 62443 controls matrix and Appendix A of the build prompt for
> deliberately deferred features. Implementation-level caveats and go-live prerequisites are
> tracked in [FUTURE_WORK.md](FUTURE_WORK.md).

## Verification status

Verified at build time (no Docker required):

| Check | Result |
|-------|--------|
| Backend `tsc --noEmit` | ✅ clean |
| Frontend `tsc --noEmit` + `vite build` | ✅ clean (Mermaid chunk-size advisory only) |
| Vitest unit + rule tests | ✅ 76 passing |
| All 20 Sigma rules: schema-valid, positive-match, negative-reject | ✅ pass |
| Sigma → Wazuh XML compile | ✅ pass |
| NIS2 `.docx` rendering (docxtemplater) | ✅ pass |

Verified live (July 2026):

| Check | Result |
|-------|--------|
| Full `docker compose up` — all services healthy | ✅ pass |
| Browser OIDC login (PKCE + OTP enrolment) as demo user | ✅ pass |
| Seed → correlation engine fires → alerts in OpenSearch & portal | ✅ pass |
| API auth end-to-end (JWT validated against Keycloak JWKS) | ✅ pass |

Still not run — see [FUTURE_WORK.md](FUTURE_WORK.md) §1: Testcontainers integration
tests and Playwright e2e. Both are wired into CI (`.github/workflows/ci.yml`).

---

## 1. Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Docker Engine + Compose v2 | ≥ 27.x | `docker compose version` |
| Node.js | 22 LTS | Only needed for local (non-container) dev & scripts |
| npm | ≥ 10 | Workspaces are used at the repo root |
| mkcert *(optional)* | latest | To mint locally-trusted TLS certs for `https://localhost` |

Linux hosts must raise `vm.max_map_count` for OpenSearch/Wazuh-indexer:

```bash
sudo sysctl -w vm.max_map_count=262144
```

Your **browser** must resolve `keycloak.local` (the OIDC issuer) to localhost. Add to
`/etc/hosts`:

```bash
echo "127.0.0.1 keycloak.local otel-collector.local" | sudo tee -a /etc/hosts
```

> **WSL2 users:** the browser runs on Windows, which does **not** read WSL's
> `/etc/hosts`. Also add the same line to `C:\Windows\System32\drivers\etc\hosts`
> (edit as Administrator, then `ipconfig /flushdns`).

## 2. Bootstrap

```bash
git clone <this repo> && cd surf-security-companion
cp .env.example .env                  # adjust passwords before anything non-local!
npm install                           # host tooling for seed/verify scripts
./scripts/gen-dev-certs.sh            # self-signed TLS for nginx + opensearch (dev only)
docker compose up -d --build
OPENSEARCH_URL=https://localhost:9200 npm run seed   # demo events so the 15 seeded scenarios (R-01…R-15) fire
```

First start takes a few minutes (Keycloak realm import, OpenSearch bootstrap, Sigma→Wazuh
compile, MinIO Object-Lock bucket creation, Grafana dashboard provisioning). Alerts appear
within ~60 s of seeding (correlation scheduler tick).

## 3. URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| SOC Portal (SPA) | https://localhost | demo users below |
| Backend API / OpenAPI | https://localhost/api/docs | JWT via portal login |
| Keycloak admin | https://localhost:8443/admin | `admin` / `.env: KC_ADMIN_PASSWORD` |
| OpenSearch Dashboards | https://localhost:5601 | `admin` / `.env: OPENSEARCH_PASSWORD` |
| MinIO console | http://localhost:9001 | `.env: MINIO_ACCESS_KEY/SECRET_KEY` |
| Grafana | http://localhost:3000 | `admin` / `.env: GRAFANA_ADMIN_PASSWORD` |
| Prometheus | http://localhost:9090 | — |

## 4. Logging in

The dev stack uses self-signed certificates, so the browser needs a one-time cert
exception for **both** origins (exceptions are stored per hostname):

1. Open **https://keycloak.local** → *Advanced* → *Proceed* (accepts the cert; any page
   content is fine).
2. Open **https://localhost** → accept the cert warning → click **Sign in**.
3. Log in with a demo user (below). All demo passwords are **`Surf-Demo-2026!`**.
4. **First login** forces MFA enrolment: scan the QR code with any TOTP authenticator app
   (Google Authenticator, Microsoft Authenticator, Authy, 1Password…) and enter the
   6-digit code. WebAuthn (passkey/security key) is offered as an alternative.
5. You land on the SOC dashboard; if you ran the seed, alerts are already waiting.

### Demo users, roles & tenants

Imported from [`keycloak/realm-export.json`](keycloak/realm-export.json) (realm `surf-security`).

| User | Password | Role | Tenant |
|------|----------|------|--------|
| `anna.analyst` | `Surf-Demo-2026!` | `SOC_ANALYST` | — (all tenants) |
| `dirk.dso` | `Surf-Demo-2026!` | `DSO_OPERATOR` | `vnb-saar` |
| `petra.platform` | `Surf-Demo-2026!` | `PLATFORM_ADMIN` | — |
| `axel.admin2` | `Surf-Demo-2026!` | `PLATFORM_ADMIN` | — (second approver for four-eyes) |
| `auditor.alice` | `Surf-Demo-2026!` | `AUDITOR` | — (read-only, cross-tenant) |
| `emil.exec` | `Surf-Demo-2026!` | `EXECUTIVE_OBSERVER` | `vnb-saar` |

Tenants seeded: `vnb-saar`, `vnb-pfalz`.

Infrastructure console credentials (Keycloak admin, Grafana, OpenSearch Dashboards,
MinIO) are listed in the URL table in §3 — the dev defaults come from `.env.example`.

## 5. Writing & testing a new Sigma rule

1. Copy an existing rule from [`rules/`](rules/) — every rule must carry `id`, `title`,
   `description`, `author`, `date`, `references`, `level`, `tags` (with `attack.*`),
   `surf.threat_id`, `surf.compliance`, `detection`, `falsepositives`, `owner`.
2. Validate against the schema: `npm run rules:validate` (AJV vs [`rules/schema/sigma-surf.json`](rules/schema/sigma-surf.json)).
3. Add **one positive and one negative fixture** under
   `backend/test/fixtures/events/<rule-id>/` (`positive.json`, `negative.json`).
4. Run fixture tests: `npm run test:rules`. CI fails if a rule misses its positive fixture
   or matches its negative one.
5. `scripts/convert-sigma.ts` compiles Sigma → Wazuh XML at container start; check the
   output with `npm run rules:convert -- --dry-run`.

Full guide: [`docs/RULE_AUTHORING.md`](docs/RULE_AUTHORING.md).

## 6. Running tests

```bash
npm run test              # Vitest unit tests (backend + frontend)
npm run test:integration  # Vitest + Testcontainers (needs Docker)
npm run test:rules        # Sigma fixture tests
npm run test:e2e          # Playwright against the compose stack
```

## 7. Verifying the hash chain

```bash
npm run verify:hashchain -- --from 2026-07-01T00:00Z --to 2026-07-14T00:00Z
```

Recomputes Merkle roots from OpenSearch, checks Ed25519 signatures and `prevRoot`
linkage against the Postgres `hashchain_ledger` and the MinIO WORM copies. The same
verification is exposed to `PLATFORM_ADMIN`/`AUDITOR` at `GET /api/admin/hashchain/verify`.

## 8. Compliance mapping

Every detection rule and platform control maps to **NIS2 Art. 21**, **IEC 62443-3-3**,
**KRITIS §8a BSIG** and **ISO 27001 Annex A** in
[`backend/src/compliance/controlsMatrix.json`](backend/src/compliance/controlsMatrix.json),
rendered to [COMPLIANCE.md](COMPLIANCE.md) at build time (`npm run compliance:render`).

## 9. Repository layout

See the build prompt §2; summary:

- `frontend/` — React 19 + Vite SPA (TanStack, shadcn/ui, oidc-client-ts)
- `backend/` — Fastify 5, Clean Architecture (`domain/ application/ infrastructure/`)
- `rules/` — **source of truth** Sigma rules (compiled to Wazuh at deploy)
- `keycloak/`, `nginx/`, `deploy/helm/` — identity, edge, Kubernetes skeleton
- `runbooks/` — eight operational scenarios (see [RUNBOOKS.md](RUNBOOKS.md))
- `scripts/` — seed, hash-chain verify, Sigma converter, purple-team artefacts
- `docs/` — architecture, data model, authoring guides, secrets migration, observability

## 10. Operations

- Dashboards: import ships automatically; source JSON at `docs/grafana-soc-dashboard.json`.
- Runbooks index: [RUNBOOKS.md](RUNBOOKS.md).
- Coordinated disclosure: [SECURITY.md](SECURITY.md).
- Secrets: `.env` in dev; Vault migration path in [`docs/SECRETS.md`](docs/SECRETS.md).
- Go-live prerequisites & known caveats: [FUTURE_WORK.md](FUTURE_WORK.md).

## 11. Dev-stack troubleshooting

Hard-won notes from getting the compose stack running (July 2026):

- **Changed a `VITE_*` value in `.env`?** It is baked into the SPA at image *build*
  time (compose passes them as build args) — run `docker compose build frontend &&
  docker compose up -d frontend`, then hard-refresh the browser (Ctrl+Shift+R).
- **Edited `nginx/nginx.conf` (or any single-file bind mount)?** The edit replaces the
  file's inode, which the running container does not see. `nginx -s reload` is not
  enough — run `docker compose up -d --force-recreate nginx`.
- **Sign-in button does nothing / `Failed to fetch`?** The browser cannot reach
  `https://keycloak.local` — check the hosts entry (on *Windows* for WSL2 users) and
  accept the cert exception for that origin (step 1 of §4).
- **All API calls return 401 after login?** Check `docker compose logs backend` for
  `jwt verification failed`. The JWKS URI must stay on the internal HTTP endpoint
  (`http://keycloak:8080/...`) — Node's `fetch` does not honor `NODE_EXTRA_CA_CERTS`
  for the self-signed nginx cert.
- **Keycloak realm changes** (in `keycloak/realm-export.json`) only import into an
  empty database: `docker compose stop keycloak && docker volume rm
  surf-security-companion_keycloak-data && docker compose up -d keycloak`. This wipes
  demo users' MFA enrolments.
- **`invalid_scope` at login?** The realm export must define the standard client
  scopes (`profile`, `roles`, …) explicitly — Keycloak suppresses its built-ins when
  an explicit `clientScopes` list is present. They are included in the shipped export.
- **Wazuh config missing / API not starting?** Never mount anything under
  `/var/ossec/etc` directly; deliver files via Wazuh's `/wazuh-config-mount/...`
  mechanism (see the `compiled-rules` mount in `docker-compose.yml`) or the
  entrypoint skips restoring its default configuration.
- **Postgres crash-loops with `initdb: directory exists but is not empty`?** A volume
  is mounted *inside* `PGDATA`; keep `PGDATA` pointed at a subdirectory
  (`/var/lib/postgresql/data/pgdata`) as configured in `docker-compose.yml`.
