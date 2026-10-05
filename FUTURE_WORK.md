# Future Work & Known Caveats

Items flagged during the initial build that are intentionally deferred, need production
hardening, or are worth a maintainer's attention before go-live. This is distinct from
**Appendix A** of the build prompt (strategic v1/v2 enhancements like AI copilots, Temporal,
OpenFGA) — these are implementation-level notes about *this* codebase.

## 1. Verification not yet run in this environment

The following were written and wired into CI but require a Docker daemon / live services and
were **not** executed during the initial build:

- **Integration tests** (`backend/test/integration`, Testcontainers Postgres) — verify the
  repository SQL, the append-only audit hash-chain trigger, and tenant-filtered reads.
  Run: `npm run test:integration` (needs Docker).
- **Playwright e2e** (`e2e/acceptance.spec.ts`) — the full DoD flow (login → case → NIS2 →
  playbook dry-run → real mass action → four-eyes approval → tenant isolation).
  Run: `docker compose up -d && npm run seed && npm run test:e2e`.
- **`docker compose up`** end-to-end — first boot exercises Keycloak realm import, OpenSearch
  bootstrap, Sigma→Wazuh compile, MinIO Object-Lock bucket creation, and Grafana provisioning.

**Action:** run all three on a machine with Docker before the first stakeholder demo, and let
CI (`.github/workflows/ci.yml`) gate them on every PR thereafter.

## 2. TypeScript `exactOptionalPropertyTypes`

This flag is **off** (every other strict check, including `noUncheckedIndexedAccess`, is on).
It collides pervasively with Zod's `.optional()`, which yields `T | undefined` and cannot be
assigned to an `exactOptionalPropertyTypes` target without conditional spreads at every call
site.

**Trade-off:** turning it back on buys stricter optional-property semantics at the cost of
`...(x !== undefined ? { x } : {})` boilerplate throughout the route and service layers.
**Action:** revisit if the team wants the stricter guarantee; it is a mechanical (if noisy)
change, best done in one pass.

## 3. NIS2 `.docx` templates are minimal placeholders

The three templates in `backend/src/compliance/nis2Templates/*.docx` are valid OOXML with the
correct docxtemplater tags (verified rendering, including the `{#actions}` loop), but they carry
**no official NIS2 layout, branding, or legal boilerplate**.

**Action:** replace them with the authority-approved report layouts. The render pipeline,
WORM storage, hash receipt, and audit-ledger chaining are complete and do not need to change —
only the template documents.

## 4. MFA enrolment on first login

The Keycloak realm seeds demo users with `CONFIGURE_TOTP` as a required action, so the **first**
login for each user forces authenticator enrolment before reaching the portal. This satisfies
the MFA requirement but can surprise a first-time demo operator.

**Action:** pre-enrol OTP for demo accounts (and inject the secret into
`E2E_OTP_<USER>` for Playwright), or brief demo operators that the first login includes an
enrolment step. WebAuthn is the intended primary factor in production; OTP is the scriptable
fallback used by e2e.

## 5. Hash-chain signing key is a soft key (MVP)

`FileEd25519Signer` reads a hex private key from disk (`HASHCHAIN_SIGNING_KEY_PATH`). This is
acceptable for dev/MVP only.

**Status (2026-07-16):** a production `Signer` is now shipped —
[`VaultTransitSigner`](backend/src/infrastructure/integrations/vaultTransitSigner.ts) keeps the
Ed25519 key inside HashiCorp Vault's Transit engine (the backend only asks Vault to sign; the
private key never leaves Vault). Selected via `HASHCHAIN_SIGNER=vault`
([`config.ts`](backend/src/infrastructure/config.ts) validates the Vault env; bound in
[`main.ts`](backend/src/main.ts)). Verification is a **local** public-key operation, so an
external auditor verifies tamper-evidence with the published public key alone — no Vault access
or signing token. The ledger `sig` format (raw Ed25519 hex) is unchanged, so soft-key rollups
stay verifiable after cut-over. Covered by
[`vaultTransitSigner.test.ts`](backend/test/unit/vaultTransitSigner.test.ts) (5 tests); env
contract, operator setup, and per-role Vault policies are in
[`docs/SECRETS.md`](docs/SECRETS.md).

**Residual:** the default (`HASHCHAIN_SIGNER=file`) is still the soft key, so production must set
`HASHCHAIN_SIGNER=vault` (or supply an HSM/PKCS#11 adapter if a hardware module is mandated).
Transit key rotation is handled: `verify()` checks a signature against **every** non-archived key
version's public key, so historical rollups stay verifiable after a rotate (covered by
`vaultTransitSigner.test.ts`). If an old version is archived/deleted in Vault below
`min_decryption_version`, its rollups can only be verified against a separately-published
public key.

## 6. Correlation scheduler vs. Wazuh — shared roster, two evaluators

The portal's in-process `CorrelationScheduler` and the compiled Wazuh ruleset both derive from
the same Sigma source, but they are **separate evaluators**. The portal evaluator implements a
deliberate subset of the Sigma condition grammar (documented in
[`docs/RULE_AUTHORING.md`](docs/RULE_AUTHORING.md)).

**Status (2026-07-16):** a conformance gate now diffs the two evaluators —
[`backend/test/rules/conformance.test.ts`](backend/test/rules/conformance.test.ts) compiles every
rule with the real `convert-sigma` converter and asserts, per rule, that the portal and Wazuh
verdicts agree. **All 20 rules are now conformant** — the divergence map is empty.

**All four structural gaps closed 2026-07-16:**
- **R-04 / R-08 / R-13** — `filter_*` negations were dropped at compile time. The converter now
  emits single-field `not filter_x` selections as Wazuh `negate="yes"` fields, so the exclusion
  runs at the sensor; their negative fixtures (admin cross-tenant / emergency-declared /
  in-change-window) prove Wazuh now suppresses them. A *multi-field* filter is
  `NOT(f1 and f2) = (not f1) or (not f2)`, inexpressible in one Wazuh rule — those (none in the
  current roster) stay portal-enforced.
- **R-11** — `>=` boundary off-by-one. The converter emitted `frequency = threshold+1` for both
  `>` and `>=`; it now emits `N` for `>= N` and `N+1` for `> N`. Boundary test: both fire at 10,
  both silent at 9.
- **R-03** — the `(sel_a | count()...) and sel_b` conjunction was reduced to the frequency of
  sel_a alone. The converter now emits a **composite**: a silent (`level="0"`) frequency
  precondition on sel_a plus a correlated rule triggered by sel_b via `<if_matched_sid>`. Tests
  pin both directions (reject-burst alone stays silent; burst + success fires).

If the compiler changes, the pinned assertions break. The gate runs in CI via
`npm run test -w backend` (it covers `test/unit` **and** `test/rules`).

**Residual (detection quality, not a conformance gap):** R-03's conjunction is *cross-entity* on
both sides — the portal fires on any success in the window, and the composite mirrors that (no
`<same_field>` on the correlated rule). Tightening both to same-`user.name` (an attacker's own
success after their own MFA burst) would be a stricter, better detection; do it in lockstep so the
two evaluators stay conformant.

## 7. Frontend bundle size

`vite build` emits a chunk-size advisory driven by **Mermaid** (~600 kB). It is already
lazy-chunked via `manualChunks`, so it does not block first paint of the SOC views.

**Action:** if first-load budget matters, dynamically `import()` `MermaidDiagram` so the Mermaid
chunk loads only when a case-flow diagram is actually rendered.

## 8. Rate limiting is per-instance

`@fastify/rate-limit` uses an in-memory store, so limits are per backend replica. With
`replicaCount.backend > 1` (Helm default is 2), effective limits are multiplied by the replica
count.

**Action:** for production, back the rate limiter with a shared Redis store so limits are
cluster-wide, especially on the login-adjacent and playbook endpoints.

## 9. Ingestion path is seed-driven in the MVP

`scripts/seed.ts` pushes representative events directly into OpenSearch so the 15 seeded
scenarios (R-01…R-15) fire.
Real log shippers (Keycloak events, API-gateway access logs, MQTT broker, K8s audit, Hetzner
syslog) are expected to feed `surf-events-*` in the same ECS + `surf.*` shape; only the pgaudit
promtail collector is wired in compose.

**Action:** stand up the remaining source-specific shippers/decoders and confirm each maps to
the normalisation schema in [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md). The `surf.enrichment.*`
booleans (impossible-travel, cross-tenant, firmware-downgrade, change-window, ip-allowlist) are
computed by the `Enricher` at the **correlation read/eval boundary** (`CorrelationScheduler`
enriches each window before evaluation), so they are derived from whatever shippers land in
`surf-events-*` without requiring a shipper to compute them. `enrich()` is idempotent, so if a
future write-side ingest path bakes the flags in, the read-side pass leaves them untouched.

**Status (2026-10-05):** a real write path exists — `POST /ingest/events`
([`docs/INGEST.md`](docs/INGEST.md): static token, nested→dotted normalisation, per-item
validation, `surf.enrichment.*` stripped on the way in) — and R-16…R-20 target the first
Vector-shipped sources (Caddy `hems` / `partner-api`, Keycloak per-IP, sshd, backend HEMS token
audit). Still open: the Vector configuration on the application VPS itself, and backend
emission of the `hems_token_*` audit events that R-20 consumes.

**Caveat:** the enricher's reference data defaults to `DEMO_REFERENCE_CONFIG` (demo geo/CIDR/change
calendar/tenant map); `ENRICHMENT_REFERENCE_PATH` overrides it per key from a JSON file
(`observability/enrichment-reference.example.json`, see `docs/INGEST.md`), but the login/firmware
history is still process-local in-memory. Production must keep that file in sync with
IPAM/CMDB/change-calendar/Keycloak and persist (or accept the cold-start/restart reset of) the
stateful history.
