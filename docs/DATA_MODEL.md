# Data Model

## Log normalisation — ECS 8.x + `surf.*`

All ingested events are normalised to **Elastic Common Schema 8.x** with a SURF extension.
Shippers deliver documents through `POST /ingest/events` ([INGEST.md](INGEST.md)), which flattens
nested objects to the flat dotted-key form used throughout (`event.action`, not `event: {action}`).
Core ECS fields used by the detection rules:

| Field | Type | Notes |
|-------|------|-------|
| `@timestamp` | date | event time (UTC) |
| `event.id` | keyword | stable id; becomes the OpenSearch `_id` |
| `event.action` | keyword | e.g. `LOGIN_ERROR`, `command_dispatch` |
| `event.outcome` | keyword | `success` / `failure` |
| `observer.product` | keyword | source system (`keycloak`, `mqtt`, `surf-engine`, …) |
| `observer.service` | keyword | subsystem (`events`, `broker`, `dispatch`, …) |
| `user.name` | keyword | actor |
| `source.ip` | ip | client address |
| `host.name` | keyword | host |
| `http.request.method` | keyword | HTTP verb (edge access logs) |
| `http.response.status_code` | long | HTTP status as an **integer** (R-16 / R-17 compare numerically) |
| `url.path` | keyword | request path without query (R-16 `/Control`, R-17 `/external/v1/`) |
| `user_agent.original` | keyword | raw User-Agent string |

### SURF extension (`surf.*`)

| Field | Type | Description |
|-------|------|-------------|
| `surf.tenant.id` | keyword | VNB tenant identifier |
| `surf.tenant.name` | keyword | Human-readable name |
| `surf.command.id` | keyword | Command ID |
| `surf.command.type` | keyword | schedule / curtailment / emergency |
| `surf.command.signed` | boolean | Signature valid at receiver |
| `surf.command.magnitude_kw` | float | Power magnitude |
| `surf.grid.section` | keyword | Netzbereich / feeder ID |
| `surf.ems.id` | keyword | EMS device ID |
| `surf.ems.firmware_version` | keyword | Reported firmware version |
| `surf.prosumer.pseudonym` | keyword | Pseudonymised prosumer ID |
| `surf.trade.cycle_id` | keyword | Trading cycle ID |
| `surf.risk.tier` | keyword | Critical / High / Medium / Low |
| `surf.ingest.received_at` | date | Set by `POST /ingest/events` when the batch was accepted |
| `surf.ingest.source` | keyword | Shipper label (`INGEST_SOURCE_LABEL`, default `vector`) |

### Ingest-time enrichment (`surf.enrichment.*`)

Some rules match booleans computed by the ingest pipeline rather than raw fields, keeping
the detection logic simple and auditable:

| Field | Fed to rule | Meaning |
|-------|-------------|---------|
| `surf.enrichment.impossible_travel` | R-02 | two logins > 500 km apart within 30 min |
| `surf.enrichment.cross_tenant_mismatch` | R-04 | query tenant ≠ session tenant |
| `surf.enrichment.firmware_downgrade` | R-10 | semver lower than last inventory |
| `surf.enrichment.in_change_window` | R-13 | inside the declared change window |
| `surf.enrichment.ip_allowlisted` | R-15, R-19 | client IP in the maintained allow-list (pgaudit connections, sshd logins) |

## Indices

- `surf-events-YYYY.MM.DD` — daily event indices (90-day hot retention, N-07).
- `surf-alerts` — portal alert store (single index; also visible in OpenSearch Dashboards).

## Portal state (Postgres 17)

`cases`, `playbook_runs`, `audit_actions` (append-only, hash-chained), `hashchain_ledger`
(append-only), `saved_queries`, `rule_state`, `tenants`. Schema in
[`001_schema.sql`](../backend/src/infrastructure/persistence/postgres/init/001_schema.sql).

## DTOs

TypeScript DTOs (`Alert`, `Case`, `PlaybookRun`) are defined in the backend `domain/entities`
and mirrored as Zod schemas in the frontend `lib/api.ts`, so the UI validates every response.
