# Event ingest (log shippers)

`POST /ingest/events` is the write path for external log shippers — in production a
[Vector](https://vector.dev) instance on the application VPS that tails Caddy, Keycloak, sshd
and backend logs and POSTs ECS batches to the SOC portal. nginx proxies `/api/` → backend `/`,
so the public URL is:

```
https://security.surf.saarland/api/ingest/events
```

Everything that lands here is written to `surf-events-YYYY.MM.DD` and evaluated by the
correlation scheduler on its next tick (≤ 60 s). The `surf.enrichment.*` flags are computed
at read time by the enricher — a shipper never sets them (they are stripped if present).

## Authentication

A **static bearer token**, deliberately not the OIDC/JWT middleware: a shipper is a machine
identity with one secret.

| Env | Config | Default | Meaning |
|-----|--------|---------|---------|
| `INGEST_TOKEN` | `ingest.token` | *(unset)* | ≥ 32 chars. Unset → route answers **503 `INGEST_DISABLED`** |
| `INGEST_SOURCE_LABEL` | `ingest.sourceLabel` | `vector` | stored in `surf.ingest.source` |
| `INGEST_DEFAULT_TENANT_ID` | `ingest.defaultTenantId` | `vnb-saar` | stamped into `surf.tenant.id` when absent |
| `INGEST_MAX_BATCH` | `ingest.maxBatch` | `500` | max events per request (1..5000) |

- Header: `Authorization: Bearer <INGEST_TOKEN>`; compared with `crypto.timingSafeEqual`.
- Wrong or missing token → **401 `UNAUTHENTICATED`**. The token value is in the pino secret
  scrub list and never appears in logs.
- Generate: `openssl rand -hex 32`. Rotate by changing `.env` on both sides and restarting
  the backend (`docker compose up -d backend`) and Vector.
- The variables reach the container through `env_file: .env` in `docker-compose.yml`, the same
  way `FLEX_API_TOKEN` and the other secrets do; the Helm chart pulls `INGEST_TOKEN` from Vault
  (`backend/ingest`, property `token`) via the External Secrets template.

## Request

```json
{ "events": [ { ...ECS document... }, ... ] }
```

- 1..`maxBatch` items, body ≤ **2 MB** (route `bodyLimit`; nginx `client_max_body_size 2m` on
  `/api/`). Larger → **413**.
- Route rate limit: **120 requests/minute per source IP** (on top of the global limiter).
- Malformed JSON, a non-object body, `events` not an array, an empty array, or more than
  `maxBatch` items → **400 `VALIDATION_ERROR`** (whole request rejected).

Each item may be **nested** or **dotted**, or a mix — both normalise to the same document:

```json
{ "@timestamp": "2026-10-05T10:00:00Z", "event": { "id": "c-1", "action": "http" }, "observer": { "product": "caddy" } }
{ "@timestamp": "2026-10-05T10:00:00Z", "event.id": "c-1", "event.action": "http", "observer.product": "caddy" }
```

## Normalisation rules (per event)

1. **Flatten** nested plain objects to dotted keys (`{"event":{"action":"x"}}` →
   `"event.action": "x"`). Arrays and `null` stay as values. A key that already contains a dot
   is kept as is. When nested and dotted spellings collide, the later key in document order
   wins. `__proto__` / `constructor` / `prototype` keys are dropped.
2. **Required fields** (after flattening):
   - `@timestamp` — ISO 8601 string, parseable, not more than **1 h in the future**, not older
     than **30 days**.
   - `event.id` — string, 1..128 chars (becomes the OpenSearch `_id`, so it must be stable and
     unique per source; Vector: `%{host}-%{file}-%{offset}` or a hash of the line).
   - `observer.product` — string, 1..64 chars (`caddy`, `keycloak`, `sshd`, `surf-backend`, …;
     this plus `observer.service` is the rule-logsource contract, see below).
3. **Server-side stamps** (always overwrite what the client sent):
   - `surf.ingest.received_at` — ISO time the batch was accepted.
   - `surf.ingest.source` — `INGEST_SOURCE_LABEL`.
   - `surf.tenant.id` — set to `INGEST_DEFAULT_TENANT_ID` when absent / null / empty.
4. **Stripped**: every key starting with `surf.enrichment.` (the enricher owns those).
5. Invalid items are **skipped, not fatal**: the rest of the batch is written in one bulk call.

## Response

`202 Accepted`, always — even when every item was rejected (`accepted: 0`):

```json
{ "accepted": 498, "rejected": [ { "index": 17, "reason": "event.id must be a string of 1..128 chars" },
                                 { "index": 231, "reason": "@timestamp is more than 1h in the future" } ] }
```

`rejected` is capped at **50 entries**; the full count is in the log line and the metric.

## Observability

- One pino line per batch: `{ source, accepted, rejected, products: { caddy: 480, sshd: 18 } }`
  (`msg: "ingest batch"`).
- Prometheus: `surf_ingest_events_total{product, outcome="accepted"|"rejected"}`.
  `product` is taken from the shipper's `observer.product`, so keep that value set small and
  stable (it is a label).

## Log-source contract (what the rules expect)

| `observer.product` | `observer.service` | Fields the rules read | Rules |
|---|---|---|---|
| `caddy` | `hems` | `http.response.status_code` (**integer**), `url.path`, `source.ip` | R-16 |
| `caddy` | `partner-api` | `http.response.status_code` (**integer**), `url.path`, `source.ip` | R-17 |
| `keycloak` | `events` | `event.action`, `event.outcome`, `user.name`, `source.ip`, `keycloak.error` | R-01, R-02, R-03, R-18 |
| `sshd` | `auth` | `event.action: ssh_login`, `event.outcome`, `source.ip`, `user.name` | R-19 (flag computed by the enricher) |
| `surf-backend` | `hems` | `event.action: hems_token_issued|rotated|revoked`, `user.name`, `surf.ems.id` | R-20 |

Status codes must be sent as JSON numbers (Vector: `.http.response.status_code = to_int!(…)`);
the evaluator compares `401` to `"401"` as different values.

## curl example

```bash
curl -sS -X POST https://security.surf.saarland/api/ingest/events \
  -H "Authorization: Bearer $INGEST_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "events": [
      { "@timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
        "event": { "id": "demo-1" },
        "observer": { "product": "caddy", "service": "hems" },
        "http": { "request": { "method": "GET" }, "response": { "status_code": 401 } },
        "url": { "path": "/APX1045765804_plim_consumption/Control" },
        "source": { "ip": "79.198.160.48" },
        "user_agent": { "original": "AMPERIX/1.4" },
        "host": { "name": "surf-vps1" } }
    ]
  }'
# → {"accepted":1,"rejected":[]}
```

## Enrichment reference data from a file

The enricher needs real reference data to compute `surf.enrichment.ip_allowlisted` (R-15,
R-19) and the other flags; `main.ts` ships demo values. Set `ENRICHMENT_REFERENCE_PATH` to a
JSON file with the `ReferenceConfig` shape — every top-level key is optional and, when
present, **replaces** the demo value for that key (no deep merge):

```json
{
  "allowlistCidrs": ["217.244.216.71/32", "91.53.165.129/32", "178.104.103.16/32", "178.105.200.25/32"],
  "geo": {},
  "changeWindows": [{ "startIso": "2026-10-05T22:00:00Z", "endIso": "2026-10-05T23:00:00Z" }],
  "tenantByUser": { "dirk.dso": "vnb-saar" },
  "firmwareBaseline": { "ems-0815": "2.4.0" }
}
```

Template: [`observability/enrichment-reference.example.json`](../observability/enrichment-reference.example.json)
(the admin workstation + server addresses). Unknown keys, malformed CIDRs, bad timestamps or
invalid JSON abort startup with a readable report. The startup log line
`enrichment reference data loaded` says whether `demo` or `file` is active.

Mount it into the (read-only) backend container, e.g. in `docker-compose.override.yml`:

```yaml
services:
  backend:
    environment:
      ENRICHMENT_REFERENCE_PATH: /config/enrichment-reference.json
    volumes:
      - ./observability/enrichment-reference.json:/config/enrichment-reference.json:ro
```

(copy the example to `observability/enrichment-reference.json` first; the file is a deployment
secret-adjacent artefact and should be treated like `.env`).
