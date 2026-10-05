# Observability

First-class, not optional. Three signals, one request id threading through all of them.

## Traces (OpenTelemetry → Tempo)

- Backend: `@opentelemetry/sdk-node` auto-instruments Fastify, pg and undici. `withSpan()`
  wraps connector calls, OpenSearch queries, MinIO writes and rule evaluations.
- Frontend: `@opentelemetry/sdk-trace-web` wraps `fetch` and injects `traceparent`, so a
  browser action and its backend handling share one trace (verified in e2e, N-12).
- Export: OTLP/HTTP to `otel-collector`, forwarded to Grafana Tempo.

## Metrics (Prometheus)

Exposed at `/metrics`. Named series (see `infrastructure/telemetry/prom.ts`):

| Metric | Type | Labels |
|--------|------|--------|
| `surf_http_request_duration_seconds` | histogram | method, route, status |
| `surf_rule_fired_total` | counter | rule_id |
| `surf_ingestion_lag_seconds` | gauge | — |
| `surf_playbook_runs_total` | counter | playbook, status |
| `surf_hashchain_rollups_total` | counter | outcome |
| `surf_tenant_scope_denials_total` | counter | — |
| `surf_ingest_events_total` | counter | product, outcome |

## Logs (Pino → Loki)

Structured JSON to stdout with request-id correlation. Secrets are redacted by path and by
value (configured secret strings are scrubbed from any message). Audit lines carry
`audit: true` for the Loki dashboard panel. Shipped to Loki via the collector / promtail.

## Dashboards

`docs/grafana-soc-dashboard.json` is auto-provisioned into Grafana (folder *SURF SOC*). It
covers HTTP p95 latency, rule firings, ingestion lag, playbook runs, hash-chain rollup success
rate, tenant-scope denials, and the live audit log stream.

## Health probes

- `GET /health` — liveness (process up).
- `GET /ready` — readiness; checks Postgres, OpenSearch and MinIO (Wazuh degradation does not
  fail readiness, only logs).

## SLO-relevant queries

- Ingestion-to-alert p95 (N-02): correlate `surf_ingestion_lag_seconds` with `surf_rule_fired_total`.
- HTTP p95 (N-03 adjacent): `histogram_quantile(0.95, sum(rate(surf_http_request_duration_seconds_bucket[5m])) by (le, route))`.
- Hash-chain health (N-09): rollup success rate panel; alert if < 1 over 2h → RB-05.
