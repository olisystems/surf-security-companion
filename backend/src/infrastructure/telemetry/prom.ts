import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

/**
 * Prometheus metrics registry. Every metric named in the observability spec
 * lives here so dashboards and alerts have a single source of truth.
 */
export class Metrics {
  readonly registry = new Registry();

  readonly httpDuration = new Histogram({
    name: 'surf_http_request_duration_seconds',
    help: 'HTTP request duration',
    labelNames: ['method', 'route', 'status'] as const,
    buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
    registers: [this.registry],
  });

  readonly ruleFired = new Counter({
    name: 'surf_rule_fired_total',
    help: 'Correlation rule firings (new alerts emitted)',
    labelNames: ['rule_id'] as const,
    registers: [this.registry],
  });

  readonly ingestionLag = new Gauge({
    name: 'surf_ingestion_lag_seconds',
    help: 'Age of the newest event in the log store',
    registers: [this.registry],
  });

  readonly playbookRuns = new Counter({
    name: 'surf_playbook_runs_total',
    help: 'Playbook runs by playbook and terminal status',
    labelNames: ['playbook', 'status'] as const,
    registers: [this.registry],
  });

  readonly hashchainRollups = new Counter({
    name: 'surf_hashchain_rollups_total',
    help: 'Hourly Merkle rollups by outcome',
    labelNames: ['outcome'] as const,
    registers: [this.registry],
  });

  readonly tenantScopeDenials = new Counter({
    name: 'surf_tenant_scope_denials_total',
    help: 'Requests denied by tenant-scope enforcement',
    registers: [this.registry],
  });

  readonly ingestEvents = new Counter({
    name: 'surf_ingest_events_total',
    help: 'Events received on POST /ingest/events by observer.product and outcome',
    labelNames: ['product', 'outcome'] as const,
    registers: [this.registry],
  });

  constructor() {
    collectDefaultMetrics({ register: this.registry });
  }

  async render(): Promise<string> {
    return this.registry.metrics();
  }
}
