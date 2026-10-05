import type { EventStore } from '../../domain/ports/repositories.js';

/**
 * Write-side ingest for external log shippers (Vector → POST /ingest/events).
 *
 * Shippers send ECS 8.x documents either nested ({"event":{"action":"x"}}) or
 * already flattened ({"event.action":"x"}). Everything is normalised to the
 * FLAT dotted-key shape the rest of the platform (seed, evaluator, enricher)
 * works with, validated per event, stamped with `surf.ingest.*`, and written to
 * the event store in ONE bulk call. Invalid items are skipped and reported —
 * never fatal for the batch — so one bad line cannot block a shipper.
 */

export interface IngestOptions {
  /** Label stored in `surf.ingest.source` (which shipper delivered the event). */
  sourceLabel: string;
  /** Tenant stamped into `surf.tenant.id` when the shipper does not set one. */
  defaultTenantId: string;
}

export interface RejectedEvent {
  index: number;
  reason: string;
}

export interface IngestResult {
  accepted: number;
  /** Capped at MAX_REPORTED_REJECTIONS entries; `rejectedTotal` carries the full count. */
  rejected: RejectedEvent[];
  rejectedTotal: number;
  /** Per `observer.product` counts, by outcome — feeds the Prometheus counter. */
  products: { accepted: Record<string, number>; rejected: Record<string, number> };
}

export type NormaliseResult =
  | { ok: true; event: Record<string, unknown> }
  | { ok: false; reason: string; product?: string };

/** Rejections reported back to the shipper per batch (the rest is counted only). */
export const MAX_REPORTED_REJECTIONS = 50;
/** Events dated further ahead than this are rejected (clock skew allowance). */
export const MAX_FUTURE_MS = 60 * 60 * 1000;
/** Events older than this are rejected (would land in a cold / purged index). */
export const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

const ISO_8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
/** Keys that would reach Object.prototype if copied onto a plain object. */
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const ENRICHMENT_PREFIX = 'surf.enrichment.';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Recursively flattens nested plain objects into dotted keys. Arrays and null
 * are leaf values; a key that already contains a dot is kept verbatim (so a
 * pre-flattened document passes through unchanged). When nested and dotted
 * spellings collide, the later key in document order wins.
 */
export function flattenEvent(input: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const walk = (obj: Record<string, unknown>, prefix: string): void => {
    for (const [key, value] of Object.entries(obj)) {
      if (FORBIDDEN_KEYS.has(key)) continue;
      const flatKey = prefix === '' ? key : `${prefix}.${key}`;
      if (isPlainObject(value)) walk(value, flatKey);
      else out[flatKey] = value;
    }
  };
  walk(input, '');
  return out;
}

function requireString(event: Record<string, unknown>, key: string, maxLength: number): string | undefined {
  const value = event[key];
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) return undefined;
  return value;
}

function productOf(event: Record<string, unknown>): string | undefined {
  const value = event['observer.product'];
  return typeof value === 'string' && value.length > 0 ? value.slice(0, 64) : undefined;
}

/**
 * Flattens, validates and stamps a single shipped event. Pure: `now` is
 * injected so the timestamp window is deterministic under test.
 */
export function normaliseEvent(raw: unknown, opts: IngestOptions, now: Date): NormaliseResult {
  if (!isPlainObject(raw)) return { ok: false, reason: 'event must be a JSON object' };
  const flat = flattenEvent(raw);
  const product = productOf(flat);
  const fail = (reason: string): NormaliseResult => ({ ok: false, reason, ...(product !== undefined ? { product } : {}) });

  const ts = flat['@timestamp'];
  if (typeof ts !== 'string' || !ISO_8601.test(ts)) return fail('@timestamp must be an ISO 8601 string');
  const tsMs = Date.parse(ts);
  if (Number.isNaN(tsMs)) return fail('@timestamp is not a parseable date');
  if (tsMs > now.getTime() + MAX_FUTURE_MS) return fail('@timestamp is more than 1h in the future');
  if (tsMs < now.getTime() - MAX_AGE_MS) return fail('@timestamp is older than 30 days');

  if (requireString(flat, 'event.id', 128) === undefined) return fail('event.id must be a string of 1..128 chars');
  if (requireString(flat, 'observer.product', 64) === undefined) {
    return fail('observer.product must be a string of 1..64 chars');
  }

  const event: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(flat)) {
    // The enricher owns surf.enrichment.*; a shipper must not pre-bake verdicts.
    if (key.startsWith(ENRICHMENT_PREFIX)) continue;
    event[key] = value;
  }
  const tenant = event['surf.tenant.id'];
  if (tenant === undefined || tenant === null || tenant === '') event['surf.tenant.id'] = opts.defaultTenantId;
  event['surf.ingest.received_at'] = now.toISOString();
  event['surf.ingest.source'] = opts.sourceLabel;
  return { ok: true, event };
}

function bump(counts: Record<string, number>, product: string | undefined): void {
  const key = product ?? 'unknown';
  counts[key] = (counts[key] ?? 0) + 1;
}

export class IngestService {
  constructor(
    private readonly events: EventStore,
    private readonly opts: IngestOptions,
  ) {}

  /** Normalises a batch and writes every valid event in one bulk operation. */
  async ingest(batch: unknown[], now: Date = new Date()): Promise<IngestResult> {
    const valid: Array<Record<string, unknown>> = [];
    const rejected: RejectedEvent[] = [];
    let rejectedTotal = 0;
    const products: IngestResult['products'] = { accepted: {}, rejected: {} };

    batch.forEach((raw, index) => {
      const result = normaliseEvent(raw, this.opts, now);
      if (result.ok) {
        valid.push(result.event);
        bump(products.accepted, productOf(result.event));
        return;
      }
      rejectedTotal += 1;
      bump(products.rejected, result.product);
      if (rejected.length < MAX_REPORTED_REJECTIONS) rejected.push({ index, reason: result.reason });
    });

    if (valid.length > 0) await this.events.ingest(valid);
    return { accepted: valid.length, rejected, rejectedTotal, products };
  }
}
