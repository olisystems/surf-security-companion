import { describe, it, expect, vi } from 'vitest';
import type { EventStore } from '../../src/domain/ports/repositories.js';
import {
  IngestService,
  MAX_REPORTED_REJECTIONS,
  flattenEvent,
  normaliseEvent,
  type IngestOptions,
} from '../../src/application/ingest/ingestService.js';

/**
 * Normalisation contract for the shipper write path: nested and dotted input
 * converge on the same flat document, required ECS fields are enforced per
 * event, `surf.ingest.*` / `surf.tenant.id` are stamped server-side, and a
 * shipper can never pre-bake `surf.enrichment.*` verdicts.
 */
const NOW = new Date('2026-10-05T12:00:00Z');
const OPTS: IngestOptions = { sourceLabel: 'vector', defaultTenantId: 'vnb-saar' };

function valid(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    '@timestamp': '2026-10-05T11:59:00Z',
    'event.id': 'evt-1',
    'observer.product': 'caddy',
    ...extra,
  };
}

function makeService(): { service: IngestService; ingest: ReturnType<typeof vi.fn> } {
  const ingest = vi.fn(async () => undefined);
  const store = { ingest } as unknown as EventStore;
  return { service: new IngestService(store, OPTS), ingest };
}

describe('flattenEvent', () => {
  it('flattens nested plain objects to dotted keys', () => {
    expect(flattenEvent({ event: { action: 'x', outcome: 'failure' }, source: { ip: '1.2.3.4' } })).toEqual({
      'event.action': 'x',
      'event.outcome': 'failure',
      'source.ip': '1.2.3.4',
    });
  });

  it('keeps dotted keys as is and recurses into nested objects under them', () => {
    expect(flattenEvent({ 'event.action': 'x', 'surf.tenant': { id: 't1' } })).toEqual({
      'event.action': 'x',
      'surf.tenant.id': 't1',
    });
  });

  it('treats arrays and null as leaf values', () => {
    const out = flattenEvent({ user: { roles: ['a', 'b'], email: null }, tags: [{ k: 1 }] });
    expect(out['user.roles']).toEqual(['a', 'b']);
    expect(out['user.email']).toBeNull();
    expect(out['tags']).toEqual([{ k: 1 }]);
  });

  it('never copies prototype-polluting keys', () => {
    const raw = JSON.parse('{"__proto__":{"polluted":true},"constructor":{"x":1},"event":{"id":"e"}}') as Record<string, unknown>;
    const out = flattenEvent(raw);
    expect(Object.keys(out)).toEqual(['event.id']);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
});

describe('normaliseEvent', () => {
  it('accepts a valid flat event and stamps surf.ingest.* + default tenant', () => {
    const res = normaliseEvent(valid(), OPTS, NOW);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.event['surf.ingest.received_at']).toBe(NOW.toISOString());
    expect(res.event['surf.ingest.source']).toBe('vector');
    expect(res.event['surf.tenant.id']).toBe('vnb-saar');
    expect(res.event['@timestamp']).toBe('2026-10-05T11:59:00Z');
  });

  it('keeps a tenant the shipper set', () => {
    const res = normaliseEvent(valid({ 'surf.tenant.id': 'vnb-pfalz' }), OPTS, NOW);
    expect(res.ok && res.event['surf.tenant.id']).toBe('vnb-pfalz');
  });

  it('strips surf.enrichment.* so the enricher owns the verdict', () => {
    const res = normaliseEvent(valid({ 'surf.enrichment.ip_allowlisted': true, surf: { enrichment: { x: 1 } } }), OPTS, NOW);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(Object.keys(res.event).filter((k) => k.startsWith('surf.enrichment.'))).toEqual([]);
  });

  it('overrides a client-supplied surf.ingest.* stamp', () => {
    const res = normaliseEvent(valid({ 'surf.ingest.source': 'spoofed', 'surf.ingest.received_at': '1999-01-01T00:00:00Z' }), OPTS, NOW);
    expect(res.ok && res.event['surf.ingest.source']).toBe('vector');
    expect(res.ok && res.event['surf.ingest.received_at']).toBe(NOW.toISOString());
  });

  it.each([
    ['non-object', 'nope', 'must be a JSON object'],
    ['array', [1], 'must be a JSON object'],
    ['missing @timestamp', valid({ '@timestamp': undefined }), '@timestamp must be an ISO 8601'],
    ['non-ISO @timestamp', valid({ '@timestamp': 'Oct 5 2026' }), '@timestamp must be an ISO 8601'],
    ['unparseable @timestamp', valid({ '@timestamp': '2026-13-45T99:99:99Z' }), 'not a parseable date'],
    ['future @timestamp', valid({ '@timestamp': '2026-10-05T13:01:00Z' }), 'in the future'],
    ['stale @timestamp', valid({ '@timestamp': '2026-09-01T12:00:00Z' }), 'older than 30 days'],
    ['missing event.id', valid({ 'event.id': undefined }), 'event.id must be'],
    ['numeric event.id', valid({ 'event.id': 42 }), 'event.id must be'],
    ['overlong event.id', valid({ 'event.id': 'x'.repeat(129) }), 'event.id must be'],
    ['missing observer.product', valid({ 'observer.product': '' }), 'observer.product must be'],
  ])('rejects %s', (_label, raw, reason) => {
    const res = normaliseEvent(raw, OPTS, NOW);
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.reason).toContain(reason);
  });

  it('allows up to 1h of clock skew into the future and 30 days into the past', () => {
    expect(normaliseEvent(valid({ '@timestamp': '2026-10-05T12:59:00Z' }), OPTS, NOW).ok).toBe(true);
    expect(normaliseEvent(valid({ '@timestamp': '2026-09-06T12:00:00Z' }), OPTS, NOW).ok).toBe(true);
    expect(normaliseEvent(valid({ '@timestamp': '2026-10-05T11:59:00+02:00' }), OPTS, NOW).ok).toBe(true);
  });

  it('reports the product of a rejected event when it is readable', () => {
    const res = normaliseEvent(valid({ 'event.id': undefined }), OPTS, NOW);
    expect(!res.ok && res.product).toBe('caddy');
  });
});

describe('IngestService.ingest', () => {
  it('normalises nested + dotted input to the same flat document and writes once', async () => {
    const { service, ingest } = makeService();
    const nested = { '@timestamp': '2026-10-05T11:59:00Z', event: { id: 'n1', action: 'x' }, observer: { product: 'caddy' } };
    const dotted = { '@timestamp': '2026-10-05T11:59:00Z', 'event.id': 'd1', 'event.action': 'x', 'observer.product': 'caddy' };

    const result = await service.ingest([nested, dotted], NOW);

    expect(result.accepted).toBe(2);
    expect(result.rejected).toEqual([]);
    expect(ingest).toHaveBeenCalledTimes(1);
    const written = ingest.mock.calls[0]?.[0] as Array<Record<string, unknown>>;
    expect(written).toHaveLength(2);
    const [a, b] = written;
    expect(a).toEqual({
      '@timestamp': '2026-10-05T11:59:00Z',
      'event.id': 'n1',
      'event.action': 'x',
      'observer.product': 'caddy',
      'surf.tenant.id': 'vnb-saar',
      'surf.ingest.received_at': NOW.toISOString(),
      'surf.ingest.source': 'vector',
    });
    expect(b).toEqual({ ...a, 'event.id': 'd1' });
    expect(result.products.accepted).toEqual({ caddy: 2 });
  });

  it('skips invalid items with their index + reason and still writes the valid ones', async () => {
    const { service, ingest } = makeService();
    const result = await service.ingest(
      [valid(), valid({ 'event.id': undefined }), valid({ '@timestamp': 'yesterday' }), valid({ '@timestamp': '2026-10-06T00:00:00Z' })],
      NOW,
    );
    expect(result.accepted).toBe(1);
    expect(result.rejectedTotal).toBe(3);
    expect(result.rejected.map((r) => r.index)).toEqual([1, 2, 3]);
    expect(result.rejected[0]?.reason).toContain('event.id');
    expect(result.rejected[1]?.reason).toContain('ISO 8601');
    expect(result.rejected[2]?.reason).toContain('future');
    expect(ingest).toHaveBeenCalledTimes(1);
    expect(result.products).toEqual({ accepted: { caddy: 1 }, rejected: { caddy: 3 } });
  });

  it('does not touch the store when every item is invalid', async () => {
    const { service, ingest } = makeService();
    const result = await service.ingest([{}, 'x'], NOW);
    expect(result.accepted).toBe(0);
    expect(result.rejectedTotal).toBe(2);
    expect(result.products.rejected).toEqual({ unknown: 2 });
    expect(ingest).not.toHaveBeenCalled();
  });

  it('caps the reported rejections but counts them all', async () => {
    const { service } = makeService();
    const result = await service.ingest(Array.from({ length: MAX_REPORTED_REJECTIONS + 10 }, () => ({})), NOW);
    expect(result.rejected).toHaveLength(MAX_REPORTED_REJECTIONS);
    expect(result.rejectedTotal).toBe(MAX_REPORTED_REJECTIONS + 10);
  });
});
