import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import { pino } from 'pino';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../src/server.js';
import { Metrics } from '../../src/infrastructure/telemetry/prom.js';
import type { AppDeps } from '../../src/infrastructure/http/deps.js';
import type { AppConfig } from '../../src/infrastructure/config.js';
import type { AuthzMiddleware } from '../../src/infrastructure/http/middleware/authz.js';
import type { EventStore } from '../../src/domain/ports/repositories.js';
import { INGEST_BODY_LIMIT_BYTES } from '../../src/infrastructure/http/routes/ingest.js';

/**
 * HTTP contract of POST /ingest/events through the real Fastify assembly
 * (error handler, body limit, static-token auth) with stubbed deps. The other
 * routes only touch their services at request time, so a minimal fake AppDeps
 * is enough to build the app without any backing store.
 */
const TOKEN = 'ingest-test-token-0123456789abcdef0123456789abcdef';
const log = pino({ level: 'silent' });

function fakeDeps(token: string | undefined, ingest: EventStore['ingest']): AppDeps {
  const config = {
    requestIdHeader: 'x-request-id',
    ingest: { token, sourceLabel: 'vector', defaultTenantId: 'vnb-saar', maxBatch: 500 },
  } as unknown as AppConfig;
  const authz = { require: () => async () => undefined } as unknown as AuthzMiddleware;
  return {
    config,
    authz,
    metrics: new Metrics(),
    eventStore: { ingest } as unknown as EventStore,
  } as unknown as AppDeps;
}

function event(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    '@timestamp': new Date(Date.now() - 60_000).toISOString(),
    'event.id': 'evt-1',
    'observer.product': 'caddy',
    ...extra,
  };
}

describe('POST /ingest/events', () => {
  describe('with INGEST_TOKEN configured', () => {
    let app: FastifyInstance;
    const ingest = vi.fn(async () => undefined);
    beforeAll(async () => {
      app = await buildServer(fakeDeps(TOKEN, ingest), log);
    });
    afterAll(async () => {
      await app.close();
    });

    it('401 without a token', async () => {
      const res = await app.inject({ method: 'POST', url: '/ingest/events', payload: { events: [event()] } });
      expect(res.statusCode).toBe(401);
      expect(res.json()).toMatchObject({ code: 'UNAUTHENTICATED' });
      expect(ingest).not.toHaveBeenCalled();
    });

    it('401 with a wrong token (same length and different length)', async () => {
      for (const wrong of [`${TOKEN.slice(0, -1)}X`, 'short']) {
        const res = await app.inject({
          method: 'POST',
          url: '/ingest/events',
          headers: { authorization: `Bearer ${wrong}` },
          payload: { events: [event()] },
        });
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ code: 'UNAUTHENTICATED' });
      }
      expect(ingest).not.toHaveBeenCalled();
    });

    it('202: nested + dotted input normalised to flat keys, stamped, enrichment stripped', async () => {
      ingest.mockClear();
      const ts = new Date(Date.now() - 60_000).toISOString();
      const res = await app.inject({
        method: 'POST',
        url: '/ingest/events',
        headers: { authorization: `Bearer ${TOKEN}` },
        payload: {
          events: [
            { '@timestamp': ts, event: { id: 'n1', action: 'x' }, observer: { product: 'caddy' }, surf: { enrichment: { ip_allowlisted: true } } },
            { '@timestamp': ts, 'event.id': 'd1', 'event.action': 'x', 'observer.product': 'caddy', 'surf.enrichment.impossible_travel': true },
          ],
        },
      });
      expect(res.statusCode).toBe(202);
      expect(res.json()).toEqual({ accepted: 2, rejected: [] });
      expect(ingest).toHaveBeenCalledTimes(1);
      const written = ingest.mock.calls[0]?.[0] as Array<Record<string, unknown>>;
      expect(written).toHaveLength(2);
      for (const doc of written) {
        expect(doc['event.action']).toBe('x');
        expect(doc['event']).toBeUndefined();
        expect(doc['observer.product']).toBe('caddy');
        expect(doc['surf.tenant.id']).toBe('vnb-saar');
        expect(doc['surf.ingest.source']).toBe('vector');
        expect(typeof doc['surf.ingest.received_at']).toBe('string');
        expect(Object.keys(doc).some((k) => k.startsWith('surf.enrichment.'))).toBe(false);
      }
    });

    it('202 with per-item rejections for invalid events (never fatal)', async () => {
      ingest.mockClear();
      const res = await app.inject({
        method: 'POST',
        url: '/ingest/events',
        headers: { authorization: `Bearer ${TOKEN}` },
        payload: {
          events: [
            event(),
            event({ 'event.id': undefined }),
            event({ '@timestamp': 'not-a-date' }),
            event({ '@timestamp': new Date(Date.now() + 2 * 3_600_000).toISOString() }),
          ],
        },
      });
      expect(res.statusCode).toBe(202);
      const body = res.json() as { accepted: number; rejected: Array<{ index: number; reason: string }> };
      expect(body.accepted).toBe(1);
      expect(body.rejected.map((r) => r.index)).toEqual([1, 2, 3]);
      expect(body.rejected[0]?.reason).toContain('event.id');
      expect(body.rejected[1]?.reason).toContain('@timestamp');
      expect(body.rejected[2]?.reason).toContain('future');
      expect(ingest).toHaveBeenCalledTimes(1);
    });

    it('202 with accepted 0 when every item is invalid', async () => {
      ingest.mockClear();
      const res = await app.inject({
        method: 'POST',
        url: '/ingest/events',
        headers: { authorization: `Bearer ${TOKEN}` },
        payload: { events: [{}, 'x'] },
      });
      expect(res.statusCode).toBe(202);
      expect(res.json()).toMatchObject({ accepted: 0 });
      expect(ingest).not.toHaveBeenCalled();
    });

    it('400 for more than maxBatch items, a non-array, or a non-object body', async () => {
      for (const payload of [{ events: Array.from({ length: 501 }, () => event()) }, { events: 'x' }, [event()], { events: [] }]) {
        const res = await app.inject({
          method: 'POST',
          url: '/ingest/events',
          headers: { authorization: `Bearer ${TOKEN}` },
          payload,
        });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ code: 'VALIDATION_ERROR' });
      }
    });

    it('400 for malformed JSON', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/ingest/events',
        headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
        payload: '{"events": [',
      });
      expect(res.statusCode).toBe(400);
    });

    it('413 for a body larger than 2 MB', async () => {
      const padding = 'x'.repeat(INGEST_BODY_LIMIT_BYTES);
      const res = await app.inject({
        method: 'POST',
        url: '/ingest/events',
        headers: { authorization: `Bearer ${TOKEN}` },
        payload: { events: [event({ message: padding })] },
      });
      expect(res.statusCode).toBe(413);
    });

    it('counts accepted/rejected events per product in surf_ingest_events_total', async () => {
      const deps = fakeDeps(TOKEN, async () => undefined);
      const local = await buildServer(deps, log);
      try {
        await local.inject({
          method: 'POST',
          url: '/ingest/events',
          headers: { authorization: `Bearer ${TOKEN}` },
          payload: { events: [event(), event({ 'observer.product': 'sshd' }), event({ 'event.id': undefined })] },
        });
        const rendered = await deps.metrics.render();
        expect(rendered).toContain('surf_ingest_events_total{product="caddy",outcome="accepted"} 1');
        expect(rendered).toContain('surf_ingest_events_total{product="sshd",outcome="accepted"} 1');
        expect(rendered).toContain('surf_ingest_events_total{product="caddy",outcome="rejected"} 1');
      } finally {
        await local.close();
      }
    });
  });

  describe('without INGEST_TOKEN', () => {
    it('503 INGEST_DISABLED even with a bearer header', async () => {
      const ingest = vi.fn(async () => undefined);
      const app = await buildServer(fakeDeps(undefined, ingest), log);
      try {
        const res = await app.inject({
          method: 'POST',
          url: '/ingest/events',
          headers: { authorization: `Bearer ${TOKEN}` },
          payload: { events: [event()] },
        });
        expect(res.statusCode).toBe(503);
        expect(res.json()).toMatchObject({ code: 'INGEST_DISABLED' });
        expect(ingest).not.toHaveBeenCalled();
      } finally {
        await app.close();
      }
    });
  });
});
