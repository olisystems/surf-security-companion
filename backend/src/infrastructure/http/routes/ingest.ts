import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { AppDeps } from '../deps.js';
import { IngestService } from '../../../application/ingest/ingestService.js';

/** Body limit for one shipper batch (the nginx edge must allow at least this — see docs/INGEST.md). */
export const INGEST_BODY_LIMIT_BYTES = 2 * 1024 * 1024;

/** Constant-time comparison; a length mismatch short-circuits (the length is not secret). */
function tokenMatches(presented: string, expected: string): boolean {
  const a = Buffer.from(presented, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Static-token preHandler for the shipper write path. Deliberately NOT the
 * OIDC/JWT middleware: a log shipper is a machine identity with one secret,
 * rotated out-of-band (docs/INGEST.md). With no token configured the route
 * stays registered but refuses every call, so a misconfigured deployment is
 * visible (503) instead of silently open.
 */
function ingestAuth(token: string | undefined) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (token === undefined) {
      await reply.code(503).send({ code: 'INGEST_DISABLED', message: 'INGEST_TOKEN is not configured' });
      return;
    }
    const header = req.headers.authorization;
    const presented = header?.startsWith('Bearer ') ? header.slice(7) : '';
    if (presented.length === 0 || !tokenMatches(presented, token)) {
      req.log.warn({ ip: req.ip }, 'ingest token rejected');
      await reply.code(401).send({ code: 'UNAUTHENTICATED', message: 'Invalid ingest token' });
    }
  };
}

export function registerIngestRoutes(app: FastifyInstance, deps: AppDeps): void {
  const { ingest } = deps.config;
  const service = new IngestService(deps.eventStore, {
    sourceLabel: ingest.sourceLabel,
    defaultTenantId: ingest.defaultTenantId,
  });
  // Only the envelope is enforced here; items are validated per event by the
  // service, where an invalid one is reported rather than failing the batch.
  const bodySchema = z.object({ events: z.array(z.unknown()).min(1).max(ingest.maxBatch) }).strict();

  app.post(
    '/ingest/events',
    {
      preHandler: [ingestAuth(ingest.token)],
      bodyLimit: INGEST_BODY_LIMIT_BYTES,
      config: { rateLimit: { max: 120, timeWindow: '1 minute' } },
      schema: {
        tags: ['ingest'],
        summary: 'Accept a batch of ECS events from a log shipper',
        description:
          'Nested or dotted-key ECS 8.x documents are normalised to flat dotted keys, stamped with surf.ingest.* and written to surf-events-*. Invalid items are skipped and reported, not fatal.',
        security: [{ ingestToken: [] }],
      },
    },
    async (req, reply) => {
      const body = bodySchema.parse(req.body);
      const result = await service.ingest(body.events);

      for (const [product, count] of Object.entries(result.products.accepted)) {
        deps.metrics.ingestEvents.inc({ product, outcome: 'accepted' }, count);
      }
      for (const [product, count] of Object.entries(result.products.rejected)) {
        deps.metrics.ingestEvents.inc({ product, outcome: 'rejected' }, count);
      }
      req.log.info(
        {
          source: ingest.sourceLabel,
          accepted: result.accepted,
          rejected: result.rejectedTotal,
          products: result.products.accepted,
        },
        'ingest batch',
      );
      return reply.code(202).send({ accepted: result.accepted, rejected: result.rejected });
    },
  );
}
