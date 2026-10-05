import Fastify, { type FastifyInstance, type FastifyBaseLogger } from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import type { Logger } from 'pino';
import type { AppDeps } from './infrastructure/http/deps.js';
import { errorHandler } from './infrastructure/http/middleware/error.js';
import { requestIdOptions } from './infrastructure/http/middleware/requestId.js';
import { registerOpenApi } from './infrastructure/http/openapi.js';
import { registerHealthRoutes } from './infrastructure/http/routes/health.js';
import { registerAlertRoutes } from './infrastructure/http/routes/alerts.js';
import { registerCaseRoutes } from './infrastructure/http/routes/cases.js';
import { registerInvestigateRoutes } from './infrastructure/http/routes/investigate.js';
import { registerPlaybookRoutes } from './infrastructure/http/routes/playbooks.js';
import { registerRuleRoutes } from './infrastructure/http/routes/rules.js';
import { registerReportRoutes } from './infrastructure/http/routes/reports.js';
import { registerAdminRoutes } from './infrastructure/http/routes/admin.js';
import { registerIngestRoutes } from './infrastructure/http/routes/ingest.js';

/**
 * Fastify assembly. The nginx edge strips /api, so routes register without
 * the prefix here and swagger advertises servers: [{url: '/api'}].
 */
export async function buildServer(deps: AppDeps, logger: Logger): Promise<FastifyInstance> {
  const app = Fastify({
    loggerInstance: logger as unknown as FastifyBaseLogger,
    ...requestIdOptions(deps.config.requestIdHeader),
    trustProxy: true, // nginx terminates TLS
    bodyLimit: 1024 * 1024,
  });

  app.setErrorHandler(errorHandler);

  await app.register(helmet, {
    // The API serves JSON only; CSP for the SPA is set by nginx with nonces.
    contentSecurityPolicy: false,
    strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
  });

  await app.register(cors, {
    origin: (origin, cb) => {
      // Same-origin deployment behind nginx: no cross-origin browsers expected.
      const allowed = [new URL(process.env['VITE_API_BASE'] ?? 'https://localhost').origin];
      if (!origin || allowed.includes(origin)) cb(null, true);
      else cb(new Error('CORS origin denied'), false);
    },
    credentials: true,
  });

  await app.register(rateLimit, {
    global: true,
    max: 300,
    timeWindow: '1 minute',
    keyGenerator: (req) => req.caller?.userId ?? req.ip,
  });

  // p95 latency histogram on every response.
  app.addHook('onResponse', (req, reply, done) => {
    deps.metrics.httpDuration.observe(
      { method: req.method, route: req.routeOptions?.url ?? 'unknown', status: String(reply.statusCode) },
      reply.elapsedTime / 1000,
    );
    done();
  });

  await registerOpenApi(app);
  registerHealthRoutes(app, deps);
  registerAlertRoutes(app, deps);
  registerCaseRoutes(app, deps);
  registerInvestigateRoutes(app, deps);
  registerPlaybookRoutes(app, deps);
  registerRuleRoutes(app, deps);
  registerReportRoutes(app, deps);
  registerAdminRoutes(app, deps);
  registerIngestRoutes(app, deps);

  return app;
}
