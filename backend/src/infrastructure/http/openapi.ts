import type { FastifyInstance } from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';

/** OpenAPI 3.1 spec at /api/openapi.json, Swagger UI at /api/docs. */
export async function registerOpenApi(app: FastifyInstance): Promise<void> {
  await app.register(swagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'SURF Security Companion API',
        description:
          'SOC portal backend: alerts, cases, investigation, safe-mode SOAR playbooks, NIS2/KRITIS/GDPR reporting, hash-chain verification.',
        version: '0.1.0',
        contact: { email: 'soc@surf-project.example' },
      },
      servers: [{ url: '/api' }],
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
          ingestToken: { type: 'http', scheme: 'bearer', bearerFormat: 'opaque' },
        },
      },
      security: [{ bearerAuth: [] }],
      tags: [
        { name: 'platform', description: 'Health & metrics' },
        { name: 'alerts', description: 'Alert lifecycle' },
        { name: 'cases', description: 'Case management' },
        { name: 'investigate', description: 'Log search & pivots' },
        { name: 'rules', description: 'Detection rules' },
        { name: 'playbooks', description: 'SOAR (safe-mode)' },
        { name: 'reports', description: 'NIS2 / KRITIS / GDPR' },
        { name: 'admin', description: 'Platform administration' },
        { name: 'ingest', description: 'Log-shipper write path (static token)' },
      ],
    },
  });
  await app.register(swaggerUi, {
    routePrefix: '/docs',
    uiConfig: { docExpansion: 'list', deepLinking: true },
  });
  app.get('/openapi.json', async () => app.swagger());
}
