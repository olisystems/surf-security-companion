import { z } from 'zod';

/**
 * Typed configuration — the only place process.env is read. Fails fast with
 * a readable report if anything required is missing or malformed.
 */
const boolFromString = z
  .string()
  .transform((v) => v === 'true' || v === '1')
  .pipe(z.boolean());

const configSchema = z.object({
  port: z.coerce.number().int().min(1).max(65535).default(8080),
  nodeEnv: z.enum(['development', 'test', 'production']).default('production'),
  logLevel: z.enum(['trace', 'debug', 'info', 'warn', 'error']).default('info'),

  oidc: z.object({
    issuerUrl: z.string().url(),
    audience: z.string().min(1),
    jwksUri: z.string().url(),
    tenantClaim: z.string().default('surf_tenant_id'),
  }),

  requestIdHeader: z.string().default('x-request-id'),

  postgres: z.object({
    host: z.string().min(1),
    port: z.coerce.number().int().default(5432),
    database: z.string().min(1),
    user: z.string().min(1),
    password: z.string().min(1),
    ssl: z.string().default('require'),
  }),

  opensearch: z.object({
    url: z.string().url(),
    username: z.string().min(1),
    password: z.string().min(1),
    caPath: z.string().optional(),
  }),

  wazuh: z.object({
    apiUrl: z.string().url(),
    user: z.string().min(1),
    password: z.string().min(1),
  }),

  minio: z.object({
    endpoint: z.string().min(1),
    accessKey: z.string().min(1),
    secretKey: z.string().min(1),
    bucketAudit: z.string().default('surf-audit'),
    bucketHashchain: z.string().default('surf-hashchain'),
    useSsl: boolFromString.default('false'),
    objectLockYears: z.coerce.number().int().min(1).default(1),
  }),

  hashchain: z
    .object({
      // 'file' = soft Ed25519 key on disk (dev/MVP); 'vault' = HashiCorp Vault
      // Transit (prod — private key never leaves Vault). See docs/SECRETS.md §5.
      signer: z.enum(['file', 'vault']).default('file'),
      signingKeyPath: z.string().default(''),
      vaultAddr: z.string().url().optional(),
      vaultToken: z.string().optional(),
      vaultTransitKey: z.string().default('surf-hashchain'),
      vaultNamespace: z.string().optional(),
      rollupIntervalMinutes: z.coerce.number().int().min(1).max(60).default(60),
    })
    .superRefine((v, ctx) => {
      if (v.signer === 'file' && v.signingKeyPath.length === 0) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['signingKeyPath'], message: 'required when hashchain.signer=file' });
      }
      if (v.signer === 'vault' && (!v.vaultAddr || !v.vaultToken)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['vaultAddr'], message: 'vaultAddr and vaultToken required when hashchain.signer=vault' });
      }
    }),

  upstream: z.object({
    flexApiUrl: z.string().url(),
    flexApiToken: z.string().min(1),
    emsApiUrl: z.string().url(),
    emsApiToken: z.string().min(1),
  }),

  alerting: z.object({
    pagerdutyRoutingKey: z.string().min(1),
    slackWebhookUrl: z.string().optional(),
  }),

  playbooks: z.object({
    dryRunDefault: boolFromString.default('true'),
    massActionThreshold: z.coerce.number().int().min(1).default(10),
    requireStepUp: boolFromString.default('true'),
  }),

  ingest: z.object({
    // Static bearer token for the log-shipper write path (POST /ingest/events).
    // Unset → the route registers but answers 503 INGEST_DISABLED.
    token: z.string().min(32).optional(),
    sourceLabel: z.string().min(1).max(64).default('vector'),
    defaultTenantId: z.string().min(1).max(64).default('vnb-saar'),
    maxBatch: z.coerce.number().int().min(1).max(5000).default(500),
  }),

  enrichment: z.object({
    // JSON file with the ReferenceConfig shape; merged over the demo defaults
    // per top-level key. Unset → demo reference data only.
    referencePath: z.string().min(1).optional(),
  }),

  rulesDir: z.string().default('/rules'),
  presignExpirySeconds: z.coerce.number().int().default(3600),
});

export type AppConfig = z.infer<typeof configSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = configSchema.safeParse({
    port: env['PORT'],
    nodeEnv: env['NODE_ENV'],
    logLevel: env['LOG_LEVEL'],
    oidc: {
      issuerUrl: env['OIDC_ISSUER_URL'],
      audience: env['OIDC_AUDIENCE'],
      jwksUri: env['OIDC_JWKS_URI'],
      tenantClaim: env['TENANT_CLAIM'],
    },
    requestIdHeader: env['REQUEST_ID_HEADER'],
    postgres: {
      host: env['PG_HOST'],
      port: env['PG_PORT'],
      database: env['PG_DB'],
      user: env['PG_USER'],
      password: env['PG_PASSWORD'],
      ssl: env['PG_SSL'],
    },
    opensearch: {
      url: env['OPENSEARCH_URL'],
      username: env['OPENSEARCH_USERNAME'],
      password: env['OPENSEARCH_PASSWORD'],
      caPath: env['OPENSEARCH_CA_PATH'],
    },
    wazuh: {
      apiUrl: env['WAZUH_API_URL'],
      user: env['WAZUH_API_USER'],
      password: env['WAZUH_API_PASS'],
    },
    minio: {
      endpoint: env['MINIO_ENDPOINT'],
      accessKey: env['MINIO_ACCESS_KEY'],
      secretKey: env['MINIO_SECRET_KEY'],
      bucketAudit: env['MINIO_BUCKET_AUDIT'],
      bucketHashchain: env['MINIO_BUCKET_HASHCHAIN'],
      useSsl: env['MINIO_USE_SSL'],
      objectLockYears: env['MINIO_OBJECT_LOCK_YEARS'],
    },
    hashchain: {
      signer: env['HASHCHAIN_SIGNER'],
      signingKeyPath: env['HASHCHAIN_SIGNING_KEY_PATH'],
      vaultAddr: env['VAULT_ADDR'],
      vaultToken: env['VAULT_TOKEN'],
      vaultTransitKey: env['VAULT_TRANSIT_KEY'],
      vaultNamespace: env['VAULT_NAMESPACE'],
      rollupIntervalMinutes: env['HASHCHAIN_ROLLUP_INTERVAL_MINUTES'],
    },
    upstream: {
      flexApiUrl: env['FLEX_API_URL'],
      flexApiToken: env['FLEX_API_TOKEN'],
      emsApiUrl: env['EMS_API_URL'],
      emsApiToken: env['EMS_API_TOKEN'],
    },
    alerting: {
      pagerdutyRoutingKey: env['PAGERDUTY_ROUTING_KEY'],
      slackWebhookUrl: env['SLACK_WEBHOOK_URL'] || undefined,
    },
    playbooks: {
      dryRunDefault: env['PLAYBOOK_DRY_RUN_DEFAULT'],
      massActionThreshold: env['PLAYBOOK_MASS_ACTION_THRESHOLD'],
      requireStepUp: env['PLAYBOOK_REQUIRE_STEPUP'],
    },
    ingest: {
      token: env['INGEST_TOKEN'] || undefined,
      sourceLabel: env['INGEST_SOURCE_LABEL'],
      defaultTenantId: env['INGEST_DEFAULT_TENANT_ID'],
      maxBatch: env['INGEST_MAX_BATCH'],
    },
    enrichment: {
      referencePath: env['ENRICHMENT_REFERENCE_PATH'] || undefined,
    },
    rulesDir: env['RULES_DIR'],
    presignExpirySeconds: env['PRESIGN_EXPIRY_SECONDS'],
  });

  if (!parsed.success) {
    const report = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Configuration invalid:\n${report}`);
  }
  return parsed.data;
}

/** Values that must never appear in logs. Used by the pino redaction setup. */
export function secretValues(config: AppConfig): string[] {
  return [
    config.postgres.password,
    config.opensearch.password,
    config.wazuh.password,
    config.minio.secretKey,
    config.upstream.flexApiToken,
    config.upstream.emsApiToken,
    config.alerting.pagerdutyRoutingKey,
    config.ingest.token ?? '',
  ].filter((v) => v.length > 0);
}
