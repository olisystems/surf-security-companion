// Composition root. OTel must start before anything else imports http/pg.
import { startOtel, stopOtel } from './infrastructure/telemetry/otel.js';
startOtel();

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './infrastructure/config.js';
import { createLogger } from './infrastructure/telemetry/pino.js';
import { Metrics } from './infrastructure/telemetry/prom.js';
import { createPool } from './infrastructure/persistence/postgres/pool.js';
import { PostgresCaseRepository } from './infrastructure/persistence/postgres/caseRepository.js';
import { PostgresAuditRepository } from './infrastructure/persistence/postgres/auditRepository.js';
import {
  PostgresHashchainRepository,
  PostgresPlaybookRunRepository,
  PostgresRuleStateRepository,
  PostgresSavedQueryRepository,
} from './infrastructure/persistence/postgres/miscRepositories.js';
import { createOpenSearchClient } from './infrastructure/persistence/opensearch/client.js';
import { OpenSearchEventStore } from './infrastructure/persistence/opensearch/eventStore.js';
import { OpenSearchAlertRepository } from './infrastructure/persistence/opensearch/alertRepository.js';
import { MinioBlobStore } from './infrastructure/persistence/minio/blobStore.js';
import {
  HttpEmsConnector,
  HttpFlexConnector,
  HttpKeycloakConnector,
  HttpWazuhConnector,
  PagerDutyConnector,
  SlackConnector,
} from './infrastructure/integrations/connectors.js';
import { FileEd25519Signer } from './infrastructure/integrations/ed25519Signer.js';
import { VaultTransitSigner } from './infrastructure/integrations/vaultTransitSigner.js';
import type { Signer } from './domain/ports/connectors.js';
import { AuthzMiddleware } from './infrastructure/http/middleware/authz.js';
import { AuditService } from './application/audit/auditService.js';
import { AlertService } from './application/alerts/alertService.js';
import { CaseService } from './application/cases/caseService.js';
import { InvestigateService } from './application/investigate/investigateService.js';
import { PlaybookService } from './application/playbooks/playbookService.js';
import { RuleService } from './application/rules/ruleService.js';
import { ReportService } from './application/reports/reportService.js';
import { Nis2Service } from './application/nis2/nis2Service.js';
import { GdprService } from './application/gdpr/gdprService.js';
import { MerkleChainService } from './application/merkleChain/merkleChainService.js';
import { SigmaRuleLoader } from './correlation/loader.js';
import { RuleEvaluator } from './correlation/evaluator.js';
import { Enricher } from './correlation/enrichment.js';
import { DefaultReferenceData, DEMO_REFERENCE_CONFIG } from './correlation/enrichmentReferenceData.js';
import { loadReferenceConfigFile, mergeReferenceConfig } from './correlation/enrichmentReferenceFile.js';
import { CorrelationScheduler, DEFAULT_SCHEDULER_CONFIG } from './correlation/scheduler.js';
import { buildServer } from './server.js';
import type { SigmaRule } from './domain/entities/sigmaRule.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const log = createLogger(config);
  const metrics = new Metrics();

  // ---- adapters
  const pgPool = createPool(config);
  const opensearch = createOpenSearchClient(config);
  const blobs = new MinioBlobStore(config);
  // Hash-chain signer: Vault Transit in production (private key stays in Vault),
  // soft on-disk key for dev/MVP. Verification is public-key-local either way.
  const signer: Signer =
    config.hashchain.signer === 'vault'
      ? new VaultTransitSigner({
          addr: config.hashchain.vaultAddr!,
          token: config.hashchain.vaultToken!,
          transitKey: config.hashchain.vaultTransitKey,
          ...(config.hashchain.vaultNamespace ? { namespace: config.hashchain.vaultNamespace } : {}),
        })
      : new FileEd25519Signer(config.hashchain.signingKeyPath);
  log.info({ signer: config.hashchain.signer }, 'hash-chain signer selected');

  const alertRepo = new OpenSearchAlertRepository(opensearch);
  await alertRepo.ensureIndex();
  const eventStore = new OpenSearchEventStore(opensearch);
  // Enrichment runs at the correlation (read/eval) boundary, not at write: raw
  // shippers write straight to surf-events-*, so computing surf.enrichment.*
  // (R-02/04/10/13/15) as the scheduler reads the window is what makes those
  // rules fire on real telemetry. Reference data is demo-seeded; a JSON file at
  // ENRICHMENT_REFERENCE_PATH overrides it per top-level key (docs/INGEST.md).
  const referencePath = config.enrichment.referencePath;
  const referenceConfig =
    referencePath !== undefined
      ? mergeReferenceConfig(DEMO_REFERENCE_CONFIG, await loadReferenceConfigFile(referencePath))
      : DEMO_REFERENCE_CONFIG;
  log.info(
    {
      source: referencePath !== undefined ? 'file' : 'demo',
      ...(referencePath !== undefined ? { path: referencePath } : {}),
      allowlistCidrs: referenceConfig.allowlistCidrs.length,
    },
    'enrichment reference data loaded',
  );
  const enrichmentRefs = new DefaultReferenceData(referenceConfig);
  const enricher = new Enricher(enrichmentRefs);
  const caseRepo = new PostgresCaseRepository(pgPool);
  const auditRepo = new PostgresAuditRepository(pgPool);
  const runRepo = new PostgresPlaybookRunRepository(pgPool);
  const ledgerRepo = new PostgresHashchainRepository(pgPool);
  const savedQueryRepo = new PostgresSavedQueryRepository(pgPool);
  const ruleStateRepo = new PostgresRuleStateRepository(pgPool);

  const keycloak = new HttpKeycloakConnector(config, log);
  const ems = new HttpEmsConnector(config, log);
  const flex = new HttpFlexConnector(config, log);
  const wazuh = new HttpWazuhConnector(config, log);
  const pager = new PagerDutyConnector(config, log);
  const slack = new SlackConnector(config.alerting.slackWebhookUrl, log);
  void flex; // reserved for enrichment lookups; wired to keep the connector hot-tested
  void slack;

  // ---- rules
  const schema = await SigmaRuleLoader.loadSchema(config.rulesDir);
  const loader = new SigmaRuleLoader(config.rulesDir, schema, log);
  const rules: SigmaRule[] = await loader.loadAll();
  const evaluator = new RuleEvaluator();

  // ---- services
  const audit = new AuditService(auditRepo, log);
  const alertService = new AlertService(alertRepo, eventStore, audit);
  const caseService = new CaseService(caseRepo, alertRepo, audit);
  const investigateService = new InvestigateService(eventStore, savedQueryRepo);
  const playbookService = new PlaybookService(runRepo, keycloak, ems, pager, audit, {
    dryRunDefault: config.playbooks.dryRunDefault,
    massActionThreshold: config.playbooks.massActionThreshold,
    requireStepUp: config.playbooks.requireStepUp,
  });
  const ruleService = new RuleService(() => rules, ruleStateRepo, evaluator, audit, true);
  const reportService = new ReportService(caseRepo, eventStore, ledgerRepo, blobs, audit, {
    auditBucket: config.minio.bucketAudit,
    presignExpirySeconds: config.presignExpirySeconds,
    requireStepUp: true,
  });
  const here = path.dirname(fileURLToPath(import.meta.url));
  const nis2Service = new Nis2Service(
    caseRepo,
    blobs,
    audit,
    {
      auditBucket: config.minio.bucketAudit,
      templatesDir: path.join(here, 'compliance', 'nis2Templates'),
      presignExpirySeconds: config.presignExpirySeconds,
      requireStepUp: true,
    },
    log,
  );
  const gdprService = new GdprService(eventStore, blobs, audit, {
    auditBucket: config.minio.bucketAudit,
    presignExpirySeconds: config.presignExpirySeconds,
  });
  const merkleChain = new MerkleChainService(
    eventStore,
    ledgerRepo,
    blobs,
    signer,
    {
      hashchainBucket: config.minio.bucketHashchain,
      rollupIntervalMinutes: config.hashchain.rollupIntervalMinutes,
    },
    log,
    (success) => metrics.hashchainRollups.inc({ outcome: success ? 'success' : 'failure' }),
  );

  const scheduler = new CorrelationScheduler(
    () => rules,
    ruleStateRepo,
    eventStore,
    alertRepo,
    evaluator,
    DEFAULT_SCHEDULER_CONFIG,
    log,
    (ruleId, count) => metrics.ruleFired.inc({ rule_id: ruleId }, count),
    { enricher, refs: enrichmentRefs },
  );

  // ---- HTTP
  const app = await buildServer(
    {
      config,
      authz: new AuthzMiddleware(config),
      metrics,
      alertService,
      caseService,
      investigateService,
      playbookService,
      ruleService,
      reportService,
      nis2Service,
      gdprService,
      merkleChain,
      auditRepo,
      eventStore,
      wazuh,
      pgPool,
      opensearch,
      minioReady: () => blobs.exists(config.minio.bucketAudit, '.keep').then(() => true).catch(() => false),
    },
    log,
  );

  scheduler.start();
  merkleChain.start();

  const shutdown = async (signal: string): Promise<void> => {
    log.info({ signal }, 'shutting down');
    scheduler.stop();
    merkleChain.stop();
    await app.close();
    await pgPool.end();
    await stopOtel();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ port: config.port, host: '0.0.0.0' });
  log.info({ port: config.port, rules: rules.length }, 'SURF Security Companion backend up');
}

main().catch((err) => {
  // logger may not exist yet (console.error is allowed by the lint config)
  console.error('fatal startup error:', err);
  process.exit(1);
});
