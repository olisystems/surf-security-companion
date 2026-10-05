import type { AlertService } from '../../application/alerts/alertService.js';
import type { CaseService } from '../../application/cases/caseService.js';
import type { InvestigateService } from '../../application/investigate/investigateService.js';
import type { PlaybookService } from '../../application/playbooks/playbookService.js';
import type { RuleService } from '../../application/rules/ruleService.js';
import type { ReportService } from '../../application/reports/reportService.js';
import type { Nis2Service } from '../../application/nis2/nis2Service.js';
import type { GdprService } from '../../application/gdpr/gdprService.js';
import type { MerkleChainService } from '../../application/merkleChain/merkleChainService.js';
import type { AuditRepository, EventStore } from '../../domain/ports/repositories.js';
import type { WazuhConnector } from '../../domain/ports/connectors.js';
import type { AuthzMiddleware } from './middleware/authz.js';
import type { Metrics } from '../telemetry/prom.js';
import type { AppConfig } from '../config.js';
import type pg from 'pg';
import type { Client as OpenSearchClient } from '@opensearch-project/opensearch';

/** Everything the route layer needs, assembled once in main.ts (composition root). */
export interface AppDeps {
  config: AppConfig;
  authz: AuthzMiddleware;
  metrics: Metrics;
  alertService: AlertService;
  caseService: CaseService;
  investigateService: InvestigateService;
  playbookService: PlaybookService;
  ruleService: RuleService;
  reportService: ReportService;
  nis2Service: Nis2Service;
  gdprService: GdprService;
  merkleChain: MerkleChainService;
  auditRepo: AuditRepository;
  eventStore: EventStore;
  wazuh: WazuhConnector;
  pgPool: pg.Pool;
  opensearch: OpenSearchClient;
  minioReady: () => Promise<boolean>;
}
