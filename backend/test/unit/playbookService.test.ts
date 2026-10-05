import { describe, it, expect, beforeEach } from 'vitest';
import { pino } from 'pino';
import { PlaybookService } from '../../src/application/playbooks/playbookService.js';
import { AuditService } from '../../src/application/audit/auditService.js';
import { StepUpRequiredError, ForbiddenError } from '../../src/application/errors.js';
import type { PlaybookRun } from '../../src/domain/entities/playbookRun.js';
import type { PlaybookRunRepository, AuditRepository } from '../../src/domain/ports/repositories.js';
import type { EmsConnector, KeycloakConnector, Pager } from '../../src/domain/ports/connectors.js';
import type { CallerContext } from '../../src/application/context.js';

const log = pino({ level: 'silent' });

function inMemoryRuns(): PlaybookRunRepository {
  const runs = new Map<string, PlaybookRun>();
  let last: string | undefined;
  return {
    create: async (r) => {
      runs.set(r.id, r);
      last = r.hash;
      return r;
    },
    getById: async (id) => runs.get(id),
    list: async ({ limit }) => [...runs.values()].slice(0, limit),
    update: async (r) => {
      runs.set(r.id, r);
      return r;
    },
    lastHash: async () => last,
  };
}

const auditRepo: AuditRepository = {
  append: async (a) => ({ ...a, hash: 'h' }),
  list: async () => [],
  lastHash: async () => undefined,
};

const keycloak: KeycloakConnector = {
  revokeToken: async (tokenId, dryRun) => ({ tokenId, priorState: { dryRun } }),
  listSessions: async () => [],
};

const ems: EmsConnector = {
  quarantine: async (emsId) => ({ emsId, quarantined: true, reversible: true, priorMode: 'normal' }),
  resetQuarantine: async (emsId) => ({ emsId, quarantined: false, reversible: true, priorMode: 'quarantine' }),
  status: async (emsId) => ({ emsId, mode: 'normal', firmware: '1.0.0' }),
};

function makePager(): Pager & { calls: number } {
  return { calls: 0, async page() { this.calls += 1; } };
}

const analyst = (mfa: boolean): CallerContext => ({
  userId: 'u1',
  username: 'anna.analyst',
  roles: ['SOC_ANALYST'],
  requestId: 'r1',
  mfaVerified: mfa,
});
const admin = (name: string, mfa = true): CallerContext => ({
  userId: name,
  username: name,
  roles: ['PLATFORM_ADMIN'],
  requestId: 'r2',
  mfaVerified: mfa,
});

describe('PlaybookService (safe-mode)', () => {
  let runs: PlaybookRunRepository;
  let pager: ReturnType<typeof makePager>;
  let audit: AuditService;

  beforeEach(() => {
    runs = inMemoryRuns();
    pager = makePager();
    audit = new AuditService(auditRepo, log);
  });

  const config = { dryRunDefault: true, massActionThreshold: 10, requireStepUp: true };

  it('requires step-up MFA to run', async () => {
    const svc = new PlaybookService(runs, keycloak, ems, pager, audit, config);
    await expect(svc.revokeToken(analyst(false), { tokenIds: ['t1'], reason: 'test' })).rejects.toBeInstanceOf(
      StepUpRequiredError,
    );
  });

  it('defaults to dry-run and executes immediately below the mass threshold', async () => {
    const svc = new PlaybookService(runs, keycloak, ems, pager, audit, config);
    const run = await svc.revokeToken(analyst(true), { tokenIds: ['t1', 't2'], reason: 'test' });
    expect(run.dryRun).toBe(true);
    expect(run.status).toBe('EXECUTED');
    expect(pager.calls).toBe(0);
  });

  it('parks a real mass action in REQUESTED and pages on-call (four-eyes)', async () => {
    const svc = new PlaybookService(runs, keycloak, ems, pager, audit, config);
    const many = Array.from({ length: 15 }, (_, i) => `t${i}`);
    const run = await svc.revokeToken(admin('petra'), { tokenIds: many, reason: 'mass', dryRun: false });
    expect(run.status).toBe('REQUESTED');
    expect(pager.calls).toBe(1);
  });

  it('rejects self-approval (requester != approver)', async () => {
    const svc = new PlaybookService(runs, keycloak, ems, pager, audit, config);
    const many = Array.from({ length: 15 }, (_, i) => `t${i}`);
    const run = await svc.revokeToken(admin('petra'), { tokenIds: many, reason: 'mass', dryRun: false });
    await expect(svc.approve(admin('petra'), run.id)).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('executes after a different admin approves', async () => {
    const svc = new PlaybookService(runs, keycloak, ems, pager, audit, config);
    const many = Array.from({ length: 15 }, (_, i) => `t${i}`);
    const requested = await svc.revokeToken(admin('petra'), { tokenIds: many, reason: 'mass', dryRun: false });
    const executed = await svc.approve(admin('axel'), requested.id);
    expect(executed.status).toBe('EXECUTED');
    expect(executed.approver).toBe('axel');
  });

  it('quarantine exposes a reversible reset path', async () => {
    const svc = new PlaybookService(runs, keycloak, ems, pager, audit, config);
    const run = await svc.quarantineEms(analyst(true), { emsIds: ['ems-1'], reason: 'contain', reset: true, dryRun: false });
    expect(run.status).toBe('EXECUTED');
    expect((run.result as { devices: Array<{ quarantined: boolean }> }).devices[0]?.quarantined).toBe(false);
  });

  it('hash-chains consecutive runs', async () => {
    const svc = new PlaybookService(runs, keycloak, ems, pager, audit, config);
    const r1 = await svc.revokeToken(analyst(true), { tokenIds: ['t1'], reason: 'one' });
    const r2 = await svc.revokeToken(analyst(true), { tokenIds: ['t2'], reason: 'two' });
    expect(r2.prevHash).toBe(r1.hash);
  });
});
