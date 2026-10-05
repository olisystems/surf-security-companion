import { describe, it, expect } from 'vitest';
import { pino } from 'pino';
import { AlertService } from '../../src/application/alerts/alertService.js';
import { AuditService } from '../../src/application/audit/auditService.js';
import { ForbiddenError, InvalidTransitionError, NotFoundError } from '../../src/application/errors.js';
import type { Alert } from '../../src/domain/entities/alert.js';
import type { AlertRepository, EventStore } from '../../src/domain/ports/repositories.js';
import type { CallerContext } from '../../src/application/context.js';

const log = pino({ level: 'silent' });

function sampleAlert(over: Partial<Alert> = {}): Alert {
  return {
    id: 'a1',
    ts: '2026-07-14T10:00:00Z',
    severity: 'high',
    ruleId: 'rule-1',
    ruleTitle: 'Test',
    description: 'd',
    source: { system: 'keycloak' },
    tenantId: 'vnb-saar',
    attack: {},
    artifacts: [],
    correlatedEventIds: [],
    status: 'NEW',
    count: 1,
    firstSeen: '2026-07-14T10:00:00Z',
    lastSeen: '2026-07-14T10:00:00Z',
    ...over,
  };
}

function inMemoryAlerts(seed: Alert[]): AlertRepository {
  const store = new Map(seed.map((a) => [a.id, a]));
  return {
    list: async () => ({ items: [...store.values()], total: store.size }),
    getById: async (id, tenantId) => {
      const a = store.get(id);
      if (!a) return undefined;
      if (tenantId !== undefined && a.tenantId !== tenantId) return undefined;
      return a;
    },
    upsert: async (a) => void store.set(a.id, a),
    setStatus: async (id, status) => {
      const a = store.get(id)!;
      const next = { ...a, status };
      store.set(id, next);
      return next;
    },
    linkCase: async (ids, caseId) => {
      for (const id of ids) if (store.has(id)) store.set(id, { ...store.get(id)!, caseId });
      return ids.length;
    },
    assign: async (ids, assignee) => {
      for (const id of ids) if (store.has(id)) store.set(id, { ...store.get(id)!, assignee });
      return ids.length;
    },
    findByFingerprint: async () => undefined,
    countByRuleSince: async () => new Map(),
  };
}

const events = { eventsByIds: async () => [] } as unknown as EventStore;
const audit = new AuditService(
  { append: async (a) => ({ ...a, hash: 'h' }), list: async () => [], lastHash: async () => undefined },
  log,
);

const analyst: CallerContext = { userId: 'u', username: 'anna', roles: ['SOC_ANALYST'], requestId: 'r', mfaVerified: false };
const dso: CallerContext = { userId: 'u2', username: 'dirk', roles: ['DSO_OPERATOR'], tenantId: 'vnb-saar', requestId: 'r', mfaVerified: false };
const dsoOther: CallerContext = { userId: 'u3', username: 'dora', roles: ['DSO_OPERATOR'], tenantId: 'vnb-pfalz', requestId: 'r', mfaVerified: false };
const auditor: CallerContext = { userId: 'u4', username: 'alice', roles: ['AUDITOR'], requestId: 'r', mfaVerified: false };

describe('AlertService', () => {
  it('enforces legal status transitions', async () => {
    const svc = new AlertService(inMemoryAlerts([sampleAlert()]), events, audit);
    await expect(svc.setStatus(analyst, 'a1', 'RESOLVED')).rejects.toBeInstanceOf(InvalidTransitionError);
    const acked = await svc.setStatus(analyst, 'a1', 'ACKNOWLEDGED');
    expect(acked.status).toBe('ACKNOWLEDGED');
  });

  it('blocks read-only roles from mutating', async () => {
    const svc = new AlertService(inMemoryAlerts([sampleAlert()]), events, audit);
    await expect(svc.setStatus(auditor, 'a1', 'ACKNOWLEDGED')).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('hides other-tenant alerts from tenant-scoped callers', async () => {
    const svc = new AlertService(inMemoryAlerts([sampleAlert({ tenantId: 'vnb-saar' })]), events, audit);
    await expect(svc.getById(dsoOther, 'a1')).rejects.toBeInstanceOf(NotFoundError);
    await expect(svc.getById(dso, 'a1')).resolves.toMatchObject({ id: 'a1' });
  });

  it('rejects empty bulk id sets', async () => {
    const svc = new AlertService(inMemoryAlerts([sampleAlert()]), events, audit);
    await expect(svc.bulk(analyst, { action: 'ack', ids: [] })).rejects.toThrow();
  });
});
