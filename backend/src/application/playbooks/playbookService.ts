import { createHash } from 'node:crypto';
import type { PlaybookName, PlaybookRun, PlaybookRunStatus } from '../../domain/entities/playbookRun.js';
import { canApprove, requiresFourEyes } from '../../domain/entities/playbookRun.js';
import type { PlaybookRunRepository } from '../../domain/ports/repositories.js';
import type { EmsConnector, KeycloakConnector, Pager } from '../../domain/ports/connectors.js';
import type { CallerContext } from '../context.js';
import type { AuditService } from '../audit/auditService.js';
import { ForbiddenError, NotFoundError, StepUpRequiredError, ValidationError } from '../errors.js';

export interface PlaybookConfig {
  dryRunDefault: boolean;
  massActionThreshold: number;
  requireStepUp: boolean;
}

export interface RevokeTokenInput {
  tokenIds: string[];
  reason: string;
  caseId?: string;
  dryRun?: boolean;
}

export interface QuarantineEmsInput {
  emsIds: string[];
  reason: string;
  caseId?: string;
  dryRun?: boolean;
  /** Reversal path: lift an existing quarantine instead of imposing one. */
  reset?: boolean;
}

/**
 * Safe-mode SOAR. Hard guards, in order:
 *  1. dry-run defaults ON — real execution must be requested explicitly;
 *  2. step-up MFA required for any run (dry or real) when configured;
 *  3. four-eyes on mass actions: run parks in REQUESTED and pages on-call;
 *  4. every step audited and hash-chained;
 *  5. reversibility: quarantine has reset; revocation records prior state.
 */
export class PlaybookService {
  constructor(
    private readonly runs: PlaybookRunRepository,
    private readonly keycloak: KeycloakConnector,
    private readonly ems: EmsConnector,
    private readonly pager: Pager,
    private readonly audit: AuditService,
    private readonly config: PlaybookConfig,
  ) {}

  private assertStepUp(caller: CallerContext): void {
    if (this.config.requireStepUp && !caller.mfaVerified) throw new StepUpRequiredError();
  }

  private runHash(run: Omit<PlaybookRun, 'hash'>, prevHash: string | undefined): string {
    const canonical = JSON.stringify({
      id: run.id,
      ts: run.ts,
      playbook: run.playbook,
      actor: run.actor,
      dryRun: run.dryRun,
      target: run.target,
      reason: run.reason,
      status: run.status,
      prevHash: prevHash ?? null,
    });
    return createHash('sha256').update(canonical).digest('hex');
  }

  private async createRun(
    caller: CallerContext,
    playbook: PlaybookName,
    target: Record<string, unknown>,
    targetCount: number,
    reason: string,
    dryRun: boolean,
    caseId?: string,
  ): Promise<PlaybookRun> {
    const prevHash = await this.runs.lastHash();
    const status: PlaybookRunStatus =
      !dryRun && requiresFourEyes(targetCount, this.config.massActionThreshold) ? 'REQUESTED' : 'APPROVED';
    const base: Omit<PlaybookRun, 'hash'> = {
      id: crypto.randomUUID(),
      ts: new Date().toISOString(),
      playbook,
      actor: caller.username,
      dryRun,
      target,
      reason,
      ...(caseId !== undefined ? { caseId } : {}),
      status,
      ...(prevHash !== undefined ? { prevHash } : {}),
      ...(caller.tenantId !== undefined ? { tenantId: caller.tenantId } : {}),
      targetCount,
    };
    return this.runs.create({ ...base, hash: this.runHash(base, prevHash) });
  }

  async revokeToken(caller: CallerContext, input: RevokeTokenInput): Promise<PlaybookRun> {
    this.assertStepUp(caller);
    if (input.tokenIds.length === 0) throw new ValidationError('tokenIds must not be empty');
    if (!input.reason.trim()) throw new ValidationError('reason is required');
    const dryRun = input.dryRun ?? this.config.dryRunDefault;

    const run = await this.createRun(
      caller,
      'REVOKE_TOKEN',
      { tokenIds: input.tokenIds },
      input.tokenIds.length,
      input.reason,
      dryRun,
      input.caseId,
    );

    if (run.status === 'REQUESTED') {
      await this.pageForApproval(run);
      await this.audit.record(caller, {
        action: 'playbook.revoke-token.requested',
        resourceType: 'playbook_run',
        resourceId: run.id,
        outcome: 'success',
        details: { targetCount: run.targetCount, dryRun },
      });
      return run;
    }
    return this.executeRevokeToken(caller, run);
  }

  async quarantineEms(caller: CallerContext, input: QuarantineEmsInput): Promise<PlaybookRun> {
    this.assertStepUp(caller);
    if (input.emsIds.length === 0) throw new ValidationError('emsIds must not be empty');
    if (!input.reason.trim()) throw new ValidationError('reason is required');
    const dryRun = input.dryRun ?? this.config.dryRunDefault;

    const run = await this.createRun(
      caller,
      'QUARANTINE_EMS',
      { emsIds: input.emsIds, reset: input.reset ?? false },
      input.emsIds.length,
      input.reason,
      dryRun,
      input.caseId,
    );

    if (run.status === 'REQUESTED') {
      await this.pageForApproval(run);
      await this.audit.record(caller, {
        action: 'playbook.quarantine-ems.requested',
        resourceType: 'playbook_run',
        resourceId: run.id,
        outcome: 'success',
        details: { targetCount: run.targetCount, dryRun },
      });
      return run;
    }
    return this.executeQuarantineEms(caller, run);
  }

  async approve(caller: CallerContext, runId: string): Promise<PlaybookRun> {
    this.assertStepUp(caller);
    if (!caller.roles.includes('PLATFORM_ADMIN')) {
      throw new ForbiddenError('Only PLATFORM_ADMIN may approve playbook runs');
    }
    const run = await this.runs.getById(runId);
    if (!run) throw new NotFoundError('PlaybookRun', runId);
    if (!canApprove(run, caller.username)) {
      throw new ForbiddenError('Run is not pending approval or approver equals requester (four-eyes)', {
        status: run.status,
        actor: run.actor,
      });
    }
    const approved = await this.runs.update({ ...run, status: 'APPROVED', approver: caller.username });
    await this.audit.record(caller, {
      action: 'playbook.approve',
      resourceType: 'playbook_run',
      resourceId: runId,
      outcome: 'success',
      details: { requester: run.actor },
    });
    return run.playbook === 'REVOKE_TOKEN'
      ? this.executeRevokeToken(caller, approved)
      : this.executeQuarantineEms(caller, approved);
  }

  async reject(caller: CallerContext, runId: string, reason: string): Promise<PlaybookRun> {
    if (!caller.roles.includes('PLATFORM_ADMIN')) {
      throw new ForbiddenError('Only PLATFORM_ADMIN may reject playbook runs');
    }
    const run = await this.runs.getById(runId);
    if (!run) throw new NotFoundError('PlaybookRun', runId);
    if (run.status !== 'REQUESTED') {
      throw new ValidationError(`run is ${run.status}, only REQUESTED runs can be rejected`);
    }
    const rejected = await this.runs.update({
      ...run,
      status: 'REJECTED',
      approver: caller.username,
      result: { rejectedReason: reason },
    });
    await this.audit.record(caller, {
      action: 'playbook.reject',
      resourceType: 'playbook_run',
      resourceId: runId,
      outcome: 'success',
      details: { reason },
    });
    return rejected;
  }

  async list(filter: { status?: PlaybookRunStatus; limit: number }): Promise<PlaybookRun[]> {
    return this.runs.list(filter);
  }

  private async executeRevokeToken(caller: CallerContext, run: PlaybookRun): Promise<PlaybookRun> {
    const tokenIds = (run.target['tokenIds'] as string[] | undefined) ?? [];
    const results: unknown[] = [];
    try {
      for (const tokenId of tokenIds) {
        results.push(await this.keycloak.revokeToken(tokenId, run.dryRun));
      }
      const executed = await this.runs.update({ ...run, status: 'EXECUTED', result: { revocations: results } });
      await this.audit.record(caller, {
        action: 'playbook.revoke-token.executed',
        resourceType: 'playbook_run',
        resourceId: run.id,
        outcome: 'success',
        details: { dryRun: run.dryRun, count: tokenIds.length },
      });
      return executed;
    } catch (err) {
      const failed = await this.runs.update({
        ...run,
        status: 'FAILED',
        result: { error: err instanceof Error ? err.message : String(err), partial: results },
      });
      await this.audit.record(caller, {
        action: 'playbook.revoke-token.executed',
        resourceType: 'playbook_run',
        resourceId: run.id,
        outcome: 'failure',
        details: { dryRun: run.dryRun },
      });
      return failed;
    }
  }

  private async executeQuarantineEms(caller: CallerContext, run: PlaybookRun): Promise<PlaybookRun> {
    const emsIds = (run.target['emsIds'] as string[] | undefined) ?? [];
    const reset = run.target['reset'] === true;
    const results: unknown[] = [];
    try {
      for (const emsId of emsIds) {
        results.push(
          reset ? await this.ems.resetQuarantine(emsId, run.dryRun) : await this.ems.quarantine(emsId, run.dryRun),
        );
      }
      const executed = await this.runs.update({ ...run, status: 'EXECUTED', result: { devices: results } });
      await this.audit.record(caller, {
        action: `playbook.quarantine-ems.${reset ? 'reset' : 'executed'}`,
        resourceType: 'playbook_run',
        resourceId: run.id,
        outcome: 'success',
        details: { dryRun: run.dryRun, count: emsIds.length, reset },
      });
      return executed;
    } catch (err) {
      const failed = await this.runs.update({
        ...run,
        status: 'FAILED',
        result: { error: err instanceof Error ? err.message : String(err), partial: results },
      });
      await this.audit.record(caller, {
        action: 'playbook.quarantine-ems.executed',
        resourceType: 'playbook_run',
        resourceId: run.id,
        outcome: 'failure',
        details: { dryRun: run.dryRun },
      });
      return failed;
    }
  }

  private async pageForApproval(run: PlaybookRun): Promise<void> {
    // Paging is best-effort: the run is already parked in REQUESTED and remains
    // approvable in the UI. A pager outage (or an unconfigured routing key) must
    // not turn the request into a 5xx after the state change was persisted; the
    // ResilientHttpClient has already logged the delivery failure.
    try {
      await this.pager.page(
        `Playbook ${run.playbook} awaiting four-eyes approval (${run.targetCount} targets)`,
        'warning',
        { runId: run.id, actor: run.actor, reason: run.reason, dryRun: run.dryRun },
      );
    } catch {
      /* logged by the http client */
    }
  }
}
