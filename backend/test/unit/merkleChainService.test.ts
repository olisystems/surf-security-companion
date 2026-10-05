import { describe, it, expect } from 'vitest';
import { pino } from 'pino';
import { MerkleChainService } from '../../src/application/merkleChain/merkleChainService.js';
import type { EventStore, HashchainRepository } from '../../src/domain/ports/repositories.js';
import type { BlobStore, Signer } from '../../src/domain/ports/connectors.js';
import type { HashchainLedgerEntry } from '../../src/domain/entities/auditAction.js';

function fakeSigner(): Signer {
  // Deterministic fake: signature = reversed message bytes; verify checks that.
  return {
    sign: async (m) => Uint8Array.from([...m].reverse()),
    publicKeyHex: async () => 'pub',
    verify: async (m, s) => Buffer.compare(Buffer.from([...m].reverse()), Buffer.from(s)) === 0,
  };
}

function fakeStores() {
  const ledger: HashchainLedgerEntry[] = [];
  const events = new Map<string, Array<{ id: string; contentHash: string; bytes: number }>>();
  const worm = new Map<string, Buffer>();

  const eventStore = {
    eventsInHour: async (hour: string) => events.get(hour) ?? [],
  } as unknown as EventStore;

  const ledgerRepo: HashchainRepository = {
    append: async (e) => void ledger.push(e),
    latest: async () => ledger[ledger.length - 1],
    range: async (from, to) => ledger.filter((e) => e.hour >= from && e.hour <= to),
  };

  const blobs = {
    putWorm: async (_b: string, key: string, body: Buffer) => {
      worm.set(key, body);
      return { etag: 'x' };
    },
    presignedGetUrl: async () => 'url',
    get: async () => Buffer.from(''),
    exists: async () => true,
  } as unknown as BlobStore;

  return { ledger, events, worm, eventStore, ledgerRepo, blobs };
}

describe('MerkleChainService', () => {
  const log = pino({ level: 'silent' });
  const config = { hashchainBucket: 'hc', rollupIntervalMinutes: 60 };

  it('links each rollup to the previous root and stores to WORM + ledger', async () => {
    const { ledger, events, worm, eventStore, ledgerRepo, blobs } = fakeStores();
    events.set('2026-07-14T08:00:00Z', [{ id: 'e1', contentHash: 'h1', bytes: 10 }]);
    events.set('2026-07-14T09:00:00Z', [{ id: 'e2', contentHash: 'h2', bytes: 20 }]);
    const svc = new MerkleChainService(eventStore, ledgerRepo, blobs, fakeSigner(), config, log);

    const first = await svc.rollupHour('2026-07-14T08:00:00Z');
    const second = await svc.rollupHour('2026-07-14T09:00:00Z');

    expect(first.prevRoot).toBeUndefined();
    expect(second.prevRoot).toBe(first.root);
    expect(second.prevHour).toBe(first.hour);
    expect(ledger).toHaveLength(2);
    expect(worm.size).toBe(2);
  });

  it('verify() passes for an untampered chain', async () => {
    const { events, eventStore, ledgerRepo, blobs } = fakeStores();
    events.set('2026-07-14T08:00:00Z', [{ id: 'e1', contentHash: 'h1', bytes: 10 }]);
    const svc = new MerkleChainService(eventStore, ledgerRepo, blobs, fakeSigner(), config, log);
    await svc.rollupHour('2026-07-14T08:00:00Z');

    const result = await svc.verify('2026-07-14T00:00:00Z', '2026-07-14T23:00:00Z');
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(1);
  });

  it('verify() detects a tampered event (root mismatch)', async () => {
    const { events, eventStore, ledgerRepo, blobs } = fakeStores();
    events.set('2026-07-14T08:00:00Z', [{ id: 'e1', contentHash: 'h1', bytes: 10 }]);
    const svc = new MerkleChainService(eventStore, ledgerRepo, blobs, fakeSigner(), config, log);
    await svc.rollupHour('2026-07-14T08:00:00Z');

    // Tamper: mutate the event content after the rollup was signed.
    events.set('2026-07-14T08:00:00Z', [{ id: 'e1', contentHash: 'TAMPERED', bytes: 10 }]);

    const result = await svc.verify('2026-07-14T00:00:00Z', '2026-07-14T23:00:00Z');
    expect(result.ok).toBe(false);
    expect(result.failures[0]?.reason).toContain('root mismatch');
  });

  it('previousHourBucket floors to the prior hour in UTC', () => {
    const bucket = MerkleChainService.previousHourBucket(new Date('2026-07-14T09:37:12.500Z'));
    expect(bucket).toBe('2026-07-14T08:00:00Z');
  });

  it('rollupDue() back-fills every missed hour so a transient failure self-heals', async () => {
    const { ledger, events, eventStore, ledgerRepo, blobs } = fakeStores();
    for (const h of ['08', '09', '10']) {
      events.set(`2026-07-14T${h}:00:00Z`, [{ id: `e${h}`, contentHash: `h${h}`, bytes: 10 }]);
    }
    const svc = new MerkleChainService(eventStore, ledgerRepo, blobs, fakeSigner(), config, log);

    // Only 08:00 got notarised (09:00 "failed"); the scheduler is now at 11:30.
    await svc.rollupHour('2026-07-14T08:00:00Z');
    await svc.rollupDue(new Date('2026-07-14T11:30:00Z')); // previous hour = 10:00

    expect(ledger.map((e) => e.hour)).toEqual([
      '2026-07-14T08:00:00Z',
      '2026-07-14T09:00:00Z',
      '2026-07-14T10:00:00Z',
    ]);
    const result = await svc.verify('2026-07-14T00:00:00Z', '2026-07-14T23:00:00Z');
    expect(result.ok).toBe(true); // contiguous, linked, no gap
  });

  it('verify() detects a missing hour (gap) even though linkage still holds', async () => {
    const { events, eventStore, ledgerRepo, blobs } = fakeStores();
    events.set('2026-07-14T08:00:00Z', [{ id: 'e1', contentHash: 'h1', bytes: 10 }]);
    events.set('2026-07-14T10:00:00Z', [{ id: 'e3', contentHash: 'h3', bytes: 10 }]);
    const svc = new MerkleChainService(eventStore, ledgerRepo, blobs, fakeSigner(), config, log);

    // 09:00 was never notarised; 10:00 links straight to 08:00.
    await svc.rollupHour('2026-07-14T08:00:00Z');
    await svc.rollupHour('2026-07-14T10:00:00Z');

    const result = await svc.verify('2026-07-14T00:00:00Z', '2026-07-14T23:00:00Z');
    expect(result.ok).toBe(false);
    expect(result.failures.some((f) => f.reason.startsWith('gap'))).toBe(true);
  });
});
