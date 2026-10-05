import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ReferenceFileError,
  loadReferenceConfigFile,
  mergeReferenceConfig,
  parseReferenceFile,
} from '../../src/correlation/enrichmentReferenceFile.js';
import { DefaultReferenceData, DEMO_REFERENCE_CONFIG } from '../../src/correlation/enrichmentReferenceData.js';

/**
 * ENRICHMENT_REFERENCE_PATH contract: a JSON file overrides the demo reference
 * data per top-level key, is validated at startup (fail fast, readable report),
 * and the shipped example file is itself valid.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const examplePath = path.resolve(here, '../../../observability/enrichment-reference.example.json');

let dir: string;
beforeAll(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'surf-refs-'));
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function tmpFile(name: string, content: string): Promise<string> {
  const p = path.join(dir, name);
  await writeFile(p, content, 'utf8');
  return p;
}

describe('mergeReferenceConfig', () => {
  it('file wins per top-level key, absent keys keep the demo value', () => {
    const merged = mergeReferenceConfig(DEMO_REFERENCE_CONFIG, { allowlistCidrs: ['203.0.113.0/24'], geo: {} });
    expect(merged.allowlistCidrs).toEqual(['203.0.113.0/24']);
    expect(merged.geo).toEqual({});
    expect(merged.changeWindows).toBe(DEMO_REFERENCE_CONFIG.changeWindows);
    expect(merged.tenantByUser).toBe(DEMO_REFERENCE_CONFIG.tenantByUser);
    expect(merged.firmwareBaseline).toBe(DEMO_REFERENCE_CONFIG.firmwareBaseline);
  });

  it('an empty file leaves the demo config intact', () => {
    expect(mergeReferenceConfig(DEMO_REFERENCE_CONFIG, {})).toEqual(DEMO_REFERENCE_CONFIG);
  });

  it('the merged allow-list drives the enricher (demo subnets are replaced, not extended)', () => {
    const merged = mergeReferenceConfig(DEMO_REFERENCE_CONFIG, { allowlistCidrs: ['217.244.216.71/32'] });
    const refs = new DefaultReferenceData(merged);
    expect(refs.allowlist.allows('217.244.216.71')).toBe(true);
    expect(refs.allowlist.allows('10.0.4.12')).toBe(false); // demo 10/8 no longer applies
  });
});

describe('loadReferenceConfigFile', () => {
  it('loads and validates a well-formed file', async () => {
    const p = await tmpFile('ok.json', JSON.stringify({
      allowlistCidrs: ['178.104.103.16/32', '10.0.0.0/8'],
      geo: { '203.0.113.66': { lat: 49.24, lon: 6.99, label: 'Saarbrücken' } },
      changeWindows: [{ startIso: '2026-10-05T22:00:00Z', endIso: '2026-10-05T23:00:00Z' }],
      tenantByUser: { 'dirk.dso': 'vnb-saar' },
      firmwareBaseline: { 'ems-0815': '2.4.0' },
    }));
    const cfg = await loadReferenceConfigFile(p);
    expect(cfg.allowlistCidrs).toEqual(['178.104.103.16/32', '10.0.0.0/8']);
    expect(cfg.geo?.['203.0.113.66']?.label).toBe('Saarbrücken');
  });

  it('the shipped example file is valid and carries the admin/server addresses', async () => {
    const cfg = await loadReferenceConfigFile(examplePath);
    expect(cfg.allowlistCidrs).toEqual(
      expect.arrayContaining(['217.244.216.71/32', '91.53.165.129/32', '178.104.103.16/32', '178.105.200.25/32']),
    );
    expect(cfg.geo).toEqual({});
  });

  it('fails fast with a readable report on an invalid CIDR and an unknown key', async () => {
    const p = await tmpFile('bad.json', JSON.stringify({ allowlistCidrs: ['not-an-ip', '10.0.0.0/33'], allowList: [] }));
    await expect(loadReferenceConfigFile(p)).rejects.toThrow(ReferenceFileError);
    await expect(loadReferenceConfigFile(p)).rejects.toThrow(/allowlistCidrs\.0: expected IPv4 address or CIDR/);
    await expect(loadReferenceConfigFile(p)).rejects.toThrow(/Unrecognized key/);
  });

  it('rejects a change window that ends before it starts', () => {
    expect(() =>
      parseReferenceFile({ changeWindows: [{ startIso: '2026-10-05T23:00:00Z', endIso: '2026-10-05T22:00:00Z' }] }),
    ).toThrow(/endIso must be after startIso/);
  });

  it('rejects malformed JSON and a missing file with the path in the message', async () => {
    const p = await tmpFile('broken.json', '{ "allowlistCidrs": [');
    await expect(loadReferenceConfigFile(p)).rejects.toThrow(/not valid JSON/);
    await expect(loadReferenceConfigFile(path.join(dir, 'missing.json'))).rejects.toThrow(/missing\.json.*\n.*cannot read/s);
  });
});
