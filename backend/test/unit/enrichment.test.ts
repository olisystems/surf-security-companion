import { describe, it, expect } from 'vitest';
import { Enricher, haversineKm, compareSemver, type Event } from '../../src/correlation/enrichment.js';
import {
  DefaultReferenceData,
  DEMO_REFERENCE_CONFIG,
} from '../../src/correlation/enrichmentReferenceData.js';

/** Builds an enricher over fresh demo reference data, plus the ref bundle for seeding state. */
function makeEnricher(): { enrich: (e: Event) => Event; refs: DefaultReferenceData } {
  const refs = new DefaultReferenceData(DEMO_REFERENCE_CONFIG);
  const enricher = new Enricher(refs);
  return { enrich: (e) => enricher.enrich(e), refs };
}

describe('haversineKm', () => {
  it('is ~0 for identical points', () => {
    expect(haversineKm({ lat: 50.11, lon: 8.68 }, { lat: 50.11, lon: 8.68 })).toBeLessThan(1);
  });
  it('Frankfurt → Singapore is a genuinely impossible hop', () => {
    const km = haversineKm({ lat: 50.11, lon: 8.68 }, { lat: 1.35, lon: 103.82 });
    expect(km).toBeGreaterThan(9000);
  });
});

describe('compareSemver', () => {
  it('orders versions numerically, not lexically', () => {
    expect(compareSemver('2.1.0', '2.4.0')).toBeLessThan(0);
    expect(compareSemver('2.10.0', '2.4.0')).toBeGreaterThan(0); // 10 > 4
    expect(compareSemver('2.1', '2.1.0')).toBe(0);
  });
});

describe('R-02 · impossible_travel', () => {
  it('true when a prior login is > 500 km away within the window', () => {
    const { enrich, refs } = makeEnricher();
    // prior successful login from Frankfurt 10 min earlier
    refs.observe({
      '@timestamp': '2026-07-16T08:00:00Z',
      'event.action': 'LOGIN',
      'event.outcome': 'success',
      'user.name': 'dirk.dso',
      'source.ip': '198.51.100.7',
    });
    const out = enrich({
      '@timestamp': '2026-07-16T08:10:00Z',
      'event.action': 'LOGIN',
      'event.outcome': 'success',
      'user.name': 'dirk.dso',
      'source.ip': '203.0.113.5', // Singapore
    });
    expect(out['surf.enrichment.impossible_travel']).toBe(true);
  });

  it('false for two logins in the same city', () => {
    const { enrich, refs } = makeEnricher();
    refs.observe({
      '@timestamp': '2026-07-16T08:00:00Z',
      'event.action': 'LOGIN',
      'event.outcome': 'success',
      'user.name': 'dirk.dso',
      'source.ip': '198.51.100.7',
    });
    const out = enrich({
      '@timestamp': '2026-07-16T08:10:00Z',
      'event.action': 'LOGIN',
      'event.outcome': 'success',
      'user.name': 'dirk.dso',
      'source.ip': '198.51.100.7',
    });
    expect(out['surf.enrichment.impossible_travel']).toBe(false);
  });

  it('false when the two logins are outside the 30 min window', () => {
    const { enrich, refs } = makeEnricher();
    refs.observe({
      '@timestamp': '2026-07-16T07:00:00Z',
      'event.action': 'LOGIN',
      'event.outcome': 'success',
      'user.name': 'dirk.dso',
      'source.ip': '198.51.100.7',
    });
    const out = enrich({
      '@timestamp': '2026-07-16T08:10:00Z', // 70 min later
      'event.action': 'LOGIN',
      'event.outcome': 'success',
      'user.name': 'dirk.dso',
      'source.ip': '203.0.113.5',
    });
    expect(out['surf.enrichment.impossible_travel']).toBe(false);
  });
});

describe('R-04 · cross_tenant_mismatch', () => {
  it('true when the queried tenant differs from the actor home tenant', () => {
    const { enrich } = makeEnricher();
    const out = enrich({
      'event.action': 'query',
      'user.name': 'app_vnb_saar', // home = vnb-saar
      'surf.query.tenant_id': 'vnb-pfalz',
    });
    expect(out['surf.enrichment.cross_tenant_mismatch']).toBe(true);
  });

  it('false when querying own tenant', () => {
    const { enrich } = makeEnricher();
    const out = enrich({
      'event.action': 'query',
      'user.name': 'app_vnb_saar',
      'surf.query.tenant_id': 'vnb-saar',
    });
    expect(out['surf.enrichment.cross_tenant_mismatch']).toBe(false);
  });
});

describe('R-10 · firmware_downgrade', () => {
  it('true when reported version is below the last inventory', () => {
    const { enrich } = makeEnricher();
    const out = enrich({
      'event.action': 'firmware_inventory',
      'surf.ems.id': 'ems-0815', // baseline 2.4.0
      'surf.ems.firmware_version': '2.1.0',
    });
    expect(out['surf.enrichment.firmware_downgrade']).toBe(true);
  });

  it('false for an upgrade, and it advances the baseline', () => {
    const { enrich, refs } = makeEnricher();
    const up = enrich({
      'event.action': 'firmware_inventory',
      'surf.ems.id': 'ems-0815',
      'surf.ems.firmware_version': '2.5.0',
    });
    expect(up['surf.enrichment.firmware_downgrade']).toBe(false);
    refs.observe({
      'event.action': 'firmware_inventory',
      'surf.ems.id': 'ems-0815',
      'surf.ems.firmware_version': '2.5.0',
    });
    // now 2.4.0 is a downgrade relative to the advanced 2.5.0 baseline
    const down = enrich({
      'event.action': 'firmware_inventory',
      'surf.ems.id': 'ems-0815',
      'surf.ems.firmware_version': '2.4.0',
    });
    expect(down['surf.enrichment.firmware_downgrade']).toBe(true);
  });
});

describe('R-13 · in_change_window', () => {
  it('false for an account created outside any declared window (rule then fires)', () => {
    const { enrich } = makeEnricher();
    const out = enrich({
      '@timestamp': '2026-07-16T10:00:00Z',
      'event.action': 'CREATE',
      'keycloak.resource_type': 'CLIENT',
      'keycloak.service_account_enabled': true,
      'user.name': 'petra.platform',
    });
    expect(out['surf.enrichment.in_change_window']).toBe(false);
  });

  it('true when inside a declared window (rule suppressed)', () => {
    const { enrich } = makeEnricher();
    const out = enrich({
      '@timestamp': '2026-07-01T22:30:00Z',
      'event.action': 'CREATE',
      'keycloak.resource_type': 'CLIENT',
      'keycloak.service_account_enabled': true,
      'user.name': 'petra.platform',
    });
    expect(out['surf.enrichment.in_change_window']).toBe(true);
  });
});

describe('R-15 · ip_allowlisted', () => {
  it('false for a public IP outside the allow-list (rule fires)', () => {
    const { enrich } = makeEnricher();
    const out = enrich({
      'event.action': 'connection_authorized',
      'user.name': 'soc_app',
      'source.ip': '198.51.100.201',
    });
    expect(out['surf.enrichment.ip_allowlisted']).toBe(false);
  });

  it('true for an internal IP inside 10.0.0.0/8', () => {
    const { enrich } = makeEnricher();
    const out = enrich({
      'event.action': 'connection_authorized',
      'user.name': 'soc_app',
      'source.ip': '10.0.4.12',
    });
    expect(out['surf.enrichment.ip_allowlisted']).toBe(true);
  });

  it('leaves the flag unset when there is no client IP (local socket) so R-15 does not fire', () => {
    const { enrich } = makeEnricher();
    const out = enrich({
      'event.action': 'connection_authorized',
      'user.name': 'soc_app',
      // no source.ip — a local unix-socket connection
    });
    expect('surf.enrichment.ip_allowlisted' in out).toBe(false);
  });

  it('is also computed for sshd logins (R-19) — false off-list, true on-list', () => {
    const { enrich } = makeEnricher();
    const off = enrich({ 'event.action': 'ssh_login', 'event.outcome': 'success', 'user.name': 'root', 'source.ip': '203.0.113.9' });
    expect(off['surf.enrichment.ip_allowlisted']).toBe(false);
    const on = enrich({ 'event.action': 'ssh_login', 'event.outcome': 'success', 'user.name': 'root', 'source.ip': '192.168.1.5' });
    expect(on['surf.enrichment.ip_allowlisted']).toBe(true);
  });
});

describe('pass-through', () => {
  it('leaves non-enrichment events untouched', () => {
    const { enrich } = makeEnricher();
    const input: Event = { 'event.action': 'command_dispatch', 'surf.command.type': 'schedule' };
    expect(enrich(input)).toEqual(input);
  });
});
