import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { pino } from 'pino';
import { SigmaRuleLoader } from '../../src/correlation/loader.js';
import { RuleEvaluator, getField } from '../../src/correlation/evaluator.js';
import type { SigmaRule } from '../../src/domain/entities/sigmaRule.js';
import { convertRule, type SigmaDoc } from '../../../scripts/convert-sigma.js';
import { wazuhFires, type Event } from './wazuhEval.js';

/**
 * Portal ↔ Wazuh conformance gate (FUTURE_WORK §6).
 *
 * The portal's in-process RuleEvaluator and the compiled Wazuh ruleset are two
 * evaluators derived from the same Sigma source. A rule that fires in one but
 * not the other is a detection gap. This test compiles each rule with the real
 * converter and diffs the two verdicts:
 *   - CONFORMANT rules must agree on their positive and negative fixtures.
 *   - Known DIVERGENT rules are pinned to their exact, documented gap; if the
 *     compiler changes, the assertion breaks and the map below must be updated.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const rulesDir = path.resolve(here, '../../../rules');
const fixturesDir = path.resolve(here, '../fixtures/events');
const BASE_RULE_ID = 100100;

/**
 * All 20 rules now compile to a Wazuh ruleset that agrees with the portal.
 * Closed structural gaps: R-04/R-08/R-13 (dropped `filter_*` negations, now
 * emitted as `negate="yes"` fields), R-11 (`>=` boundary → frequency N not N+1),
 * and R-03 (dropped conjunction, now a `<if_matched_sid>` composite rule).
 */
const DIVERGENCES: Record<string, string> = {};
const CONFORMANT = [
  'R-01', 'R-02', 'R-03', 'R-04', 'R-05', 'R-06', 'R-07', 'R-08',
  'R-09', 'R-10', 'R-11', 'R-12', 'R-13', 'R-14', 'R-15', 'R-16',
  'R-17', 'R-18', 'R-19', 'R-20', 'R-21', 'R-22',
] as const;

const log = pino({ level: 'silent' });
const evaluator = new RuleEvaluator();
let rules: SigmaRule[];
let xmlByFileId: Map<string, string>;

/** Mirrors CorrelationScheduler.filterByLogsource so the portal verdict is faithful. */
function scopeToLogsource(rule: SigmaRule, events: Event[]): Event[] {
  const { product, service } = rule.logsource;
  return events.filter((e) => {
    const p = getField(e, 'observer.product') ?? getField(e, 'event.module');
    const s = getField(e, 'observer.service') ?? getField(e, 'event.dataset');
    if (product && String(p ?? '') !== product) return false;
    if (service && String(s ?? '') !== service) return false;
    return true;
  });
}

function portalFires(rule: SigmaRule, events: Event[]): boolean {
  return evaluator.evaluate(rule, scopeToLogsource(rule, events)).matched;
}

function wazuhFiresFor(fileId: string, events: Event[]): boolean {
  const xml = xmlByFileId.get(fileId);
  if (xml === undefined) throw new Error(`no compiled Wazuh rule for ${fileId}`);
  return wazuhFires(xml, events);
}

function fixture(fileId: string, kind: 'positive' | 'negative'): Event[] {
  return JSON.parse(readFileSync(path.join(fixturesDir, fileId, `${kind}.json`), 'utf8')) as Event[];
}

beforeAll(async () => {
  const schema = await SigmaRuleLoader.loadSchema(rulesDir);
  rules = await new SigmaRuleLoader(rulesDir, schema, log).loadAll();

  // Compile every rule with the real converter, keyed by fileId, exactly as the
  // sigma-compiler container does (rule ids assigned in sorted file order).
  const { readdirSync } = await import('node:fs');
  const files = readdirSync(rulesDir).filter((f) => /^R-\d{2}-.*\.ya?ml$/.test(f)).sort();
  xmlByFileId = new Map();
  files.forEach((file, i) => {
    const doc = parseYaml(readFileSync(path.join(rulesDir, file), 'utf8')) as SigmaDoc;
    const fileId = (/^(R-\d{2})/.exec(file) ?? [])[1] ?? file;
    xmlByFileId.set(fileId, convertRule(doc, BASE_RULE_ID + i));
  });
});

describe('portal ↔ Wazuh conformance', () => {
  it('compiles all 20 rules to a Wazuh rule with at least one field', () => {
    expect(xmlByFileId.size).toBe(22);
    for (const [fileId, xml] of xmlByFileId) {
      expect(xml, `${fileId} should be a <rule>`).toContain('<rule id=');
      expect(xml, `${fileId} should carry at least one field`).toContain('<field ');
    }
  });

  describe('conformant rules agree on their fixtures', () => {
    for (const fileId of CONFORMANT) {
      it(`${fileId}: portal and Wazuh both fire on positive, neither on negative`, () => {
        const rule = rules.find((r) => r.fileId === fileId);
        expect(rule, `rule ${fileId} loaded`).toBeDefined();

        const pos = fixture(fileId, 'positive');
        expect(portalFires(rule!, pos), `${fileId} portal on positive`).toBe(true);
        expect(wazuhFiresFor(fileId, pos), `${fileId} Wazuh on positive`).toBe(true);

        const neg = fixture(fileId, 'negative');
        expect(portalFires(rule!, neg), `${fileId} portal on negative`).toBe(false);
        expect(wazuhFiresFor(fileId, neg), `${fileId} Wazuh on negative`).toBe(false);
      });
    }
  });

  it('every rule is classified as conformant or a documented divergence', () => {
    const all = [...CONFORMANT, ...Object.keys(DIVERGENCES)];
    expect(all).toHaveLength(22);
    expect(new Set(all).size).toBe(22);
    expect(Object.keys(DIVERGENCES)).toHaveLength(0); // all gaps closed
  });

  describe('closed compiler gaps stay closed', () => {
    const ts = (secondsAgo: number): string => new Date(Date.now() - secondsAgo * 1000).toISOString();
    const ruleOf = (fileId: string): SigmaRule => {
      const r = rules.find((x) => x.fileId === fileId);
      if (!r) throw new Error(`rule ${fileId} not loaded`);
      return r;
    };
    const r11Failures = (n: number): Event[] =>
      Array.from({ length: n }, (_, i) => ({
        '@timestamp': ts(100 - i * 5), 'event.id': `r11-${n}-${i}`, 'observer.product': 'mqtt',
        'observer.service': 'broker', 'event.action': 'schedule_delivery', 'event.outcome': 'failure',
        'surf.ems.id': 'ems-2222', 'host.name': 'mqtt-broker-01',
      }));
    const mfaRejects = (n: number): Event[] =>
      Array.from({ length: n }, (_, i) => ({
        '@timestamp': ts(200 - i * 10), 'event.id': `r03-${n}-${i}`, 'observer.product': 'keycloak',
        'observer.service': 'events', 'event.action': 'LOGIN_ERROR',
        'keycloak.error': 'invalid_authentication', 'keycloak.credential_type': 'otp',
        'user.name': 'anna.analyst', 'source.ip': '203.0.113.77',
      }));

    it('R-11 (>= boundary): 10 failures both fire, 9 failures both stay silent', () => {
      expect(portalFires(ruleOf('R-11'), r11Failures(10))).toBe(true);
      expect(wazuhFiresFor('R-11', r11Failures(10))).toBe(true);
      expect(portalFires(ruleOf('R-11'), r11Failures(9))).toBe(false);
      expect(wazuhFiresFor('R-11', r11Failures(9))).toBe(false);
    });

    it('R-03 (conjunction): 6 MFA rejects WITHOUT a success — portal AND Wazuh both stay silent', () => {
      // Before the fix Wazuh fired on the reject burst alone; the composite rule
      // now also requires the login_success trigger, matching the portal.
      const events = mfaRejects(6);
      expect(portalFires(ruleOf('R-03'), events)).toBe(false);
      expect(wazuhFiresFor('R-03', events)).toBe(false);
    });

    it('R-03 (conjunction): 6 MFA rejects followed by a success — portal AND Wazuh both fire', () => {
      const events: Event[] = [
        ...mfaRejects(6),
        {
          '@timestamp': ts(30), 'event.id': 'r03-success', 'observer.product': 'keycloak',
          'observer.service': 'events', 'event.action': 'LOGIN', 'event.outcome': 'success',
          'user.name': 'anna.analyst', 'source.ip': '203.0.113.77',
        },
      ];
      expect(portalFires(ruleOf('R-03'), events)).toBe(true);
      expect(wazuhFiresFor('R-03', events)).toBe(true);
    });
  });
});
