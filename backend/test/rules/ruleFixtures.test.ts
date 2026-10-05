import { describe, it, expect, beforeAll } from 'vitest';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SigmaRuleLoader } from '../../src/correlation/loader.js';
import { RuleEvaluator } from '../../src/correlation/evaluator.js';
import type { SigmaRule } from '../../src/domain/entities/sigmaRule.js';
import { pino } from 'pino';

/**
 * The CI gate that enforces the detection contract:
 *   - every rule matches its positive fixture,
 *   - every rule does NOT match its negative fixture.
 * A regression in either direction fails the build.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const rulesDir = path.resolve(here, '../../../rules');
const fixturesDir = path.resolve(here, '../fixtures/events');
const log = pino({ level: 'silent' });

let rules: SigmaRule[];
const evaluator = new RuleEvaluator();

beforeAll(async () => {
  const schema = await SigmaRuleLoader.loadSchema(rulesDir);
  rules = await new SigmaRuleLoader(rulesDir, schema, log).loadAll();
});

function ruleForFixture(dir: string): SigmaRule {
  const rule = rules.find((r) => r.fileId === dir);
  if (!rule) throw new Error(`no loaded rule matches fixture dir ${dir}`);
  return rule;
}

describe('Sigma rule fixtures', () => {
  const fixtureDirs = readdirSync(fixturesDir).filter((d) => /^R-\d{2}$/.test(d)).sort();

  it('has a fixture directory for all 20 rules', () => {
    expect(fixtureDirs).toHaveLength(20);
  });

  for (const dir of fixtureDirs) {
    describe(dir, () => {
      const posPath = path.join(fixturesDir, dir, 'positive.json');
      const negPath = path.join(fixturesDir, dir, 'negative.json');

      it('has positive and negative fixtures', () => {
        expect(existsSync(posPath), `${dir} positive.json`).toBe(true);
        expect(existsSync(negPath), `${dir} negative.json`).toBe(true);
      });

      it('matches its positive fixture', () => {
        const events = JSON.parse(readFileSync(posPath, 'utf8')) as Array<Record<string, unknown>>;
        const result = evaluator.evaluate(ruleForFixture(dir), events);
        expect(result.matched, `${dir} should match positive fixture`).toBe(true);
      });

      it('does not match its negative fixture', () => {
        const events = JSON.parse(readFileSync(negPath, 'utf8')) as Array<Record<string, unknown>>;
        const result = evaluator.evaluate(ruleForFixture(dir), events);
        expect(result.matched, `${dir} should NOT match negative fixture`).toBe(false);
      });
    });
  }
});
