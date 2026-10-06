# Rule Authoring

Sigma rules under `/rules/*.yml` are the **source of truth**. They are validated on load,
compiled to Wazuh XML at deploy, and evaluated in-process by the correlation scheduler.

## Required fields

Every rule must include (enforced by [`rules/schema/sigma-surf.json`](../rules/schema/sigma-surf.json)):

`id` (UUID), `title`, `description`, `author`, `date` (`YYYY/MM/DD`), `references` (≥1 URI),
`level` (`critical|high|medium|low|informational`), `tags` (must contain an `attack.*` tag),
`logsource`, `detection` (with `condition`), `falsepositives` (≥1), `owner`, `surf.compliance`
(≥1). `surf.threat_id` (`AV-NN`) is recommended.

**ATT&CK tagging feeds the content pack.** Use `attack.t1110` (enterprise), `attack.ics.T0813`
(ICS), and an `attack.<tactic>` tag (e.g. `attack.credential_access`). The
[content pack](CONTENT_PACK.md) derives its coverage map and Navigator layers from these; a rule
with a technique but no tactic tag shows up as a content gap. Changing tags means re-running
`npm run pack:build` (CI's `pack:check` enforces it).

## Supported detection grammar

The evaluator implements a deliberate subset of Sigma (everything the 22 rules need). Adding
a construct beyond this list means extending `src/correlation/evaluator.ts` **with tests**.

```
condition: selection
condition: selection and not filter
condition: selection | count() > N
condition: selection | count() by <field> > N
condition: selection | count(<field>) by <field> >= N     # distinct-count
condition: (sel_a | count() by <field> >= N) and sel_b     # MFA-fatigue style
```

Field matchers: exact value, list (`in`), `|contains` (substring), and `|contains` with a
list (contains-any). `timeframe: <n>[smhd]` bounds aggregated conditions.
`|startswith`, `|endswith` and `|re` are **not** supported by either evaluator (portal or Wazuh
compiler) — use `|contains` (R-17 matches `/external/v1/` by substring for exactly that reason).
List values use Sigma `in` semantics in both evaluators (`[401, 403]`, `[a, b, c]`).

## Wazuh rule id block

Primary compiled rules take ids **100100 + file index** (reserved SURF range `100100–100899`);
`convert-sigma.ts` assigns them in file order, so keep the `R-NN` prefixes contiguous. A
conjunctive rule also emits a **composite** rule at `id + 900` (the `101000+` band) so it can
never collide with a primary. The converter fails closed if any id is duplicated.

## Workflow

```bash
# 1. author rules/R-21-my-rule.yml (copy an existing rule)
# 2. validate against the schema
npm run rules:validate
# 3. add fixtures
#    backend/test/fixtures/events/R-21/positive.json   (must match)
#    backend/test/fixtures/events/R-21/negative.json   (must NOT match)
# 4. run the fixture gate
npm run test:rules
# 5. preview the compiled Wazuh XML
npm run rules:convert -- --dry-run
```

CI (`rule-tests.yml`) fails the build if any rule misses its positive fixture or matches its
negative one — this is the detection contract.

## Enrichment vs. detection

Prefer computing complex conditions (geo distance, semver comparison, allow-list membership)
at **ingest time** as a `surf.enrichment.*` boolean, then matching that boolean in the rule.
This keeps rules readable, portable to Wazuh, and cheap to evaluate every 60 s.
