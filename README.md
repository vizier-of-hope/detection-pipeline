# Detection-as-Code Pipeline

Sigma rules in Git, tested on every pull request, compiled to 10 SIEM query languages
(Splunk SPL/CIM, Elastic Lucene/EQL/ES|QL, Defender XDR and Sentinel ASIM KQL, CrowdStrike
LogScale, Google SecOps UDM/YARA-L), and deployed to Splunk and Elastic through gated environments.

A Claude Code subagent, `detection-engineer` (`.claude/agents/detection-engineer.md`), writes,
translates and reviews detections using this tooling and the references in `docs/siem/`.

```
PR opened ──► lint ─┐
              validate ─┼─► build (convert + dry-run) ──► artifact
              test ─┘
merge to main ──► same gates ──► deploy-staging (all rules) ──► [approval] ──► deploy-production (test + stable only)
```

## Layout

| Path | Purpose |
|---|---|
| `rules/` | Sigma rules, one per file, `lowercase_snake_case.yml` |
| `tests/events/<rule-file-name>.yml` | Sample events per rule: `true_positives` and `true_negatives` |
| `dettools/evaluator.py` | Offline Sigma evaluator that runs rule logic against sample events |
| `dettools/validate.py` | Team policy: required metadata, UUID ids, ATT&CK tags, unique ids/titles, fixture present |
| `dettools/targets.py` | SIEM target registry (backend + pipeline per language; required vs best-effort) |
| `dettools/convert.py` | Builds `build/splunk/savedsearches.conf`, `build/elastic/rules.ndjson`, `build/queries/<target>/`, `build/coverage.md`, `build/manifest.json` |
| `dettools/translate.py` | Translate one rule (file or stdin) to every target: `python -m dettools.translate rule.yml [--json]` |
| `dettools/scaffold.py` | Create a policy-compliant rule + fixture pair with a fresh UUID |
| `dettools/fieldmap.py` | Regenerates `docs/siem/field-mappings.md` from the pipelines |
| `docs/siem/` | Per-language references, field mappings, review checklist |
| `.claude/agents/detection-engineer.md` | The detection engineering agent |
| `dettools/deploy.py` | Upserts Splunk saved searches (REST) and imports Kibana detection rules |
| `.github/workflows/detections.yml` | The CI/CD pipeline |

## Pipeline gates

1. **Lint**: `yamllint` on rules and fixtures.
2. **Validate**: `sigma check --fail-on-issues` (spec, condition and ATT&CK tag checks), then `python -m dettools.validate` (team policy).
3. **Test**: `pytest`. Each rule must match every true positive and no true negative. The evaluator also has its own self-tests, plus tests for conversion and deployment.
4. **Build**: converts all rules, writes a job summary, runs a deploy dry-run, uploads `build/` as an artifact.
5. **Deploy staging**: on merge to `main`, deploys every rule, including `experimental`, so new rules can be tuned on real data.
6. **Deploy production**: after approval, deploys only `test` and `stable` rules.

## Rule lifecycle

`status` controls where a rule goes:

| Status | Staging | Production |
|---|---|---|
| `experimental` | yes | no |
| `test` | yes | yes |
| `stable` | yes | yes |

Promote a rule by changing its `status` in a PR.

## Local workflow

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt   # Linux/macOS: .venv/bin/pip
yamllint -s rules tests/events
sigma check --fail-on-issues rules
python -m dettools.validate
pytest -q
python -m dettools.convert
python -m dettools.deploy --target all --dry-run
```

Optional: `pip install pre-commit && pre-commit install` runs the same gates on every commit.

## Adding a rule

1. Run `python -m dettools.scaffold --title "..." --product windows --category process_creation --tactic execution --technique t1059.001`
   (or add `rules/<area>/<name>.yml` by hand with a fresh UUID).
2. Add `tests/events/<name>.yml` with the same `rule_id`, at least one true positive and one true negative. Use Sigma field names (`Image`, `CommandLine`, ...), not SIEM field names.
3. Start with `status: experimental`. Open a PR.

## One-time GitHub setup

1. Push this directory to a GitHub repository.
2. **Settings → Environments**: create `staging` and `production`. On `production`, add *Required reviewers*.
3. In each environment, add the secrets for the SIEM it targets:
   - Splunk: `SPLUNK_URL` (management port, e.g. `https://splunk:8089`), `SPLUNK_TOKEN` (token with permission to write saved searches).
   - Elastic: `KIBANA_URL` (e.g. `https://kibana:5601`), `KIBANA_API_KEY` (API key with Security rules write privileges).
4. Optional environment variables: `DEPLOY_TARGET` (`splunk`, `elastic` or `all`; default `all`), `SPLUNK_APP` (default `search`), `KIBANA_SPACE` (default `default`). If you use only one SIEM, set `DEPLOY_TARGET` or the deploy fails on missing credentials.
5. **Settings → Branches**: protect `main`. Require a PR review and the `Lint YAML`, `Validate rules`, `Unit-test rules` and `Convert to SIEM queries` checks.

## SIEM targets

`python -m dettools.translate --list` shows them. Targets are logsource-aware: Windows endpoint
rules, Entra ID sign-in rules (`sentinel_signin`) and AWS CloudTrail rules (`splunk_cloudtrail`,
`sentinel_cloudtrail`, `elastic_cloudtrail`) each compile only to the targets that can map their
fields. CloudTrail rules use CloudTrail's own JSON field names (`eventName`, `userIdentity.type`);
`dettools/targets.py` maps them to Sentinel `AWSCloudTrail` columns and Elastic ECS fields. Cloud
rules are compiled to query files but not deployed by `dettools.deploy`.
**Required** targets (`splunk`, `elastic_lucene`, and the per-logsource required targets)
fail the build when a rule can't convert; the rest are best-effort and every gap is listed with
its reason in `build/coverage.md` (also in the CI job summary). Caveats per target (e.g. ES|QL
`like` is case-sensitive) are in `docs/siem/`. Excluded backends: SPL2 (wrong AND/OR grouping),
QRadar AQL and SentinelOne PowerQuery (incompatible with pySigma 1.5); write those by hand.

## Field mappings

- **Splunk**: Sysmon pipeline plus Splunk Windows pipeline. Queries use `source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1` and Sysmon field names.
- **Elastic**: `ecs_windows` pipeline, ECS field names (`process.command_line`, ...).

Change pipelines in `dettools/convert.py` to match how your data is ingested. Example: use `splunk_cim` for CIM data models.

## Limits

- The offline evaluator covers field matching, modifiers (`contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `windash`, `gt`/`lt`, `exists`, `fieldref`), `null`, and keyword searches. Correlation rules and placeholders (`expand`) raise `UnsupportedSigmaFeature`, so such tests fail loudly instead of passing silently.
- Unit tests check rule logic, not field mappings. Validate mappings by running new rules in staging.
- The deploy step creates and updates rules. It does not delete rules that were removed from the repo. Retire a rule by disabling it in the SIEM, or extend `deploy.py` to remove `sigma-managed` rules that are missing from the manifest.
