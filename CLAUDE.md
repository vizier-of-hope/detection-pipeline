# Detection pipeline

Sigma detection-as-code repo compiled to many SIEM languages. For detection work (new rules,
translating SIEM queries, reviews, coverage) delegate to the `detection-engineer` agent
(`.claude/agents/detection-engineer.md`); its references live in `docs/siem/`.

- Python: `.venv/Scripts/python` (Windows). Set `PYTHONIOENCODING=utf-8` (windash emits en/em dashes).
- Gates: `yamllint -s rules tests/events`, `sigma check --fail-on-issues rules`,
  `python -m dettools.validate`, `pytest -q`, `python -m dettools.convert`.
- SIEM targets: `dettools/targets.py`. After adding a target or upgrading pySigma, run
  `python -m dettools.fieldmap` and `pytest`.
- Never run `dettools.deploy` without `--dry-run` unless the user asks for a deploy.
- Keep LF line endings (yamllint enforces it on YAML).

## Agent tests

`agent-tests/` (see its README) holds the agent regression kit. The offline checks run inside
`pytest`. Live runs (`python agent-tests/run.py`) need the `claude` CLI and cost model usage.
After changing any agent file or `cases.yml`, run `pytest`.

## Third-party security agents

`.claude/agents/security-*.md` are copied from
https://github.com/msitarzewski/agency-agents (MIT), `security/` at commit
f99f6aa910a442b0197b768ce0ea7751e35e2060. One local change: the review agents (AI-Generated
Code Auditor, AppSec Engineer, Security Architect, Blockchain Security Auditor, Cloud Security
Architect, Compliance Auditor, Threat Intelligence Analyst) got a read-only frontmatter line
`tools: Read, Grep, Glob, WebFetch, WebSearch`. The hands-on agents (Incident Responder,
Penetration Tester, Secrets & Credential Engineer, Senior SecOps, Threat Detection Engineer)
keep all tools.
- Rule writing, translation and review in this repo: use `detection-engineer`, not
  "Threat Detection Engineer". The latter assumes `detections/`, `compiled/` and
  `scripts/test_detection.py`, which don't exist here.
- Good companions: Threat Intelligence Analyst (CTI -> ATT&CK techniques, then hand to
  `detection-engineer`), Incident Responder, Cloud Security Architect, Penetration Tester
  (authorized scope only).
- Update: re-clone that repo, copy `security/*.md` over these files, then re-add the
  `tools:` line to the review agents (upstream files have none).
