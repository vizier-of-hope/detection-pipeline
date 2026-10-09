# SIEM language references

Used by the `detection-engineer` agent (`.claude/agents/detection-engineer.md`) and by humans.

| Language | Doc | How queries are produced |
|---|---|---|
| Sigma (source of truth) | [sigma.md](sigma.md) | hand-written in `rules/` |
| Splunk SPL / CIM tstats | [splunk-spl.md](splunk-spl.md) | compiled (`splunk` required, `splunk_cim`) |
| Microsoft Sentinel / Defender XDR KQL | [kql.md](kql.md) | compiled (`microsoft_xdr`, `sentinel_asim`) |
| Elastic Lucene / EQL / ES\|QL | [elastic.md](elastic.md) | compiled (`elastic_lucene` required, `elastic_eql`, `elastic_esql`) |
| CrowdStrike Falcon LogScale (CQL) | [crowdstrike-logscale.md](crowdstrike-logscale.md) | compiled (`crowdstrike_logscale`) |
| Google SecOps UDM / YARA-L 2.0 | [google-secops.md](google-secops.md) | compiled (`secops_udm`, `secops_yaral`) |
| IBM QRadar AQL | [qradar-aql.md](qradar-aql.md) | hand-written (no compatible backend) |
| SentinelOne S1QL / PowerQuery | [sentinelone-pq.md](sentinelone-pq.md) | hand-written (backend broken on pySigma 1.5) |

- [field-mappings.md](field-mappings.md) is **generated** by `python -m dettools.fieldmap`
  from the pinned pipelines. A test fails if it goes stale.
- [review-checklist.md](review-checklist.md) is the rubric for rule reviews.

## Excluded backends and why

| Backend | Reason |
|---|---|
| `splunk_spl2` | Emits `A OR B AND C` ungrouped. SPL2 `WHERE` is AND-first, so mixed logic compiles wrong. |
| `qradar-aql` | No release compatible with pySigma 1.x. |
| `sentinelone-pq` | Validates field names after mapping, so it rejects every field under pySigma 1.5.1. |

When upgrading pySigma or a backend, re-run `pytest`. `tests/test_targets.py` checks every
target for AND/OR precedence safety, and `fieldmap --check` catches mapping drift.
