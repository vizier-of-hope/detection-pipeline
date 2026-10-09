# Elastic Security reference: Lucene, EQL, ES|QL

Targets: `elastic_lucene` (deployed to Kibana via `build/elastic/rules.ndjson`), `elastic_eql`,
`elastic_esql`. Field names are ECS (`ecs_windows` pipeline: Winlogbeat 7+ / Elastic Agent).

## Shared caveats from the compiled output

- The pipeline maps `Image` to `process.executable.caseless`. A `.caseless` multi-field
  (lowercase normalizer) exists in Elastic Endpoint / Elastic Agent integration mappings, but not
  in every Winlogbeat template. Check the index mapping, or matches silently return nothing.
- Compiled queries do **not** add `event.category:process` or similar scoping. They rely on the
  rule's index patterns. Narrow `index` in the rule (e.g. `logs-endpoint.events.process-*`,
  `logs-windows.sysmon_operational-*`) to stay precise and fast.

## Lucene (query_string)

- Its boolean operators are not true precedence operators. The backend parenthesizes everything.
  Keep that when hand-editing.
- Escape `+ - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \ /` and spaces inside unquoted terms.
  Inside a wildcard term, backslashes are doubled: `process.executable:*\\certutil.exe`.
- Wildcards on `keyword` fields are case-sensitive. That's why `.caseless` matters.
- `NOT` alone needs a positive clause: `*:* AND NOT x:y`.
- Prefer **KQL (kuery)** when hand-writing Kibana rules: `process.name : "certutil.exe" and
  process.args : ("-urlcache" or "/urlcache")`. Its precedence is `not` > `and` > `or`.

## EQL

```eql
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "certutil.exe" or process.pe.original_file_name == "CertUtil.exe") and
  process.command_line : ("*urlcache*", "*verifyctl*") and process.command_line : "*http*"
```

- `:` is a case-insensitive wildcard match. `==` is case-sensitive. `like~` is
  case-insensitive wildcard and `regex~` is case-insensitive regex. Precedence: `not` > `and` > `or`.
- Compiled output uses `any where`. Replace it with the event category (`process`, `network`,
  `file`, `registry`, `library`) for speed and precision.
- Sequences are EQL's strength:

```eql
sequence by host.id with maxspan=2m
  [process where event.type == "start" and process.name : "winword.exe"]
  [process where event.type == "start" and process.parent.name : "winword.exe" and process.name : ("powershell.exe","cmd.exe")]
```

  Sequences by `process.entity_id` follow one process tree. Add `until [...]` to expire a sequence early.

## ES|QL

```esql
FROM logs-endpoint.events.process-* METADATA _id, _index, _version
| WHERE TO_LOWER(process.name) == "certutil.exe"
    AND (TO_LOWER(process.command_line) LIKE "*urlcache*" OR TO_LOWER(process.command_line) LIKE "*verifyctl*")
| KEEP @timestamp, host.name, user.name, process.command_line, process.parent.executable
```

- **`LIKE`, `==`, `IN`, `STARTS_WITH`, `ENDS_WITH` are case-sensitive**; Sigma is not. The stock
  backend ignores this (it would miss `vssadmin Delete Shadows` for a rule on `delete`), so
  `dettools.targets.esql_case_insensitive` rewrites every string match to `to_lower(field) ... "lowercased"`.
  `RLIKE` is left as-is because Sigma `|re` is case-sensitive too. Do the same when hand-writing.
  Cost: `to_lower()` prevents index pushdown, so always narrow `FROM` to real index patterns.
- `FROM *` in compiled output: replace it with real index patterns.
- Non-aggregating ES|QL rules need `METADATA _id, _index, _version` for alert deduplication.
  The backend adds it.
- Aggregation: `| STATS failures = COUNT(*), users = COUNT_DISTINCT(user.name) BY source.ip | WHERE failures >= 20`.

## Rule settings

Threshold rules suit simple counts. EQL rules suit sequences. Set `from: now-6m` with
`interval: 5m` (lookback covers ingestion lag). Map `severity`/`risk_score` from the Sigma level.
`dettools.convert` does this for the Lucene rule.
