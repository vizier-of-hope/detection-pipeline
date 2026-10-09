# Google SecOps (Chronicle): UDM search and YARA-L 2.0

Targets: `secops_udm` (UDM search predicate) and `secops_yaral` (full YARA-L 2.0 rule).
Pipeline `secops_udm` maps Sigma fields onto UDM: `metadata.event_type`, `principal.*` (the
actor / parent process), `target.*` (the created process / destination), `src.*`, `network.*`.

## Semantics that bite

- String comparison is **case-sensitive** unless you add `nocase`. The backend adds it.
- Regex literals are `/.../` (RE2), so forward slashes inside must be escaped `\/`.
  YARA-L also has `re.regex($e.field, `pattern`)`.
- **Repeated fields** (e.g. `target.process.file.names`, `principal.ip`) match if *any*
  element matches. `!=` on a repeated field behaves surprisingly. Prefer positive matches.
- **AND/OR precedence is not stated in Google's docs** (only "use parentheses to override").
  Always parenthesize mixed logic. `tests/test_targets.py` enforces this on compiled output.
- `NOT` is unreliable in UDM search (the backend uses `!=`). Keep negations simple.
- Known mapping issue: the pinned pipeline maps Sigma `CurrentDirectory` to
  `target.process.file.full_path`, which is semantically wrong. Avoid `CurrentDirectory` in
  rules that ship to SecOps, or hand-fix it in the output.

## YARA-L 2.0 rule structure

```yaral
rule certutil_download {
  meta:
    author = "Detection Engineering Team"
    severity = "HIGH"
    mitre_attack_technique = "T1105"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    ($e.target.process.file.full_path = /\\certutil\.exe$/ nocase or
     $e.target.process.file.names = "CertUtil.exe" nocase)
    $e.target.process.command_line = /[-\/](urlcache|verifyctl)/ nocase
    $e.principal.hostname = $host
  match:
    $host over 10m
  outcome:
    $risk_score = 70
    $cmdlines = array_distinct($e.target.process.command_line)
  condition:
    $e
}
```

- Lines in `events:` are implicitly ANDed.
- `match: $var over <window>` groups events. `condition: #e >= 20` counts them.
  `condition: $e1 and $e2` requires both.
- Multi-event ordering: join the events on a shared variable (`$e1.principal.hostname = $h`,
  `$e2.principal.hostname = $h`) and add
  `$e1.metadata.event_timestamp.seconds < $e2.metadata.event_timestamp.seconds`.
- `outcome:` computes `$risk_score` and aggregates (`count_distinct`, `array_distinct`, `max`).
- Reference lists: `$e.principal.ip in %allowlisted_ips`. Data tables and `cidr` lists are
  also available.

## Brute-force example (hand-written)

```yaral
rule brute_force_single_source {
  meta:
    severity = "MEDIUM"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $ip
    $e.target.user.userid = $user
  match:
    $ip over 5m
  outcome:
    $users = count_distinct($user)
  condition:
    #e >= 20 and $users >= 5
}
```

Validate rules in the SecOps rules editor before enabling. This repo does not deploy to SecOps.
