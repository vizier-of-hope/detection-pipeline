# SentinelOne Singularity: S1QL / PowerQuery (hand-written)

`pysigma-backend-sentinelone-pq` 0.1.6 is broken under pySigma 1.5.1: it validates field names
after mapping them, so every field is rejected. SentinelOne queries are **hand-written**.
Label them as untested and tell the user to validate them in the Event Search console.

**Confidence note:** the operator semantics below come from SentinelOne's public docs as I
understood them, not from a compiler. State that when you deliver a query, and recommend a test
run in the console.

## Field model (Singularity Data Lake / Deep Visibility, S1QL 2.0)

| Sigma field | S1QL field |
|---|---|
| `Image` | `tgt.process.image.path` |
| `CommandLine` | `tgt.process.cmdline` |
| `ParentImage` | `src.process.image.path` |
| `ParentCommandLine` | `src.process.cmdline` |
| `User` | `src.process.user` (actor) / `tgt.process.user` |
| `OriginalFileName` | `tgt.process.displayName` is the closest field. There is no exact equivalent, so say so |
| `DestinationIp` / `DestinationPort` | `dst.ip.address` / `dst.port.number` |
| `QueryName` | `event.dns.request` |
| `TargetFilename` | `tgt.file.path` |
| `TargetObject` | `registry.keyPath` |
| host | `endpoint.name`, `endpoint.os = 'windows'` |

Event scoping: `event.type = 'Process Creation'`, `'IP Connect'`, `'DNS Resolved'`,
`'File Creation'`, `'Registry Value Modified'`.

## Semantics

- `contains`, `in`, `=` and `matches` (regex). Add `:anycase` for case-insensitive matching
  (`contains:anycase`, `in:anycase`). Use `:anycase` to keep Sigma's case-insensitivity.
- List form: `tgt.process.cmdline contains:anycase ('urlcache', 'verifyctl')` matches any value.
- Parenthesize all mixed AND/OR logic, because the precedence isn't verified here.

## Pattern

```s1ql
event.type = 'Process Creation' and endpoint.os = 'windows'
and tgt.process.image.path contains:anycase '\certutil.exe'
and tgt.process.cmdline contains:anycase ('urlcache', 'verifyctl')
and tgt.process.cmdline contains:anycase ('http://', 'https://', 'ftp://')
```

PowerQuery aggregation (pipe stages after the filter):

```s1ql
event.type = 'Login' and event.login.loginIsSuccessful = false
| group failures = count(), users = estimate_distinct(event.login.userName) by src.endpoint.ip.address
| filter failures >= 20 and users >= 5
```

STAR custom rules take the filter expression, without pipe stages, plus a cooldown. Correlation
rules need the aggregation form.
