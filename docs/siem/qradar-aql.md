# IBM QRadar AQL reference (hand-written: no compatible pySigma backend)

`pysigma-backend-qradar-aql` has no release compatible with pySigma 1.x, so QRadar queries are
**hand-written** from the Sigma rule. Label them as untested in every answer.

## Field model: the biggest source of error

QRadar normalizes a few columns (`sourceip`, `destinationip`, `destinationport`, `username`,
`qid`, `devicetype`, `logsourceid`, `starttime`). Everything else, such as process image and command
line, is a **custom event property (CEP)** whose name depends on the DSM and on local tuning.
Common names include `"Process Name"`, `"Process CommandLine"`, `"Parent Process Name"`,
`"Image"`, `"Command"` and `"EventID"`. **Always tell the user to confirm the CEP names in Log
Activity**, and present the mapping you assumed.

| Sigma field | Typical AQL (Windows / Sysmon DSM) |
|---|---|
| `Image` | `"Process Path"` or `"Image"` (CEP) |
| `CommandLine` | `"Process CommandLine"` / `"Command"` (CEP) |
| `ParentImage` | `"Parent Process Path"` (CEP) |
| `User` | `username` |
| `DestinationIp` / `SourceIp` | `destinationip` / `sourceip` |
| `DestinationPort` | `destinationport` |
| `EventID` | `"EventID"` (CEP) or `QIDNAME(qid)` |

## Semantics

- SQL precedence: `NOT` > `AND` > `OR`. Parenthesize mixed logic.
- String literals use `'single quotes'`. Property names with spaces use `"double quotes"`.
- `LIKE` is case-sensitive and `ILIKE` is case-insensitive. Wildcards are `%` (any) and `_` (one).
  Sigma is case-insensitive, so use `ILIKE`.
- Regex: `MATCHES` / `IMATCHES` (Java regex). CIDR: `INCIDR('10.0.0.0/8', sourceip)`.
- Time: `LAST 10 MINUTES`, or `START '2026-10-09 00:00' STOP '2026-10-09 01:00'`.

## Pattern

```sql
SELECT starttime, LOGSOURCENAME(logsourceid) AS host, username,
       "Process Path", "Process CommandLine"
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Windows%'
  AND "EventID" = '1'
  AND ("Process Path" ILIKE '%\certutil.exe' OR "Process CommandLine" ILIKE 'certutil%')
  AND ("Process CommandLine" ILIKE '%urlcache%' OR "Process CommandLine" ILIKE '%verifyctl%')
  AND ("Process CommandLine" ILIKE '%http://%' OR "Process CommandLine" ILIKE '%https://%')
LAST 10 MINUTES
```

## Aggregation

```sql
SELECT sourceip, COUNT(*) AS failures, UNIQUECOUNT(username) AS users
FROM events
WHERE "EventID" = '4625'
GROUP BY sourceip
HAVING failures >= 20 AND users >= 5
LAST 5 MINUTES
```

## Turning it into a QRadar rule

QRadar rules are built from tests, not raw AQL. Use the rule test *"when the event matches this
AQL filter query"* with the WHERE clause only. Use *"when at least N events are seen with the same
<property> in M minutes"* for thresholds. Always check performance in the Rule Performance
Analysis view.
