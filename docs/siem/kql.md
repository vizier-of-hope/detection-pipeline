# KQL reference: Microsoft Sentinel and Defender XDR

Targets: `microsoft_xdr` (advanced-hunting tables: `DeviceProcessEvents`,
`DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`...) and
`sentinel_asim` (ASIM parsers: `imProcessCreate`, `imNetworkSession`, `imFileEvent`,
`imRegistry`, `imDns`, `imAuthentication`).

In **Sentinel**, the `Device*` tables only exist with the Microsoft Defender XDR connector
streaming raw events. Without it, use ASIM or `SecurityEvent` / `Event` (Sysmon) tables.

## Semantics that bite

- Precedence is SQL-like: `not()` > `and` > `or`. Always parenthesize mixed logic.
- `==` is case-sensitive. `=~` is case-insensitive. `!=` / `!~` are their negations.
- `contains` is a case-insensitive substring match but cannot use the term index.
  `has` is an indexed whole-term match and much faster, but `has "urlcache"` won't match
  `-urlcache:x` if the tokenizer splits differently. Use `has` for whole words,
  `contains` for fragments, and `_cs` variants (`contains_cs`, `has_cs`) for case-sensitive matches.
- `startswith` / `endswith` are case-insensitive. `in~ (...)` is a case-insensitive set match.
  `has_any (...)` is fast for term lists.
- Strings: `"C:\\Windows"` or verbatim `@"C:\Windows"`.
- `matches regex` uses RE2: no backreferences and no lookaround.
- `NOT` on a missing column yields null, so `where not(Field has "x")` can drop rows where
  `Field` is empty. Use `isempty()` / `isnotempty()` explicitly.

## Pattern

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where (FolderPath endswith @"\certutil.exe" or ProcessVersionInfoOriginalFileName =~ "CertUtil.exe")
| where ProcessCommandLine has_any ("urlcache", "verifyctl")
| where ProcessCommandLine has_any ("http://", "https://", "ftp://")
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessCommandLine, ReportId, DeviceId
```

Defender **custom detection rules** need `Timestamp`, `DeviceId` and `ReportId` in the output,
plus an entity column. Sentinel **scheduled analytics** need entity mapping (Host, Account,
Process), a query frequency and period (period >= frequency, plus ingestion lag), and a
threshold.

## Aggregation and correlation (hand-written)

```kql
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == 4625
| summarize Failures = count(), Users = dcount(TargetUserName), Sample = make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 5m)
| where Failures >= 20 and Users >= 5
```

Sequence: `join kind=inner` on a key, with `where (T2 - T1) between (0s .. 10m)`. Or use
`row_window_session()` / `scan` for ordered patterns. Filter both sides of a join before joining.

## Performance

Put the time filter first, then indexed `has` filters, then `contains` / regex. Use `project` early.
Avoid `search *` and `union *` in rules.
