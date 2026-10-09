# CrowdStrike Falcon / LogScale (CQL) reference

Target: `crowdstrike_logscale` (pipeline `crowdstrike_falcon`). Falcon telemetry events in
Next-Gen SIEM / Falcon LogScale: `ProcessRollup2` (+ `SyntheticProcessRollup2`),
`NetworkConnectIP4`/`IP6`, `DnsRequest`, `NewExecutableWritten`, `RegGenericValueUpdate`, etc.

## Semantics that bite

- **Precedence: `not` > `or` > `and` (explicit and implicit).** `a or b c` means `(a or b) and c`.
  This is the reverse of SQL/KQL, and verified against the LogScale operator docs. The compiled
  output relies on it, so don't "fix" it by removing implicit ANDs. Parenthesize when hand-writing.
- `field=value` is an exact match, and **case-sensitive**. `*` wildcards are allowed:
  `ImageFileName=*\certutil.exe`. Use regex with `/i` for case-insensitive matching:
  `ImageFileName=/\\certutil\.exe$/i`. The backend emits regexes for this reason.
- Tags start with `#` (`#event_simpleName`, `#repo`). Filter on tags first, because they are indexed.
- **Only the parent's file name** (`ParentBaseFileName`) is in process events. Sigma
  `ParentImage` with a full path won't convert, so use `ParentImage|endswith: '\name.exe'`.
  `ParentCommandLine` isn't on `ProcessRollup2` at all. Join on `ParentProcessId` = `TargetProcessId`
  if needed.
- Free text `"urlcache"` searches all fields. Field-scoped filters are faster and more precise.

## Pattern

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\certutil\.exe$/i or OriginalFilename=/^certutil\.exe$/i
| CommandLine=/[-\/](urlcache|verifyctl)/i
| CommandLine=/(https?|ftp):\/\//i
| table([@timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
```

Each `|` stage is an AND with the previous one. Splitting stages is the clearest way to avoid
precedence mistakes.

## Aggregation and correlation (hand-written)

```logscale
#event_simpleName=UserLogonFailed2
| bucket(span=5m, field=[RemoteAddressIP4], function=[count(as=failures), count(UserName, distinct=true, as=users)])
| failures >= 20 and users >= 5
```

- `groupBy([aid], function=[count(), collect([CommandLine])])`, then filter with `| _count > 10`.
- `in(field=ImageFileName, values=["*\\a.exe","*\\b.exe"], ignoreCase=true)`.
- Joins: `join({#event_simpleName=NetworkConnectIP4}, field=[aid, ContextProcessId], key=[aid, TargetProcessId])`.
  In NG-SIEM correlation rules, prefer `correlate()` or `selfJoinFilter()` where available.
- `aid` + `TargetProcessId` identifies a process. `ContextProcessId` on other events points at it.

## Deploying

Falcon Custom IOA rules use their own regex-per-field model, not CQL. NG-SIEM correlation rules
take CQL with a schedule and lookback. This repo does not deploy to CrowdStrike, so the output
is for the user to import.
