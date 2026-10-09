# Splunk SPL reference for detections

Targets: `splunk` (raw Sysmon events) and `splunk_cim` (tstats over CIM data models).
Deployed as scheduled saved searches by `dettools/deploy.py` (`build/splunk/savedsearches.conf`).

## Semantics that bite

- **Precedence in `search`**: `NOT` > `OR` > implicit/explicit `AND`.
  `a=1 b=2 OR b=3` means `a=1 AND (b=2 OR b=3)`. In `where`/`eval` it is the opposite:
  `AND` binds before `OR`, as in SQL. Parenthesize whenever you hand-write mixed logic.
- `search` field values are case-insensitive. Field *names* are case-sensitive.
  `where` comparisons are case-sensitive. Use `lower()`, `like()` or `match()`.
- Wildcards: `*` only, and a leading `*` is slow. Prefer `TERM()` or indexed fields for hot paths.
  Backslashes in quoted values must be doubled: `Image="*\\certutil.exe"`.
- `field!=value` excludes events where the field is missing. `NOT field=value` keeps them.
  Pick deliberately.
- `IN` in `search` is case-insensitive and supports wildcards: `process IN ("*a*","*b*")`.
- SPL2 (`splunk_spl2` backend) is NOT used. Its backend emits `A OR B AND C` without grouping,
  but SPL2 `WHERE` is AND-first, so the compiled logic is wrong.

## Raw-event pattern (what `splunk` target emits)

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image="*\\certutil.exe" OR OriginalFileName="CertUtil.exe")
  CommandLine IN ("*-urlcache *", "*/urlcache *")
| table _time host User Image CommandLine ParentImage
```

Add `index=<your_index>` in the saved search, or with a macro, before production. Without it
Splunk searches the user's default indexes only.

## CIM / tstats pattern (`splunk_cim` target)

```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="certutil.exe" Processes.process="*urlcache*"
    by Processes.dest Processes.user Processes.parent_process Processes.process
| `drop_dm_object_name(Processes)`
```

`summariesonly=true` is fast but only sees accelerated summaries, which lag by the summary range.
The compiled output uses `false`, which is correct but slower.

## Aggregations and correlation (hand-written)

```spl
index=wineventlog EventCode=4625
| bin _time span=5m
| stats count dc(TargetUserName) as users values(TargetUserName) as sample by _time IpAddress
| where count>=20 AND users>=5
```

Sequences: `transaction` is expensive. Prefer `stats min(_time) max(_time) values(...) by key`,
then filter on ordering with `where`.

## Alerting fields (savedsearches.conf)

`cron_schedule`, `dispatch.earliest_time`/`latest_time`: overlap the window by the ingestion lag,
e.g. `-15m@m` to `-5m@m` on a 10-minute cron. Set `alert.suppress=1` with
`alert.suppress.fields=host,User` and `alert.suppress.period=1h` to throttle noisy rules.

## Performance

Lead with indexed terms: `index`, `sourcetype`, `source`, `EventCode`. Avoid leading wildcards
on large fields. Use `tstats` when a data model is accelerated. Move `| where` regex work after
cheap filters.
