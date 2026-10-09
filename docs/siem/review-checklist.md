# Detection review checklist

Score each item **pass / fail / n/a**. Every fail needs a concrete example: the event or string
that breaks the rule. Fixes come with a new fixture that proves them.

## 1. Logic and intent
- [ ] The title, description and ATT&CK tags describe what the logic actually matches.
- [ ] The condition does what the author meant (check `and`/`or`/`not` grouping, `1 of` vs `all of`).
- [ ] The logsource really records the behaviour. For example, `process_creation` can't see in-memory-only activity.

## 2. Evasion resistance
- [ ] Renamed binary: `OriginalFileName` (or a hash or signature) is matched alongside `Image`.
- [ ] Flag variants: `|windash`, abbreviations (`-enc`, `-e`, `-ec`), `:`/`=` separators, quoting.
- [ ] Case: nothing relies on a case-sensitive match unless `|cased` is intended.
- [ ] Obfuscation: caret insertion (`c^ertutil`), env-var expansion, double spaces, and alternate
      paths (`SysWOW64`, UNC, `\\?\`). Accept the gaps you can't cover and record them in `description`.
- [ ] Filters can't be triggered by the attacker, e.g. by appending a whitelisted string to the command line.

## 3. False positives
- [ ] `falsepositives` names real sources: software, admin tools, scheduled tasks.
- [ ] Filters are narrow, named `filter_<reason>`, and each has a true-negative fixture.
- [ ] The `level` matches fidelity: `high`/`critical` only when an analyst can act on one hit.

## 4. Portability (multi-SIEM)
- [ ] The rule converts for every target the user deploys to. Check `build/coverage.md`.
- [ ] Each field it uses is mapped for those targets (`docs/siem/field-mappings.md`).
- [ ] Compiled output was read against each language doc, looking for: case sensitivity (ES|QL
      `like`), missing data-source scoping (Elastic `FROM *` / `any where`), parent-path limits
      (LogScale), wrong field mapping (SecOps `CurrentDirectory`), and required tables or
      connectors (Defender `Device*` tables in Sentinel).

## 5. Performance
- [ ] Indexed and cheap predicates come first in hand-written queries: event code, table, tag.
- [ ] No leading-wildcard regex where `endswith`/`contains` works. Regexes are anchored.
- [ ] Aggregations bound their time window and group-by cardinality.

## 6. Tests and metadata
- [ ] At least 2 TP (canonical + evasion variant) and 2 TN (closest benign look-alikes).
- [ ] All gates pass: yamllint, sigma check, validate, pytest, convert.
- [ ] `status` is right for the evidence: new means `experimental`. Promote to `test` only after
      a staging soak with a known alert volume.
- [ ] `references` cite the technique or procedure source.
