"""Compile Sigma rules into SIEM-native artifacts.

Run: python -m dettools.convert
Outputs (under build/):
  splunk/savedsearches.conf   one scheduled alert per rule (Sysmon field names)
  elastic/rules.ndjson        Kibana detection-engine import file (ECS field names)
  queries/<target>/<rule>.<ext>  one file per rule for every target in dettools.targets
  coverage.md / coverage.json    rule x target matrix, with the reason for every gap
  manifest.json               rule metadata + queries, consumed by dettools.deploy

A rule that fails a required target (Splunk, Elastic Lucene) fails the build.
Best-effort targets only record the failure in the coverage report.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

from dettools.common import BUILD_DIR, REPO_ROOT, load_rules
from dettools.targets import TARGETS, backend_for, convert, join_queries

SPLUNK_SEVERITY = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SPLUNK_SCHEDULE = {"cron": "*/10 * * * *", "earliest": "-10m@m", "latest": "now"}


def splunk_stanza(name: str, query: str, raw: dict) -> str:
    description = " ".join(str(raw.get("description", "")).split())
    lines = [
        f"[{name}]",
        f"search = {query}",
        f"description = {description}",
        "enableSched = 1",
        f"cron_schedule = {SPLUNK_SCHEDULE['cron']}",
        f"dispatch.earliest_time = {SPLUNK_SCHEDULE['earliest']}",
        f"dispatch.latest_time = {SPLUNK_SCHEDULE['latest']}",
        "counttype = number of events",
        "relation = greater than",
        "quantity = 0",
        "alert.track = 1",
        f"alert.severity = {SPLUNK_SEVERITY[raw['level']]}",
        "alert.suppress = 0",
    ]
    return "\n".join(lines) + "\n"


def coverage_markdown(coverage: list[dict]) -> str:
    keys = list(TARGETS)
    lines = [
        "## Target coverage\n",
        "| Rule | " + " | ".join(keys) + " |",
        "|---|" + "---|" * len(keys),
    ]
    for row in coverage:
        cells = ["yes" if k in row["converted"] else "**no**" for k in keys]
        lines.append(f"| {row['title']} | " + " | ".join(cells) + " |")
    gaps = [(row["path"], k, reason) for row in coverage for k, reason in row["gaps"].items()]
    if gaps:
        lines += ["", "### Gaps", ""]
        lines += [f"- `{path}` -> `{k}`: {reason[:300]}" for path, k, reason in gaps]
    caveats = [t for t in TARGETS.values() if t.caveat]
    lines += ["", "### Target notes", ""]
    lines += [f"- `{t.key}` ({t.siem}, {t.language}): {t.caveat}" for t in caveats]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=BUILD_DIR)
    args = parser.parse_args(argv)

    manifest, stanzas, ndjson, failures, coverage = [], [], [], [], []
    query_files: dict[Path, str] = {}
    for loaded in load_rules():
        raw, rel = loaded.raw, loaded.path.relative_to(REPO_ROOT).as_posix()
        name = f"SIGMA - {raw['title']}"

        # Backends are logsource-specific, so only compile the targets that apply to this rule.
        applicable = {key: t for key, t in TARGETS.items() if t.applies_to(loaded.rule)}
        queries, gaps = {}, {}
        for key, target in applicable.items():
            try:
                queries[key] = join_queries(convert(target, loaded.rule))
            except Exception as exc:  # pySigma raises many specific error types
                reason = " ".join(str(exc).split())
                if target.required:
                    failures.append(f"{rel} [{key}]: {reason}")
                gaps[key] = reason
        coverage.append({"path": rel, "title": raw["title"], "converted": sorted(queries), "gaps": gaps})
        if any(k in gaps for k, t in applicable.items() if t.required):
            continue

        # Splunk + Elastic are the deployed endpoint targets; cloud rules compile to KQL only
        # (query files + manifest), since dettools.deploy ships to Splunk/Kibana, not Sentinel.
        endpoint = "splunk" in applicable and "elastic_lucene" in applicable
        spl, siem_rules = "", []
        if endpoint:
            try:
                # Processing pipelines mutate the rule, so each backend gets its own copy.
                splunk_queries = convert(TARGETS["splunk"], loaded.rule)
                spl = splunk_queries[0] if len(splunk_queries) == 1 else " OR ".join(f"({q})" for q in splunk_queries)
                siem_rules = backend_for("elastic_lucene").convert_rule(copy.deepcopy(loaded.rule), "siem_rule_ndjson")
            except Exception as exc:
                failures.append(f"{rel}: {exc}")
                continue

        for key, query in queries.items():
            query_files[args.out / "queries" / key / f"{loaded.stem}.{TARGETS[key].ext}"] = query + "\n"

        stanza = ""
        if endpoint:
            stanza = splunk_stanza(name, spl, raw)
            stanzas.append(stanza)
            for siem_rule in siem_rules:
                # Kibana assigns its own object id; rules are matched on rule_id (= Sigma id).
                siem_rule.pop("id", None)
                siem_rule.setdefault("tags", [])
                siem_rule["tags"] = sorted(set(siem_rule["tags"]) | {"sigma-managed", f"status:{raw['status']}"})
                ndjson.append(json.dumps(siem_rule, sort_keys=True))
        manifest.append({
            "id": str(raw["id"]),
            "title": raw["title"],
            "name": name,
            "status": raw["status"],
            "level": raw["level"],
            "path": rel,
            "splunk": {"search": spl, "stanza": stanza},
            "elastic_rule_ids": [r["rule_id"] for r in siem_rules],
            "queries": queries,
            "gaps": gaps,
        })

    if failures:
        print("Conversion FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1

    (args.out / "splunk").mkdir(parents=True, exist_ok=True)
    (args.out / "elastic").mkdir(parents=True, exist_ok=True)
    (args.out / "splunk" / "savedsearches.conf").write_text("\n".join(stanzas), encoding="utf-8")
    (args.out / "elastic" / "rules.ndjson").write_text("\n".join(ndjson) + "\n", encoding="utf-8")
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    for path, query in query_files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(query, encoding="utf-8")
    (args.out / "coverage.json").write_text(json.dumps(coverage, indent=2), encoding="utf-8")
    (args.out / "coverage.md").write_text(coverage_markdown(coverage), encoding="utf-8")
    print(f"Converted {len(manifest)} rule(s) into {args.out}")
    for row in coverage:
        for key, reason in row["gaps"].items():
            print(f"  gap: {row['path']} [{key}]: {reason[:160]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
