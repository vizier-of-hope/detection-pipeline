"""Create a new Sigma rule and its test fixture with policy-compliant boilerplate.

Run:
  python -m dettools.scaffold --title "Suspicious Rundll32 Without DLL" \
      --product windows --category process_creation --tactic defense-evasion --technique t1218.011

Writes rules/<product>/<category>/<name>.yml and tests/events/<name>.yml. The detection
and fixture events are placeholders: replace them, then run validate + pytest.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import uuid

import yaml

from dettools.common import EVENTS_DIR, RULES_DIR

CATEGORY_PREFIX = {"process_creation": "proc_creation"}


def rule_name(title: str, product: str, category: str) -> str:
    prefix = CATEGORY_PREFIX.get(category, category)
    product_short = {"windows": "win"}.get(product, product)
    slug = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")
    return f"{prefix}_{product_short}_{slug}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--title", required=True)
    parser.add_argument("--product", required=True, help="e.g. windows, linux, macos, aws, azure, okta")
    parser.add_argument("--category", help="e.g. process_creation, network_connection, file_event")
    parser.add_argument("--service", help="e.g. security, cloudtrail, sysmon (use instead of/with category)")
    parser.add_argument("--tactic", required=True, help="ATT&CK tactic, e.g. execution")
    parser.add_argument("--technique", required=True, help="ATT&CK technique, e.g. t1059.001")
    parser.add_argument("--level", default="medium", choices=["informational", "low", "medium", "high", "critical"])
    parser.add_argument("--author", default="Detection Engineering Team")
    args = parser.parse_args(argv)

    if not (args.category or args.service):
        parser.error("give --category and/or --service")

    group = args.category or args.service
    name = rule_name(args.title, args.product, group)
    rule_path = RULES_DIR / args.product / group / f"{name}.yml"
    fixture_path = EVENTS_DIR / f"{name}.yml"
    for p in (rule_path, fixture_path):
        if p.exists():
            print(f"Refusing to overwrite {p}")
            return 1

    rule_id = str(uuid.uuid4())
    technique = args.technique.lower().removeprefix("attack.")
    logsource = {"product": args.product}
    if args.category:
        logsource["category"] = args.category
    if args.service:
        logsource["service"] = args.service

    rule = {
        "title": args.title,
        "id": rule_id,
        "status": "experimental",
        "description": "TODO: what behaviour this detects and why it matters.",
        "references": [f"https://attack.mitre.org/techniques/{technique.upper().replace('.', '/')}/"],
        "author": args.author,
        "date": dt.date.today().isoformat(),
        "tags": [f"attack.{args.tactic.lower().removeprefix('attack.')}", f"attack.{technique}"],
        "logsource": logsource,
        "detection": {
            "selection": {"TODO_Field|contains": "TODO_value"},
            "condition": "selection",
        },
        "falsepositives": ["TODO: known benign causes"],
        "level": args.level,
    }
    fixture = {
        "rule_id": rule_id,
        "true_positives": [{"name": "TODO malicious example", "event": {"TODO_Field": "xx TODO_value xx"}}],
        "true_negatives": [{"name": "TODO benign look-alike", "event": {"TODO_Field": "benign"}}],
    }

    rule_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    dump = lambda d: yaml.safe_dump(d, sort_keys=False, allow_unicode=True, width=120)  # noqa: E731
    rule_path.write_text(dump(rule), encoding="utf-8")
    fixture_path.write_text(dump(fixture), encoding="utf-8")
    print(rule_path)
    print(fixture_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
