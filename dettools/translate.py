"""Translate one Sigma rule (a file, or stdin with '-') into every registered SIEM language.

Run:
  python -m dettools.translate rules/windows/process_creation/foo.yml
  python -m dettools.translate draft.yml --target microsoft_xdr --target splunk
  python -m dettools.translate draft.yml --json        # machine-readable, for agents
  python -m dettools.translate --list                  # show available targets

Exit code is 1 if the rule does not parse or any *requested* target fails.
With no --target, every target whose logsource fits the rule is tried and only required targets
affect the exit code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sigma.rule import SigmaRule

from dettools.targets import TARGETS, convert, join_queries


def translate(rule_yaml: str, keys: list[str] | None = None) -> dict[str, dict]:
    rule = SigmaRule.from_yaml(rule_yaml)
    if keys is None:  # default: only the targets whose backend/pipeline fits this rule's logsource
        keys = [key for key, target in TARGETS.items() if target.applies_to(rule)]
    results = {}
    for key in keys:
        target = TARGETS[key]
        entry = {"siem": target.siem, "language": target.language, "required": target.required}
        try:
            entry["query"] = join_queries(convert(target, rule))
        except Exception as exc:  # pySigma raises many specific error types
            entry["error"] = " ".join(str(exc).split())
        if target.caveat:
            entry["caveat"] = target.caveat
        results[key] = entry
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("rule", nargs="?", help="Sigma rule file, or '-' for stdin")
    parser.add_argument("--target", action="append", choices=sorted(TARGETS), help="repeatable; default: all")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--list", action="store_true", help="list targets and exit")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # windash emits en/em dashes

    if args.list:
        for t in TARGETS.values():
            flag = "required" if t.required else "best-effort"
            print(f"{t.key:22} {t.siem} - {t.language} ({flag})")
        return 0
    if not args.rule:
        parser.error("rule is required unless --list is given")

    text = sys.stdin.read() if args.rule == "-" else Path(args.rule).read_text(encoding="utf-8")
    try:
        results = translate(text, args.target)  # None -> targets that apply to this rule's logsource
    except Exception as exc:
        print(f"Rule failed to parse as Sigma: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for key, r in results.items():
            print(f"===== {key}: {r['siem']} ({r['language']})")
            print(r.get("query") or f"!! NOT CONVERTIBLE: {r['error']}")
            if r.get("caveat"):
                print(f"-- note: {r['caveat']}")
            print()

    failed = [k for k, r in results.items() if "error" in r and (args.target or r["required"])]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
