"""Enforce the team's rule-quality policy on every Sigma rule.

Run: python -m dettools.validate
Exits non-zero and prints every violation if any rule fails policy.
"""

from __future__ import annotations

import re
import sys
import uuid
from collections import defaultdict
from pathlib import Path

from dettools.common import REPO_ROOT, STATUS_ORDER, load_fixture, load_rule, rule_files

REQUIRED_FIELDS = [
    "title", "id", "status", "description", "author", "date",
    "tags", "logsource", "detection", "falsepositives", "level",
]
LEVELS = {"informational", "low", "medium", "high", "critical"}
FILENAME_RE = re.compile(r"^[a-z0-9_]+\.yml$")
TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TACTIC_RE = re.compile(r"^attack\.[a-z-]+$")
MAX_TITLE_LEN = 110


def validate_rule(path: Path) -> tuple[list[str], dict | None]:
    errors: list[str] = []
    rel = path.relative_to(REPO_ROOT).as_posix()

    if not FILENAME_RE.match(path.name):
        errors.append(f"{rel}: filename must be lowercase snake_case ending in .yml")

    try:
        loaded = load_rule(path)
    except Exception as exc:  # pySigma raises many specific error types
        return [f"{rel}: failed to parse as Sigma: {exc}"], None
    raw = loaded.raw

    for field in REQUIRED_FIELDS:
        if not raw.get(field):
            errors.append(f"{rel}: missing required field '{field}'")

    try:
        uuid.UUID(str(raw.get("id", "")))
    except ValueError:
        errors.append(f"{rel}: id must be a UUID")

    if raw.get("status") not in STATUS_ORDER:
        errors.append(f"{rel}: status must be one of {STATUS_ORDER}")
    if raw.get("level") not in LEVELS:
        errors.append(f"{rel}: level must be one of {sorted(LEVELS)}")
    if len(str(raw.get("title", ""))) > MAX_TITLE_LEN:
        errors.append(f"{rel}: title longer than {MAX_TITLE_LEN} characters")

    tags = raw.get("tags") or []
    if not any(TECHNIQUE_RE.match(t) for t in tags):
        errors.append(f"{rel}: needs at least one ATT&CK technique tag (attack.tNNNN)")
    if not any(TACTIC_RE.match(t) and not TECHNIQUE_RE.match(t) for t in tags):
        errors.append(f"{rel}: needs at least one ATT&CK tactic tag (e.g. attack.execution)")

    if "TODO" in path.read_text(encoding="utf-8"):
        errors.append(f"{rel}: contains TODO placeholders from dettools.scaffold")

    errors.extend(validate_fixture(loaded, rel))
    return errors, raw


def validate_fixture(loaded, rel: str) -> list[str]:
    fixture = loaded.fixture_path
    frel = fixture.relative_to(REPO_ROOT).as_posix()
    if not fixture.exists():
        return [f"{rel}: missing test fixture {frel}"]
    data = load_fixture(fixture)
    errors = []
    if "TODO" in fixture.read_text(encoding="utf-8"):
        errors.append(f"{frel}: contains TODO placeholders from dettools.scaffold")
    if str(data.get("rule_id")) != str(loaded.raw.get("id")):
        errors.append(f"{frel}: rule_id does not match rule id {loaded.raw.get('id')}")
    if not data.get("true_positives"):
        errors.append(f"{frel}: needs at least one true_positives case")
    if not data.get("true_negatives"):
        errors.append(f"{frel}: needs at least one true_negatives case")
    return errors


def main() -> int:
    paths = rule_files()
    if not paths:
        print("No rules found under rules/")
        return 1

    errors: list[str] = []
    ids: dict[str, list[str]] = defaultdict(list)
    titles: dict[str, list[str]] = defaultdict(list)

    for path in paths:
        rule_errors, raw = validate_rule(path)
        errors.extend(rule_errors)
        if raw:
            rel = path.relative_to(REPO_ROOT).as_posix()
            ids[str(raw.get("id"))].append(rel)
            titles[str(raw.get("title")).lower()].append(rel)

    for value, files in list(ids.items()) + list(titles.items()):
        if len(files) > 1:
            errors.append(f"duplicate id/title '{value}' in: {', '.join(files)}")

    if errors:
        print(f"Policy validation FAILED ({len(errors)} issue(s)):")
        for err in errors:
            print(f"  - {err}")
        return 1
    print(f"Policy validation passed for {len(paths)} rule(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
