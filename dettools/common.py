"""Shared helpers: locating rules, loading them, and loading test fixtures."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.rule import SigmaRule

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
EVENTS_DIR = REPO_ROOT / "tests" / "events"
BUILD_DIR = REPO_ROOT / "build"

# Promotion order. Rules below the deploy threshold are built but not shipped.
STATUS_ORDER = ["experimental", "test", "stable"]


@dataclass
class LoadedRule:
    path: Path
    raw: dict
    rule: SigmaRule

    @property
    def stem(self) -> str:
        return self.path.stem

    @property
    def fixture_path(self) -> Path:
        return EVENTS_DIR / f"{self.stem}.yml"


def rule_files(rules_dir: Path = RULES_DIR) -> list[Path]:
    return sorted(p for p in rules_dir.rglob("*") if p.suffix in (".yml", ".yaml"))


def load_rule(path: Path) -> LoadedRule:
    text = path.read_text(encoding="utf-8")
    return LoadedRule(path=path, raw=yaml.safe_load(text), rule=SigmaRule.from_yaml(text))


def load_rules(rules_dir: Path = RULES_DIR) -> list[LoadedRule]:
    return [load_rule(p) for p in rule_files(rules_dir)]


def load_fixture(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def meets_status(status: str, minimum: str) -> bool:
    return STATUS_ORDER.index(status) >= STATUS_ORDER.index(minimum)
