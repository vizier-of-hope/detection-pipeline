"""Unit tests: every rule must fire on its true positives and stay quiet on its true negatives."""

import pytest

from dettools.common import load_fixture, load_rules
from dettools.evaluator import rule_matches


def _cases():
    for loaded in load_rules():
        if not loaded.fixture_path.exists():
            continue  # missing fixtures are reported by dettools.validate
        fixture = load_fixture(loaded.fixture_path)
        for expected, key in ((True, "true_positives"), (False, "true_negatives")):
            for case in fixture.get(key) or []:
                yield pytest.param(
                    loaded.rule, case["event"], expected,
                    id=f"{loaded.stem}::{key[:-1]}::{case.get('name', 'unnamed')}",
                )


@pytest.mark.parametrize("rule,event,expected", list(_cases()))
def test_rule_against_event(rule, event, expected):
    assert rule_matches(rule, event) is expected
