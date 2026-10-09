"""Checks on the multi-SIEM target registry, translate CLI and scaffold CLI."""

import json
import re

import pytest
import yaml
from sigma.conditions import ConditionAND, ConditionOR
from sigma.rule import SigmaRule

from dettools import scaffold, translate
from dettools.common import load_rules
from dettools.targets import TARGETS, backend_for, convert, join_queries

PROBE_TEMPLATE = r"""
title: Precedence Probe
id: 00000000-0000-4000-8000-000000000001
status: test
logsource: {{category: process_creation, product: windows}}
detection:
  sel_a: {{CommandLine|contains: 'aaa1'}}
  sel_b: {{Image|endswith: '\bbb2.exe'}}
  sel_c: {{ParentCommandLine|contains: 'ccc3'}}
  condition: {condition}
level: low
"""
PROBE_CONDITIONS = [
    "(sel_a or sel_b) and sel_c",
    "sel_a and (sel_b or sel_c)",
    "sel_a or (sel_b and sel_c)",
    "not (sel_a or sel_b) and sel_c",
]
# Languages whose vendor docs do not state AND/OR precedence: every mix must be grouped.
UNVERIFIED_PRECEDENCE = {"secops_udm", "secops_yaral"}
PRECEDENCE_RULE = PROBE_TEMPLATE.format(condition=PROBE_CONDITIONS[0])

_STRINGS = re.compile(r'"(?:[^"\\]|\\.)*"' + r"|'(?:[^'\\]|\\.)*'" + r"|/(?:[^/\\]|\\.)+/")
_BOOL = re.compile(r"\b(and|or)\b", re.IGNORECASE)


def mixed_operator_groups(query: str) -> list[str]:
    """Parenthesis groups that contain both AND and OR at the same nesting level.

    Such a group means the result depends on the language's AND/OR precedence.
    """
    text = _STRINGS.sub('""', query)
    stack: list[list] = [[0, set()]]
    bad = []
    for i, ch in enumerate(text):
        if ch == "(":
            stack.append([i, set()])
        elif ch == ")" and len(stack) > 1:
            start, ops = stack.pop()
            if ops == {"and", "or"}:
                bad.append(text[start:i + 1])
        else:
            m = _BOOL.match(text, i)
            if m and (i == 0 or not text[i - 1].isalnum() and text[i - 1] != "_"):
                stack[-1][1].add(m.group(1).lower())
    if stack[0][1] == {"and", "or"}:
        bad.append(text)
    return bad


def test_mixed_operator_detector():
    assert mixed_operator_groups('a = "x and y" AND (b OR c)') == []
    assert mixed_operator_groups("(a or b and c) and d") == ["(a or b and c)"]
    assert mixed_operator_groups("a OR b AND c")


@pytest.mark.parametrize("key", [k for k, t in TARGETS.items() if not t.and_binds_tighter])
def test_or_tighter_targets_have_matching_backend_precedence(key):
    # Only languages verified to bind OR tighter than AND (SPL search, LogScale) may emit ungrouped
    # mixes, and only if the backend's precedence model agrees. SPL2 failed exactly this check.
    backend = backend_for(key)
    precedence = list(backend.precedence)
    assert backend.parenthesize or precedence.index(ConditionOR) < precedence.index(ConditionAND), precedence


@pytest.mark.parametrize("condition", PROBE_CONDITIONS)
@pytest.mark.parametrize("key", [k for k, t in TARGETS.items() if t.and_binds_tighter])
def test_mixed_and_or_are_always_parenthesised(key, condition):
    rule = SigmaRule.from_yaml(PROBE_TEMPLATE.format(condition=condition))
    try:
        query = join_queries(convert(TARGETS[key], rule))
    except Exception as exc:
        pytest.skip(f"{key} cannot express the probe rule: {exc}")
    if key == "secops_yaral":
        query = query.split("events:", 1)[1].split("condition", 1)[0]  # only the event predicates
    if condition == "sel_a or (sel_b and sel_c)" and key not in UNVERIFIED_PRECEDENCE:
        return  # `a or b and c` already means this in AND-tighter languages
    assert mixed_operator_groups(query) == [], query


@pytest.mark.parametrize("key", [k for k, t in TARGETS.items() if t.required])
def test_required_targets_convert_every_rule(key):
    for loaded in load_rules():
        if not TARGETS[key].applies_to(loaded.rule):
            continue  # a target is only required to compile the rules it applies to
        assert join_queries(convert(TARGETS[key], loaded.rule)).strip(), loaded.path


def test_translate_json_reports_queries_and_errors(capsys):
    # An endpoint rule, so microsoft_xdr maps to DeviceProcessEvents (pinned, not load_rules()[0],
    # which a non-endpoint-logsource rule could otherwise displace).
    loaded = next(r for r in load_rules() if r.path.name == "proc_creation_win_certutil_download.yml")
    assert translate.main([str(loaded.path), "--json"]) == 0
    results = json.loads(capsys.readouterr().out)
    # With no --target, translate runs only the targets whose logsource fits the rule.
    assert set(results) == {k for k, t in TARGETS.items() if t.applies_to(loaded.rule)}
    assert "sentinel_signin" not in results  # sign-in target does not apply to an endpoint rule
    for r in results.values():
        assert ("query" in r) != ("error" in r)
    assert results["splunk"]["query"] and results["microsoft_xdr"]["query"].startswith("DeviceProcessEvents")


def test_translate_fails_when_requested_target_fails(tmp_path):
    bad = tmp_path / "bad.yml"
    # LogScale only has the parent's file name, so a full-path ParentImage match cannot convert.
    bad.write_text(PRECEDENCE_RULE.replace("CommandLine|contains: 'aaa1'", r"ParentImage: 'C:\x\aaa1.exe'"), encoding="utf-8")
    assert translate.main([str(bad), "--target", "crowdstrike_logscale"]) == 1


def test_scaffold_creates_parseable_rule_and_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(scaffold, "RULES_DIR", tmp_path / "rules")
    monkeypatch.setattr(scaffold, "EVENTS_DIR", tmp_path / "events")
    assert scaffold.main([
        "--title", "Rundll32 Without DLL Argument", "--product", "windows",
        "--category", "process_creation", "--tactic", "defense-evasion", "--technique", "T1218.011",
    ]) == 0
    rule_file = tmp_path / "rules/windows/process_creation/proc_creation_win_rundll32_without_dll_argument.yml"
    fixture = yaml.safe_load((tmp_path / "events" / rule_file.name).read_text(encoding="utf-8"))
    rule = SigmaRule.from_yaml(rule_file.read_text(encoding="utf-8"))
    assert str(rule.id) == fixture["rule_id"]
    assert {t.name for t in rule.tags} >= {"defense-evasion", "t1218.011"}
    # Refuses to clobber existing work.
    assert scaffold.main([
        "--title", "Rundll32 Without DLL Argument", "--product", "windows",
        "--category", "process_creation", "--tactic", "defense-evasion", "--technique", "T1218.011",
    ]) == 1


def test_field_mapping_doc_is_current():
    # docs/siem/field-mappings.md is generated from the pipelines; regenerate after upgrades.
    from dettools import fieldmap
    assert fieldmap.main(["--check"]) == 0, "run: python -m dettools.fieldmap"


def test_esql_postprocess_makes_string_matches_case_insensitive():
    from dettools.targets import esql_case_insensitive as ci
    q = ('from * | where (starts_with(a.b, "AbC") or ends_with(c, "\\X.EXE")) and d in ("P", "q") '
         'and e.f=="Mixed" and g like "*Delete*" and user.name rlike "^ADM.*" and h like "say \\" like \\"Q\\""')
    out = ci(q)
    assert 'starts_with(to_lower(a.b), "abc")' in out
    assert 'ends_with(to_lower(c), "\\x.exe")' in out
    assert 'to_lower(d) in ("p", "q")' in out
    assert 'to_lower(e.f) == "mixed"' in out
    assert 'to_lower(g) like "*delete*"' in out
    assert 'user.name rlike "^ADM.*"' in out  # Sigma regexes stay case-sensitive
    assert 'to_lower(h) like "say \\" like \\"q\\""' in out  # quotes inside literals don't confuse it


def test_compiled_esql_has_no_case_sensitive_string_match():
    for loaded in load_rules():
        query = join_queries(convert(TARGETS["elastic_esql"], loaded.rule))
        code = _STRINGS.sub('""', query)
        # Every == / like / in / starts_with / ends_with operand must be wrapped in to_lower().
        for m in re.finditer(r'(\S+)\s*(?:==|\blike\b|\bin\b)\s*[("]', code):
            operand = m.group(1).lstrip("(")
            if operand not in ("rlike", "from", "|"):
                assert operand.startswith("to_lower("), f"{loaded.path.name}: {m.group(0)!r} in {query}"
        for m in re.finditer(r"\b(?:starts_with|ends_with)\((\S+)", code):
            assert m.group(1).lstrip("(").startswith("to_lower("), f"{loaded.path.name}: {m.group(0)!r}"
