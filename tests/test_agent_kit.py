"""Offline checks for the agent definitions and the live agent test kit (agent-tests/)."""

import importlib.util
import os
import sys
from pathlib import Path

import pytest
import yaml
from sigma.rule import SigmaRule

from dettools.common import load_fixture
from dettools.evaluator import rule_matches

REPO = Path(__file__).resolve().parent.parent
AGENTS = REPO / ".claude" / "agents"
KIT = REPO / "agent-tests"
FAKE = Path(__file__).resolve().parent / "agent_kit" / "fake_claude.py"

if not (KIT / "fixtures").exists():
    # Inside a run.py workspace the answers are removed on purpose; nothing to check here.
    pytest.skip("agent-tests fixtures not present", allow_module_level=True)

# Some tests spin up a throwaway workspace that links the repo's own .venv; skip them where no
# repo venv exists (CI / the pipeline Docker image install deps globally instead).
_VENV_PY = REPO / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
requires_repo_venv = pytest.mark.skipif(
    not _VENV_PY.exists(),
    reason="needs the repo .venv linked into throwaway workspaces (absent in CI/Docker)",
)

READ_ONLY = {"Read", "Grep", "Glob", "WebFetch", "WebSearch"}
REVIEW_AGENTS = {
    "AI-Generated Code Security Auditor", "Application Security Engineer", "Security Architect",
    "Blockchain Security Auditor", "Cloud Security Architect", "Compliance Auditor",
    "Threat Intelligence Analyst",
}
HANDS_ON_AGENTS = {
    "Incident Responder", "Penetration Tester", "Secrets & Credential Hygiene Engineer",
    "Senior SecOps Engineer", "Threat Detection Engineer", "detection-engineer",
}
KNOWN_CHECKS = {
    "delegated_to", "output_matches", "output_matches_any", "files_absent", "no_changes",
    "subagent_forbidden_tools", "gates_pass", "new_rule", "rule_matches",
}


def _frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), path.name
    return yaml.safe_load(text[4:text.index("\n---\n", 4)])


def _agents() -> dict[str, dict]:
    return {fm["name"]: fm for fm in (_frontmatter(p) for p in sorted(AGENTS.glob("*.md")))}


def _tools(fm: dict) -> set[str] | None:
    raw = fm.get("tools")
    return None if raw is None else {t.strip() for t in str(raw).split(",") if t.strip()}


def _load_runner():
    # agent-tests/ isn't an importable package name, so load run.py by path. Dataclasses need the
    # module registered in sys.modules before it executes.
    if "agent_kit_run" in sys.modules:
        return sys.modules["agent_kit_run"]
    spec = importlib.util.spec_from_file_location("agent_kit_run", KIT / "run.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_kit_run"] = module
    spec.loader.exec_module(module)
    return module


# ----------------------------------------------------------------- agent definitions

def test_every_agent_has_valid_unique_frontmatter():
    names = []
    for path in AGENTS.glob("*.md"):
        fm = _frontmatter(path)
        assert fm.get("name") and fm.get("description"), path.name
        names.append(fm["name"])
    assert len(names) == len(set(names))
    assert set(_agents()) == REVIEW_AGENTS | HANDS_ON_AGENTS


@pytest.mark.parametrize("name", sorted(REVIEW_AGENTS))
def test_review_agents_are_read_only(name):
    tools = _tools(_agents()[name])
    assert tools is not None, f"{name} has no tools: line, so it inherits every tool"
    assert tools <= READ_ONLY, f"{name} has non-read-only tools: {sorted(tools - READ_ONLY)}"


def test_detection_engineer_can_run_the_gates_and_references_real_files():
    fm = _agents()["detection-engineer"]
    assert {"Bash", "Write", "Edit", "Read"} <= _tools(fm)
    body = (AGENTS / "detection-engineer.md").read_text(encoding="utf-8")
    for doc in ("docs/siem/field-mappings.md", "docs/siem/sigma.md", "docs/siem/review-checklist.md"):
        assert doc in body and (REPO / doc).exists(), doc
    for module in ("scaffold", "translate", "validate", "convert", "evaluator", "targets"):
        assert (REPO / "dettools" / f"{module}.py").exists(), module


# ----------------------------------------------------------------- cases.yml integrity

def test_cases_file_is_well_formed():
    runner = _load_runner()
    cases = runner.load_cases(KIT / "cases.yml")
    agent_names = {runner._norm_agent(n) for n in _agents()}
    for case in cases:
        assert case["prompt"].strip(), case["id"]
        assert set(case.get("checks", {})) <= KNOWN_CHECKS, case["id"]
        for rel in case.get("plant", []):
            assert (KIT / "fixtures" / "plant" / rel).exists(), f"{case['id']}: missing plant {rel}"
        target = case.get("checks", {}).get("delegated_to")
        if target:
            assert runner._norm_agent(target) in agent_names, f"{case['id']}: unknown agent {target}"
        for spec in case.get("checks", {}).get("rule_matches", []):
            assert (REPO / spec["rule"]).exists() or spec["rule"] in case.get("plant", []), spec["rule"]


def test_planted_rule_hides_its_flaws_from_the_normal_gates():
    # The review case is only meaningful if the planted rule passes its own fixture yet misses
    # every attack variant the case expects the agent to fix.
    runner = _load_runner()
    case = next(c for c in runner.load_cases(KIT / "cases.yml") if c["id"] == "de_review_planted")
    plant = KIT / "fixtures" / "plant"
    rule_rel = next(p for p in case["plant"] if p.startswith("rules/"))
    rule = SigmaRule.from_yaml((plant / rule_rel).read_text(encoding="utf-8"))
    fixture = load_fixture(plant / next(p for p in case["plant"] if p.startswith("tests/")))
    assert all(rule_matches(rule, c["event"]) for c in fixture["true_positives"])
    assert not any(rule_matches(rule, c["event"]) for c in fixture["true_negatives"])
    for spec in case["checks"]["rule_matches"]:
        if spec["expect"]:
            assert rule_matches(rule, spec["event"]) is False, f"planted rule already catches {spec['event']}"


# ----------------------------------------------------------------- runner, with a fake claude

def test_parse_stream_tracks_delegation_and_subagent_tools():
    runner = _load_runner()
    lines = [
        '{"type":"assistant","message":{"content":[{"type":"tool_use","id":"a","name":"Task","input":{"subagent_type":"X"}}]}}',
        '{"type":"assistant","parent_tool_use_id":"a","message":{"content":[{"type":"tool_use","id":"b","name":"Write","input":{}}]}}',
        "not json",
        '{"type":"result","result":"done","is_error":false}',
    ]
    t = runner.parse_stream(lines)
    assert t.delegations == {"a": "X"} and t.subagent_tools == [("X", "Write")] and t.final == "done"


def _fake_case(runner, scenario, checks, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_SCENARIO", scenario)
    case = {"id": f"fake_{scenario}", "prompt": "do the thing | with & \"quotes\"", "max_turns": 3,
            "timeout": 300, "allowed_tools": ["Read"], "checks": checks}
    return runner.run_case(case, runner.resolve_claude(str(FAKE)), None, keep=False)


READONLY_CHECKS = {
    "delegated_to": "Compliance Auditor", "files_absent": ["soc2.md"], "no_changes": True,
    "subagent_forbidden_tools": ["Write", "Edit", "Bash"], "output_matches": ["change management"],
}


@requires_repo_venv
def test_runner_passes_a_well_behaved_read_only_agent(monkeypatch):
    runner = _load_runner()
    result = _fake_case(runner, "readonly_good", READONLY_CHECKS, monkeypatch)
    assert result["passed"], result["checks"]


@requires_repo_venv
def test_runner_catches_a_read_only_agent_that_writes(monkeypatch):
    runner = _load_runner()
    result = _fake_case(runner, "readonly_bad", READONLY_CHECKS, monkeypatch)
    failed = {c["check"] for c in result["checks"] if not c["ok"]}
    assert not result["passed"]
    assert failed == {"no file matches soc2.md", "repository unchanged", "subagent never used ['Bash', 'Edit', 'Write']"}
    assert not (REPO / "soc2.md").exists(), "the fake must only ever write inside the workspace"


@requires_repo_venv
def test_runner_verifies_new_rule_logic_and_gates_in_the_workspace(monkeypatch):
    runner = _load_runner()
    spec = yaml.safe_load((KIT / "cases.yml").read_text(encoding="utf-8"))
    new_rule = next(c for c in spec["cases"] if c["id"] == "de_new_rule")["checks"]["new_rule"]
    checks = {"delegated_to": "detection-engineer", "gates_pass": True, "new_rule": new_rule}
    result = _fake_case(runner, "new_rule_good", checks, monkeypatch)
    assert result["passed"], result["checks"]
    assert not list((REPO / "rules").rglob("proc_creation_win_schtasks_users_public.yml"))


@requires_repo_venv
def test_workspace_cleanup_never_touches_the_real_venv():
    runner = _load_runner()
    work = runner.make_workspace({"id": "cleanup", "plant": []})
    assert os.path.lexists(work / ".venv")
    assert not (work / "agent-tests" / "fixtures").exists(), "answers must not be visible to agents"
    runner.remove_workspace(work)
    assert not work.parent.exists()
    assert runner.VENV_PY.exists(), "real venv was damaged by cleanup"
