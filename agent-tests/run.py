"""Live regression tests for the project's Claude Code agents.

Run (from the repo root):
  python agent-tests/run.py --list
  python agent-tests/run.py                       # every case in agent-tests/cases.yml
  python agent-tests/run.py --case de_new_rule --keep
  python agent-tests/run.py --claude path/to/claude --model claude-sonnet-5-5

Each case runs `claude -p` headless in a throwaway copy of the repo (the real repo is never
touched), with the case's tool allowlist. It then checks the transcript and the copy: which
subagent was delegated to, which tools that subagent used, which files changed, whether the
repo gates pass, and whether rules really match the given events.
Results go to agent-tests/results/<timestamp>.json. Exit code 1 if any case fails.

Costs real model usage: every case is a full agent run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

KIT = Path(__file__).resolve().parent
REPO = KIT.parent
sys.path.insert(0, str(REPO))

from sigma.rule import SigmaRule  # noqa: E402

from dettools.evaluator import rule_matches  # noqa: E402

PLANT_DIR = KIT / "fixtures" / "plant"
COPY_IGNORE = shutil.ignore_patterns(".git", ".venv", "build", "reports", ".pytest_cache", "__pycache__", "results")
SNAPSHOT_SKIP_DIRS = {".venv", "build", "reports", ".pytest_cache", "__pycache__", ".git"}
VENV_PY = REPO / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
AUTH_ERROR = re.compile(r"not logged in|please run /login|invalid api key", re.IGNORECASE)


# --------------------------------------------------------------------------- workspace

def make_workspace(case: dict) -> Path:
    root = Path(tempfile.mkdtemp(prefix=f"agent-test-{case['id']}-"))
    work = root / "repo"
    shutil.copytree(REPO, work, ignore=COPY_IGNORE)
    shutil.rmtree(work / "agent-tests" / "fixtures", ignore_errors=True)  # agents must not see answers
    _link_venv(work / ".venv")
    for rel in case.get("plant", []):
        dest = work / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PLANT_DIR / rel, dest)
    return work


def _link_venv(link: Path) -> None:
    """Reuse the real venv without copying it: a junction on Windows, a symlink elsewhere."""
    target = REPO / ".venv"
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)
    else:
        link.symlink_to(target, target_is_directory=True)


def remove_workspace(work: Path) -> None:
    link = work / ".venv"
    # Remove the link itself first so nothing can ever recurse into the real venv.
    if os.path.lexists(link):
        try:
            os.unlink(link)
        except OSError:
            os.rmdir(link)  # Windows directory junction
    if os.path.lexists(link):
        raise RuntimeError(f"refusing to delete {work}: could not remove venv link")
    shutil.rmtree(work.parent, ignore_errors=True)


def snapshot(work: Path) -> dict[str, str]:
    files = {}
    for dirpath, dirnames, filenames in os.walk(work):
        dirnames[:] = [d for d in dirnames if d not in SNAPSHOT_SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            files[path.relative_to(work).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def diff(before: dict[str, str], after: dict[str, str]) -> dict[str, list[str]]:
    return {
        "created": sorted(set(after) - set(before)),
        "deleted": sorted(set(before) - set(after)),
        "modified": sorted(k for k in set(before) & set(after) if before[k] != after[k]),
    }


# --------------------------------------------------------------------------- claude

@dataclass
class Transcript:
    final: str = ""
    delegations: dict[str, str] = field(default_factory=dict)       # tool_use_id -> subagent_type
    subagent_tools: list[tuple[str, str]] = field(default_factory=list)  # (subagent_type, tool name)
    all_tools: list[str] = field(default_factory=list)
    is_error: bool = False
    raw_lines: int = 0


def parse_stream(lines: list[str]) -> Transcript:
    t = Transcript()
    pending: list[tuple[str | None, str]] = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        t.raw_lines += 1
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "result":
            t.final = str(event.get("result") or "")
            t.is_error = bool(event.get("is_error"))
            continue
        message = event.get("message") or {}
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        parent = event.get("parent_tool_use_id")
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "tool_use":
                continue
            name, tool_input = item.get("name", ""), item.get("input") or {}
            t.all_tools.append(name)
            if isinstance(tool_input, dict) and tool_input.get("subagent_type"):
                t.delegations[item.get("id", "")] = str(tool_input["subagent_type"])
            if parent:
                pending.append((parent, name))
    for parent, name in pending:
        t.subagent_tools.append((t.delegations.get(parent, "?"), name))
    return t


def claude_command(claude: list[str], case: dict, model: str | None) -> list[str]:
    # The prompt goes in on stdin: if `claude` is a .cmd shim, cmd.exe would mangle | & " in argv.
    cmd = [*claude, "-p", "--output-format", "stream-json", "--verbose",
           "--max-turns", str(case["max_turns"])]
    model = case.get("model") or model  # a case may pin its own model (e.g. one less prone to flagging)
    if model:
        cmd += ["--model", model]
    if case.get("allowed_tools"):
        cmd += ["--allowedTools", ",".join(case["allowed_tools"])]
    if case.get("disallowed_tools"):
        cmd += ["--disallowedTools", ",".join(case["disallowed_tools"])]
    return cmd


def run_claude(claude: list[str], case: dict, work: Path, model: str | None) -> tuple[Transcript, str]:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        claude_command(claude, case, model), input=case["prompt"], cwd=work, env=env, capture_output=True,
        text=True, encoding="utf-8", errors="replace", timeout=case["timeout"],
    )
    transcript = parse_stream(proc.stdout.splitlines())
    if proc.returncode != 0 and not transcript.final:
        transcript.is_error = True
    return transcript, proc.stderr[-2000:]


# --------------------------------------------------------------------------- checks

def _ci_search(pattern: str, text: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE | re.DOTALL) is not None


def _norm_agent(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _load_rule(path: Path) -> SigmaRule:
    return SigmaRule.from_yaml(path.read_text(encoding="utf-8"))


def _gates(work: Path) -> tuple[bool, str]:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    out = []
    for args in (["-m", "dettools.validate"], ["-m", "pytest", "-q", "-p", "no:cacheprovider"]):
        proc = subprocess.run([str(VENV_PY), *args], cwd=work, env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=600)
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
        out.append(f"{' '.join(args)} -> exit {proc.returncode}: {' | '.join(tail)}")
        if proc.returncode != 0:
            return False, "\n".join(out)
    return True, "\n".join(out)


def run_checks(case: dict, t: Transcript, work: Path, changes: dict[str, list[str]]) -> list[tuple[str, bool, str]]:
    checks = case.get("checks", {})
    results: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, ok, detail))

    add("claude run completed", not t.is_error and bool(t.final),
        t.final[:300] if t.is_error else ("" if t.final else f"no final result ({t.raw_lines} stream events)"))

    if "delegated_to" in checks:
        want = _norm_agent(checks["delegated_to"])
        used = sorted(set(t.delegations.values()))
        add(f"delegated to {checks['delegated_to']}", any(_norm_agent(u) == want for u in used),
            f"subagents used: {used or 'none'}")

    for pattern in checks.get("output_matches", []):
        add(f"output matches /{pattern}/", _ci_search(pattern, t.final))
    if checks.get("output_matches_any"):
        pats = checks["output_matches_any"]
        add(f"output matches any of {pats}", any(_ci_search(p, t.final) for p in pats))

    for pattern in checks.get("files_absent", []):
        present = [p for p in snapshot(work) if fnmatch.fnmatch(p, pattern)]
        add(f"no file matches {pattern}", not present, ", ".join(present))

    if checks.get("no_changes"):
        changed = changes["created"] + changes["modified"] + changes["deleted"]
        add("repository unchanged", not changed, json.dumps(changes))

    if checks.get("subagent_forbidden_tools"):
        forbidden = set(checks["subagent_forbidden_tools"])
        hits = sorted({f"{agent}:{tool}" for agent, tool in t.subagent_tools if tool in forbidden})
        add(f"subagent never used {sorted(forbidden)}", not hits, ", ".join(hits))

    if checks.get("gates_pass"):
        ok, detail = _gates(work)
        add("repo gates pass (validate + pytest)", ok, detail)

    if "new_rule" in checks:
        spec = checks["new_rule"]
        candidates = [p for p in changes["created"] if p.startswith("rules/") and p.endswith((".yml", ".yaml"))]
        verdicts = []
        for rel in candidates:
            try:
                rule = _load_rule(work / rel)
                tp = all(rule_matches(rule, e) for e in spec.get("true_positives", []))
                tn = not any(rule_matches(rule, e) for e in spec.get("true_negatives", []))
                verdicts.append((rel, tp and tn, f"tp={tp} tn={tn}"))
            except Exception as exc:  # unsupported features, parse errors
                verdicts.append((rel, False, f"error: {exc}"))
        add("new rule matches all TPs and no TNs", any(v[1] for v in verdicts),
            "; ".join(f"{r}: {d}" for r, _, d in verdicts) or "no new rule files created")

    for i, spec in enumerate(checks.get("rule_matches", []), 1):
        path = work / spec["rule"]
        try:
            got = rule_matches(_load_rule(path), spec["event"])
            add(f"rule_matches #{i} expect={spec['expect']}", got is spec["expect"],
                f"{spec['rule']} -> {got} for {spec['event']}")
        except Exception as exc:
            add(f"rule_matches #{i} expect={spec['expect']}", False, f"error: {exc}")
    return results


# --------------------------------------------------------------------------- main

def load_cases(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    defaults = data.get("defaults", {})
    cases = []
    for case in data["cases"]:
        merged = {**defaults, **case}
        merged.setdefault("max_turns", 40)
        merged.setdefault("timeout", 1200)
        cases.append(merged)
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate case ids in cases file")
    return cases


def resolve_claude(arg: str | None) -> list[str]:
    exe = arg or shutil.which("claude")
    if not exe:
        raise SystemExit("claude CLI not found. Install Claude Code or pass --claude <path>.")
    if exe.endswith(".py"):
        return [sys.executable, exe]
    return [exe]


def run_case(case: dict, claude: list[str], model: str | None, keep: bool) -> dict:
    work = make_workspace(case)
    started = time.time()
    try:
        before = snapshot(work)
        try:
            transcript, stderr = run_claude(claude, case, work, model)
        except subprocess.TimeoutExpired:
            transcript, stderr = Transcript(is_error=True), f"timed out after {case['timeout']}s"
        changes = diff(before, snapshot(work))
        checks = run_checks(case, transcript, work, changes)
    finally:
        if keep:
            print(f"  kept workspace: {work}")
        else:
            remove_workspace(work)
    return {
        "id": case["id"],
        "passed": all(ok for _, ok, _ in checks),
        "seconds": round(time.time() - started, 1),
        "checks": [{"check": n, "ok": ok, "detail": d} for n, ok, d in checks],
        "delegations": sorted(set(transcript.delegations.values())),
        "subagent_tools": sorted({f"{a}:{t}" for a, t in transcript.subagent_tools}),
        "changes": changes,
        "final_answer": transcript.final[-4000:],
        "stderr_tail": stderr,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", type=Path, default=KIT / "cases.yml")
    parser.add_argument("--case", action="append", help="run only these case ids (repeatable)")
    parser.add_argument("--claude", help="path to the claude CLI (default: on PATH)")
    parser.add_argument("--model", help="model for the main session, e.g. claude-sonnet-5-5")
    parser.add_argument("--keep", action="store_true", help="keep workspaces for inspection")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--results", type=Path, default=KIT / "results")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    cases = load_cases(args.cases)
    if args.list:
        for c in cases:
            flag = "[skip] " if c.get("skip") else ""
            print(f"{c['id']:32} {flag}{c.get('description', '')}")
        return 0
    if args.case:
        unknown = set(args.case) - {c["id"] for c in cases}
        if unknown:
            raise SystemExit(f"unknown case id(s): {sorted(unknown)}")
        cases = [c for c in cases if c["id"] in args.case]  # explicit ids run even if marked skip
    else:
        skipped = [c["id"] for c in cases if c.get("skip")]
        if skipped:
            print(f"skipping (run explicitly with --case to force): {', '.join(skipped)}\n")
        cases = [c for c in cases if not c.get("skip")]

    claude = resolve_claude(args.claude)
    results = []
    for case in cases:
        print(f"== {case['id']}: {case.get('description', '')}")
        result = run_case(case, claude, args.model, args.keep)
        for c in result["checks"]:
            mark = "PASS" if c["ok"] else "FAIL"
            print(f"  [{mark}] {c['check']}" + (f"  ({c['detail'][:300]})" if c["detail"] and not c["ok"] else ""))
        print(f"  -> {'PASSED' if result['passed'] else 'FAILED'} in {result['seconds']}s")
        results.append(result)
        if AUTH_ERROR.search(result["final_answer"] + result["stderr_tail"]):
            print("\nclaude is not signed in: run `claude` once, use /login, then re-run. Stopping.")
            break

    args.results.mkdir(parents=True, exist_ok=True)
    out = args.results / f"{dt.datetime.now():%Y%m%d-%H%M%S}.json"
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    passed = sum(r["passed"] for r in results)
    print(f"\n{passed}/{len(results)} case(s) passed. Details: {out.relative_to(REPO)}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
