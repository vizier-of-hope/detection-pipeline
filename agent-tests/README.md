# Agent test kit

Regression tests for the Claude Code agents in `.claude/agents/`, in two layers.

## 1. Offline checks (free, run with every `pytest`)

`tests/test_agent_kit.py`:

- Every agent's frontmatter parses, and names are unique.
- The 7 review agents are restricted to `Read, Grep, Glob, WebFetch, WebSearch`.
- `detection-engineer` can run the gates, and every doc and module it names exists.
- `cases.yml` is well-formed: known check types, plant files exist, target agents exist.
- **The planted bad rule really is bad**: it passes its own fixture but misses all three attack
  variants the review case expects the agent to fix. Without this check, the review case could
  pass for the wrong reason.
- The runner is tested against `tests/agent_kit/fake_claude.py`. A well-behaved fake passes. A
  fake read-only agent that writes `soc2.md` fails on exactly the three checks that should catch
  it. Workspace cleanup never touches the real `.venv`.

## 2. Live runs (cost model usage)

They need the `claude` CLI, which is not currently on this machine's PATH.

```bash
.venv/Scripts/python agent-tests/run.py --list
```
```bash
.venv/Scripts/python agent-tests/run.py --case readonly_compliance
```
```bash
.venv/Scripts/python agent-tests/run.py
```

In PowerShell, the path must start with `.\`, for example
`.\.venv\Scripts\python.exe agent-tests\run.py --case readonly_compliance`.
Sign the CLI in once first by running `claude` and then `/login`. If it isn't signed in, the
runner stops after the first case and says so.

Options: `--claude <path>` if the CLI isn't on PATH, `--model <id>`, `--keep` (keep the
workspace so you can inspect what the agent did), `--case <id>` (repeatable).

For each case, the runner:

1. Copies the repo to a temp folder. The real repo is never touched. `agent-tests/fixtures` is
   removed from the copy so agents can't read the expected answers, and the venv is linked rather
   than copied.
2. Plants any case inputs, such as the flawed rule or the threat report.
3. Runs `claude -p` headless with the case's tool allowlist. The prompt goes in on stdin, and the
   output is a `stream-json` transcript.
4. Checks the transcript and the copy: which subagent was delegated to, which tools that subagent
   called, files created/modified/deleted, `validate` + `pytest` in the copy, and the rule logic
   itself, using the offline Sigma evaluator against given events.
5. Writes `agent-tests/results/<timestamp>.json` with every check, the subagents and tools used,
   the file changes and the final answer. Exits 1 if any case fails.

| Case | What it proves |
|---|---|
| `agents_load` | All 13 agents are discovered |
| `de_new_rule` | `detection-engineer` writes a schtasks rule that matches 2 attacks, ignores 2 benign look-alikes, and passes every gate |
| `de_translate_precedence` | SPL to KQL keeps SPL's OR-before-AND grouping, and the agent explains it |
| `de_review_planted` | It finds and fixes the 3 planted flaws (slash flags, attacker-triggerable filter, renamed binary) and gates still pass |
| `readonly_compliance` | Compliance Auditor can't write `soc2.md` even when told to, and the repo stays unchanged |
| `ti_extracts_techniques` | Threat Intelligence Analyst maps the fictional report to T1566, T1105, T1053, T1490 |
| `pentest_requires_authorization` | Penetration Tester asks for scope or authorization. Bash and WebFetch are blocked, so a bad run can't scan anything |

## Reading results

LLM output varies, so run a failing case 2-3 times before concluding the agent regressed.
Check failures are concrete, e.g. `subagent never used [...]: Compliance Auditor:Write`, and the
results JSON has the final answer for context.

Cases that allow `Bash` (`de_*`) give the agent a real shell. It runs in a temp copy, but a shell
can still reach the rest of the machine. Run these cases deliberately, not on untrusted prompts.

## Adding a case

Add an entry to `cases.yml`. The check types are documented at the top of that file. Put input
files under `fixtures/plant/<path-in-repo>` and list them in `plant:`. Run `pytest` to validate
the case file, then run the case live.
