#!/bin/sh
# Full detection-pipeline gate suite, in the same order as CLAUDE.md / CI.
# Stops at the first failing gate with a non-zero exit code.
set -e
export PYTHONIOENCODING=utf-8

echo "== yamllint =="
yamllint -s rules tests/events

echo "== sigma check (valid Sigma + real ATT&CK tags) =="
sigma check --fail-on-issues rules

echo "== validate (team rule-quality policy) =="
python -m dettools.validate

echo "== pytest (rule logic + tooling) =="
python -m pytest -q

echo "== convert (compile every rule to each SIEM target) =="
python -m dettools.convert

echo ""
echo "All gates passed. Compiled artifacts are in build/."
