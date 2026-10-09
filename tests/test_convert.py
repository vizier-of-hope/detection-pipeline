"""Build-level checks on converted artifacts."""

import json

from dettools import convert
from dettools.common import load_rules
from dettools.targets import TARGETS


def test_convert_produces_artifacts_for_every_rule(tmp_path):
    assert convert.main(["--out", str(tmp_path)]) == 0
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    elastic = [json.loads(line) for line in (tmp_path / "elastic" / "rules.ndjson").read_text(encoding="utf-8").splitlines()]
    conf = (tmp_path / "splunk" / "savedsearches.conf").read_text(encoding="utf-8")

    rules = load_rules()
    all_ids = {str(r.raw["id"]) for r in rules}
    # Splunk + Elastic are the endpoint deploy targets; cloud rules compile to their own targets only.
    endpoint_ids = {str(r.raw["id"]) for r in rules if TARGETS["elastic_lucene"].applies_to(r.rule)}

    assert {m["id"] for m in manifest} == all_ids
    assert {r["rule_id"] for r in elastic} == endpoint_ids
    for m in manifest:
        if m["id"] in endpoint_ids:
            assert f"[{m['name']}]" in conf
        else:
            assert m["queries"], f"{m['title']} compiled to no target"  # e.g. a cloud rule -> KQL


def test_backend_pipelines_do_not_leak(tmp_path):
    # Regression: pipelines mutate rules in place; Splunk/Sysmon conditions must not reach Elastic.
    convert.main(["--out", str(tmp_path)])
    for line in (tmp_path / "elastic" / "rules.ndjson").read_text(encoding="utf-8").splitlines():
        query = json.loads(line)["query"]
        assert "EventCode" not in query and "WinEventLog" not in query
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    for m in manifest:
        assert "process.command_line" not in m["splunk"]["search"]
