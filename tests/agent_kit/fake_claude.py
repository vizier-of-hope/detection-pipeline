"""Stand-in for `claude -p --output-format stream-json`, used to test agent-tests/run.py offline.

Behaviour is picked with FAKE_CLAUDE_SCENARIO:
  readonly_good   delegates to Compliance Auditor, which only reads
  readonly_bad    same, but the subagent writes soc2.md (the runner must catch it)
  new_rule_good   delegates to detection-engineer and writes a valid schtasks rule + fixture
"""

import json
import os
import sys
from pathlib import Path

RULE = r"""title: Scheduled Task Running From Users Public
id: 3c1d2e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f
status: experimental
description: Detects schtasks.exe creating a task whose action runs from C:\Users\Public.
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: Detection Engineering Team
date: 2026-10-09
tags:
  - attack.persistence
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\schtasks.exe'
    - OriginalFileName: 'schtasks.exe'
  selection_cli:
    CommandLine|contains|windash: '-create'
  selection_path:
    CommandLine|contains: '\users\public\'
  condition: all of selection_*
falsepositives:
  - Rare; software installers staging in Public
level: high
"""

FIXTURE = r"""rule_id: 3c1d2e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f
true_positives:
  - name: create from public
    event:
      Image: 'C:\Windows\System32\schtasks.exe'
      CommandLine: 'schtasks /create /tn x /tr C:\Users\Public\l.exe /sc onlogon'
  - name: dash flags
    event:
      Image: 'C:\Windows\System32\schtasks.exe'
      CommandLine: 'SCHTASKS -Create -TN x -TR "C:\users\public\a.bat" -SC minute'
true_negatives:
  - name: query
    event:
      Image: 'C:\Windows\System32\schtasks.exe'
      CommandLine: 'schtasks /query /fo list'
  - name: system32 action
    event:
      Image: 'C:\Windows\System32\schtasks.exe'
      CommandLine: 'schtasks /create /tn Backup /tr C:\Windows\System32\backup.exe /sc daily'
"""


def emit(obj):
    print(json.dumps(obj), flush=True)


def tool_use(tool_id, name, tool_input, parent=None):
    emit({"type": "assistant", "parent_tool_use_id": parent,
          "message": {"content": [{"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}]}})


def main():
    prompt = sys.stdin.read()
    if not prompt.strip() or "stream-json" not in sys.argv or "-p" not in sys.argv:
        print("fake claude: expected -p, stream-json and a prompt on stdin", file=sys.stderr)
        return 2
    scenario = os.environ.get("FAKE_CLAUDE_SCENARIO", "")
    emit({"type": "system", "subtype": "init"})

    if scenario.startswith("readonly"):
        tool_use("t1", "Agent", {"subagent_type": "Compliance Auditor", "prompt": "review"})
        tool_use("t2", "Read", {"file_path": "README.md"}, parent="t1")
        if scenario == "readonly_bad":
            Path("soc2.md").write_text("findings\n", encoding="utf-8")
            tool_use("t3", "Write", {"file_path": "soc2.md"}, parent="t1")
        emit({"type": "result", "subtype": "success", "is_error": False,
              "result": "Compliance Auditor findings: change management evidence is partial."})
        return 0

    if scenario == "new_rule_good":
        tool_use("t1", "Agent", {"subagent_type": "detection-engineer", "prompt": "write rule"})
        name = "proc_creation_win_schtasks_users_public"
        rule = Path("rules/windows/process_creation") / f"{name}.yml"
        rule.parent.mkdir(parents=True, exist_ok=True)
        rule.write_text(RULE, encoding="utf-8", newline="\n")
        Path(f"tests/events/{name}.yml").write_text(FIXTURE, encoding="utf-8", newline="\n")
        tool_use("t2", "Write", {"file_path": str(rule)}, parent="t1")
        emit({"type": "result", "subtype": "success", "is_error": False,
              "result": "Rule written. Gates: validate passed, pytest passed."})
        return 0

    print(f"fake claude: unknown scenario {scenario!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
