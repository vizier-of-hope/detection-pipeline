# Validating rules with Atomic Red Team

How to exercise the detection rules in this repo against real behaviour using
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (ART), and confirm the rule
fires. This complements the offline fixture tests (`tests/test_rules.py`), which prove rule
*logic*; ART proves the rule fires on *real telemetry* in a SIEM.

## ⚠️ Lab only

Several techniques here use genuinely disruptive offensive tooling: Inveigh / Responder and
mitm6 actively poison name resolution on the local network, and `ntlmrelayx` relays real
credentials. Run these **only** on an isolated VM or lab subnet you own, with a snapshot to
revert to, and never on a production or shared network. Unauthorized use is likely illegal.

Install [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) in the lab first so
process-creation events (Event ID 1) exist for the rules to match.

## Install ART (Windows PowerShell, in the lab VM)

```powershell
Install-Module -Name invoke-atomicredteam, powershell-yaml -Scope CurrentUser -Force
Import-Module invoke-atomicredteam
Install-AtomicRedTeam -getAtomics
```

## General loop

```powershell
Invoke-AtomicTest <TECHNIQUE> -ShowDetails     # list atomics + commands
Invoke-AtomicTest <TECHNIQUE> -GetPrereqs      # fetch required tools
Invoke-AtomicTest <TECHNIQUE> -TestNumbers 1   # run atomic #1
Invoke-AtomicTest <TECHNIQUE> -TestNumbers 1 -Cleanup
```

## Per-rule mapping

| Rule | Technique | How to exercise |
|---|---|---|
| `proc_creation_win_inveigh_llmnr_nbtns_spoofing` | T1557.001 | ART atomics (Inveigh / Responder) — see below |
| `proc_creation_win_mitm6_ntlmrelayx_dhcpv6_spoofing` | T1557.003 / .001 | Custom mini-atomic (ART T1557 lacks mitm6) — see below |
| `proc_creation_win_runtimebroker_masquerading` | T1036.005 | Custom mini-atomic (ART T1036.005 doesn't drop RuntimeBroker.exe) — see below |
| `signin_azure_aitm_token_theft_risk` | T1557 (cloud) | Not applicable to ART — replay a `SigninLogs` record into Sentinel (see below) |

### T1557.001 — Inveigh (LLMNR/NBT-NS/mDNS poisoning)

```powershell
Invoke-AtomicTest T1557.001 -ShowDetails       # find the Inveigh test number
Invoke-AtomicTest T1557.001 -GetPrereqs
Invoke-AtomicTest T1557.001 -TestNumbers 1
Invoke-AtomicTest T1557.001 -TestNumbers 1 -Cleanup
```

The rule keys on the command line (`Invoke-Inveigh`, `Inveigh.exe`, or `-SpooferIP` + `-LLMNR`
together). If an atomic dot-sources Inveigh and calls it with defaults, those tokens may not
appear in the process command line — a real coverage gap. If so, add a fixture reproducing it
and widen the rule.

### T1557.003 — mitm6 / ntlmrelayx (custom mini-atomic)

ART's T1557 atomics are LLMNR/NBT-NS, not mitm6. Generate the process events directly (lab
subnet only):

```powershell
# mitm6 (rogue DHCPv6/DNS). Ctrl+C to stop.
mitm6.exe -d lab.local
# ntlmrelayx (NTLM relay). Separate shell.
ntlmrelayx.exe -6 -t ldaps://dc01.lab.local -wh attacker-wpad
```

The rule matches `mitm6.exe` / `ntlmrelayx.exe` images (incl. renamed, via `OriginalFileName`)
and `mitm6.py` / `ntlmrelayx` command lines.

### T1036.005 — RuntimeBroker masquerade (custom mini-atomic)

Copy any benign exe into the loader's deceptive folder and run it from there:

```powershell
$dir = "$env:LOCALAPPDATA\Microsoft\RuntimeBrokers"
New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item C:\Windows\System32\notepad.exe "$dir\RuntimeBroker.exe"
& "$dir\RuntimeBroker.exe"                    # Sysmon EID 1: RuntimeBroker.exe outside System32
# cleanup
Stop-Process -Name RuntimeBroker -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $dir
```

The rule fires on any `RuntimeBroker.exe` whose path is not `C:\Windows\System32\RuntimeBroker.exe`.

### signin_azure_aitm_token_theft_risk — cloud, not ART

ART is endpoint-focused; nothing makes Entra ID emit an `anomalousToken` sign-in. Validate by
replaying a sample `SigninLogs` record (with `ResultType == 0` and
`RiskEventTypes_V2` containing `anomalousToken` or `tokenIssuerAnomaly`) into a Sentinel /
Log Analytics custom table, then run the compiled query from
`build/queries/sentinel_signin/`. Cloud attack-simulation tooling can drive this end to end.

## Confirming the rule fired

1. **At the source (quickest):** Event Viewer -> `Microsoft-Windows-Sysmon/Operational`,
   confirm an Event ID 1 whose `Image` / `CommandLine` match the rule.
2. **Through the compiled query:** promote the rule from `experimental` to `test`, then
   `python -m dettools.deploy --target splunk --min-status test`, run the atomic, and confirm
   the alert. The raw query is also in `build/queries/<target>/<rule>.<ext>` to paste into the
   SIEM search bar directly.

## Beyond ART: full validation strategy

ART only covers endpoint, single-event behaviour on one host. It cannot make cloud/identity
logs appear, cannot reproduce multi-host network interaction or multi-stage chains, and does
not measure a rule's false-positive rate. Use the right tool per rule class:

| Rule class | Example in repo | Tool / method |
|---|---|---|
| Endpoint, single event | inveigh, runtimebroker, mitm6 (process launch) | **Atomic Red Team** (this doc) |
| Cloud / identity | `signin_azure_aitm_token_theft_risk` | **[Stratus Red Team](https://github.com/DataDog/stratus-red-team)** (AWS/Azure/GCP/Entra), Microsoft Attack Simulation, or replay a `SigninLogs` record into Sentinel |
| Network attack needing a victim | inveigh/mitm6 full poison->capture->relay chain | **Lab with a victim VM**, or **[CALDERA](https://github.com/mitre/caldera)** / **[PurpleSharp](https://github.com/mvelazc0/PurpleSharp)** for multi-host orchestration |
| Multi-stage / correlation / APT emulation | (future correlation rules) | **CALDERA**, MITRE adversary emulation plans |
| Catch-all variants (logic) | every rule | **`tests/test_rules.py` fixtures** — the only layer that runs every commit |
| False-positive rate | every rule | Run the compiled query over **historical production logs** before enabling alerting |

ART answers one question — "does the rule fire when this exact behaviour happens?" It does not
prove the rule catches other variants of the technique (that is the true-negative/evasion
fixtures' job) or that it is quiet in production (that is FP measurement). Treat live testing,
fixtures, and FP measurement as three complementary legs, not substitutes.

## Promotion flow

`experimental` (built, not shipped) -> validate logic (`pytest tests/test_rules.py`) ->
promote to `test` -> deploy to lab and confirm live with ART -> measure false positives on
historical data -> promote to `stable`.
