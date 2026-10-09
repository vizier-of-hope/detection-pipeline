"""Self-tests for the offline evaluator, so rule test results can be trusted."""

import pytest
from sigma.rule import SigmaRule

from dettools.evaluator import UnsupportedSigmaFeature, rule_matches


def make_rule(detection: str) -> SigmaRule:
    return SigmaRule.from_yaml(
        "title: t\n"
        "id: 00000000-0000-4000-8000-000000000000\n"
        "logsource: {product: windows, category: process_creation}\n"
        "detection:\n" + detection
    )


@pytest.mark.parametrize(
    "detection,event,expected",
    [
        ("  sel: {Image|endswith: '\\\\cmd.exe'}\n  condition: sel", {"Image": "C:\\X\\CMD.EXE"}, True),
        ("  sel: {Image|endswith: '\\\\cmd.exe'}\n  condition: sel", {"Image": "C:\\cmd.exe.bak"}, False),
        ("  sel: {Image|endswith: '\\\\cmd.exe'}\n  condition: sel", {"Other": "x"}, False),
        ("  sel: {CommandLine|contains|all: [a, b]}\n  condition: sel", {"CommandLine": "xaxbx"}, True),
        ("  sel: {CommandLine|contains|all: [a, b]}\n  condition: sel", {"CommandLine": "xax"}, False),
        ("  sel: {User|re: '^SYS.*M$'}\n  condition: sel", {"User": "SYSTEM"}, True),
        ("  sel: {Port|gt: 1024}\n  condition: sel", {"Port": 4444}, True),
        ("  sel: {Port|gt: 1024}\n  condition: sel", {"Port": 80}, False),
        ("  sel: {Ip|cidr: 10.0.0.0/8}\n  condition: sel", {"Ip": "10.1.2.3"}, True),
        ("  sel: {Ip|cidr: 10.0.0.0/8}\n  condition: sel", {"Ip": "192.168.1.1"}, False),
        ("  sel: {Parent: null}\n  condition: sel", {"Image": "x"}, True),
        ("  sel: {Parent|exists: true}\n  condition: sel", {"Image": "x"}, False),
        ("  sel: {A: x}\n  f: {B: y}\n  condition: sel and not f", {"A": "X", "B": "y"}, False),
        ("  sel: {A: x}\n  f: {B: y}\n  condition: sel and not f", {"A": "X", "B": "z"}, True),
        ("  sel: {A: x}\n  condition: sel", {"A": ["q", "x"]}, True),
        ("  sel: {CommandLine|windash|contains: ' -enc '}\n  condition: sel", {"CommandLine": "p /enc x"}, True),
        ("  kw: [mimikatz]\n  condition: kw", {"Msg": "ran Mimikatz.exe"}, False),
        ("  kw: ['*mimikatz*']\n  condition: kw", {"Msg": "ran Mimikatz.exe"}, True),
    ],
)
def test_semantics(detection, event, expected):
    assert rule_matches(make_rule(detection), event) is expected


def test_placeholder_is_unsupported():
    rule = make_rule("  sel: {User|expand: '%admins%'}\n  condition: sel")
    with pytest.raises(UnsupportedSigmaFeature):
        rule_matches(rule, {"User": "bob"})
