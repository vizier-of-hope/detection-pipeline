"""Minimal offline Sigma evaluator used to unit-test rules against sample events.

pySigma parses the rule and expands the condition into a boolean tree of
field/value comparisons. This module walks that tree against a plain dict
event, so rule logic can be tested in CI without a SIEM.

Matching follows Sigma semantics:
- string comparisons are case-insensitive, wildcards `*` and `?` supported
- a list in the event matches if any element matches
- a missing field never matches, except `field: null`
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Mapping

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

_MISSING = object()


class UnsupportedSigmaFeature(Exception):
    """Raised when a rule uses a construct this evaluator cannot test."""


def _sigma_string_regex(value: SigmaString) -> re.Pattern:
    parts = []
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(part, str):
            parts.append(re.escape(part))
        else:
            raise UnsupportedSigmaFeature(f"placeholder in value {value!r}")
    flags = re.DOTALL if isinstance(value, SigmaCasedString) else re.DOTALL | re.IGNORECASE
    return re.compile("".join(parts), flags)


def _get_field(event: Mapping[str, Any], field: str) -> Any:
    """Look up a field, supporting dotted paths into nested dicts."""
    if field in event:
        return event[field]
    current: Any = event
    for key in field.split("."):
        if isinstance(current, Mapping) and key in current:
            current = current[key]
        else:
            return _MISSING
    return current


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _match_value(event: Mapping[str, Any], actual: Any, expected: Any) -> bool:
    if isinstance(expected, SigmaNull):
        return actual is _MISSING or actual is None
    if isinstance(expected, SigmaExists):
        present = actual is not _MISSING and actual is not None
        return present == expected.exists
    if actual is _MISSING or actual is None:
        return False

    for item in _as_list(actual):
        if _match_single(event, item, expected):
            return True
    return False


def _match_single(event: Mapping[str, Any], item: Any, expected: Any) -> bool:
    if isinstance(expected, SigmaExpansion):
        # e.g. windash: one value expanded into -x, /x, –x ... variants (OR semantics)
        return any(_match_single(event, item, v) for v in expected.values)
    if isinstance(expected, SigmaString):
        if isinstance(item, (dict, list)):
            return False
        return bool(_sigma_string_regex(expected).fullmatch(str(item)))
    if isinstance(expected, SigmaRegularExpression):
        expected.compile()
        flags = 0
        for flag in expected.flags:
            flags |= SigmaRegularExpression.sigma_to_re_flag[flag]
        return re.search(expected.regexp.to_plain(), str(item), flags) is not None
    if isinstance(expected, SigmaNumber):
        try:
            return float(item) == float(expected.number)
        except (TypeError, ValueError):
            return False
    if isinstance(expected, SigmaBool):
        if isinstance(item, bool):
            return item == expected.boolean
        return str(item).lower() == str(expected.boolean).lower()
    if isinstance(expected, SigmaCompareExpression):
        try:
            number = float(item)
        except (TypeError, ValueError):
            return False
        ref = float(expected.number.number)
        ops = SigmaCompareExpression.CompareOperators
        return {
            ops.LT: number < ref,
            ops.LTE: number <= ref,
            ops.GT: number > ref,
            ops.GTE: number >= ref,
            ops.NEQ: number != ref,
        }[expected.op]
    if isinstance(expected, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(item)) in expected.network
        except ValueError:
            return False
    if isinstance(expected, SigmaFieldReference):
        other = _get_field(event, expected.field)
        return other is not _MISSING and str(other).lower() == str(item).lower()
    raise UnsupportedSigmaFeature(f"value type {type(expected).__name__}")


def _iter_strings(value: Any):
    if isinstance(value, Mapping):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _iter_strings(v)
    elif value is not None:
        yield str(value)


def _evaluate(node: Any, event: Mapping[str, Any]) -> bool:
    if isinstance(node, ConditionAND):
        return all(_evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _evaluate(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_value(event, _get_field(event, node.field), node.value)
    if isinstance(node, ConditionValueExpression):
        # Keyword search: match against any string value in the event.
        return any(_match_single(event, s, node.value) for s in _iter_strings(event))
    raise UnsupportedSigmaFeature(f"condition node {type(node).__name__}")


def rule_matches(rule: SigmaRule, event: Mapping[str, Any]) -> bool:
    """Return True if any condition of the rule matches the event."""
    if any("|" in c for c in rule.detection.condition):
        raise UnsupportedSigmaFeature("legacy aggregation conditions cannot be unit-tested offline")
    return any(_evaluate(cond.parse(), event) for cond in rule.detection.parsed_condition)
