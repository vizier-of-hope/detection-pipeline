"""Registry of SIEM query-language targets that Sigma rules are compiled to.

Each Target pairs a pySigma backend with the processing pipeline that maps Sigma
field names onto that SIEM's schema. Add a SIEM by adding one entry here.

required=True    a failed conversion fails the build (these targets are deployed)
required=False   best-effort: failures are recorded in build/coverage.md, the build continues

Deliberately NOT registered:
  splunk_spl2   pySigma-backend-splunk 2.1.0 emits `A OR B AND C` without grouping, but SPL2
                WHERE evaluates AND before OR, so mixed conditions compile to the wrong logic.
  qradar_aql    pySigma-backend-qradar-aql has no release compatible with pySigma 1.x.
                Hand-write AQL using docs/siem/qradar-aql.md.
  sentinelone   pysigma-backend-sentinelone-pq 0.1.6 validates field names after mapping them, so
                every field is rejected under pySigma 1.5.1. Hand-write PowerQuery (docs/siem/sentinelone-pq.md).
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from functools import cache
from typing import Callable

from sigma.backends.crowdstrike import LogScaleBackend
from sigma.backends.elasticsearch import EqlBackend, ESQLBackend, LuceneBackend
from sigma.backends.kusto import KustoBackend
from sigma.backends.secops import SecOpsBackend
from sigma.backends.splunk import SplunkBackend
from sigma.conversion.base import Backend
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.crowdstrike import crowdstrike_falcon_pipeline
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.secops import secops_udm_pipeline
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.pipelines.splunk import splunk_cim_data_model, splunk_windows_pipeline
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation
from sigma.rule import SigmaRule


def endpoint_logsource(rule: SigmaRule) -> bool:
    """Windows endpoint telemetry (process_creation etc.) — the targets' default scope."""
    return rule.logsource.category == "process_creation"


def signin_logsource(rule: SigmaRule) -> bool:
    """Entra ID / Azure AD interactive and non-interactive sign-in logs."""
    return (rule.logsource.service or "").lower() == "signinlogs"


def cloudtrail_logsource(rule: SigmaRule) -> bool:
    """AWS CloudTrail management events. Rules use CloudTrail's own JSON field names."""
    return (rule.logsource.product or "").lower() == "aws" and (rule.logsource.service or "").lower() == "cloudtrail"


# CloudTrail JSON field -> Sentinel AWSCloudTrail column (AWS S3 connector).
SENTINEL_CLOUDTRAIL_FIELDS = {
    "eventSource": "EventSource",
    "eventName": "EventName",
    "eventType": "EventTypeName",
    "errorCode": "ErrorCode",
    "awsRegion": "AWSRegion",
    "sourceIPAddress": "SourceIpAddress",
    "userAgent": "UserAgent",
    "recipientAccountId": "RecipientAccountId",
    "userIdentity.type": "UserIdentityType",
    "userIdentity.arn": "UserIdentityArn",
    "userIdentity.userName": "UserIdentityUserName",
    "userIdentity.accountId": "UserIdentityAccountId",
    "userIdentity.invokedBy": "UserIdentityInvokedBy",
}

# CloudTrail JSON field -> ECS field written by the Elastic AWS integration (aws.cloudtrail dataset).
ELASTIC_CLOUDTRAIL_FIELDS = {
    "eventSource": "event.provider",
    "eventName": "event.action",
    "eventType": "aws.cloudtrail.event_type",
    "errorCode": "aws.cloudtrail.error_code",
    "awsRegion": "cloud.region",
    "sourceIPAddress": "source.address",
    "userAgent": "user_agent.original",
    "recipientAccountId": "aws.cloudtrail.recipient_account_id",
    "userIdentity.type": "aws.cloudtrail.user_identity.type",
    "userIdentity.arn": "aws.cloudtrail.user_identity.arn",
    "userIdentity.userName": "user.name",
    "userIdentity.accountId": "cloud.account.id",
    "userIdentity.invokedBy": "aws.cloudtrail.user_identity.invoked_by",
}


def _pipeline(*transformations) -> ProcessingPipeline:
    return ProcessingPipeline(name="cloudtrail", priority=10, items=[ProcessingItem(t) for t in transformations])


@dataclass(frozen=True)
class Target:
    key: str
    siem: str
    language: str
    make_backend: Callable[[], Backend]
    ext: str
    output_format: str = "default"
    required: bool = False
    # Which rules this target compiles. Backends/pipelines are logsource-specific: the Windows
    # endpoint targets cannot map sign-in-log fields and vice versa, so convert/translate only
    # run a target on the rules it applies to.
    applies_to: Callable[[SigmaRule], bool] = endpoint_logsource
    # True when the language evaluates AND before OR (SQL-like). Those targets must
    # parenthesize OR groups; tests/test_targets.py enforces it.
    and_binds_tighter: bool = True
    caveat: str = ""
    # Optional rewrite of each compiled query string, for semantics the backend gets wrong.
    postprocess: Callable[[str], str] | None = None


_STR = r'"(?:[^"\\]|\\.)*"'
_FIELD = r"[A-Za-z_@][\w.@]*"
_ESQL_CI = re.compile(
    rf"(?P<str>{_STR})"
    rf"|(?P<fn>starts_with|ends_with)\((?P<fn_field>{_FIELD}), (?P<fn_val>{_STR})\)"
    rf"|(?P<in_field>{_FIELD}) in \((?P<in_vals>{_STR}(?:, {_STR})*)\)"
    # Lookbehind stops a match starting mid-word (`rlike` must not parse as field `r` + `like`).
    rf"|(?<![\w.@])(?P<cmp_field>{_FIELD})(?:\s*(?P<op>==)|\s+(?P<op_like>like)\b)\s*(?P<cmp_val>{_STR})"
)


def esql_case_insensitive(query: str) -> str:
    """Make ES|QL string matches case-insensitive, as Sigma requires.

    ES|QL `like`, `==`, `in`, `starts_with` and `ends_with` are case-sensitive, so the stock
    backend misses e.g. `vssadmin Delete Shadows` for a rule written as 'delete'. Lowercase both
    sides. `rlike` is left alone: Sigma regexes are case-sensitive unless they use (?i).
    """
    def repl(m: re.Match) -> str:
        if m.group("str"):
            return m.group("str")  # literal outside a match expression: untouched
        if m.group("fn"):
            return f"{m.group('fn')}(to_lower({m.group('fn_field')}), {m.group('fn_val').lower()})"
        if m.group("in_field"):
            return f"to_lower({m.group('in_field')}) in ({m.group('in_vals').lower()})"
        op = m.group("op") or m.group("op_like")
        return f"to_lower({m.group('cmp_field')}) {op} {m.group('cmp_val').lower()}"

    return _ESQL_CI.sub(repl, query)


TARGETS: dict[str, Target] = {t.key: t for t in [
    Target(
        "splunk", "Splunk", "SPL", lambda: SplunkBackend(sysmon_pipeline() + splunk_windows_pipeline()),
        ext="spl", required=True, and_binds_tighter=False,
        caveat="Sysmon field names, source=WinEventLog:Microsoft-Windows-Sysmon/Operational.",
    ),
    Target(
        "splunk_cim", "Splunk (CIM / tstats)", "SPL", lambda: SplunkBackend(splunk_cim_data_model()),
        ext="spl", output_format="data_model", and_binds_tighter=False,
        caveat="Requires accelerated CIM data models (Endpoint.Processes etc.).",
    ),
    Target(
        "elastic_lucene", "Elastic Security", "Lucene", lambda: LuceneBackend(ecs_windows()),
        ext="lucene", required=True, and_binds_tighter=True,
        caveat="ECS field names (Winlogbeat 7+ / Elastic Agent).",
    ),
    Target(
        "elastic_eql", "Elastic Security", "EQL", lambda: EqlBackend(ecs_windows()),
        ext="eql",
    ),
    Target(
        "elastic_esql", "Elastic Security", "ES|QL", lambda: ESQLBackend(ecs_windows()),
        ext="esql", postprocess=esql_case_insensitive,
        caveat="String matches are wrapped in to_lower() for Sigma's case-insensitivity (blocks index"
               " pushdown, so narrow the FROM index). `rlike` stays case-sensitive, as in Sigma.",
    ),
    Target(
        "microsoft_xdr", "Microsoft Defender XDR / Sentinel", "KQL", lambda: KustoBackend(microsoft_xdr_pipeline()),
        ext="kql",
        caveat="Advanced-hunting tables (DeviceProcessEvents...). In Sentinel these need the Defender XDR connector.",
    ),
    Target(
        "sentinel_asim", "Microsoft Sentinel (ASIM)", "KQL", lambda: KustoBackend(sentinel_asim_pipeline()),
        ext="kql",
        caveat="ASIM parsers (imProcessCreate...). Fields without an ASIM mapping fail conversion.",
    ),
    Target(
        "crowdstrike_logscale", "CrowdStrike Falcon / LogScale", "CQL (LogScale)",
        lambda: LogScaleBackend(crowdstrike_falcon_pipeline()),
        ext="logscale", and_binds_tighter=False,
        caveat="LogScale binds `or` tighter than `and` (implicit AND), so ungrouped output is correct.",
    ),
    Target(
        "secops_udm", "Google SecOps (Chronicle)", "UDM search", lambda: SecOpsBackend(secops_udm_pipeline()),
        ext="udm",
    ),
    Target(
        "secops_yaral", "Google SecOps (Chronicle)", "YARA-L 2.0", lambda: SecOpsBackend(secops_udm_pipeline()),
        ext="yaral", output_format="yara_l",
    ),
    Target(
        "sentinel_signin", "Microsoft Sentinel (Entra sign-in)", "KQL",
        lambda: KustoBackend(azure_monitor_pipeline(query_table="SigninLogs")),
        ext="kql", required=True, and_binds_tighter=True, applies_to=signin_logsource,
        caveat="Entra ID SigninLogs columns (ResultType, IPAddress, AppDisplayName...). Needs the"
               " Azure Active Directory / Entra ID connector feeding SigninLogs into Sentinel.",
    ),
    Target(
        "splunk_cloudtrail", "Splunk (AWS CloudTrail)", "SPL",
        lambda: SplunkBackend(_pipeline(AddConditionTransformation({"sourcetype": "aws:cloudtrail"}))),
        ext="spl", required=True, and_binds_tighter=False, applies_to=cloudtrail_logsource,
        caveat="Splunk Add-on for AWS (sourcetype aws:cloudtrail), which keeps CloudTrail's JSON field names.",
    ),
    Target(
        "sentinel_cloudtrail", "Microsoft Sentinel (AWS CloudTrail)", "KQL",
        lambda: KustoBackend(
            _pipeline(FieldMappingTransformation(SENTINEL_CLOUDTRAIL_FIELDS))
            + azure_monitor_pipeline(query_table="AWSCloudTrail")
        ),
        ext="kql", required=True, and_binds_tighter=True, applies_to=cloudtrail_logsource,
        caveat="AWSCloudTrail table from the Amazon Web Services S3 connector. Only top-level and"
               " userIdentity fields are mapped; requestParameters/responseElements are JSON strings there.",
    ),
    Target(
        "elastic_cloudtrail", "Elastic Security (AWS CloudTrail)", "Lucene",
        lambda: LuceneBackend(_pipeline(
            FieldMappingTransformation(ELASTIC_CLOUDTRAIL_FIELDS),
            AddConditionTransformation({"event.dataset": "aws.cloudtrail"}),
        )),
        ext="lucene", and_binds_tighter=True, applies_to=cloudtrail_logsource,
        caveat="ECS fields from the Elastic AWS integration (event.dataset aws.cloudtrail).",
    ),
]}


@cache
def backend_for(key: str) -> Backend:
    return TARGETS[key].make_backend()


def convert(target: Target, rule: SigmaRule) -> list:
    """Convert one rule for one target. Pipelines mutate rules, so always work on a copy."""
    queries = backend_for(target.key).convert_rule(copy.deepcopy(rule), target.output_format)
    if target.postprocess:
        queries = [target.postprocess(q) if isinstance(q, str) else q for q in queries]
    return queries


def join_queries(queries: list) -> str:
    """Rules can compile to several queries (e.g. one per log source); render them as one string."""
    queries = [q if isinstance(q, str) else str(q) for q in queries]
    return queries[0] if len(queries) == 1 else "\n\n".join(queries)
