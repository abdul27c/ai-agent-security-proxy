"""Agentic Tool-Call Firewall — OWASP LLM06 (Excessive Agency).

Every tool/function call proposed by the model is checked against the
declarative policy *before* anything executes:

1. Turn-level budget         (max tool calls per turn — LLM10)
2. Denylist                  (always blocked, regardless of allowlist)
3. Allowlist / default-deny  (unknown tools are blocked when default_action=deny)
4. Argument schema           (required, unknown, type, length, enum, range, regex)
5. Semantic argument checks  (path traversal, path prefix jail, URL/domain
                              allowlist + SSRF, read-only SQL, deny patterns)
6. Secret exfiltration       (credentials smuggled inside arguments)
7. Human-in-the-loop         (require_approval tools -> REQUIRE_APPROVAL)

A call with *any* violation is BLOCKED; approval is only requested for calls
that are otherwise fully policy-compliant.
"""

from __future__ import annotations

import ipaddress
import json
import posixpath
import re
import urllib.parse
from typing import Any

from .config import ArgConstraint, SecurityPolicy, ToolAction, ToolRule
from .models import Decision, Finding, Severity, Stage, ToolCall, ToolCallVerdict
from .redaction import SECRET, Redactor

_TYPE_CHECKS: dict[str, Any] = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}

_SQL_WRITE_KEYWORDS = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|create|replace|merge|grant|revoke|rename|"
    r"exec|execute|call|attach|detach|pragma|vacuum|copy|load|into\s+outfile|lock|unlock)\b",
    re.IGNORECASE,
)
_SQL_READ_START = re.compile(r"^\s*\(?\s*(select|with|explain|show|describe|desc)\b", re.IGNORECASE)
_SQL_COMMENTS = re.compile(r"--[^\n]*|/\*.*?\*/|#[^\n]*", re.DOTALL)
_SQL_STRINGS = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"")

_TRAVERSAL = re.compile(r"(^|[\\/])\.\.([\\/]|$)|%2e%2e|%252e|\.\.%2f|%2f\.\.|\x00|%00", re.IGNORECASE)

_SSRF_HOSTNAMES = {"localhost", "localhost.localdomain", "metadata.google.internal", "metadata"}


def _finding(rule_id: str, severity: Severity, message: str, evidence: Any = None, owasp=("LLM06",)) -> Finding:
    ev = None if evidence is None else str(evidence)[:120]
    return Finding(
        rule_id=rule_id,
        stage=Stage.TOOL,
        category="tool_policy_violation",
        severity=severity,
        message=message,
        owasp=list(owasp),
        evidence=ev,
    )


# --------------------------------------------------------------------------- #
# Semantic validators (pure functions -> easy to unit test)
# --------------------------------------------------------------------------- #
def check_path(value: str, c: ArgConstraint, arg: str) -> list[Finding]:
    out: list[Finding] = []
    decoded = urllib.parse.unquote(urllib.parse.unquote(value))
    if c.no_path_traversal and (_TRAVERSAL.search(value) or _TRAVERSAL.search(decoded) or decoded.startswith("~")):
        out.append(_finding("TF-014", Severity.CRITICAL, f"Path traversal sequence in '{arg}'", value))
    if c.allowed_path_prefixes:
        normalized = posixpath.normpath(decoded.replace("\\", "/"))
        if decoded.endswith("/") and not normalized.endswith("/"):
            normalized += "/"
        if not any(
            normalized == p.rstrip("/") or normalized.startswith(p if p.endswith("/") else p + "/")
            for p in c.allowed_path_prefixes
        ):
            out.append(
                _finding(
                    "TF-015",
                    Severity.HIGH,
                    f"'{arg}' is outside allowed path prefixes {c.allowed_path_prefixes}",
                    normalized,
                )
            )
    return out


def _is_private_host(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in _SSRF_HOSTNAMES or host.endswith(".localhost") or host.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Decimal / hex encoded IPv4 (e.g. http://2130706433/ == 127.0.0.1)
        try:
            ip = ipaddress.ip_address(int(host, 0))
        except ValueError:
            return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not ip.is_global


def check_url(value: str, c: ArgConstraint, arg: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        parsed = urllib.parse.urlsplit(value.strip())
        host = (parsed.hostname or "").rstrip(".").lower()
    except ValueError:
        return [_finding("TF-017", Severity.HIGH, f"'{arg}' is not a valid URL", value)]

    if parsed.scheme.lower() not in [s.lower() for s in c.allowed_schemes]:
        out.append(_finding("TF-017", Severity.HIGH, f"URL scheme '{parsed.scheme}' not in {c.allowed_schemes}", value))
    if not host:
        out.append(_finding("TF-017", Severity.HIGH, f"'{arg}' has no host", value))
        return out
    if parsed.username or parsed.password:
        out.append(_finding("TF-016", Severity.HIGH, "URL contains embedded credentials / userinfo", value))
    if c.block_private_networks and _is_private_host(host):
        out.append(
            _finding(
                "TF-018",
                Severity.CRITICAL,
                f"SSRF: '{host}' resolves to a private, loopback or metadata address",
                value,
            )
        )
        return out
    if c.allowed_domains:
        allowed = False
        for d in c.allowed_domains:
            d = d.lower().lstrip(".")
            if host == d or (c.allow_subdomains and host.endswith("." + d)):
                allowed = True
                break
        if not allowed:
            out.append(_finding("TF-016", Severity.HIGH, f"Domain '{host}' is not in the allowlist", value))
    return out


def check_sql(value: str, arg: str) -> list[Finding]:
    stripped = _SQL_STRINGS.sub("''", _SQL_COMMENTS.sub(" ", value))
    statements = [s for s in (part.strip() for part in stripped.split(";")) if s]
    out: list[Finding] = []
    if len(statements) > 1:
        out.append(_finding("TF-020", Severity.CRITICAL, f"Stacked SQL statements in '{arg}'", value))
    for stmt in statements:
        write = _SQL_WRITE_KEYWORDS.search(stmt)
        if write or not _SQL_READ_START.match(stmt):
            kw = write.group(0).upper() if write else stmt.split()[0].upper()
            out.append(
                _finding("TF-019", Severity.CRITICAL, f"Destructive / write SQL ({kw}) in read-only '{arg}'", value)
            )
            break
    return out


# --------------------------------------------------------------------------- #
class ToolFirewall:
    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy = policy.tool_firewall
        self.redactor = Redactor(policy.redaction)
        self._deny_compiled: dict[tuple[str, str], list[re.Pattern[str]]] = {}
        for tool, rule in self.policy.tools.items():
            for arg, c in rule.args.items():
                self._deny_compiled[(tool, arg)] = [re.compile(p) for p in c.deny_patterns]

    # ------------------------------------------------------------------ #
    def _validate_arg(self, tool: str, arg: str, value: Any, c: ArgConstraint) -> list[Finding]:
        out: list[Finding] = []
        if c.type and not _TYPE_CHECKS[c.type](value):
            return [
                _finding(
                    "TF-012", Severity.MEDIUM, f"Argument '{arg}' must be {c.type}, got {type(value).__name__}", value
                )
            ]
        if c.enum is not None and value not in c.enum:
            out.append(_finding("TF-021", Severity.HIGH, f"Argument '{arg}' not in allowed values {c.enum}", value))
        is_number = isinstance(value, (int, float)) and not isinstance(value, bool)
        if is_number and ((c.min is not None and value < c.min) or (c.max is not None and value > c.max)):
            out.append(
                _finding("TF-022", Severity.MEDIUM, f"Argument '{arg}'={value} outside range [{c.min}, {c.max}]", value)
            )
        if isinstance(value, str):
            if c.max_length and len(value) > c.max_length:
                out.append(
                    _finding(
                        "TF-013",
                        Severity.MEDIUM,
                        f"Argument '{arg}' exceeds max length {c.max_length}",
                        len(value),
                        owasp=("LLM06", "LLM10"),
                    )
                )
            if c.pattern and not re.fullmatch(c.pattern, value):
                out.append(
                    _finding("TF-025", Severity.HIGH, f"Argument '{arg}' does not match required pattern", value)
                )
            for pat in self._deny_compiled.get((tool, arg), []):
                if pat.search(value):
                    out.append(
                        _finding(
                            "TF-023", Severity.HIGH, f"Argument '{arg}' matches deny pattern '{pat.pattern}'", value
                        )
                    )
            if c.no_path_traversal or c.allowed_path_prefixes:
                out.extend(check_path(value, c, arg))
            if c.allowed_domains or "url" in arg.lower():
                out.extend(check_url(value, c, arg))
            if c.sql_read_only:
                out.extend(check_sql(value, arg))
        return out

    def _secret_scan(self, arguments: dict[str, Any]) -> list[Finding]:
        blob = json.dumps(arguments, default=str)
        result = self.redactor.redact(blob, Stage.TOOL, kinds={SECRET}, owasp=("LLM02", "LLM06"))
        return [
            f.model_copy(
                update={
                    "rule_id": "TF-024",
                    "category": "credential_exfiltration",
                    "severity": Severity.CRITICAL,
                    "message": f"Credential in tool arguments ({f.rule_id}): possible exfiltration",
                }
            )
            for f in result.findings
        ]

    def evaluate_call(self, call: ToolCall) -> ToolCallVerdict:
        name = call.name.strip()
        key = name.lower()
        findings: list[Finding] = []

        rule: ToolRule | None = self.policy.tools.get(name) or self.policy.tools.get(key)

        if key in self.policy.denylist or (rule and rule.action is ToolAction.DENY):
            findings.append(_finding("TF-001", Severity.CRITICAL, f"Tool '{name}' is denylisted", name))
        elif rule is None and self.policy.default_action == "deny":
            findings.append(_finding("TF-002", Severity.HIGH, f"Tool '{name}' is not on the allowlist", name))

        if rule is not None and not findings:
            for arg, c in rule.args.items():
                if c.required and arg not in call.arguments:
                    findings.append(_finding("TF-010", Severity.MEDIUM, f"Missing required argument '{arg}'"))
            for arg, value in call.arguments.items():
                c = rule.args.get(arg)
                if c is None:
                    if not rule.allow_unknown_args:
                        findings.append(_finding("TF-011", Severity.MEDIUM, f"Unexpected argument '{arg}'", arg))
                    continue
                findings.extend(self._validate_arg(name, arg, value, c))

        if self.policy.scan_args_for_secrets and call.arguments:
            findings.extend(self._secret_scan(call.arguments))

        if findings:
            decision = Decision.BLOCK
        elif rule is not None and rule.action is ToolAction.REQUIRE_APPROVAL:
            decision = Decision.REQUIRE_APPROVAL
            findings.append(
                _finding("TF-003", rule.risk, f"Tool '{name}' is high-risk and requires human approval", name)
            )
        else:
            decision = Decision.ALLOW

        safe_args = json.loads(self.redactor.redact(json.dumps(call.arguments, default=str), Stage.TOOL).text)
        return ToolCallVerdict(name=name, arguments=safe_args, decision=decision, findings=findings)

    def evaluate(self, calls: list[ToolCall]) -> list[ToolCallVerdict]:
        if not self.policy.enabled:
            return [ToolCallVerdict(name=c.name, arguments=c.arguments, decision=Decision.ALLOW) for c in calls]
        verdicts = [self.evaluate_call(c) for c in calls]
        limit = self.policy.max_tool_calls_per_turn
        if len(calls) > limit:
            budget = _finding(
                "TF-004",
                Severity.HIGH,
                f"{len(calls)} tool calls exceed per-turn budget of {limit}",
                owasp=("LLM06", "LLM10"),
            )
            for v in verdicts[limit:]:
                v.decision = Decision.BLOCK
                v.findings.append(budget)
        return verdicts
