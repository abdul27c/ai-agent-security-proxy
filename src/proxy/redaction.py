"""PII and secret detection / redaction engine.

Shared by the input guard (mask data before it reaches the upstream LLM), the
tool firewall (stop credential exfiltration through tool arguments) and the
output guard (stop credentials leaking back to the user).

Design notes
------------
* Detectors are plain compiled regexes plus optional validators (e.g. Luhn for
  card numbers) so behaviour is deterministic and auditable.
* Overlapping matches are resolved by priority, then length, so a JWT is not
  partially re-matched as a "generic secret".
* The raw value is never logged. Events carry a masked preview and a truncated
  SHA-256 fingerprint for correlation.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .config import RedactionAction, RedactionPolicy
from .models import Finding, RedactionEvent, Severity, Stage

SECRET = "secret"  # noqa: S105 - detector category label, not a credential
PII = "pii"


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _ssn_valid(value: str) -> bool:
    area, group, serial = value.split("-")
    return area not in {"000", "666"} and not area.startswith("9") and group != "00" and serial != "0000"


def _mixed_charset(value: str) -> bool:
    """Real AWS secrets mix cases and digits; filters out hex digests like SHA-1."""
    return any(c.isupper() for c in value) and any(c.islower() for c in value) and any(c.isdigit() for c in value)


@dataclass(frozen=True)
class Detector:
    rule_id: str
    entity_type: str
    kind: str  # SECRET or PII
    pattern: re.Pattern[str]
    severity: Severity
    priority: int = 50
    group: int = 0
    validator: Callable[[str], bool] | None = None


def _d(rule_id, entity, kind, regex, severity, priority=50, group=0, validator=None, flags=0):
    return Detector(rule_id, entity, kind, re.compile(regex, flags), severity, priority, group, validator)


DETECTORS: tuple[Detector, ...] = (
    _d(
        "SEC-PRIVKEY",
        "PRIVATE_KEY",
        SECRET,
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----",
        Severity.CRITICAL,
        priority=100,
    ),
    _d(
        "SEC-AWS-AKID",
        "AWS_ACCESS_KEY_ID",
        SECRET,
        r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b",
        Severity.CRITICAL,
        priority=90,
    ),
    _d(
        "SEC-AWS-SECRET",
        "AWS_SECRET_ACCESS_KEY",
        SECRET,
        r"(?i)(?<![a-z0-9])(?:aws|secret[_-]?(?:access[_-]?)?key|secret)(?![a-z0-9]).{0,40}?[=:\s\"']+([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])",
        Severity.CRITICAL,
        priority=90,
        group=1,
        validator=_mixed_charset,
    ),
    _d("SEC-ANTHROPIC", "ANTHROPIC_API_KEY", SECRET, r"\bsk-ant-[A-Za-z0-9_\-]{20,}", Severity.CRITICAL, priority=85),
    _d(
        "SEC-OPENAI",
        "OPENAI_API_KEY",
        SECRET,
        r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}",
        Severity.CRITICAL,
        priority=80,
    ),
    _d(
        "SEC-GITHUB",
        "GITHUB_TOKEN",
        SECRET,
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        Severity.CRITICAL,
        priority=85,
    ),
    _d("SEC-SLACK", "SLACK_TOKEN", SECRET, r"\bxox[abposr]-[A-Za-z0-9-]{10,}", Severity.HIGH, priority=85),
    _d("SEC-STRIPE", "STRIPE_KEY", SECRET, r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}", Severity.CRITICAL, priority=85),
    _d("SEC-GOOGLE", "GOOGLE_API_KEY", SECRET, r"\bAIza[0-9A-Za-z_\-]{35}", Severity.HIGH, priority=85),
    _d(
        "SEC-JWT",
        "JWT",
        SECRET,
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        Severity.HIGH,
        priority=75,
    ),
    _d(
        "SEC-GENERIC",
        "GENERIC_SECRET",
        SECRET,
        r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret|token|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*[\"']?([^\s\"',;]{8,})",
        Severity.HIGH,
        priority=40,
        group=1,
    ),
    _d(
        "PII-EMAIL",
        "EMAIL_ADDRESS",
        PII,
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        Severity.MEDIUM,
        priority=60,
    ),
    _d("PII-SSN", "US_SSN", PII, r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", Severity.HIGH, priority=70, validator=_ssn_valid),
    _d(
        "PII-CREDIT-CARD",
        "CREDIT_CARD",
        PII,
        r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)",
        Severity.HIGH,
        priority=65,
        validator=luhn_valid,
    ),
    _d(
        "PII-PHONE",
        "PHONE_NUMBER",
        PII,
        r"(?<![\d-])(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\d-])",
        Severity.LOW,
        priority=30,
    ),
)


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def mask_preview(value: str) -> str:
    """Keep just enough of the value to be recognisable to its owner."""
    if "@" in value and len(value) < 320:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(len(value) - 6, 16)}{value[-2:]}"


@dataclass
class RedactionResult:
    text: str
    events: list[RedactionEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    blocked: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.events)


@dataclass(frozen=True)
class _Match:
    detector: Detector
    start: int
    end: int
    value: str


class Redactor:
    def __init__(self, policy: RedactionPolicy | None = None) -> None:
        self.policy = policy or RedactionPolicy()

    def find(self, text: str, kinds: set[str] | None = None) -> list[_Match]:
        candidates: list[_Match] = []
        for det in DETECTORS:
            if kinds is not None and det.kind not in kinds:
                continue
            if self.policy.action_for(det.entity_type) is RedactionAction.IGNORE:
                continue
            for m in det.pattern.finditer(text):
                start, end = m.span(det.group)
                value = m.group(det.group)
                if det.validator and not det.validator(value):
                    continue
                candidates.append(_Match(det, start, end, value))

        # Resolve overlaps: higher priority wins, then longer span.
        candidates.sort(key=lambda c: (-c.detector.priority, -(c.end - c.start), c.start))
        chosen: list[_Match] = []
        for cand in candidates:
            if all(cand.end <= c.start or cand.start >= c.end for c in chosen):
                chosen.append(cand)
        return sorted(chosen, key=lambda c: c.start)

    def redact(
        self,
        text: str,
        stage: Stage,
        kinds: set[str] | None = None,
        owasp: tuple[str, ...] = ("LLM02",),
    ) -> RedactionResult:
        if not self.policy.enabled or not text:
            return RedactionResult(text=text)

        matches = self.find(text, kinds)
        if not matches:
            return RedactionResult(text=text)

        result = RedactionResult(text=text)
        out: list[str] = []
        cursor = 0
        seen_rules: dict[str, int] = {}
        for m in matches:
            det = m.detector
            replacement = f"[REDACTED:{det.entity_type}]"
            out.append(text[cursor : m.start])
            out.append(replacement)
            cursor = m.end
            result.events.append(
                RedactionEvent(
                    rule_id=det.rule_id,
                    entity_type=det.entity_type,
                    stage=stage,
                    start=m.start,
                    end=m.end,
                    replacement=replacement,
                    preview=mask_preview(m.value),
                    fingerprint=fingerprint(m.value),
                )
            )
            if self.policy.action_for(det.entity_type) is RedactionAction.BLOCK:
                result.blocked = True
            seen_rules[det.rule_id] = seen_rules.get(det.rule_id, 0) + 1
        out.append(text[cursor:])
        result.text = "".join(out)

        by_rule = {m.detector.rule_id: m for m in matches}
        for rule_id, count in seen_rules.items():
            det = by_rule[rule_id].detector
            action = self.policy.action_for(det.entity_type)
            verb = "blocked" if action is RedactionAction.BLOCK else "redacted"
            result.findings.append(
                Finding(
                    rule_id=rule_id,
                    stage=stage,
                    category="secret_exposure" if det.kind == SECRET else "pii_exposure",
                    severity=det.severity,
                    message=f"{det.entity_type} detected and {verb} ({count} occurrence{'s' * (count > 1)})",
                    owasp=list(owasp),
                    evidence=mask_preview(by_rule[rule_id].value),
                )
            )
        return result
