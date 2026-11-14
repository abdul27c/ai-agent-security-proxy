"""Core data models shared by every guardrail stage.

Every stage of the pipeline (input guard, tool firewall, output guard) emits
``Finding`` objects. Findings are aggregated into a single ``Decision`` and a
0-100 ``risk_score`` so downstream consumers get one deterministic verdict.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Decision(StrEnum):
    """Final verdict for a request, a tool call, or a guardrail stage."""

    ALLOW = "ALLOW"
    SANITIZED = "SANITIZED"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"

    @property
    def precedence(self) -> int:
        return _DECISION_PRECEDENCE[self]

    @classmethod
    def most_severe(cls, *decisions: Decision) -> Decision:
        """Return the most restrictive decision (BLOCK > APPROVAL > SANITIZED > ALLOW)."""
        if not decisions:
            return cls.ALLOW
        return max(decisions, key=lambda d: d.precedence)


_DECISION_PRECEDENCE = {
    Decision.ALLOW: 0,
    Decision.SANITIZED: 1,
    Decision.REQUIRE_APPROVAL: 2,
    Decision.BLOCK: 3,
}


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        """Probability-style weight used by the risk score aggregator."""
        return _SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_WEIGHTS = {
    Severity.LOW: 0.10,
    Severity.MEDIUM: 0.30,
    Severity.HIGH: 0.60,
    Severity.CRITICAL: 0.90,
}
_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class Stage(StrEnum):
    INPUT = "input_guard"
    TOOL = "tool_firewall"
    TOOL_RESULT = "tool_result_guard"
    OUTPUT = "output_guard"


class Finding(BaseModel):
    """A single triggered security rule."""

    rule_id: str
    stage: Stage
    category: str
    severity: Severity
    message: str
    owasp: list[str] = Field(default_factory=list)
    evidence: str | None = Field(default=None, description="Short, already-masked snippet that triggered the rule.")


class RedactionEvent(BaseModel):
    """Record of one piece of sensitive data that was masked.

    Raw values are never stored; ``fingerprint`` is a truncated SHA-256 that lets
    incident responders correlate the same leaked secret across log lines.
    """

    rule_id: str
    entity_type: str
    stage: Stage
    start: int
    end: int
    replacement: str
    preview: str
    fingerprint: str


class ToolCall(BaseModel):
    """A tool/function invocation proposed by the LLM."""

    name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    id: str | None = None


class ToolCallVerdict(BaseModel):
    name: str
    arguments: dict[str, Any]
    decision: Decision
    findings: list[Finding] = Field(default_factory=list)
    executed: bool = False
    result: str | None = None


def risk_score(findings: list[Finding]) -> int:
    """Aggregate findings into a 0-100 score using a noisy-OR combination.

    Independent signals compound (two mediums score higher than one) but the
    score saturates below 100 unless a critical rule fires, which keeps it
    interpretable as "likelihood the request is malicious".
    """
    remaining = 1.0
    for finding in findings:
        remaining *= 1.0 - finding.severity.weight
    return round((1.0 - remaining) * 100)
