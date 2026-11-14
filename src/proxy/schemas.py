"""HTTP request / response contracts for the proxy API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from .agent import ChatMessage, Simulation
from .models import Decision, Finding, RedactionEvent, ToolCall, ToolCallVerdict


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=100_000)
    history: list[ChatMessage] = Field(default_factory=list, max_length=50)
    session_id: str | None = Field(default=None, max_length=128)
    simulation: Simulation | None = Field(
        default=None,
        description="Mock backend only: force the model's response / tool calls to test guardrails.",
    )


class ApprovalTicket(BaseModel):
    approval_id: str
    status: Literal["pending", "approved", "rejected", "expired"] = "pending"
    tools: list[str]
    reason: str
    expires_at: str


class ChatResponse(BaseModel):
    request_id: str
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    response: str
    triggered_rules: list[Finding] = Field(default_factory=list)
    redactions: list[RedactionEvent] = Field(default_factory=list)
    tool_calls: list[ToolCallVerdict] = Field(default_factory=list)
    approval: ApprovalTicket | None = None
    stage_decisions: dict[str, Decision] = Field(default_factory=dict)
    backend: str
    policy_version: str
    latency_ms: float


class ScanRequest(BaseModel):
    prompt: str | None = Field(default=None, max_length=100_000)
    tool_calls: list[ToolCall] = Field(default_factory=list, max_length=50)
    output: str | None = Field(default=None, max_length=200_000)

    @model_validator(mode="after")
    def _non_empty(self) -> ScanRequest:
        if self.prompt is None and not self.tool_calls and self.output is None:
            raise ValueError("Provide at least one of 'prompt', 'tool_calls' or 'output'")
        return self


class ScanResponse(BaseModel):
    request_id: str
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    triggered_rules: list[Finding] = Field(default_factory=list)
    redactions: list[RedactionEvent] = Field(default_factory=list)
    sanitized_prompt: str | None = None
    sanitized_output: str | None = None
    tool_calls: list[ToolCallVerdict] = Field(default_factory=list)
    stage_decisions: dict[str, Decision] = Field(default_factory=dict)
    latency_ms: float


class ApprovalDecisionRequest(BaseModel):
    approve: bool
    reviewer: str = Field(min_length=1, max_length=128)
    comment: str | None = Field(default=None, max_length=1000)


class ApprovalDecisionResponse(BaseModel):
    approval_id: str
    status: Literal["approved", "rejected"]
    reviewer: str
    tool_calls: list[ToolCallVerdict] = Field(default_factory=list)
