"""Security pipeline orchestration.

    request ─► Input Guard ─► Agent.plan ─► Tool Firewall ─► (sandboxed tools
            ─► tool-result guard) ─► Agent.respond ─► Output Guard ─► response

Every stage contributes findings and a stage decision. The request's final
decision is the most restrictive stage decision; the risk score is the
noisy-OR of all findings. The pipeline fails closed: any upstream error
results in a BLOCK, never in an unchecked pass-through.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .agent import Agent, ChatMessage, ToolResult, execute_mock_tool
from .audit import AuditEvent, AuditLogger, sha256_text
from .config import SecurityPolicy
from .input_guard import InputGuard
from .models import Decision, Finding, RedactionEvent, Severity, Stage, ToolCall, ToolCallVerdict, risk_score
from .output_guard import OutputGuard
from .redaction import SECRET
from .schemas import (
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    ApprovalTicket,
    ChatRequest,
    ChatResponse,
    ScanRequest,
    ScanResponse,
)
from .tool_firewall import ToolFirewall

ToolExecutor = Callable[[ToolCall], str]

BLOCKED_INPUT_MSG = "Request blocked by AI security gateway: {reason}"
BLOCKED_TOOL_MSG = "The agent attempted a tool action that violates security policy and was stopped: {reason}"
APPROVAL_MSG = (
    "This action requires human approval before it can run ({tools}). "
    "Approval ticket {approval_id} has been created for a reviewer."
)
QUARANTINE_MSG = "[quarantined by security gateway: tool output contained embedded instructions]"


class UpstreamError(RuntimeError):
    pass


@dataclass
class PendingApproval:
    approval_id: str
    request_id: str
    calls: list[ToolCall]
    tools: list[str]
    reason: str
    expires_at: datetime
    status: str = "pending"

    def ticket(self) -> ApprovalTicket:
        status = self.status
        if status == "pending" and datetime.now(UTC) > self.expires_at:
            status = "expired"
        return ApprovalTicket(
            approval_id=self.approval_id,
            status=status,  # type: ignore[arg-type]
            tools=self.tools,
            reason=self.reason,
            expires_at=self.expires_at.isoformat(timespec="seconds"),
        )


class ApprovalStore:
    """In-memory HITL queue. Swap for Redis/DB in a multi-replica deployment."""

    def __init__(self, ttl: timedelta = timedelta(minutes=30)) -> None:
        self._items: dict[str, PendingApproval] = {}
        self._lock = threading.Lock()
        self.ttl = ttl

    def create(self, request_id: str, calls: list[ToolCall], tools: list[str], reason: str) -> PendingApproval:
        item = PendingApproval(
            approval_id=f"apr_{secrets.token_hex(8)}",
            request_id=request_id,
            calls=calls,
            tools=tools,
            reason=reason,
            expires_at=datetime.now(UTC) + self.ttl,
        )
        with self._lock:
            self._items[item.approval_id] = item
        return item

    def get(self, approval_id: str) -> PendingApproval | None:
        with self._lock:
            return self._items.get(approval_id)

    def list(self) -> list[ApprovalTicket]:
        with self._lock:
            return [i.ticket() for i in self._items.values()]


@dataclass
class _Acc:
    """Accumulates findings/decisions across stages."""

    findings: list[Finding] = field(default_factory=list)
    redactions: list[RedactionEvent] = field(default_factory=list)
    stages: dict[str, Decision] = field(default_factory=dict)

    def stage(self, name: Stage, decision: Decision) -> None:
        prev = self.stages.get(name.value, Decision.ALLOW)
        self.stages[name.value] = Decision.most_severe(prev, decision)

    @property
    def decision(self) -> Decision:
        return Decision.most_severe(*self.stages.values())

    @property
    def risk(self) -> int:
        return risk_score(self.findings)


def _primary_reason(findings: list[Finding]) -> str:
    if not findings:
        return "policy violation"
    top = max(findings, key=lambda f: f.severity.rank)
    return f"{top.message} [{top.rule_id}]"


class SecurityPipeline:
    def __init__(
        self,
        policy: SecurityPolicy,
        agent: Agent,
        audit: AuditLogger,
        approvals: ApprovalStore | None = None,
        tool_executor: ToolExecutor = execute_mock_tool,
    ) -> None:
        self.policy = policy
        self.agent = agent
        self.audit = audit
        self.approvals = approvals or ApprovalStore()
        self.tool_executor = tool_executor
        self.input_guard = InputGuard(policy)
        self.firewall = ToolFirewall(policy)
        self.output_guard = OutputGuard(policy)

    @property
    def system_prompt(self) -> str:
        prompt = self.policy.agent.system_prompt
        canary = self.policy.output_guard.canary_token
        return f"{prompt}\n[internal-ref:{canary}]" if canary else prompt

    # ------------------------------------------------------------------ #
    def _emit(
        self,
        *,
        request_id: str,
        endpoint: str,
        acc: _Acc,
        latency_ms: float,
        input_text: str | None,
        tools: list[ToolCallVerdict],
        approval_id: str | None = None,
        client_ip: str | None = None,
        session_id: str | None = None,
    ) -> None:
        self.audit.record(
            AuditEvent(
                request_id=request_id,
                endpoint=endpoint,
                decision=acc.decision,
                risk_score=acc.risk,
                triggered_rules=list(dict.fromkeys(f.rule_id for f in acc.findings)),
                owasp_categories=sorted({o for f in acc.findings for o in f.owasp}),
                redaction_count=len(acc.redactions),
                redacted_entities=sorted({r.entity_type for r in acc.redactions}),
                tool_calls=[{"name": t.name, "decision": t.decision.value, "executed": t.executed} for t in tools],
                approval_id=approval_id,
                stage_decisions=acc.stages,
                latency_ms=latency_ms,
                backend=self.agent.name,
                policy_version=self.policy.version,
                policy_sha256=self.policy.sha256,
                input_sha256=sha256_text(input_text),
                client_ip=client_ip,
                session_id=session_id,
            )
        )

    def _guard_tool_result(self, call: ToolCall, raw: str, acc: _Acc) -> str:
        if not self.policy.tool_firewall.scan_tool_results:
            return raw
        injected = self.input_guard.detect_injection(raw, stage=Stage.TOOL_RESULT)
        serious = [f for f in injected if f.severity.rank >= Severity.HIGH.rank]
        content = raw
        if serious:
            acc.findings.extend(
                f.model_copy(update={"message": f"Indirect prompt injection in '{call.name}' output: {f.message}"})
                for f in serious
            )
            acc.stage(Stage.TOOL_RESULT, Decision.SANITIZED)
            content = QUARANTINE_MSG
        red = self.input_guard.redactor.redact(content, Stage.TOOL_RESULT, kinds={SECRET})
        if red.changed:
            acc.findings.extend(red.findings)
            acc.redactions.extend(red.events)
            acc.stage(Stage.TOOL_RESULT, Decision.SANITIZED)
        return red.text

    # ------------------------------------------------------------------ #
    def chat(self, req: ChatRequest, request_id: str, client_ip: str | None = None) -> ChatResponse:
        start = time.perf_counter()
        acc = _Acc()
        verdicts: list[ToolCallVerdict] = []
        ticket: ApprovalTicket | None = None

        def finish(text: str) -> ChatResponse:
            latency = round((time.perf_counter() - start) * 1000, 2)
            self._emit(
                request_id=request_id,
                endpoint="/v1/agent/chat",
                acc=acc,
                latency_ms=latency,
                input_text=req.message,
                tools=verdicts,
                approval_id=ticket.approval_id if ticket else None,
                client_ip=client_ip,
                session_id=req.session_id,
            )
            return ChatResponse(
                request_id=request_id,
                decision=acc.decision,
                risk_score=acc.risk,
                response=text,
                triggered_rules=acc.findings,
                redactions=acc.redactions,
                tool_calls=verdicts,
                approval=ticket,
                stage_decisions=acc.stages,
                backend=self.agent.name,
                policy_version=self.policy.version,
                latency_ms=latency,
            )

        # 1. Input guard: current message + any client-supplied history.
        messages: list[ChatMessage] = []
        for item in [*req.history, ChatMessage(role="user", content=req.message)]:
            if item.role == "system":
                acc.findings.append(
                    Finding(
                        rule_id="PI-011",
                        stage=Stage.INPUT,
                        category="role_spoofing",
                        severity=Severity.HIGH,
                        message="Client-supplied 'system' message rejected; only the proxy sets the system prompt",
                        owasp=["LLM01"],
                    )
                )
                acc.stage(Stage.INPUT, Decision.BLOCK)
                continue
            inspection = self.input_guard.inspect(item.content)
            acc.findings.extend(inspection.findings)
            acc.redactions.extend(inspection.redactions)
            acc.stage(Stage.INPUT, inspection.decision)
            messages.append(ChatMessage(role=item.role, content=inspection.sanitized_text))

        if acc.decision is Decision.BLOCK:
            return finish(BLOCKED_INPUT_MSG.format(reason=_primary_reason(acc.findings)))

        # 2. Agent proposes an answer and/or tool calls.
        simulation = req.simulation if self.agent.name == "mock" else None
        try:
            turn = self.agent.plan(self.system_prompt, messages, simulation)
        except Exception as exc:  # fail closed
            raise UpstreamError(f"upstream model error: {type(exc).__name__}") from exc

        # 3. Tool firewall.
        verdicts = self.firewall.evaluate(turn.tool_calls)
        for v in verdicts:
            acc.findings.extend(v.findings)
            acc.stage(Stage.TOOL, v.decision)

        if any(v.decision is Decision.BLOCK for v in verdicts):
            blocked = [f for v in verdicts if v.decision is Decision.BLOCK for f in v.findings]
            return finish(BLOCKED_TOOL_MSG.format(reason=_primary_reason(blocked)))

        gated = [v for v in verdicts if v.decision is Decision.REQUIRE_APPROVAL]
        if gated:
            tools = [v.name for v in gated]
            reason = "; ".join(f.message for v in gated for f in v.findings)
            pending = self.approvals.create(request_id, turn.tool_calls, tools, reason)
            ticket = pending.ticket()
            return finish(APPROVAL_MSG.format(tools=", ".join(tools), approval_id=pending.approval_id))

        # 4. Execute allowed tools in the sandbox and guard their results.
        results: list[ToolResult] = []
        for call, verdict in zip(turn.tool_calls, verdicts, strict=True):
            raw = self.tool_executor(call)
            safe = self._guard_tool_result(call, raw, acc)
            verdict.executed = True
            verdict.result = safe
            results.append(ToolResult(name=call.name, call_id=call.id, content=safe))

        try:
            text = self.agent.respond(self.system_prompt, messages, turn, results)
        except Exception as exc:
            raise UpstreamError(f"upstream model error: {type(exc).__name__}") from exc

        # 5. Output guard.
        out = self.output_guard.inspect(text)
        acc.findings.extend(out.findings)
        acc.redactions.extend(out.redactions)
        acc.stage(Stage.OUTPUT, out.decision)
        return finish(out.sanitized_text)

    # ------------------------------------------------------------------ #
    def scan(self, req: ScanRequest, request_id: str, client_ip: str | None = None) -> ScanResponse:
        start = time.perf_counter()
        acc = _Acc()
        sanitized_prompt = sanitized_output = None
        verdicts: list[ToolCallVerdict] = []

        if req.prompt is not None:
            inspection = self.input_guard.inspect(req.prompt)
            acc.findings.extend(inspection.findings)
            acc.redactions.extend(inspection.redactions)
            acc.stage(Stage.INPUT, inspection.decision)
            sanitized_prompt = inspection.sanitized_text
        if req.tool_calls:
            verdicts = self.firewall.evaluate(req.tool_calls)
            for v in verdicts:
                acc.findings.extend(v.findings)
                acc.stage(Stage.TOOL, v.decision)
        if req.output is not None:
            out = self.output_guard.inspect(req.output)
            acc.findings.extend(out.findings)
            acc.redactions.extend(out.redactions)
            acc.stage(Stage.OUTPUT, out.decision)
            sanitized_output = out.sanitized_text

        latency = round((time.perf_counter() - start) * 1000, 2)
        self._emit(
            request_id=request_id,
            endpoint="/v1/scan/prompt",
            acc=acc,
            latency_ms=latency,
            input_text=req.prompt,
            tools=verdicts,
            client_ip=client_ip,
        )
        return ScanResponse(
            request_id=request_id,
            decision=acc.decision,
            risk_score=acc.risk,
            triggered_rules=acc.findings,
            redactions=acc.redactions,
            sanitized_prompt=sanitized_prompt,
            sanitized_output=sanitized_output,
            tool_calls=verdicts,
            stage_decisions=acc.stages,
            latency_ms=latency,
        )

    # ------------------------------------------------------------------ #
    def decide_approval(self, approval_id: str, req: ApprovalDecisionRequest) -> ApprovalDecisionResponse:
        item = self.approvals.get(approval_id)
        if item is None:
            raise KeyError(approval_id)
        ticket = item.ticket()
        if ticket.status != "pending":
            raise ValueError(f"approval is already {ticket.status}")

        if not req.approve:
            item.status = "rejected"
            return ApprovalDecisionResponse(approval_id=approval_id, status="rejected", reviewer=req.reviewer)

        # Re-validate against the *current* policy: it may have changed since the ticket was raised.
        verdicts = self.firewall.evaluate(item.calls)
        if any(v.decision is Decision.BLOCK for v in verdicts):
            item.status = "rejected"
            raise PermissionError(_primary_reason([f for v in verdicts for f in v.findings]))

        item.status = "approved"
        for call, verdict in zip(item.calls, verdicts, strict=True):
            output = self.output_guard.inspect(self.tool_executor(call))
            verdict.executed = True
            verdict.result = output.sanitized_text
        self.audit.record(
            AuditEvent(
                event_type="approval_decision",
                request_id=item.request_id,
                endpoint="/v1/approvals",
                decision=Decision.ALLOW,
                risk_score=0,
                approval_id=approval_id,
                latency_ms=0.0,
                tool_calls=[
                    {"name": v.name, "decision": "APPROVED", "executed": True, "reviewer": req.reviewer}
                    for v in verdicts
                ],
                backend=self.agent.name,
                policy_version=self.policy.version,
            )
        )
        return ApprovalDecisionResponse(
            approval_id=approval_id, status="approved", reviewer=req.reviewer, tool_calls=verdicts
        )
