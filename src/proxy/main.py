"""FastAPI entrypoint for the AI agent security proxy.

Run locally:   uvicorn proxy.main:app --app-dir src --reload
"""

import re
import secrets
import uuid
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from . import __version__
from .agent import Agent, build_agent
from .audit import AuditLogger
from .config import SecurityPolicy, Settings, load_policy
from .models import Decision
from .pipeline import SecurityPipeline, UpstreamError
from .schemas import (
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    ApprovalTicket,
    ChatRequest,
    ChatResponse,
    ScanRequest,
    ScanResponse,
)

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

#: HTTP status per decision for the enforcing chat endpoint.
STATUS_FOR_DECISION = {
    Decision.ALLOW: 200,
    Decision.SANITIZED: 200,
    Decision.REQUIRE_APPROVAL: 403,
    Decision.BLOCK: 403,
}


def create_app(
    settings: Settings | None = None,
    policy: SecurityPolicy | None = None,
    agent: Agent | None = None,
    audit: AuditLogger | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    policy = policy or load_policy(settings.policy_path)
    agent = agent or build_agent(settings, policy)
    audit = audit or AuditLogger(path=settings.audit_log_path)

    app = FastAPI(
        title="AI Agent Security Proxy",
        version=__version__,
        description="Runtime security gateway enforcing OWASP Top 10 for LLM Applications controls "
        "on prompts, agent tool calls and model outputs.",
    )
    app.state.settings = settings
    app.state.pipeline = SecurityPipeline(policy, agent, audit)

    def pipeline() -> SecurityPipeline:
        return app.state.pipeline

    def require_admin(x_admin_token: Annotated[str | None, Header()] = None) -> None:
        expected = settings.admin_token
        if expected and not (x_admin_token and secrets.compare_digest(x_admin_token, expected)):
            raise HTTPException(status_code=401, detail="invalid or missing X-Admin-Token")

    Pipe = Annotated[SecurityPipeline, Depends(pipeline)]

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request.state.request_id = incoming if _REQUEST_ID.match(incoming) else f"req_{uuid.uuid4().hex[:16]}"
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    def client_ip(request: Request) -> str | None:
        return request.client.host if request.client else None

    # ------------------------------------------------------------------ #
    @app.get("/health", tags=["ops"])
    def health(p: Pipe) -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "backend": p.agent.name,
            "policy": {"name": p.policy.name, "version": p.policy.version, "sha256": p.policy.sha256},
        }

    @app.get("/v1/policies", tags=["policy"])
    def get_policies(p: Pipe) -> dict[str, Any]:
        pol = p.policy
        fw = pol.tool_firewall
        return {
            "name": pol.name,
            "version": pol.version,
            "sha256": pol.sha256,
            "summary": {
                "allowed_tools": sorted(n for n, r in fw.tools.items() if r.action.value == "allow"),
                "approval_required_tools": sorted(
                    n for n, r in fw.tools.items() if r.action.value == "require_approval"
                ),
                "denylisted_tools": sorted(fw.denylist),
                "default_tool_action": fw.default_action,
            },
            "policy": pol.model_dump(mode="json", exclude={"agent"}),
        }

    @app.post("/v1/policies/reload", tags=["policy"], dependencies=[Depends(require_admin)])
    def reload_policy() -> dict[str, Any]:
        new_policy = load_policy(settings.policy_path)
        old: SecurityPipeline = app.state.pipeline
        app.state.pipeline = SecurityPipeline(new_policy, old.agent, old.audit, old.approvals, old.tool_executor)
        return {"reloaded": True, "version": new_policy.version, "sha256": new_policy.sha256}

    @app.post(
        "/v1/agent/chat",
        tags=["proxy"],
        response_model=ChatResponse,
        responses={403: {"model": ChatResponse, "description": "BLOCK or REQUIRE_APPROVAL"}},
    )
    def agent_chat(body: ChatRequest, request: Request, p: Pipe) -> JSONResponse:
        try:
            result = p.chat(body, request.state.request_id, client_ip(request))
        except UpstreamError as exc:
            return JSONResponse(
                status_code=502,
                content={"request_id": request.state.request_id, "decision": Decision.BLOCK.value, "detail": str(exc)},
            )
        return JSONResponse(status_code=STATUS_FOR_DECISION[result.decision], content=result.model_dump(mode="json"))

    @app.post("/v1/scan/prompt", tags=["proxy"], response_model=ScanResponse)
    def scan_prompt(body: ScanRequest, request: Request, p: Pipe) -> ScanResponse:
        return p.scan(body, request.state.request_id, client_ip(request))

    @app.get("/v1/approvals", tags=["hitl"], response_model=list[ApprovalTicket], dependencies=[Depends(require_admin)])
    def list_approvals(p: Pipe) -> list[ApprovalTicket]:
        return p.approvals.list()

    @app.post(
        "/v1/approvals/{approval_id}",
        tags=["hitl"],
        response_model=ApprovalDecisionResponse,
        dependencies=[Depends(require_admin)],
    )
    def decide_approval(approval_id: str, body: ApprovalDecisionRequest, p: Pipe) -> ApprovalDecisionResponse:
        try:
            return p.decide_approval(approval_id, body)
        except KeyError:
            raise HTTPException(status_code=404, detail="approval not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=f"re-validation failed: {exc}") from None

    @app.get("/v1/audit/recent", tags=["ops"], dependencies=[Depends(require_admin)])
    def recent_audit(p: Pipe, limit: Annotated[int, Query(ge=1, le=500)] = 50) -> list[dict[str, Any]]:
        return p.audit.recent(limit)

    return app


def __getattr__(name: str) -> Any:
    # Lazily build the module-level ``app`` so importing this module (e.g. in
    # tests) has no side effects such as reading env vars or opening log files.
    if name == "app":
        globals()["app"] = application = create_app()
        return application
    raise AttributeError(name)
