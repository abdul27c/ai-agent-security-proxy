"""Security policy schema + loader, and runtime settings.

The policy is declarative YAML validated by Pydantic. A malformed policy fails
loudly at startup instead of silently degrading to a permissive default.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import Severity

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = _REPO_ROOT / "policies" / "security_policy.yaml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #
# Input guard
# --------------------------------------------------------------------------- #
class CustomPattern(_Strict):
    id: str
    pattern: str
    severity: Severity = Severity.HIGH
    message: str = "Matched custom deny pattern"


class InputGuardPolicy(_Strict):
    enabled: bool = True
    max_prompt_chars: int = Field(default=16_000, gt=0)
    block_on_severity: Severity = Severity.HIGH
    block_risk_threshold: int = Field(default=70, ge=0, le=100)
    decode_obfuscation: bool = True
    custom_patterns: list[CustomPattern] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #
class RedactionAction(StrEnum):
    REDACT = "redact"
    BLOCK = "block"
    IGNORE = "ignore"


class RedactionPolicy(_Strict):
    enabled: bool = True
    default_action: RedactionAction = RedactionAction.REDACT
    entities: dict[str, RedactionAction] = Field(
        default_factory=dict,
        description="Per-entity override, e.g. {PRIVATE_KEY: block, PHONE_NUMBER: ignore}.",
    )

    def action_for(self, entity_type: str) -> RedactionAction:
        return self.entities.get(entity_type, self.default_action)


# --------------------------------------------------------------------------- #
# Tool firewall
# --------------------------------------------------------------------------- #
ArgType = Literal["string", "integer", "number", "boolean", "array", "object"]


class ArgConstraint(_Strict):
    type: ArgType | None = None
    required: bool = False
    max_length: int | None = Field(default=None, gt=0)
    min: float | None = None
    max: float | None = None
    enum: list[Any] | None = None
    pattern: str | None = Field(default=None, description="Value must fully match this regex.")
    deny_patterns: list[str] = Field(default_factory=list)
    # Filesystem
    no_path_traversal: bool = False
    allowed_path_prefixes: list[str] = Field(default_factory=list)
    # Network
    allowed_domains: list[str] = Field(default_factory=list)
    allow_subdomains: bool = True
    allowed_schemes: list[str] = Field(default_factory=lambda: ["https"])
    block_private_networks: bool = True
    # Database
    sql_read_only: bool = False


class ToolAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ToolRule(_Strict):
    action: ToolAction = ToolAction.ALLOW
    description: str = ""
    risk: Severity = Severity.LOW
    allow_unknown_args: bool = False
    args: dict[str, ArgConstraint] = Field(default_factory=dict)


class ToolFirewallPolicy(_Strict):
    enabled: bool = True
    default_action: Literal["deny", "allow"] = "deny"
    max_tool_calls_per_turn: int = Field(default=5, gt=0)
    scan_args_for_secrets: bool = True
    scan_tool_results: bool = True
    denylist: list[str] = Field(default_factory=list)
    tools: dict[str, ToolRule] = Field(default_factory=dict)

    @field_validator("denylist")
    @classmethod
    def _lower(cls, v: list[str]) -> list[str]:
        return [t.strip().lower() for t in v]


# --------------------------------------------------------------------------- #
# Output guard
# --------------------------------------------------------------------------- #
class OutputGuardPolicy(_Strict):
    enabled: bool = True
    max_output_chars: int = Field(default=20_000, gt=0)
    canary_token: str | None = None
    system_prompt_overlap_threshold: float = Field(default=0.25, ge=0.0, le=1.0)
    shingle_size: int = Field(default=6, ge=2)
    allowed_image_domains: list[str] = Field(default_factory=list)
    redact_secrets: bool = True
    redact_pii: bool = False
    leak_action: Literal["block", "redact"] = "block"


class AgentPolicy(_Strict):
    system_prompt: str = "You are a helpful assistant."


class SecurityPolicy(_Strict):
    version: str = "1"
    name: str = "default"
    agent: AgentPolicy = Field(default_factory=AgentPolicy)
    input_guard: InputGuardPolicy = Field(default_factory=InputGuardPolicy)
    redaction: RedactionPolicy = Field(default_factory=RedactionPolicy)
    tool_firewall: ToolFirewallPolicy = Field(default_factory=ToolFirewallPolicy)
    output_guard: OutputGuardPolicy = Field(default_factory=OutputGuardPolicy)

    # Populated by the loader; not part of the YAML schema.
    source_path: str | None = Field(default=None, exclude=True)
    sha256: str | None = Field(default=None, exclude=True)


def load_policy(path: str | os.PathLike[str] | None = None) -> SecurityPolicy:
    """Load and validate a policy file. Raises on any schema violation."""
    policy_path = Path(path or os.environ.get("SECURITY_POLICY_PATH") or DEFAULT_POLICY_PATH)
    raw = policy_path.read_bytes()
    data: dict[str, Any] = yaml.safe_load(raw) or {}
    policy = SecurityPolicy.model_validate(data)
    policy.source_path = str(policy_path)
    policy.sha256 = hashlib.sha256(raw).hexdigest()
    return policy


# --------------------------------------------------------------------------- #
# Runtime settings (12-factor style, from environment)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Settings:
    backend: str = "mock"
    upstream_base_url: str = "https://api.openai.com/v1"
    upstream_api_key: str | None = None
    upstream_model: str = "gpt-4o-mini"
    upstream_timeout_s: float = 30.0
    policy_path: str | None = None
    audit_log_path: str | None = None
    admin_token: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ
        return cls(
            backend=env.get("PROXY_BACKEND", "mock").lower(),
            upstream_base_url=env.get("UPSTREAM_BASE_URL", cls.upstream_base_url),
            upstream_api_key=env.get("UPSTREAM_API_KEY"),
            upstream_model=env.get("UPSTREAM_MODEL", cls.upstream_model),
            upstream_timeout_s=float(env.get("UPSTREAM_TIMEOUT_S", cls.upstream_timeout_s)),
            policy_path=env.get("SECURITY_POLICY_PATH"),
            audit_log_path=env.get("AUDIT_LOG_PATH"),
            admin_token=env.get("PROXY_ADMIN_TOKEN"),
        )
