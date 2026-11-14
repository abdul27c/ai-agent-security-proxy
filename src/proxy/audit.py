"""Structured security audit logging.

Every decision produces exactly one JSON line suitable for shipping to a SIEM
(Splunk, Elastic, Datadog, CloudWatch...). Raw prompts are never logged — only
a SHA-256 digest, rule IDs and masked redaction metadata — so the audit trail
does not itself become a sensitive-data store (OWASP LLM02).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
import threading
from collections import deque
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from .models import Decision


class AuditEvent(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="milliseconds"))
    event_type: str = "security_decision"
    request_id: str
    endpoint: str
    decision: Decision
    risk_score: int
    triggered_rules: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    redaction_count: int = 0
    redacted_entities: list[str] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    approval_id: str | None = None
    stage_decisions: dict[str, Decision] = Field(default_factory=dict)
    latency_ms: float
    backend: str | None = None
    policy_version: str | None = None
    policy_sha256: str | None = None
    input_sha256: str | None = None
    client_ip: str | None = None
    session_id: str | None = None


def sha256_text(text: str | None) -> str | None:
    return None if text is None else hashlib.sha256(text.encode()).hexdigest()


class _JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


class AuditLogger:
    """Thread-safe JSON-lines audit sink with an in-memory ring buffer for the API."""

    def __init__(self, path: str | None = None, buffer_size: int = 500, stream: bool = True) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        self._logger = logging.getLogger(f"proxy.audit.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        formatter = _JsonLineFormatter()
        if stream:
            handler: logging.Handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
        if path:
            file_handler = logging.FileHandler(path, encoding="utf-8")
            file_handler.setFormatter(formatter)
            self._logger.addHandler(file_handler)

    def record(self, event: AuditEvent) -> dict[str, Any]:
        payload = event.model_dump(mode="json")
        with self._lock:
            self._buffer.append(payload)
        self._logger.info(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return payload

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._buffer)[-limit:][::-1]

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)
