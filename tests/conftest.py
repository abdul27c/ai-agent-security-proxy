from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from proxy.agent import MockAgent
from proxy.audit import AuditLogger
from proxy.config import SecurityPolicy, Settings, load_policy
from proxy.main import create_app
from proxy.pipeline import SecurityPipeline


@pytest.fixture(scope="session")
def policy() -> SecurityPolicy:
    return load_policy()


@pytest.fixture
def audit() -> AuditLogger:
    logger = AuditLogger(stream=False)
    yield logger
    logger.close()


@pytest.fixture
def pipeline(policy: SecurityPolicy, audit: AuditLogger) -> SecurityPipeline:
    return SecurityPipeline(policy, MockAgent(), audit)


@pytest.fixture
def make_client(policy: SecurityPolicy):
    created: list[AuditLogger] = []

    def _make(settings: Settings | None = None, **kwargs) -> TestClient:
        audit = AuditLogger(stream=False)
        created.append(audit)
        app = create_app(settings=settings or Settings(), policy=kwargs.pop("policy", policy), audit=audit, **kwargs)
        return TestClient(app)

    yield _make
    for a in created:
        a.close()


@pytest.fixture
def client(make_client) -> TestClient:
    return make_client()
