from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from proxy.config import DEFAULT_POLICY_PATH, SecurityPolicy, Settings, load_policy
from proxy.models import Decision, Finding, Severity, Stage, risk_score


def test_default_policy_loads(policy: SecurityPolicy) -> None:
    assert policy.name == "default-enterprise"
    assert policy.sha256 and len(policy.sha256) == 64
    assert "execute_shell" in policy.tool_firewall.denylist
    assert policy.tool_firewall.tools["send_email"].action.value == "require_approval"


def test_env_var_policy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({"name": "custom", "version": "9"}))
    monkeypatch.setenv("SECURITY_POLICY_PATH", str(p))
    loaded = load_policy()
    assert loaded.name == "custom"
    assert loaded.tool_firewall.default_action == "deny"  # secure default


@pytest.mark.parametrize(
    "doc",
    [
        {"input_guard": {"enabeld": True}},  # typo must not silently pass
        {"input_guard": {"block_on_severity": "extreme"}},
        {"tool_firewall": {"default_action": "maybe"}},
        {"tool_firewall": {"tools": {"x": {"args": {"a": {"type": "uuid"}}}}}},
        {"output_guard": {"system_prompt_overlap_threshold": 2}},
    ],
)
def test_invalid_policy_rejected(tmp_path: Path, doc: dict) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(doc))
    with pytest.raises(ValidationError):
        load_policy(p)


def test_empty_policy_file_uses_secure_defaults(tmp_path: Path) -> None:
    p = tmp_path / "empty.yaml"
    p.write_text("")
    pol = load_policy(p)
    assert pol.input_guard.enabled and pol.tool_firewall.default_action == "deny"


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROXY_BACKEND", "OpenAI")
    monkeypatch.setenv("UPSTREAM_API_KEY", "dummy")
    monkeypatch.setenv("PROXY_ADMIN_TOKEN", "t0ken")
    s = Settings.from_env()
    assert s.backend == "openai"
    assert "t0ken" not in repr(s)  # secret excluded from repr


def test_default_policy_path_exists() -> None:
    assert DEFAULT_POLICY_PATH.is_file()


def test_decision_precedence() -> None:
    assert Decision.most_severe() is Decision.ALLOW
    assert Decision.most_severe(Decision.ALLOW, Decision.SANITIZED) is Decision.SANITIZED
    assert Decision.most_severe(Decision.REQUIRE_APPROVAL, Decision.SANITIZED) is Decision.REQUIRE_APPROVAL
    assert Decision.most_severe(Decision.REQUIRE_APPROVAL, Decision.BLOCK, Decision.ALLOW) is Decision.BLOCK


def _f(sev: Severity) -> Finding:
    return Finding(rule_id="X", stage=Stage.INPUT, category="t", severity=sev, message="m")


def test_risk_score_noisy_or() -> None:
    assert risk_score([]) == 0
    assert risk_score([_f(Severity.MEDIUM)]) == 30
    assert risk_score([_f(Severity.MEDIUM)] * 2) == 51
    assert risk_score([_f(Severity.CRITICAL)]) == 90
    assert risk_score([_f(Severity.CRITICAL)] * 5) == 100
