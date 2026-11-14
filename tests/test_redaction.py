from __future__ import annotations

import pytest

from proxy.config import RedactionAction, RedactionPolicy
from proxy.models import Stage
from proxy.redaction import PII, SECRET, Redactor, fingerprint, luhn_valid, mask_preview

redactor = Redactor(RedactionPolicy())


@pytest.mark.parametrize(
    ("text", "entity"),
    [
        ("key AKIAIOSFODNN7EXAMPLE end", "AWS_ACCESS_KEY_ID"),
        ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS_SECRET_ACCESS_KEY"),
        ("token ghp_" + "a1B2" * 9, "GITHUB_TOKEN"),
        ("github_pat_" + "A" * 30, "GITHUB_TOKEN"),
        ("OPENAI_API_KEY=sk-proj-" + "x" * 40, "OPENAI_API_KEY"),
        ("key sk-ant-api03-" + "y" * 40, "ANTHROPIC_API_KEY"),
        ("slack xoxb-1234567890-abcdefghij", "SLACK_TOKEN"),
        ("stripe sk_live_" + "4" * 24, "STRIPE_KEY"),
        ("google AIza" + "B" * 35, "GOOGLE_API_KEY"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "JWT"),
        ("password: hunter2hunter2", "GENERIC_SECRET"),
        ("contact jane.doe@example.com today", "EMAIL_ADDRESS"),
        ("ssn 123-45-6789", "US_SSN"),
        ("card 4111 1111 1111 1111", "CREDIT_CARD"),
        ("card 5500-0000-0000-0004", "CREDIT_CARD"),
        ("call (555) 123-4567", "PHONE_NUMBER"),
        ("-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBg\n-----END PRIVATE KEY-----", "PRIVATE_KEY"),
    ],
)
def test_entities_detected_and_masked(text: str, entity: str) -> None:
    result = redactor.redact(text, Stage.INPUT)
    entities = [e.entity_type for e in result.events]
    assert entity in entities, entities
    assert f"[REDACTED:{entity}]" in result.text


@pytest.mark.parametrize(
    "text",
    [
        "order number 4111 1111 1111 1112",  # fails Luhn
        "ssn 000-12-3456",  # invalid area
        "ssn 666-12-3456",
        "ssn 123-00-4567",
        "commit da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1, not an AWS secret
        "secret: da39a3ee5e6b4b0d3255bfef95601890afd80709x",  # hex only -> no mixed charset
        "version 1.2.3 released on 2024-01-15",
        "the AKIA prefix alone is fine",
    ],
)
def test_non_sensitive_values_untouched(text: str) -> None:
    result = redactor.redact(text, Stage.INPUT, kinds={PII} if "ssn" in text or "order" in text else None)
    assert [e.entity_type for e in result.events if e.entity_type != "GENERIC_SECRET"] == []


def test_raw_value_never_in_events() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    result = redactor.redact(f"x {secret} y", Stage.INPUT)
    dumped = result.events[0].model_dump_json() + "".join(f.model_dump_json() for f in result.findings)
    assert secret not in dumped
    assert result.events[0].fingerprint == fingerprint(secret)
    assert result.events[0].preview.startswith("AKIA") and "*" in result.events[0].preview


def test_offsets_point_into_original_text() -> None:
    text = "mail bob@example.com now"
    event = redactor.redact(text, Stage.INPUT).events[0]
    assert text[event.start : event.end] == "bob@example.com"


def test_overlap_resolution_prefers_specific_detector() -> None:
    # "api_key=sk-proj-..." matches both the generic and the OpenAI detector.
    result = redactor.redact("api_key=sk-proj-" + "z" * 40, Stage.INPUT)
    assert [e.entity_type for e in result.events] == ["OPENAI_API_KEY"]


def test_multiple_occurrences_counted() -> None:
    result = redactor.redact("a@x.com and b@y.org", Stage.INPUT)
    assert len(result.events) == 2
    assert len(result.findings) == 1
    assert "2 occurrences" in result.findings[0].message


def test_kind_filter() -> None:
    text = "bob@example.com AKIAIOSFODNN7EXAMPLE"
    only_secrets = redactor.redact(text, Stage.OUTPUT, kinds={SECRET})
    assert [e.entity_type for e in only_secrets.events] == ["AWS_ACCESS_KEY_ID"]
    assert "bob@example.com" in only_secrets.text


def test_block_and_ignore_actions() -> None:
    policy = RedactionPolicy(entities={"EMAIL_ADDRESS": RedactionAction.IGNORE, "US_SSN": RedactionAction.BLOCK})
    r = Redactor(policy)
    assert r.redact("bob@example.com", Stage.INPUT).events == []
    blocked = r.redact("ssn 123-45-6789", Stage.INPUT)
    assert blocked.blocked
    assert "blocked" in blocked.findings[0].message


def test_disabled_redaction() -> None:
    r = Redactor(RedactionPolicy(enabled=False))
    assert r.redact("AKIAIOSFODNN7EXAMPLE", Stage.INPUT).text == "AKIAIOSFODNN7EXAMPLE"


def test_helpers() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert not luhn_valid("1234")
    assert mask_preview("bob@example.com") == "b***@example.com"
    assert mask_preview("short") == "*****"
    assert len(fingerprint("x")) == 12
