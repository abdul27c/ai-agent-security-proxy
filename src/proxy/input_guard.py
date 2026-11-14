"""Input Guardrail Engine — OWASP LLM01 (Prompt Injection) & LLM02 (Sensitive Info).

Pipeline for every inbound prompt::

    raw text
      -> length check (LLM10)
      -> normalisation (NFKC, strip zero-width / bidi controls)
      -> detection over several *views* of the text
           * normalised
           * de-leeted       ("1gn0r3"            -> "ignore")
           * de-spaced       ("i g n o r e"       -> "ignore")
           * decoded blobs   (base64 / hex / %XX  -> re-scanned recursively)
      -> heuristic cue scoring (many weak signals)
      -> PII / secret redaction
      -> decision: BLOCK | SANITIZED | ALLOW

All rules are deterministic regexes with stable IDs so they can be audited,
unit tested and referenced from SIEM alerts.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

from .config import InputGuardPolicy, SecurityPolicy
from .models import Decision, Finding, RedactionEvent, Severity, Stage, risk_score
from .redaction import Redactor

_FLAGS = re.IGNORECASE | re.MULTILINE


@dataclass(frozen=True)
class InjectionRule:
    rule_id: str
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str
    owasp: tuple[str, ...] = ("LLM01",)


def _rule(rule_id: str, category: str, severity: Severity, regex: str, message: str, owasp=("LLM01",)):
    return InjectionRule(rule_id, category, severity, re.compile(regex, _FLAGS), message, owasp)


_OVERRIDE_VERBS = r"(?:ignore|disregard|forget|override|bypass|skip|abandon|drop|neglect|discard)"
_PRIOR = (
    r"(?:previous|prior|above|earlier|preceding|initial|original|system|developer|safety|"
    r"all(?:\s+of)?(?:\s+the|\s+your)?|your|any|these|those|existing)"
)
_DIRECTIVES = (
    r"(?:instructions?|prompts?|rules|directives?|guidelines|guardrails|constraints|"
    r"policies|programming|training|context|commands?)"
)

INJECTION_RULES: tuple[InjectionRule, ...] = (
    _rule(
        "PI-001",
        "instruction_override",
        Severity.CRITICAL,
        rf"\b{_OVERRIDE_VERBS}\b[^.\n]{{0,30}}?\b{_PRIOR}\b[^.\n]{{0,20}}?\b{_DIRECTIVES}\b",
        "Attempt to override or discard prior instructions",
    ),
    _rule(
        "PI-002",
        "instruction_override",
        Severity.HIGH,
        r"\b(?:from\s+now\s+on|henceforth|for\s+the\s+rest\s+of\s+(?:this|the)\s+conversation)\b"
        r"[^.\n]{0,40}\byou\s+(?:will|must|shall|are|should)\b"
        r"|\b(?:new|updated|real|actual|true)\s+(?:system\s+)?(?:instructions?|rules|directives?)\s*[:\-]",
        "Injected replacement instructions",
    ),
    _rule(
        "PI-003",
        "system_prompt_extraction",
        Severity.HIGH,
        r"\b(?:reveal|show|print|display|output|repeat|leak|dump|expose|disclose|recite|tell\s+me|"
        r"give\s+me|what\s+(?:is|are|were))\b[^.\n]{0,40}?\b(?:system|initial|original|hidden|secret|"
        r"developer|internal|confidential)\s+(?:prompt|instructions?|message|rules|configuration|directives?)"
        r"|\b(?:reveal|print|dump|leak|repeat|recite|output|disclose|expose)\b[^.\n]{0,20}?\byour\s+"
        r"(?:prompt|instructions|system\s+message)"
        r"|\bwhat\s+(?:are|were)\s+your\s+(?:exact\s+|original\s+|initial\s+)?instructions\b"
        r"|\brepeat\s+(?:everything|all|the\s+(?:text|words))\s+(?:above|before|preceding)"
        r"|\b(?:start|begin)\s+your\s+(?:reply|response|answer)\s+with\s+[\"']?you\s+are\b",
        "Attempt to extract the system prompt",
        owasp=("LLM01", "LLM07"),
    ),
    _rule(
        "PI-004",
        "jailbreak_persona",
        Severity.HIGH,
        r"\b(?:DAN|do\s+anything\s+now|STAN|DUDE|AIM)\b(?=[^.\n]{0,60}\b(?:mode|persona|prompt|now|jailbreak|no\s+restrictions|ai)\b)"
        r"|\b(?:developer|god|jailbreak|unrestricted|evil|chaos)\s+mode\b"
        r"|\bjailbr(?:eak|oken)\b"
        r"|\b(?:ai|assistant|model|chatbot|bot|persona|version\s+of\s+(?:yourself|you))\b[^.\n]{0,30}?"
        r"\b(?:with|has|have|having|without)\s+(?:no|any)\s+(?:restrictions|limits|limitations|filters|"
        r"guidelines|rules|ethics|morals|censorship)\b",
        "Known jailbreak persona or restriction-removal phrasing",
    ),
    _rule(
        "PI-005",
        "roleplay_bypass",
        Severity.HIGH,
        r"\b(?:pretend|imagine|act\s+as|role-?play\s+as|you\s+are\s+now|behave\s+like|simulate)\b"
        r"[^.\n]{0,60}?\b(?:unrestricted|unfiltered|uncensored|evil|malicious|jailbroken|amoral|"
        r"no\s+(?:rules|restrictions|limits|filters)|without\s+(?:rules|restrictions|limits|filters|guidelines))\b"
        r"|\byou\s+are\s+no\s+longer\s+(?:bound|restricted|an?\s+(?:ai|assistant))\b",
        "Role-play framing used to bypass safety constraints",
    ),
    _rule(
        "PI-006",
        "delimiter_injection",
        Severity.HIGH,
        r"<\|(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\|>"
        r"|\[/?INST\]|<</?SYS>>|</?\s*system\s*>"
        r"|^\s*#{2,}\s*(?:system|instructions?|admin)\b\s*:?"
        r"|^\s*(?:system|assistant)\s*:\s*\S"
        r"|\b(?:BEGIN|END)\s+(?:SYSTEM|ADMIN|DEVELOPER)\s+(?:PROMPT|INSTRUCTIONS?|MESSAGE|OVERRIDE)\b",
        "Chat-template or role delimiter injection",
    ),
    _rule(
        "PI-007",
        "authority_impersonation",
        Severity.MEDIUM,
        r"\b(?:i\s+am|i'm|this\s+is)\s+(?:your|the|an?)\s+(?:developer|creator|administrator|admin|"
        r"owner|operator|system\s+administrator)\b"
        r"|\b(?:admin|sudo|root|maintenance|debug|superuser)\s+(?:mode|access|override)\s+"
        r"(?:enabled|activated|granted|on)\b"
        r"|\bauthori[sz]ed\s+(?:security\s+)?override\b",
        "Claims elevated authority to unlock behaviour",
    ),
    _rule(
        "PI-008",
        "safety_bypass",
        Severity.MEDIUM,
        r"\b(?:disable|turn\s+off|deactivate|bypass|circumvent|evade|switch\s+off)\b[^.\n]{0,30}?"
        r"\b(?:your\s+)?(?:safety|guardrails?|content\s+filters?|moderation|restrictions|safeguards|alignment)\b",
        "Request to disable safety controls",
    ),
    _rule(
        "PI-009",
        "data_exfiltration",
        Severity.HIGH,
        r"\b(?:send|post|upload|exfiltrate|forward|transmit|leak)\b[^.\n]{0,60}?"
        r"\b(?:conversation|chat\s+history|system\s+prompt|credentials?|secrets?|api\s+keys?|"
        r"database|passwords?)\b[^.\n]{0,40}?\b(?:to|at|into)\s+(?:https?://|\S+@\S+)"
        r"|!\[[^\]]*\]\(https?://[^)]*(?:\{|%7b|\$\(|<)[^)]*\)",
        "Instruction to exfiltrate data to an external destination",
        owasp=("LLM01", "LLM02"),
    ),
    _rule(
        "PI-010",
        "encoded_instruction",
        Severity.HIGH,
        r"\b(?:decode|decrypt|deobfuscate|unscramble|rot13|base64[-\s]?decode)\b[^.\n]{0,50}?"
        r"\b(?:and|then)\b[^.\n]{0,20}?\b(?:follow|execute|run|obey|do\s+what|carry\s+out|comply)\b",
        "Instruction to decode and execute a hidden payload",
    ),
)

# Weak signals. Individually benign, collectively characteristic of injection.
_CUE_WORDS = re.compile(
    r"\b(ignore|disregard|instructions?|system\s+prompt|rules|restrictions|jailbreak|bypass|override|"
    r"pretend|unrestricted|unfiltered|confidential|reveal|developer|uncensored|obey|comply|"
    r"no\s+longer|guardrails?|policy|policies)\b",
    re.IGNORECASE,
)
_HEURISTIC_MIN_CUES = 5

_INVISIBLE = re.compile(r"[­​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_SPACED = re.compile(r"\b(?:[a-z][ ._\-*]){3,}[a-z]\b", re.IGNORECASE)
_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[\s:]?){12,}(?![0-9a-fA-F])")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")


_SQUASHED_PHRASES = re.compile(
    r"(?:ignore|disregard|forget|bypass|override)(?:all|the|your|any)*(?:previous|prior|above|system)"
    r"(?:instructions?|prompts?|rules)|(?:reveal|print|show|dump)(?:me)?(?:the|your)?systemprompt|jailbreak"
)


def _strip(text: str) -> str:
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))


def normalize(text: str) -> str:
    return re.sub(r"[ \t\f\v]+", " ", _strip(text))


def despace(text: str) -> str:
    """Collapse runs like ``i g n o r e`` (a double space is treated as a word gap)."""
    return normalize(_SPACED.sub(lambda m: re.sub(r"[ ._\-*]", "", m.group(0)), _strip(text)))


def _printable(text: str) -> bool:
    if not text:
        return False
    good = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return good / len(text) >= 0.9 and any(ch.isalpha() for ch in text)


def decode_blobs(text: str) -> list[tuple[str, str]]:
    """Return ``(encoding, decoded_text)`` for every decodable blob in ``text``."""
    out: list[tuple[str, str]] = []
    for m in _B64.finditer(text):
        blob = m.group(0)
        if blob.isalpha() and (blob.islower() or blob.isupper()):
            continue  # plain words / identifiers, not base64
        padded = blob + "=" * (-len(blob) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(padded).decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if _printable(decoded):
                out.append(("base64", decoded))
                break
    for m in _HEX.finditer(text):
        try:
            decoded = bytes.fromhex(re.sub(r"[\s:]", "", m.group(0))).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable(decoded):
            out.append(("hex", decoded))
    if len(_PCT.findall(text)) >= 3:
        decoded = urllib.parse.unquote(urllib.parse.unquote_plus(text))
        if decoded != text and _printable(decoded):
            out.append(("url-encoding", decoded))
    return out


def _evidence(text: str, m: re.Match[str], width: int = 80) -> str:
    snippet = m.group(0).strip().replace("\n", " ")
    return snippet if len(snippet) <= width else snippet[: width - 1] + "…"


@dataclass
class InputInspection:
    decision: Decision
    sanitized_text: str
    findings: list[Finding] = field(default_factory=list)
    redactions: list[RedactionEvent] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        return risk_score(self.findings)

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK


class InputGuard:
    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy: InputGuardPolicy = policy.input_guard
        self.redactor = Redactor(policy.redaction)
        self._custom = tuple(
            _rule(p.id, "custom_policy", p.severity, p.pattern, p.message) for p in self.policy.custom_patterns
        )

    # ------------------------------------------------------------------ #
    def _scan(self, text: str, stage: Stage, view: str | None = None) -> list[Finding]:
        findings = []
        for rule in INJECTION_RULES + self._custom:
            m = rule.pattern.search(text)
            if m:
                msg = rule.message if view is None else f"{rule.message} (detected after {view})"
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        stage=stage,
                        category=rule.category,
                        severity=rule.severity,
                        message=msg,
                        owasp=list(rule.owasp),
                        evidence=_evidence(text, m),
                    )
                )
        return findings

    def detect_injection(self, text: str, stage: Stage = Stage.INPUT, _depth: int = 0) -> list[Finding]:
        """Run every injection detector over all views of ``text`` (deduplicated by rule)."""
        findings: dict[str, Finding] = {}

        def add(items: list[Finding]) -> None:
            for f in items:
                findings.setdefault(f.rule_id, f)

        raw_invisible = len(_INVISIBLE.findall(text))
        norm = normalize(text)
        add(self._scan(norm, stage))

        deleet = norm.lower().translate(_LEET)
        if deleet != norm.lower():
            add(self._scan(deleet, stage, view="leetspeak normalisation"))
        despaced = despace(text)
        if despaced != norm:
            add(self._scan(despaced, stage, view="character-spacing normalisation"))
            squashed = re.sub(r"[^a-z]", "", norm.lower().translate(_LEET))
            m = _SQUASHED_PHRASES.search(squashed)
            if m and not findings:
                add(
                    [
                        Finding(
                            rule_id="PI-OBF-002",
                            stage=stage,
                            category="obfuscation",
                            severity=Severity.HIGH,
                            message="Character-spaced injection phrase detected",
                            owasp=["LLM01"],
                            evidence=m.group(0)[:80],
                        )
                    ]
                )

        if raw_invisible:
            add(
                [
                    Finding(
                        rule_id="PI-OBF-001",
                        stage=stage,
                        category="obfuscation",
                        severity=Severity.MEDIUM,
                        message=f"{raw_invisible} invisible/bidi control character(s) stripped",
                        owasp=["LLM01"],
                    )
                ]
            )

        if self.policy.decode_obfuscation and _depth < 2:
            for encoding, decoded in decode_blobs(norm):
                inner = self.detect_injection(decoded, stage, _depth + 1)
                inner = [f for f in inner if not f.rule_id.startswith("PI-HEU")]
                if inner:
                    rules = ", ".join(sorted({f.rule_id for f in inner}))
                    add(
                        [
                            Finding(
                                rule_id="PI-ENC-001",
                                stage=stage,
                                category="encoding_smuggling",
                                severity=Severity.CRITICAL,
                                message=f"{encoding}-encoded payload contains prompt injection ({rules})",
                                owasp=["LLM01"],
                                evidence=decoded[:80],
                            )
                        ]
                    )

        cues = {m.group(0).lower() for m in _CUE_WORDS.finditer(despaced.translate(_LEET))}
        if len(cues) >= _HEURISTIC_MIN_CUES and not findings:
            add(
                [
                    Finding(
                        rule_id="PI-HEU-001",
                        stage=stage,
                        category="heuristic",
                        severity=Severity.MEDIUM,
                        message=f"High density of injection cue words ({len(cues)} distinct)",
                        owasp=["LLM01"],
                        evidence=", ".join(sorted(cues))[:80],
                    )
                ]
            )
        return list(findings.values())

    # ------------------------------------------------------------------ #
    def inspect(self, text: str) -> InputInspection:
        if not self.policy.enabled:
            return InputInspection(decision=Decision.ALLOW, sanitized_text=text)

        if len(text) > self.policy.max_prompt_chars:
            finding = Finding(
                rule_id="PI-LEN-001",
                stage=Stage.INPUT,
                category="unbounded_consumption",
                severity=Severity.HIGH,
                message=f"Prompt length {len(text)} exceeds limit of {self.policy.max_prompt_chars}",
                owasp=["LLM10"],
            )
            return InputInspection(decision=Decision.BLOCK, sanitized_text="", findings=[finding])

        injection = [
            f.model_copy(update={"evidence": self.redactor.redact(f.evidence, Stage.INPUT).text}) if f.evidence else f
            for f in self.detect_injection(text)
        ]
        redaction = self.redactor.redact(normalize(text), Stage.INPUT)

        findings = injection + redaction.findings
        threshold_rank = self.policy.block_on_severity.rank
        must_block = (
            any(f.severity.rank >= threshold_rank for f in injection)
            or risk_score(injection) >= self.policy.block_risk_threshold
            or redaction.blocked
        )
        if must_block:
            decision = Decision.BLOCK
        elif redaction.changed:
            decision = Decision.SANITIZED
        else:
            decision = Decision.ALLOW

        return InputInspection(
            decision=decision,
            sanitized_text=redaction.text,
            findings=findings,
            redactions=redaction.events,
        )
