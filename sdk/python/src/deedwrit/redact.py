"""The redacted preview a receipt carries in place of raw arguments.

A port of packages/core/src/redact.js. The preview is signed as part of the
receipt but never recomputed by a verifier, so it need not match JavaScript
byte for byte; it does need to catch the same things. The patterns are the
same, compiled ASCII-only so ``\\b`` and ``\\d`` mean what they mean in
JavaScript.
"""

from __future__ import annotations

import re
from typing import Any, Callable, NamedTuple, Optional


def _luhn(s: str) -> bool:
    digits = re.sub(r"[^0-9]", "", s)
    if not 13 <= len(digits) <= 19:
        return False
    total, double = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


class Detector(NamedTuple):
    type: str
    severity: str
    pattern: "re.Pattern[str]"
    confirm: Optional[Callable[[str], bool]] = None


def _p(src: str) -> "re.Pattern[str]":
    return re.compile(src, re.ASCII)


DEFAULT_DETECTORS: list[Detector] = [
    Detector("aws_access_key", "secret", _p(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Detector("github_token", "secret", _p(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    # Anthropic before OpenAI, and OpenAI's pattern excludes sk-ant-: a
    # mislabelled finding sends an incident responder to the wrong vendor.
    Detector("anthropic_key", "secret", _p(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    Detector("openai_key", "secret", _p(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    Detector("stripe_key", "secret", _p(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    Detector("slack_token", "secret", _p(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Detector("google_api_key", "secret", _p(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    Detector("private_key_block", "secret", _p(r"-----BEGIN[ A-Z]*PRIVATE KEY-----")),
    Detector("jwt", "secret", _p(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    Detector("bearer_token", "secret", _p(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*")),
    Detector("credit_card", "financial", _p(r"\b(?:\d[ -]?){12,18}\d\b"), _luhn),
    Detector("us_ssn", "pii", _p(r"\b(?!000|666|9\d\d)\d{3}-\d{2}-\d{4}\b")),
    Detector("iban", "financial", _p(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    Detector("email", "pii", _p(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Detector("phone_e164", "pii", _p(r"(?<![\w.])\+[1-9]\d{7,14}(?![\w.])")),
]

DENY_KEYS = [
    "password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "auth",
    "credential", "credentials", "private_key", "client_secret", "session_key", "cvv", "cvc",
]


def _mask(kind: str, match: str) -> str:
    tail = re.sub(r"[^A-Za-z0-9]", "", match)[-4:]
    return f"[redacted:{kind}:…{tail}]"


class Finding(NamedTuple):
    path: str
    type: str
    severity: str


def redact(
    value: Any,
    detectors: Optional[list[Detector]] = None,
    deny_keys: Optional[list[str]] = None,
) -> tuple[Any, list[Finding]]:
    """A copy of ``value`` with secrets and personal data masked, and what was found."""
    dets = DEFAULT_DETECTORS if detectors is None else detectors
    deny = [k.lower() for k in (DENY_KEYS if deny_keys is None else deny_keys)]
    findings: list[Finding] = []

    def scan(s: str, path: str) -> str:
        out = s
        for d in dets:
            def sub(m: "re.Match[str]", d: Detector = d) -> str:
                text = m.group(0)
                if d.confirm and not d.confirm(text):
                    return text
                findings.append(Finding(path, d.type, d.severity))
                return _mask(d.type, text)

            out = d.pattern.sub(sub, out)
        return out

    def walk(v: Any, path: str) -> Any:
        if isinstance(v, str):
            return scan(v, path)
        if isinstance(v, (list, tuple)):
            return [walk(item, f"{path}[{i}]") for i, item in enumerate(v)]
        if isinstance(v, dict):
            out = {}
            for k, val in v.items():
                child = f"{path}.{k}" if path else str(k)
                if str(k).lower() in deny:
                    findings.append(Finding(child, f"key:{str(k).lower()}", "secret"))
                    out[k] = "[redacted:by-key]"
                    continue
                out[k] = walk(val, child)
            return out
        return v

    return walk(value, ""), findings


def has_secrets(findings: list[Finding]) -> bool:
    return any(f.severity in ("secret", "financial") for f in findings)
