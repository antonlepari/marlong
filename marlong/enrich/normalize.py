"""Normalisation & enrichment.

Turns raw text from any source into structured entities and flags
indicators that a defender would care about (exposed secrets, emails,
hosts). De-duplication happens here too, keyed on the stable Finding id.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List

from ..core.schema import Finding

# --- entity patterns ---
_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"https?://[^\s\"'<>)]+")
# Require at least one non-numeric label so version strings like "1.0" or "v2.3" are excluded.
# The TLD must be all-alpha (no digit-only labels) and at least 2 chars.
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b"
)

# --- credential / secret indicators (defensive: find your own leaks) ---
_SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "generic_secret_assignment": re.compile(
        r"(?i)(?:api[_\-]?key|secret|password|passwd|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    ),
    "github_token":    re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
    "github_token_v2": re.compile(r"\bgithub_pat_[0-9A-Za-z_]{82}\b"),
    "stripe_key":      re.compile(r"\bsk_live_[0-9A-Za-z]{24}\b"),
    "npm_token":       re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"),
    "telegram_bot":    re.compile(r"\b\d{8,10}:[0-9A-Za-z_\-]{35}\b"),
}


def extract_entities(text: str) -> Dict[str, List[str]]:
    if not text:
        return {}
    out: Dict[str, List[str]] = {}

    def add(key: str, values: Iterable[str]) -> None:
        uniq = sorted({v for v in values})
        if uniq:
            out[key] = uniq

    add("emails", _EMAIL.findall(text))
    add("ipv4", _IPV4.findall(text))
    add("urls", _URL.findall(text))
    # domains, minus anything that is the domain part of an already-found email
    email_domains = {e.split("@", 1)[1].lower() for e in out.get("emails", [])}
    domains = [d for d in _DOMAIN.findall(text) if d.lower() not in email_domains]
    add("domains", domains)
    return out


def detect_secrets(text: str) -> List[str]:
    if not text:
        return []
    hits: List[str] = []
    for label, pat in _SECRET_PATTERNS.items():
        if pat.search(text):
            hits.append(label)
    return sorted(set(hits))


def enrich(finding: Finding) -> Finding:
    """Attach entities + secret indicators and bump severity if needed."""
    haystack = " ".join(filter(None, [finding.title, finding.snippet,
                                       finding.metadata.get("text", "")]))
    entities = extract_entities(haystack)
    if entities:
        # merge with anything the collector already set
        for k, v in entities.items():
            merged = sorted(set(finding.entities.get(k, [])) | set(v))
            finding.entities[k] = merged

    secrets = detect_secrets(haystack)
    if secrets:
        finding.tags = sorted(set(finding.tags) | {"exposed-secret"})
        finding.metadata["secret_indicators"] = secrets
        finding.severity = "high"
    return finding


def deduplicate(findings: Iterable[Finding]) -> List[Finding]:
    seen: Dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.id, f)
    return list(seen.values())
