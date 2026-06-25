"""Configuration and scope guardrails.

Credentials are read from environment variables so they never live in
source control. The ``scope`` guardrail is a safety feature: when set,
Marlong refuses to run against any target outside the authorised list.
"""
from __future__ import annotations

import os
import fnmatch
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Config:
    # --- credentials (set via environment) ---
    google_api_key: Optional[str] = field(default_factory=lambda: os.getenv("MARLONG_GOOGLE_API_KEY"))
    google_cse_id: Optional[str] = field(default_factory=lambda: os.getenv("MARLONG_GOOGLE_CSE_ID"))
    github_token: Optional[str] = field(default_factory=lambda: os.getenv("MARLONG_GITHUB_TOKEN"))

    # --- politeness / rate limiting ---
    request_delay: float = 1.0        # seconds between outbound requests
    request_timeout: float = 20.0
    max_results_per_dork: int = 10
    user_agent: str = "Marlong-OSINT/0.1 (+authorized-research-only)"

    # --- scope guardrail ---
    # Glob patterns of targets you are AUTHORISED to investigate, e.g.
    # ["*.example.com", "example.com", "acme-corp"]. Empty = no enforcement
    # (a loud warning is printed instead).
    scope: List[str] = field(default_factory=list)

    def in_scope(self, target: str) -> bool:
        if not self.scope:
            return True
        return any(fnmatch.fnmatch(target.lower(), pat.lower()) for pat in self.scope)

    @property
    def google_ready(self) -> bool:
        return bool(self.google_api_key and self.google_cse_id)

    @property
    def github_ready(self) -> bool:
        return bool(self.github_token)
