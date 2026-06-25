"""Certificate Transparency collector via crt.sh.

Uses the free crt.sh JSON API (no authentication required).
Yields one Finding per unique name_value (subdomain / SAN entry),
deduplicated within a single collect() call.
"""
from __future__ import annotations

import logging
from typing import Iterable, Set

from ..config import Config
from ..core.base import BaseCollector, register
from ..core.schema import Finding
from .http import DEFAULT_RETRY_STATUSES, HttpClient

log = logging.getLogger("marlong.crtsh")

_ENDPOINT = "https://crt.sh/"
# crt.sh sporadically answers a valid query with 404 (or a timeout) when its
# backend is busy; a retry almost always succeeds. Treat 404 as transient here.
_CRTSH_RETRY_STATUSES = (404,) + DEFAULT_RETRY_STATUSES


@register
class CrtShCollector(BaseCollector):
    name = "crtsh"
    description = "Subdomain enumeration via certificate transparency logs (crt.sh)."

    def __init__(self, config: Config):
        super().__init__(config)
        self.http = HttpClient(config.user_agent, config.request_delay, config.request_timeout)

    def available(self) -> bool:
        return True

    def collect(self, target: str) -> Iterable[Finding]:
        resp = self.http.get(
            _ENDPOINT,
            params={"q": f"%.{target}", "output": "json"},
            retry_statuses=_CRTSH_RETRY_STATUSES,
        )
        if resp is None or resp.status_code != 200:
            log.warning("crtsh query failed (%s) for: %s",
                        getattr(resp, "status_code", "no-response"), target)
            return

        try:
            entries = resp.json()
        except Exception as exc:
            log.warning("crtsh: failed to parse JSON for %s: %s", target, exc)
            return

        seen: Set[str] = set()
        for entry in entries:
            raw_name = entry.get("name_value", "")
            # name_value may contain newline-separated SANs
            for name in raw_name.splitlines():
                name = name.strip().lstrip("*.")
                if not name or name in seen:
                    continue
                seen.add(name)
                yield Finding(
                    source=self.name,
                    type="subdomain",
                    target=target,
                    title=name,
                    url=f"https://{name}",
                    snippet=f"common_name={entry.get('common_name', '')}",
                    severity="info",
                    tags=["crtsh", "subdomain"],
                    metadata={
                        "common_name": entry.get("common_name", ""),
                        "issuer_name": entry.get("issuer_name", ""),
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                    },
                )
