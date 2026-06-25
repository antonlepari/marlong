"""Google dorking via the official Programmable Search Engine (CSE) API.

We deliberately use the sanctioned JSON API rather than scraping
google.com directly: scraping violates Google's Terms of Service and gets
blocked quickly. Get a key at https://developers.google.com/custom-search
and create a search engine at https://programmablesearchengine.google.com
(set it to search the whole web).
"""
from __future__ import annotations

import logging
from typing import Iterable, List

import yaml
from pathlib import Path

from ..config import Config
from ..core.base import BaseCollector, register
from ..core.schema import Finding
from .http import HttpClient

log = logging.getLogger("marlong.google")

_ENDPOINT = "https://www.googleapis.com/customsearch/v1"
_DORKS_FILE = Path(__file__).resolve().parent.parent / "dorks" / "google_dorks.yaml"


def load_dorks(path: Path = _DORKS_FILE) -> List[str]:
    if not path.exists():
        return ["site:{target}"]
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return list(data.get("dorks", ["site:{target}"]))


@register
class GoogleDorkCollector(BaseCollector):
    name = "google_dork"
    description = "Advanced Google queries via the Programmable Search API."

    def __init__(self, config: Config):
        super().__init__(config)
        self.http = HttpClient(config.user_agent, config.request_delay, config.request_timeout)
        self.dorks = load_dorks()

    def available(self) -> bool:
        if not self.config.google_ready:
            log.warning("google_dork disabled: set MARLONG_GOOGLE_API_KEY and MARLONG_GOOGLE_CSE_ID")
            return False
        return True

    def _query(self, q: str) -> List[dict]:
        params = {
            "key": self.config.google_api_key,
            "cx": self.config.google_cse_id,
            "q": q,
            "num": min(self.config.max_results_per_dork, 10),
        }
        resp = self.http.get(_ENDPOINT, params=params)
        if resp is None or resp.status_code != 200:
            log.warning("google query failed (%s) for: %s",
                        getattr(resp, "status_code", "no-response"), q)
            return []
        return resp.json().get("items", []) or []

    def collect(self, target: str) -> Iterable[Finding]:
        if not self.available():
            return
        for template in self.dorks:
            query = template.format(target=target)
            for item in self._query(query):
                yield Finding(
                    source=self.name,
                    type="web_result",
                    target=target,
                    title=item.get("title", ""),
                    url=item.get("link", ""),
                    snippet=item.get("snippet", ""),
                    tags=["google-dork"],
                    metadata={"dork": query, "display_link": item.get("displayLink", "")},
                )
