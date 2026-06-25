"""GitHub dorking via the official Search API.

Searches both code and repositories. Code search requires an
authenticated token (a fine-grained or classic PAT with public_repo /
read access is enough) and is limited to ~10 requests/minute, which the
shared HttpClient backoff handles. Create a token at
https://github.com/settings/tokens
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, List

import yaml

from ..config import Config
from ..core.base import BaseCollector, register
from ..core.schema import Finding
from .http import HttpClient

log = logging.getLogger("marlong.github")

_CODE_ENDPOINT = "https://api.github.com/search/code"
_REPO_ENDPOINT = "https://api.github.com/search/repositories"
_DORKS_FILE = Path(__file__).resolve().parent.parent / "dorks" / "github_dorks.yaml"


def load_dorks(path: Path = _DORKS_FILE) -> dict:
    if not path.exists():
        return {"code": ['"{target}"'], "repo": ["{target}"]}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


@register
class GitHubDorkCollector(BaseCollector):
    name = "github_dork"
    description = "Search GitHub code and repositories with dork templates."

    def __init__(self, config: Config):
        super().__init__(config)
        self.http = HttpClient(config.user_agent, max(config.request_delay, 6.5),
                               config.request_timeout)
        self.dorks = load_dorks()

    def available(self) -> bool:
        if not self.config.github_ready:
            log.warning("github_dork disabled: set MARLONG_GITHUB_TOKEN")
            return False
        return True

    @property
    def _headers(self) -> dict:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.config.github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _search(self, endpoint: str, query: str) -> List[dict]:
        params = {"q": query, "per_page": min(self.config.max_results_per_dork, 30)}
        resp = self.http.get(endpoint, params=params, headers=self._headers)
        if resp is None or resp.status_code != 200:
            log.warning("github search failed (%s) for: %s",
                        getattr(resp, "status_code", "no-response"), query)
            return []
        return resp.json().get("items", []) or []

    def collect(self, target: str) -> Iterable[Finding]:
        if not self.available():
            return

        for template in self.dorks.get("code", []):
            q = template.format(target=target)
            for item in self._search(_CODE_ENDPOINT, q):
                repo = item.get("repository", {}) or {}
                yield Finding(
                    source=self.name,
                    type="code_match",
                    target=target,
                    title=f"{repo.get('full_name', '?')}/{item.get('path', '')}",
                    url=item.get("html_url", ""),
                    snippet=item.get("path", ""),
                    tags=["github-dork", "code"],
                    metadata={"dork": q, "repo": repo.get("full_name", "")},
                )

        for template in self.dorks.get("repo", []):
            q = template.format(target=target)
            for item in self._search(_REPO_ENDPOINT, q):
                yield Finding(
                    source=self.name,
                    type="repository",
                    target=target,
                    title=item.get("full_name", ""),
                    url=item.get("html_url", ""),
                    snippet=item.get("description") or "",
                    tags=["github-dork", "repo"],
                    metadata={"dork": q, "stars": item.get("stargazers_count", 0)},
                )
