"""PDF hunter: discover, download, and analyse PDF documents.

Two modes:
  1. Discovery  - uses the Google CSE backend to find `filetype:pdf`
     documents related to a target (needs Google keys).
  2. Local parse - analyses PDFs already on disk (works fully offline).

For each PDF it extracts document metadata (author, creator, producer,
timestamps - which routinely leak internal usernames, software versions
and file paths) and a slice of body text for entity extraction.
"""
from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Iterable, List, Optional

from pypdf import PdfReader

from ..config import Config
from ..core.base import BaseCollector, register
from ..core.schema import Finding
from .http import HttpClient
from .google_dork import _ENDPOINT as GOOGLE_ENDPOINT

log = logging.getLogger("marlong.pdf")

_MAX_TEXT_CHARS = 20_000


def _parse_pdf_bytes(data: bytes, source_label: str) -> dict:
    reader = PdfReader(io.BytesIO(data))
    meta = reader.metadata or {}
    info = {k.lstrip("/"): str(v) for k, v in dict(meta).items()} if meta else {}
    text_parts: List[str] = []
    chars = 0
    for page in reader.pages:
        try:
            t = page.extract_text() or ""
        except Exception:  # malformed page, keep going
            t = ""
        text_parts.append(t)
        chars += len(t)
        if chars >= _MAX_TEXT_CHARS:
            break
    return {
        "doc_metadata": info,
        "pages": len(reader.pages),
        "text": "\n".join(text_parts)[:_MAX_TEXT_CHARS],
        "source_label": source_label,
    }


@register
class PdfHunter(BaseCollector):
    name = "pdf_hunter"
    description = "Find and analyse PDF documents (metadata + text leaks)."

    def __init__(self, config: Config, local_pdfs: Optional[List[str]] = None):
        super().__init__(config)
        self.http = HttpClient(config.user_agent, config.request_delay, config.request_timeout)
        self.local_pdfs = local_pdfs or []

    def available(self) -> bool:
        # Local parsing always works; discovery needs Google keys.
        return True

    def _discover_urls(self, target: str) -> List[str]:
        if not self.config.google_ready:
            log.info("pdf_hunter discovery skipped (no Google keys); local files only")
            return []
        params = {
            "key": self.config.google_api_key,
            "cx": self.config.google_cse_id,
            "q": f"site:{target} filetype:pdf",
            "num": min(self.config.max_results_per_dork, 10),
        }
        resp = self.http.get(GOOGLE_ENDPOINT, params=params)
        if resp is None or resp.status_code != 200:
            return []
        return [it.get("link", "") for it in resp.json().get("items", []) if it.get("link")]

    def _fetch_and_parse(self, url: str, target: str) -> Optional[Finding]:
        resp = self.http.get(url)
        if resp is None or resp.status_code != 200:
            return None
        if "pdf" not in resp.headers.get("Content-Type", "").lower() and not url.lower().endswith(".pdf"):
            return None
        try:
            parsed = _parse_pdf_bytes(resp.content, url)
        except Exception as exc:
            log.warning("could not parse %s: %s", url, exc)
            return None
        return self._finding_from_parsed(parsed, target, url, title=url.rsplit("/", 1)[-1])

    def _finding_from_parsed(self, parsed: dict, target: str, url: str, title: str) -> Finding:
        dm = parsed["doc_metadata"]
        tags = ["pdf"]
        if dm.get("Author") or dm.get("Creator") or dm.get("Producer"):
            tags.append("metadata-present")
        return Finding(
            source=self.name,
            type="pdf_document",
            target=target,
            title=title or dm.get("Title", "untitled.pdf"),
            url=url,
            snippet=(parsed["text"][:280]).strip(),
            tags=tags,
            metadata={
                "doc_metadata": dm,
                "pages": parsed["pages"],
                "text": parsed["text"],
            },
        )

    def collect(self, target: str) -> Iterable[Finding]:
        # 1. discovered PDFs
        for url in self._discover_urls(target):
            f = self._fetch_and_parse(url, target)
            if f:
                yield f
        # 2. local PDFs supplied on the command line
        for p in self.local_pdfs:
            path = Path(p)
            if not path.exists():
                log.warning("local pdf not found: %s", p)
                continue
            try:
                parsed = _parse_pdf_bytes(path.read_bytes(), str(path))
            except Exception as exc:
                log.warning("could not parse %s: %s", path, exc)
                continue
            yield self._finding_from_parsed(parsed, target, str(path), title=path.name)
