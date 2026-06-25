"""Common data model shared by every collector.

Every collector, no matter the source, normalises its results into a
``Finding``. This is the single schema the rest of the pipeline
(normalisation, storage, reporting) understands.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(*parts: str) -> str:
    """Deterministic id so the same finding from two runs de-dupes cleanly."""
    h = hashlib.sha256("||".join(p or "" for p in parts).encode("utf-8"))
    return h.hexdigest()[:16]


@dataclass
class Finding:
    source: str                       # collector name, e.g. "google_dork"
    type: str                         # e.g. "web_result", "code_match", "pdf_document"
    target: str                       # the scan target this relates to
    title: str = ""
    url: str = ""
    snippet: str = ""
    severity: str = "info"            # info | low | medium | high
    tags: List[str] = field(default_factory=list)
    entities: Dict[str, List[str]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(default_factory=_now)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(self.source, self.type, self.url or self.title, self.target)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)
