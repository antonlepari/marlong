"""The scan pipeline.

Flow:  targets x collectors  ->  raw Findings  ->  enrich (entities,
secrets)  ->  de-duplicate  ->  store (SQLite)  ->  report (HTML/PDF).
"""
from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from .base import all_collectors, get_collector
from .schema import Finding
from ..config import Config
from ..enrich.normalize import deduplicate, enrich
from ..storage.db import Store
from ..reporting import report as reporting

log = logging.getLogger("marlong.pipeline")


class Scan:
    def __init__(self, config: Config, db_path: str = "marlong.db"):
        self.config = config
        self.store = Store(db_path)

    def run(self, targets: List[str], collector_names: Optional[List[str]] = None,
            out_dir: str = "reports", local_pdfs: Optional[List[str]] = None) -> dict:
        collector_names = collector_names or all_collectors()
        scan_id = uuid.uuid4().hex[:12]
        self.store.new_scan(scan_id, targets, collector_names)

        # scope guardrail
        approved = []
        for t in targets:
            if self.config.in_scope(t):
                approved.append(t)
            else:
                log.warning("SKIPPED out-of-scope target: %s (not in configured scope)", t)
        if not self.config.scope:
            log.warning("No scope configured — only investigate targets you are AUTHORISED to test.")

        raw: List[Finding] = []
        for name in collector_names:
            cls = get_collector(name)
            # pdf_hunter accepts local files
            if name == "pdf_hunter":
                collector = cls(self.config, local_pdfs=local_pdfs)
            else:
                collector = cls(self.config)
            if not collector.available():
                continue
            for target in approved:
                log.info("[%s] collecting for %s", name, target)
                try:
                    for finding in collector.collect(target):
                        raw.append(finding)
                except Exception as exc:
                    log.error("[%s] error on %s: %s", name, target, exc)

        enriched = [enrich(f) for f in raw]
        findings = deduplicate(enriched)
        saved = self.store.save_findings(scan_id, findings)

        html_path = reporting.generate_html(scan_id, findings, out_dir)
        pdf_path = reporting.generate_pdf(scan_id, findings, out_dir)

        self.store.close()
        return {
            "scan_id": scan_id,
            "targets": approved,
            "collectors": collector_names,
            "finding_count": saved,
            "high_severity": sum(1 for f in findings if f.severity == "high"),
            "report_html": html_path,
            "report_pdf": pdf_path,
            "findings": findings,
        }
