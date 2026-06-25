"""Marlong command-line interface.

Examples
--------
  # list available collectors
  python -m marlong collectors

  # scan a domain with every collector that has credentials
  python -m marlong scan -t example.com

  # only google + pdf, analyse a couple of local PDFs too
  python -m marlong scan -t acme.com -c google_dork -c pdf_hunter \\
      --pdf ./report.pdf --pdf ./leaked.pdf -o ./reports

Set credentials via environment variables:
  MARLONG_GOOGLE_API_KEY, MARLONG_GOOGLE_CSE_ID, MARLONG_GITHUB_TOKEN
"""
from __future__ import annotations

import argparse
import logging
import sys
from typing import List

from . import __version__
from .config import Config
from .core.base import all_collectors
from .core.pipeline import Scan

# importing the collector modules registers them
from .collectors import google_dork, github_dork, pdf_hunter, crtsh  # noqa: F401


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)-7s %(name)s: %(message)s",
    )


def _cmd_version(_args) -> int:
    print(f"Marlong OSINT Engine v{__version__}")
    deps = {
        "pypdf": "pypdf",
        "reportlab": "reportlab",
    }
    for label, module in deps.items():
        try:
            __import__(module)
            status = "installed"
        except ImportError:
            status = "not installed"
        print(f"  {label:<10}: {status}")
    return 0


def _cmd_collectors(_args) -> int:
    print("Available collectors:")
    cfg = Config()
    from .core.base import get_collector
    for name in all_collectors():
        cls = get_collector(name)
        # instantiate cheaply just to read availability where possible
        try:
            ready = cls(cfg).available()
        except TypeError:
            ready = True
        flag = "ready" if ready else "needs credentials"
        print(f"  - {name:<14} [{flag}]  {cls.description}")
    return 0


def _cmd_scan(args) -> int:
    cfg = Config()
    if args.scope:
        cfg.scope = args.scope
    if args.max_results:
        cfg.max_results_per_dork = args.max_results

    scan = Scan(cfg, db_path=args.db)
    result = scan.run(
        targets=args.target,
        collector_names=args.collector or None,
        out_dir=args.out,
        local_pdfs=args.pdf or None,
    )

    print("\n=== Marlong scan complete ===")
    print(f"scan id      : {result['scan_id']}")
    print(f"targets      : {', '.join(result['targets']) or '(none in scope)'}")
    print(f"collectors   : {', '.join(result['collectors'])}")
    print(f"findings     : {result['finding_count']} "
          f"(high severity: {result['high_severity']})")
    print(f"HTML report  : {result['report_html']}")
    print(f"PDF report   : {result['report_pdf'] or '(reportlab not installed)'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="marlong", description="Marlong — modular OSINT engine")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("version", help="print version and optional dependency status")
    sub.add_parser("collectors", help="list available collectors")

    s = sub.add_parser("scan", help="run a scan")
    s.add_argument("-t", "--target", action="append", required=True,
                   help="target (repeatable): domain, org name, keyword")
    s.add_argument("-c", "--collector", action="append",
                   help="collector to use (repeatable); default = all ready")
    s.add_argument("--pdf", action="append", help="local PDF path to analyse (repeatable)")
    s.add_argument("--scope", action="append", help="authorised target glob (repeatable)")
    s.add_argument("--max-results", type=int, help="max results per dork")
    s.add_argument("-o", "--out", default="reports", help="report output directory")
    s.add_argument("--db", default="marlong.db", help="SQLite database path")
    return p


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    if args.command == "version":
        return _cmd_version(args)
    if args.command == "collectors":
        return _cmd_collectors(args)
    if args.command == "scan":
        return _cmd_scan(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
