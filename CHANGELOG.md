# Changelog

All notable changes to Marlong are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-06-05

### Fixed
- **`crtsh` collector failing intermittently.** crt.sh sporadically answers
  valid queries with `404` or `5xx` errors (and occasional timeouts) when its
  backend is under load. The HTTP client previously treated these as final and
  gave up, so certificate-transparency scans failed at random. The client now
  retries transient server errors (`500/502/503/504`) with exponential backoff,
  and `crtsh` additionally treats its spurious `404` responses as retryable.

### Changed
- `HttpClient.get()` accepts a `retry_statuses` parameter so collectors can opt
  into retrying source-specific transient status codes.

### Documentation
- Added Windows installation instructions to the README (`py` launcher,
  `py -m pip`, `--user` fallback, and a virtual-environment recipe).
- Documented credential setup for PowerShell (`$env:` / `setx`) and Command
  Prompt (`set`) alongside the existing Bash syntax.
- Clarified that Windows users run `py -m marlong …` in the Usage section.

## [0.2.0] - 2026-06-01

### Added
- `crtsh` collector: subdomain enumeration via certificate transparency logs
  (crt.sh), no credentials required.

### Changed
- Improved secret-indicator detection (AWS/Google/GitHub keys, JWTs, Stripe
  keys, npm tokens, Telegram bots, private keys, and more).
- Enhanced HTML/PDF reporting output.

### Fixed
- Assorted bug fixes across the pipeline.

## [0.1.0] - 2026-06-01

### Added
- Initial release of the Marlong OSINT engine: plugin-based modular monolith
  with Google dorking, GitHub dorking, and PDF discovery + analysis.
- Common `Finding` schema with enrichment, deduplication, and SQLite storage.
- HTML/PDF report generation and a `--scope` authorisation guardrail.

[0.2.1]: https://github.com/antonlepari/marlong/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/antonlepari/marlong/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/antonlepari/marlong/releases/tag/v0.1.0
