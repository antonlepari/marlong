# Marlong

A modular OSINT engine. Marlong runs **Google dorking**, **GitHub dorking**,
**certificate transparency lookups**, and **PDF discovery + analysis**,
normalises everything into one schema, flags exposed secrets, and produces
HTML/PDF reports.

It is built for **authorised** work: attack-surface review of your own
assets, bug-bounty recon within scope, threat intelligence, and research.

## Architecture

Marlong is a plugin-based **modular monolith** with a clean pipeline. Each
stage is swappable, so it can grow into the full queue/worker/web stack
later without rewrites.

```
                 ┌─────────────┐
   targets  ───▶ │  Pipeline   │  (core/pipeline.py — orchestration)
                 └──────┬──────┘
                        │  for each (target × collector)
          ┌─────────────┼──────────────┬──────────────────┐
          ▼             ▼              ▼                   ▼
   google_dork     github_dork      crtsh            pdf_hunter
   (CSE API)     (Search API)   (crt.sh JSON)   (discover+parse PDFs)
          └─────────────┼──────────────┴──────────────────┘
                        ▼
                  raw Findings  (core/schema.py — one common model)
                        ▼
                 enrich + dedupe  (enrich/normalize.py)
                  · entities: emails, domains, IPs, URLs
                  · secret indicators: AWS/Google/GitHub keys, JWTs,
                    Stripe keys, npm tokens, Telegram bots, private keys…
                        ▼
                 store (storage/db.py — SQLite)
                        ▼
                 report (reporting/report.py — HTML + PDF)
```

**Why this shape:** dorking is rate-limited and bursty, and you will keep
adding sources — so collectors share one interface and one polite HTTP
client, and the schema + enrichment + storage + reporting layers never
need to know which source produced a finding. To scale up, swap the inline
loop in `pipeline.py` for a task queue (Celery/Redis) and the SQLite store
for PostgreSQL + a search index; nothing else changes.

## Collectors

| Name | Credentials required | What it finds |
|---|---|---|
| `crtsh` | None | Subdomains via certificate transparency logs (crt.sh) |
| `pdf_hunter` | None (discovery needs Google keys) | PDF metadata + text leaks |
| `google_dork` | `MARLONG_GOOGLE_API_KEY` + `MARLONG_GOOGLE_CSE_ID` | Exposed files, admin panels, config leaks |
| `github_dork` | `MARLONG_GITHUB_TOKEN` | Secrets committed to public repos |

## Requirements

- Python 3.8+
- Dependencies: `requests`, `pypdf`, `PyYAML`, `reportlab`

## Install

### Linux / macOS

On most Linux/macOS systems `python3` and `pip3` are the correct commands.
Use whichever matches your environment:

```bash
# if your system defaults to Python 3
pip install -r requirements.txt

# if pip points to Python 2 (common on older Linux distros)
pip3 install -r requirements.txt

# if you get a permission error, install for your user only
pip3 install --user -r requirements.txt
```

> **Tip:** check which Python version you have with `python3 --version`.
> Marlong requires Python 3.8 or later.

### Windows

On Windows the launcher is `py` and the interpreter is `python` (there is no
`python3`/`pip3`). Install [Python 3.8+](https://www.python.org/downloads/windows/)
and **tick "Add python.exe to PATH"** in the installer.

```powershell
# check your version (PowerShell or Command Prompt)
py --version

# install dependencies
py -m pip install -r requirements.txt

# if you hit a permission error, install for your user only
py -m pip install --user -r requirements.txt
```

> **Tip:** `py -m pip` is the most reliable form on Windows — it always uses
> the same interpreter `py` runs, even with several Python versions installed.
> A virtual environment avoids permission issues entirely:
>
> ```powershell
> py -m venv .venv
> .\.venv\Scripts\activate
> pip install -r requirements.txt
> ```

## Credentials

Set as environment variables — collectors that lack credentials disable
themselves gracefully:

| Variable | Used by | Where to get it |
|---|---|---|
| `MARLONG_GOOGLE_API_KEY` | google_dork, pdf_hunter | https://developers.google.com/custom-search |
| `MARLONG_GOOGLE_CSE_ID` | google_dork, pdf_hunter | https://programmablesearchengine.google.com |
| `MARLONG_GITHUB_TOKEN` | github_dork | https://github.com/settings/tokens (PAT) |

The Google module uses the **official Programmable Search API**, not page
scraping — scraping google.com violates its Terms of Service and gets
blocked fast.

### Setting the variables

```bash
# Linux / macOS (bash/zsh) — current shell session
export MARLONG_GITHUB_TOKEN="ghp_your_token_here"
export MARLONG_GOOGLE_API_KEY="your_api_key"
export MARLONG_GOOGLE_CSE_ID="your_cse_id"
```

```powershell
# Windows PowerShell — current session
$env:MARLONG_GITHUB_TOKEN = "ghp_your_token_here"
$env:MARLONG_GOOGLE_API_KEY = "your_api_key"
$env:MARLONG_GOOGLE_CSE_ID  = "your_cse_id"

# Windows PowerShell — persist for future sessions (run once)
setx MARLONG_GITHUB_TOKEN "ghp_your_token_here"
```

```bat
:: Windows Command Prompt (cmd.exe) — current session
set MARLONG_GITHUB_TOKEN=ghp_your_token_here
set MARLONG_GOOGLE_API_KEY=your_api_key
set MARLONG_GOOGLE_CSE_ID=your_cse_id
```

> On Windows, `setx` persists the variable but only affects **new** terminals —
> reopen your shell after running it. Never commit tokens to source control.

## Usage

The examples below use `python3` (Linux/macOS). On **Windows** use `py` instead
— e.g. `py -m marlong version`. Use plain `python` if that is what your `PATH`
resolves to.

```bash
# print version and dependency status
python3 -m marlong version

# list collectors and whether they are ready
python3 -m marlong collectors

# scan a domain with every ready collector
python3 -m marlong scan -t example.com

# certificate transparency only (no API key needed)
python3 -m marlong scan -t example.com -c crtsh

# pick collectors, analyse local PDFs, write reports elsewhere
python3 -m marlong scan -t acme.com \
    -c google_dork -c github_dork -c pdf_hunter \
    --pdf ./report.pdf --pdf ./old_leak.pdf \
    -o ./reports

# enforce a scope guardrail (targets outside it are refused)
python3 -m marlong scan -t acme.com --scope "*.acme.com" --scope "acme.com"

# verbose output
python3 -m marlong -v scan -t acme.com -c crtsh
```

Output: a row per finding in SQLite (`marlong.db`) plus
`reports/marlong_report_<id>.html` and `.pdf`.

## Extending: add a collector

```python
from marlong.core.base import BaseCollector, register
from marlong.core.schema import Finding

@register
class MyCollector(BaseCollector):
    name = "my_source"
    description = "One-line description shown in 'collectors' output"

    def available(self) -> bool:
        return bool(self.config.some_credential)

    def collect(self, target):
        # fetch data, then yield Finding objects
        yield Finding(source=self.name, type="web_result", target=target,
                      title="...", url="...", snippet="...")
```

Import it once in `cli.py` and it appears automatically in all commands.

Dork templates live in `marlong/dorks/*.yaml` and use a `{target}`
placeholder — edit them without touching code.

## Responsible use

Only run Marlong against assets you own or are explicitly authorised to
assess. Set `--scope` so the engine refuses anything else. Respect each
provider's Terms of Service and rate limits (handled by the built-in
throttle/backoff). The secret-detection patterns exist so defenders can
find their *own* leaked credentials and rotate them.

## Roadmap ideas

- More collectors: Wayback Machine, Shodan, DNS brute-force, breach-DB lookups
- Task queue (Celery) + worker model for large scans
- PostgreSQL + OpenSearch backends
- FastAPI + React dashboard with an entity-relationship graph view
