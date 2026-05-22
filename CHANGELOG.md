# Changelog

## [v1.0.0] — Current Release

### Bug Fixes
- **CRITICAL** `--commands`, `--list-modules`, `--list-profiles`, `--preflight`, `--db-stats` all
  returned `Error: Missing argument 'TARGET'` — fixed by making TARGET optional and handling
  all standalone flags before Click argument validation
- **CRITICAL** `return_headers=True` not supported in `fetch()` — caused `KeyError` crashes
  in WAF, CORS, headers, CMS, and S3 bucket modules. Rebuilt `http_client.py` to support it.
- **CRITICAL** `extra_headers={}` param not supported — CORS module probes were silently
  sending wrong origins. Added to `fetch()` signature.
- `twitter`, `zoomeye`, `masscan` missing from their module groups — now included
- Progress bar used old emoji symbols `⚠ ℹ ✔ ✘` — replaced with professional `[*][+][!][-]`

### New Modules (5)
- **`waf`** — WAF/CDN fingerprinting: 15+ vendors, 4 detection vectors, per-WAF bypass hints
- **`headers`** — HTTP security headers audit: OWASP grade A+–F, cookie flags, info disclosure
- **`cors`** — CORS scanner: 10 bypass techniques + PoC JS exploit per vulnerability
- **`cms`** — CMS detection: WordPress/Drupal/Joomla/Django/Laravel/Spring + 7 more, version extraction
- **`s3buckets`** — Cloud bucket finder: AWS S3, GCS, Azure Blob, DigitalOcean Spaces

### New Profiles (6)
- `red_team` — 38-module complete attack surface mapping
- `bug_bounty` — 22-module bug bounty focused
- `passive_recon` — 20-module 100% passive, OPSEC safe
- `web_audit` — 14-module web security audit
- `social_eng` — 12-module social engineering prep

### Infrastructure
- `http_client.py` — Rebuilt: `return_headers`, `extra_headers`, proper error dict
- `logger.py` — Rebuilt: Sliver-style `[*][+][!][-][>]` with `HH:MM:SS` timestamps
- `engine.py` — Progress bar upgraded: `HH:MM:SS [+] [02/20] [████░░░░] 45% name results elapsed`
- `cli.py` — Full rewrite: `--commands` full reference, standalone flags fixed, clean Sliver output
- `module_guide.py` — Full rewrite: all 53 modules documented with sources, output fields, pentest tips
- `requirements.txt` — Complete: all transitive deps included
- `.env.example` — 35+ keys documented: `ZOOMEYE_API_KEY`, `INTELX_API_KEY`, webhooks, proxy
- `install.sh` — One-command installer with venv support
- `.github/workflows/ci.yml` — GitHub Actions CI: syntax check + CLI flag tests on Python 3.10/11/12
- `tests/test_cli.py` — Tests every standalone flag
- `CONTRIBUTING.md` — Module template + code style guide
- `pyproject.toml` — Production-ready build config

### Total
- **80 Python files · 0 syntax errors · 53 modules · 13 profiles**
