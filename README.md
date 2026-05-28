# VAPT Bug Bounty Power Toolkit

An all-in-one Python CLI + React dashboard for **efficient bug bounty hunting** on authorized targets. Built to maximize your chance of finding and reporting **real, bounty-worthy vulnerabilities**.

## 🔥 What Makes This Different

This isn't just a scanner — it's a complete **bug bounty workflow tool**:

- **10 bounty-focused checks** that surface findings worth money (JS secrets, open redirects, IDOR, cloud buckets, etc.)
- **Concurrent scanning engine** — 3-5x faster than sequential scanning
- **Program management** — store your HackerOne/Bugcrowd programs with scope and bounty tables
- **Auto-generated submission reports** — formatted for direct platform submission
- **Premium dark-mode dashboard** — visualize findings, estimate bounties, copy reports with one click

## What It Checks

### Standard Checks (17)
- DNS records (A, AAAA, MX, NS, TXT, CNAME) + SPF/DMARC validation
- WHOIS metadata and domain expiry risk
- SSL certificate presence, expiry, and cipher info
- HTTP security headers (HSTS, CSP, XFO, X-Content-Type-Options, etc.)
- Enabled HTTP methods from OPTIONS responses
- Common path exposure (`.git/HEAD`, `.env`, `/phpinfo.php`, etc.)
- Extended sensitive path detection (16 paths)
- CORS misconfiguration and cookie flag analysis
- TLS version checks (1.0/1.1/1.2/1.3)
- Technology fingerprinting (WordPress, React, Angular, server banners)
- Endpoint discovery crawler (configurable depth + page limits)
- Open port scanning (18 common ports)
- Subdomain enumeration via certificate transparency
- Subdomain takeover heuristics for dangling CNAMEs
- CVE enrichment from NVD for detected service fingerprints
- Optional Nuclei template scanning
- Optional ZAP passive alert integration

### 🐛 Bug Bounty Checks (10) — `--mode bounty`
- **JS Secret Scanner** — scans JS files for 32 secret patterns (AWS keys, Stripe, GitHub tokens, JWTs, private keys, database URLs, etc.)
- **Wayback URL Discovery** — queries Wayback Machine for historical URLs, finds hidden endpoints and forgotten APIs
- **Open Redirect Detection** — tests 20+ common redirect parameters with 6 payloads
- **IDOR Pattern Detection** — identifies sequential numeric IDs in URLs suggesting authorization bypass opportunities
- **Parameter Discovery** — aggregates all input parameters and categorizes them by injection type (SQLi, XSS, SSRF, LFI)
- **Info Harvester** — scrapes pages for leaked email addresses and internal server paths
- **Cloud Bucket Finder** — checks S3 and GCS bucket name patterns for public access
- **Extended Directory Bruteforce** — 195-path bug bounty wordlist covering admin panels, API docs, backups, configs, source maps
- **Security.txt Analysis** — reads vulnerability disclosure policy info
- **CRLF / Header Injection** — tests for HTTP header injection via URL parameters

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Quick Start

### Standard scan:
```bash
python -m vapt_tool --target example.com
```

### 🐛 Bug bounty scan (runs all extended checks):
```bash
python -m vapt_tool --target example.com --mode bounty
```

### Concurrent scan with 16 threads:
```bash
python -m vapt_tool --target example.com --mode bounty --workers 16
```

### Rate-limited scan (avoid blocking):
```bash
python -m vapt_tool --target example.com --mode bounty --rate-limit 5
```

## Program Management

### Add a program:
```bash
python -m vapt_tool --add-program
```

### List saved programs:
```bash
python -m vapt_tool --list-programs
```

### Scan all in-scope targets from a program:
```bash
python -m vapt_tool --scan-program "Example Corp"
```

## Report Formats

### Generate bounty submission report:
```bash
python -m vapt_tool --target example.com --mode bounty --format json,md,bounty
```

This creates:
- `target.json` — full machine-readable report
- `target.md` — human-readable report
- `target_bounty.md` — **HackerOne/Bugcrowd-ready submission report** with:
  - Executive summary with estimated bounty ranges
  - Per-finding: Title, Severity, Impact, Steps to Reproduce, Evidence, Remediation
  - Sorted by severity (critical first)

## Authenticated Scanning

```bash
python -m vapt_tool --target app.example.com \
    --auth-header "X-Org-ID:acme" \
    --cookie "sessionid=abc123" \
    --bearer-token "eyJ..."
```

### Authenticated crawl with login:
```bash
python -m vapt_tool --target example.com \
    --auth-login-url "https://example.com/login" \
    --auth-login-method POST \
    --auth-login-form "username=demo&password=secret"
```

## React Dashboard

The dashboard provides a premium dark-mode interface with 4 tabs:

```bash
cd dashboard
npm install
npm run dev
```

py -m uvicorn vapt_tool.server:app --reload

### Tabs:
- 📊 **Dashboard** — KPI cards, severity chart, bounty estimator, target-by-target findings with severity filtering
- 🔍 **Scan** — Run scans from the UI with Standard/Bounty mode toggle, all configuration options
- 🏆 **Programs** — Manage bug bounty programs (add, delete, scan)
- 🔑 **Secrets** — Dedicated viewer for leaked secrets with copy-to-clipboard

### Run scans from the UI:
```bash
py -m pip install -r requirements.txt
py -m uvicorn vapt_tool.server:app --reload
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan/start` | Start a scan (supports `mode: bounty`) |
| GET | `/scan/status/{job_id}` | Poll scan progress |
| GET | `/programs` | List saved programs |
| POST | `/programs` | Add a new program |
| DELETE | `/programs/{name}` | Delete a program |
| POST | `/reports/finding` | Generate copy-paste report for a finding |

## CLI Reference

```
python -m vapt_tool [options]

Target Selection:
  --target TARGET           Single target (domain, IP, or URL)
  --targets-file FILE       File with one target per line
  --scope-file FILE         Scope file (prefix with ! for exclusions)
  --strict-scope            Skip out-of-scope targets

Scan Mode:
  --mode {standard,bounty}  Scan mode (default: standard)
  --workers N               Concurrent threads (default: 8)
  --rate-limit N            Max requests/second for bruteforce (default: 15)

Output:
  --out-dir DIR             Output directory (default: reports)
  --format FORMATS          Report formats: json,md,bounty (default: json,md)

Program Management:
  --scan-program NAME       Scan all targets from a saved program
  --add-program             Interactively add a program
  --list-programs           Show saved programs

Authentication:
  --auth-header KEY:VALUE   Custom header (repeatable)
  --cookie KEY=VALUE        Cookie (repeatable)
  --bearer-token TOKEN      Bearer token
  --auth-login-url URL      Login endpoint
  --auth-login-method POST  Login HTTP method
  --auth-login-form DATA    Login form payload
  --auth-login-json JSON    Login JSON payload

Integrations:
  --enable-nuclei           Enable Nuclei scan
  --nuclei-severity LEVELS  Nuclei severities
  --zap-base-url URL        ZAP API base URL
```

## Notes and Limitations

- Use this tool **only on assets you own or have explicit written permission to test**
- Unauthorized scanning is illegal and unethical
- Port checks use a common port list and are not a full-range scan
- CVE enrichment uses fingerprint-based matching and may include false positives
- Takeover detection is heuristic and should be confirmed manually
- JS secret scanning may produce false positives — always validate before reporting
- Cloud bucket checking generates external requests; be aware of rate limits
- Bounty mode generates significantly more HTTP requests than standard mode
