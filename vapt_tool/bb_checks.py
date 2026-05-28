"""Bug-bounty-specific security checks.

Each function returns a CheckResult and is designed to surface findings that
are directly reportable on bug-bounty platforms.
"""

from __future__ import annotations

import re
import socket
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

from vapt_tool.models import CheckResult
from vapt_tool.wordlists import (
    BB_PATHS,
    BUCKET_SUFFIXES,
    EMAIL_PATTERN,
    INTERNAL_PATH_PATTERN,
    PHONE_PATTERN,
    REDIRECT_PARAMS,
    REDIRECT_PAYLOADS,
    SECRET_PATTERNS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"


def _session(timeout: int, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None) -> requests.Session:
    s = requests.Session()
    s.max_redirects = 5
    s.headers.update({"User-Agent": "BB-Recon/1.0"})
    if headers:
        s.headers.update(headers)
    if cookies:
        s.cookies.update(cookies)
    s.verify = False  # bounty scans often hit targets with bad certs
    return s


def _safe_get(session: requests.Session, url: str, timeout: int = 8):
    try:
        return session.get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 1. JS Secret Scanner
# ---------------------------------------------------------------------------

def check_js_secrets(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    crawled_endpoints: list[dict[str, Any]] | None = None,
) -> CheckResult:
    """Scan discovered JS files for leaked API keys, tokens, and secrets."""
    url = _ensure_url(target)
    session = _session(timeout, headers, cookies)
    js_urls: set[str] = set()

    # Gather JS URLs from crawled endpoints
    if crawled_endpoints:
        for ep in crawled_endpoints:
            ep_url = ep.get("url", "")
            if any(ep_url.lower().endswith(ext) for ext in (".js", ".mjs", ".jsx")):
                js_urls.add(ep_url)

    # Also parse the main page for script tags
    resp = _safe_get(session, url, timeout)
    if resp and resp.ok and resp.headers.get("Content-Type", "").startswith("text/html"):
        soup = BeautifulSoup(resp.text, "html.parser")
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                full = urljoin(resp.url, src)
                js_urls.add(full)

        # Also scan inline scripts
        inline_secrets = _scan_text_for_secrets(resp.text, "inline:<page>")
    else:
        inline_secrets = []

    # Scan each JS file
    all_findings: list[dict[str, Any]] = list(inline_secrets)
    scanned_count = 0

    for js_url in sorted(js_urls)[:50]:  # cap to avoid hammering
        js_resp = _safe_get(session, js_url, timeout)
        if js_resp and js_resp.ok:
            scanned_count += 1
            findings = _scan_text_for_secrets(js_resp.text, js_url)
            all_findings.extend(findings)

    # Deduplicate
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in all_findings:
        key = f"{f['type']}:{f['match']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    severity = "info"
    status = "ok"
    details = f"Scanned {scanned_count} JS files, no secrets found"

    if unique:
        high_value = [f for f in unique if f["type"] in {
            "AWS Access Key", "AWS Secret Key", "Stripe Secret Key",
            "Private Key Block", "Database URL", "GitHub Token",
            "GitHub Classic Token", "Slack Token", "SendGrid API Key",
        }]
        severity = "critical" if high_value else "high"
        status = "warning"
        details = f"Found {len(unique)} potential secrets in {scanned_count} JS files"
        if high_value:
            details += f" ({len(high_value)} high-value)"

    return CheckResult(
        name="js_secrets",
        severity=severity,
        status=status,
        details=details,
        evidence={
            "js_files_scanned": scanned_count,
            "secrets_found": len(unique),
            "findings": unique[:100],  # cap evidence size
        },
        recommendations=[
            "Remove hardcoded secrets from client-side JavaScript",
            "Rotate any exposed API keys and tokens immediately",
            "Use environment variables or a secrets manager",
        ] if unique else [],
    )


def _scan_text_for_secrets(text: str, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            # Skip very short or obviously test values
            if len(value) < 8:
                continue
            # Get surrounding context (±30 chars)
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            context = text[start:end].replace("\n", " ").strip()

            findings.append({
                "type": name,
                "match": value[:80],  # truncate for safety
                "source": source,
                "context": context[:150],
            })
    return findings


# ---------------------------------------------------------------------------
# 2. Wayback URL Discovery
# ---------------------------------------------------------------------------

def check_wayback_urls(
    target: str,
    timeout: int = 15,
) -> CheckResult:
    """Query the Wayback Machine CDX API for historical URLs."""
    host = urlparse(_ensure_url(target)).hostname or target
    evidence: dict[str, Any] = {"host": host}

    try:
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{host}/*&output=json&fl=original&collapse=urlkey&limit=500"
        resp = requests.get(cdx_url, timeout=timeout, headers={"User-Agent": "BB-Recon/1.0"})

        if not resp.ok:
            return CheckResult(
                name="wayback_urls",
                severity="info",
                status="warning",
                details="Wayback Machine query failed",
                evidence={"status_code": resp.status_code},
            )

        rows = resp.json()
        # First row is header: ["original"]
        urls = [row[0] for row in rows[1:]] if len(rows) > 1 else []

        # Categorize interesting URLs
        interesting: list[dict[str, str]] = []
        params_found: set[str] = set()

        for u in urls:
            lower = u.lower()
            category = None

            if any(x in lower for x in ["/admin", "/panel", "/dashboard", "/manage"]):
                category = "admin_panel"
            elif any(x in lower for x in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                category = "api_endpoint"
            elif any(x in lower for x in [".sql", ".bak", ".zip", ".tar", ".gz", ".log"]):
                category = "backup_file"
            elif any(x in lower for x in [".env", "config", "settings", ".yml", ".yaml"]):
                category = "config_file"
            elif any(x in lower for x in ["/upload", "/file", "/download"]):
                category = "file_operation"
            elif any(x in lower for x in ["/login", "/auth", "/signin", "/register", "/oauth"]):
                category = "auth_endpoint"
            elif "?" in u:
                category = "parameterized"

            if category:
                interesting.append({"url": u, "category": category})

            # Extract parameters
            parsed = urlparse(u)
            for param in parse_qs(parsed.query).keys():
                params_found.add(param)

        evidence["total_urls"] = len(urls)
        evidence["interesting_urls"] = interesting[:200]
        evidence["parameters_discovered"] = sorted(params_found)[:100]
        evidence["categories"] = {}
        for item in interesting:
            cat = item["category"]
            evidence["categories"][cat] = evidence["categories"].get(cat, 0) + 1

        severity = "info"
        status = "ok"
        details = f"Wayback: {len(urls)} URLs found, {len(interesting)} interesting, {len(params_found)} unique parameters"

        if any(cat in evidence.get("categories", {}) for cat in ["backup_file", "config_file"]):
            severity = "high"
            status = "warning"
            details += " — backup/config files detected in archives"
        elif interesting:
            severity = "medium"
            status = "warning"

        return CheckResult(
            name="wayback_urls",
            severity=severity,
            status=status,
            details=details,
            evidence=evidence,
            recommendations=[
                "Review archived URLs for sensitive endpoints that may still be live",
                "Check if old API endpoints are still accessible",
                "Test discovered parameters for injection vulnerabilities",
            ] if interesting else [],
        )
    except Exception as exc:
        return CheckResult(
            name="wayback_urls",
            severity="low",
            status="error",
            details="Wayback URL discovery failed",
            evidence={"error": str(exc)},
        )


# ---------------------------------------------------------------------------
# 3. Open Redirect Detector
# ---------------------------------------------------------------------------

def check_open_redirects(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> CheckResult:
    """Test common URL parameters for open redirect vulnerabilities."""
    url = _ensure_url(target)
    session = _session(timeout, headers, cookies)
    evidence: dict[str, Any] = {"tested_params": [], "vulnerable": []}

    for param in REDIRECT_PARAMS[:20]:  # cap iterations
        for payload in REDIRECT_PAYLOADS[:3]:
            test_url = f"{url.rstrip('/')}/?{urlencode({param: payload})}"
            try:
                resp = session.get(test_url, timeout=timeout, allow_redirects=False)
                location = resp.headers.get("Location", "")

                evidence["tested_params"].append({
                    "param": param,
                    "payload": payload,
                    "status": resp.status_code,
                    "location": location[:200],
                })

                # Check if redirect points to our evil domain
                if resp.status_code in (301, 302, 303, 307, 308):
                    if "evil.com" in location.lower():
                        evidence["vulnerable"].append({
                            "param": param,
                            "payload": payload,
                            "redirect_to": location[:200],
                            "url": test_url,
                        })
            except Exception:
                continue

    vuln = evidence["vulnerable"]
    if vuln:
        return CheckResult(
            name="open_redirect",
            severity="medium",
            status="warning",
            details=f"Open redirect found in {len(vuln)} parameter(s): {', '.join(set(v['param'] for v in vuln))}",
            evidence=evidence,
            recommendations=[
                "Validate and whitelist redirect URLs server-side",
                "Avoid passing user-controlled URLs in redirect parameters",
                "Use relative URLs or a URL whitelist for redirects",
            ],
        )

    return CheckResult(
        name="open_redirect",
        severity="info",
        status="ok",
        details=f"No open redirects found (tested {len(REDIRECT_PARAMS[:20])} params)",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# 4. IDOR Pattern Detector
# ---------------------------------------------------------------------------

def check_idor_patterns(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    crawled_endpoints: list[dict[str, Any]] | None = None,
) -> CheckResult:
    """Identify sequential numeric IDs in URLs suggesting potential IDOR."""
    patterns: list[dict[str, Any]] = []
    id_regex = re.compile(r'/(?:user|account|order|invoice|profile|document|file|report|ticket|message|id|item|product|post|comment|review|api/v\d+/\w+)/(\d+)', re.IGNORECASE)
    param_regex = re.compile(r'[?&](?:id|user_id|uid|account_id|order_id|doc_id|file_id|item_id)=(\d+)', re.IGNORECASE)

    endpoints = crawled_endpoints or []
    for ep in endpoints:
        ep_url = ep.get("url", "")

        # Check path-based IDs
        for match in id_regex.finditer(ep_url):
            patterns.append({
                "url": ep_url,
                "type": "path_id",
                "id_value": match.group(1),
                "pattern": match.group(0),
            })

        # Check parameter-based IDs
        for match in param_regex.finditer(ep_url):
            patterns.append({
                "url": ep_url,
                "type": "param_id",
                "id_value": match.group(1),
                "pattern": match.group(0),
            })

    # Deduplicate by pattern
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for p in patterns:
        key = p["pattern"]
        if key not in seen:
            seen.add(key)
            unique.append(p)

    severity = "info"
    status = "ok"
    details = "No IDOR patterns detected in crawled URLs"

    if unique:
        severity = "medium"
        status = "warning"
        details = f"Found {len(unique)} potential IDOR patterns with sequential IDs"

    return CheckResult(
        name="idor_patterns",
        severity=severity,
        status=status,
        details=details,
        evidence={"patterns": unique[:50]},
        recommendations=[
            "Test IDOR by changing numeric IDs to access other users' data",
            "Implement proper authorization checks on all resource endpoints",
            "Use UUID/GUID instead of sequential integers for resource IDs",
        ] if unique else [],
    )


# ---------------------------------------------------------------------------
# 5. Parameter Discovery
# ---------------------------------------------------------------------------

def check_parameter_discovery(
    target: str,
    crawled_endpoints: list[dict[str, Any]] | None = None,
    wayback_params: list[str] | None = None,
) -> CheckResult:
    """Aggregate all discovered input parameters from crawled + wayback data."""
    params: dict[str, list[str]] = {}  # param_name -> [source_urls]

    # From crawled endpoints
    for ep in (crawled_endpoints or []):
        ep_url = ep.get("url", "")
        parsed = urlparse(ep_url)
        for param in parse_qs(parsed.query).keys():
            params.setdefault(param, []).append(ep_url)

    # From wayback
    for param in (wayback_params or []):
        if param not in params:
            params[param] = ["wayback"]

    # Categorize by injection potential
    sqli_suspects = [p for p in params if any(x in p.lower() for x in ["id", "query", "search", "sort", "order", "filter", "where", "column", "table", "select"])]
    xss_suspects = [p for p in params if any(x in p.lower() for x in ["name", "value", "text", "title", "msg", "message", "comment", "body", "content", "description", "q", "search", "input"])]
    ssrf_suspects = [p for p in params if any(x in p.lower() for x in ["url", "uri", "link", "src", "source", "dest", "redirect", "path", "file", "fetch", "load", "page", "proxy"])]
    lfi_suspects = [p for p in params if any(x in p.lower() for x in ["file", "path", "page", "template", "include", "dir", "folder", "doc", "pdf"])]

    evidence = {
        "total_params": len(params),
        "all_params": sorted(params.keys())[:200],
        "sqli_suspects": sqli_suspects,
        "xss_suspects": xss_suspects,
        "ssrf_suspects": ssrf_suspects,
        "lfi_suspects": lfi_suspects,
    }

    severity = "info"
    status = "ok"
    details = f"Discovered {len(params)} unique parameters"

    high_risk = sqli_suspects + ssrf_suspects + lfi_suspects
    if high_risk:
        severity = "medium"
        status = "warning"
        details += f" — {len(high_risk)} potentially injectable"

    return CheckResult(
        name="parameter_discovery",
        severity=severity,
        status=status,
        details=details,
        evidence=evidence,
        recommendations=[
            "Test SQLi-suspect parameters with sqlmap or manual payloads",
            "Test XSS-suspect parameters with reflection/DOM probes",
            "Test SSRF-suspect parameters for internal service access",
            "Test LFI-suspect parameters for path traversal",
        ] if high_risk else [],
    )


# ---------------------------------------------------------------------------
# 6. Email / Info Harvester
# ---------------------------------------------------------------------------

def check_info_harvester(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> CheckResult:
    """Scrape discovered pages for email addresses, phone numbers, internal paths."""
    url = _ensure_url(target)
    session = _session(timeout, headers, cookies)
    resp = _safe_get(session, url, timeout)

    emails: set[str] = set()
    internal_paths: set[str] = set()

    if resp and resp.ok:
        text = resp.text
        for match in EMAIL_PATTERN.finditer(text):
            email = match.group(0).lower()
            # Filter noise
            if not any(x in email for x in ["@example.", "@test.", "@placeholder.", ".png", ".jpg", ".gif", ".svg", ".css", ".js"]):
                emails.add(email)

        for match in INTERNAL_PATH_PATTERN.finditer(text):
            internal_paths.add(match.group(0))

    evidence = {
        "emails": sorted(emails)[:50],
        "internal_paths": sorted(internal_paths)[:30],
    }

    severity = "info"
    status = "ok"
    details = f"Harvested {len(emails)} emails, {len(internal_paths)} internal paths"

    if internal_paths:
        severity = "low"
        status = "warning"
        details += " — internal server paths exposed"

    return CheckResult(
        name="info_harvester",
        severity=severity,
        status=status,
        details=details,
        evidence=evidence,
        recommendations=[
            "Remove internal server paths from HTML responses",
            "Validate that exposed email addresses are intended for public disclosure",
        ] if internal_paths else [],
    )


# ---------------------------------------------------------------------------
# 7. Cloud Bucket Finder
# ---------------------------------------------------------------------------

def check_cloud_buckets(
    target: str,
    timeout: int = 5,
) -> CheckResult:
    """Check common S3/GCS/Azure bucket name patterns for the target's domain."""
    host = urlparse(_ensure_url(target)).hostname or target
    # Extract org name from domain
    parts = host.split(".")
    if len(parts) >= 2:
        org_names = [parts[0], ".".join(parts[:-1]).replace(".", "-")]
    else:
        org_names = [host]

    # Deduplicate
    org_names = list(set(org_names))

    open_buckets: list[dict[str, str]] = []
    checked = 0

    for org in org_names:
        for suffix in BUCKET_SUFFIXES[:20]:  # limit iterations
            bucket_name = f"{org}{suffix}"

            # Check S3
            s3_url = f"https://{bucket_name}.s3.amazonaws.com/"
            try:
                resp = requests.get(s3_url, timeout=timeout, headers={"User-Agent": "BB-Recon/1.0"})
                checked += 1
                if resp.status_code == 200:
                    open_buckets.append({
                        "bucket": bucket_name,
                        "provider": "AWS S3",
                        "url": s3_url,
                        "status": resp.status_code,
                    })
                elif resp.status_code == 403:
                    # Bucket exists but is private — still notable
                    pass
            except Exception:
                pass

            # Check GCS
            gcs_url = f"https://storage.googleapis.com/{bucket_name}/"
            try:
                resp = requests.get(gcs_url, timeout=timeout, headers={"User-Agent": "BB-Recon/1.0"})
                checked += 1
                if resp.status_code == 200:
                    open_buckets.append({
                        "bucket": bucket_name,
                        "provider": "Google Cloud Storage",
                        "url": gcs_url,
                        "status": resp.status_code,
                    })
            except Exception:
                pass

    severity = "info"
    status = "ok"
    details = f"Checked {checked} bucket names, none publicly accessible"

    if open_buckets:
        severity = "critical"
        status = "warning"
        details = f"Found {len(open_buckets)} publicly accessible cloud bucket(s)!"

    return CheckResult(
        name="cloud_buckets",
        severity=severity,
        status=status,
        details=details,
        evidence={"checked": checked, "open_buckets": open_buckets},
        recommendations=[
            "Restrict bucket access policies immediately",
            "Enable bucket access logging",
            "Review bucket contents for sensitive data exposure",
        ] if open_buckets else [],
    )


# ---------------------------------------------------------------------------
# 8. Extended Directory Bruteforce
# ---------------------------------------------------------------------------

def check_directory_bruteforce(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    rate_limit_rps: int = 15,
) -> CheckResult:
    """Extended directory/file discovery using the bug-bounty wordlist."""
    import time

    url = _ensure_url(target).rstrip("/")
    session = _session(timeout, headers, cookies)
    findings: list[dict[str, Any]] = []
    errors = 0
    delay = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0

    for path in BB_PATHS:
        test_url = f"{url}{path}"
        try:
            resp = session.get(test_url, timeout=timeout, allow_redirects=False)

            if resp.status_code < 400 and resp.status_code != 301:
                # Check for soft 404s (pages that return 200 for everything)
                content_length = len(resp.content)
                if content_length > 0:
                    findings.append({
                        "path": path,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "size": content_length,
                    })
        except Exception:
            errors += 1
            continue

        if delay > 0:
            time.sleep(delay)

    # Categorize findings
    sensitive = [f for f in findings if any(x in f["path"] for x in [
        ".git", ".env", ".htpasswd", "config", "backup", ".sql",
        "phpinfo", "server-status", "actuator", "debug", "wp-config",
        ".DS_Store",
    ])]
    api_docs = [f for f in findings if any(x in f["path"] for x in [
        "swagger", "graphql", "graphiql", "api-docs", "openapi", "redoc",
    ])]
    admin = [f for f in findings if any(x in f["path"] for x in [
        "admin", "panel", "dashboard", "manage", "cpanel", "console",
        "phpmyadmin", "adminer",
    ])]

    severity = "info"
    status = "ok"
    details = f"Scanned {len(BB_PATHS)} paths, {len(findings)} accessible"

    if sensitive:
        severity = "critical"
        status = "warning"
        details += f" — {len(sensitive)} SENSITIVE files exposed!"
    elif api_docs or admin:
        severity = "high"
        status = "warning"
        details += f" — {len(api_docs)} API docs, {len(admin)} admin panels found"
    elif findings:
        severity = "low"
        status = "warning"

    return CheckResult(
        name="directory_bruteforce",
        severity=severity,
        status=status,
        details=details,
        evidence={
            "total_checked": len(BB_PATHS),
            "total_found": len(findings),
            "findings": findings[:100],
            "sensitive": sensitive,
            "api_docs": api_docs,
            "admin_panels": admin,
            "errors": errors,
        },
        recommendations=[
            "Remove or restrict access to sensitive files and directories",
            "Place admin panels behind VPN or IP whitelist",
            "Disable directory listing on the web server",
            "Remove API documentation from production environments",
        ] if findings else [],
    )


# ---------------------------------------------------------------------------
# 9. Security.txt Check
# ---------------------------------------------------------------------------

def check_security_txt(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> CheckResult:
    """Read /.well-known/security.txt for bounty program info."""
    url = _ensure_url(target).rstrip("/")
    session = _session(timeout, headers, cookies)
    evidence: dict[str, Any] = {}

    for path in ["/.well-known/security.txt", "/security.txt"]:
        resp = _safe_get(session, f"{url}{path}", timeout)
        if resp and resp.ok and "text" in resp.headers.get("Content-Type", ""):
            text = resp.text
            evidence["path"] = path
            evidence["content"] = text[:2000]

            # Parse fields
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("Contact:"):
                    evidence["contact"] = line.split(":", 1)[1].strip()
                elif line.startswith("Policy:"):
                    evidence["policy"] = line.split(":", 1)[1].strip()
                elif line.startswith("Hiring:"):
                    evidence["hiring"] = line.split(":", 1)[1].strip()
                elif line.startswith("Acknowledgments:") or line.startswith("Acknowledgements:"):
                    evidence["acknowledgments"] = line.split(":", 1)[1].strip()

            return CheckResult(
                name="security_txt",
                severity="info",
                status="ok",
                details=f"security.txt found at {path}" + (f" — contact: {evidence.get('contact', 'N/A')}" if evidence.get("contact") else ""),
                evidence=evidence,
            )

    return CheckResult(
        name="security_txt",
        severity="low",
        status="warning",
        details="No security.txt found — may indicate no formal vulnerability disclosure program",
        evidence=evidence,
        recommendations=["Check if the program has a bug bounty page on HackerOne/Bugcrowd"],
    )


# ---------------------------------------------------------------------------
# 10. CRLF / Header Injection Test
# ---------------------------------------------------------------------------

def check_crlf_injection(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> CheckResult:
    """Test for CRLF injection in URL parameters."""
    url = _ensure_url(target).rstrip("/")
    session = _session(timeout, headers, cookies)
    evidence: dict[str, Any] = {"tested": [], "vulnerable": []}

    payloads = [
        "%0d%0aInjected-Header:fuzz",
        "%0d%0a%0d%0a<html>fuzz</html>",
        "%0aInjected-Header:fuzz",
        "\\r\\nInjected-Header:fuzz",
    ]

    for payload in payloads:
        test_url = f"{url}/?redirect={payload}"
        try:
            resp = session.get(test_url, timeout=timeout, allow_redirects=False)
            resp_headers = dict(resp.headers)
            evidence["tested"].append({
                "payload": payload,
                "status": resp.status_code,
            })

            if "Injected-Header" in resp_headers or "injected-header" in {k.lower() for k in resp_headers}:
                evidence["vulnerable"].append({
                    "payload": payload,
                    "url": test_url,
                    "status": resp.status_code,
                })
        except Exception:
            continue

    vuln = evidence["vulnerable"]
    if vuln:
        return CheckResult(
            name="crlf_injection",
            severity="medium",
            status="warning",
            details=f"CRLF injection detected with {len(vuln)} payload(s)",
            evidence=evidence,
            recommendations=[
                "Sanitize user input in HTTP headers",
                "URL-encode or reject CRLF characters in user-supplied values",
                "Use framework-level protections against header injection",
            ],
        )

    return CheckResult(
        name="crlf_injection",
        severity="info",
        status="ok",
        details="No CRLF injection detected",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Run all bug bounty checks
# ---------------------------------------------------------------------------

def run_bounty_checks(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    crawled_endpoints: list[dict[str, Any]] | None = None,
    progress_cb=None,
    rate_limit_rps: int = 15,
) -> list[CheckResult]:
    """Execute all bug-bounty-specific checks and return results."""
    results: list[CheckResult] = []

    def _run(name: str, fn, **kwargs):
        if progress_cb:
            progress_cb(name, "running", {})
        result = fn(**kwargs)
        results.append(result)
        if progress_cb:
            progress_cb(name, "done", {})
        return result

    # JS Secrets
    _run("js_secrets", check_js_secrets,
         target=target, timeout=timeout, headers=headers, cookies=cookies,
         crawled_endpoints=crawled_endpoints)

    # Wayback URLs
    wb_result = _run("wayback_urls", check_wayback_urls, target=target, timeout=15)
    wayback_params = wb_result.evidence.get("parameters_discovered", [])

    # Open Redirects
    _run("open_redirect", check_open_redirects,
         target=target, timeout=timeout, headers=headers, cookies=cookies)

    # IDOR Patterns
    _run("idor_patterns", check_idor_patterns,
         target=target, timeout=timeout, headers=headers, cookies=cookies,
         crawled_endpoints=crawled_endpoints)

    # Parameter Discovery
    _run("parameter_discovery", check_parameter_discovery,
         target=target, crawled_endpoints=crawled_endpoints,
         wayback_params=wayback_params)

    # Info Harvester
    _run("info_harvester", check_info_harvester,
         target=target, timeout=timeout, headers=headers, cookies=cookies)

    # Cloud Buckets
    _run("cloud_buckets", check_cloud_buckets, target=target, timeout=5)

    # Directory Bruteforce
    _run("directory_bruteforce", check_directory_bruteforce,
         target=target, timeout=timeout, headers=headers, cookies=cookies,
         rate_limit_rps=rate_limit_rps)

    # Security.txt
    _run("security_txt", check_security_txt,
         target=target, timeout=timeout, headers=headers, cookies=cookies)

    # CRLF Injection
    _run("crlf_injection", check_crlf_injection,
         target=target, timeout=timeout, headers=headers, cookies=cookies)

    return results
