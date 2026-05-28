from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
import ipaddress
import json
import subprocess
from html import unescape

import dns.exception
import dns.resolver
import requests
import urllib3
import whois
from bs4 import BeautifulSoup
from requests.exceptions import SSLError
from urllib3.exceptions import InsecureRequestWarning

from vapt_tool.models import CheckResult

COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    6379,
    8080,
    8443,
]

PORT_SERVICE_FINGERPRINTS = {
    21: "ftp",
    22: "openssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
}

TAKEOVER_CNAME_HINTS = {
    "github.io": "Potential dangling GitHub Pages record",
    "herokuapp.com": "Potential dangling Heroku app DNS record",
    "azurewebsites.net": "Potential dangling Azure App Service DNS record",
    "cloudfront.net": "Potential dangling CloudFront distribution DNS record",
    "fastly.net": "Potential dangling Fastly DNS record",
    "surge.sh": "Potential dangling Surge domain DNS record",
    "readthedocs.io": "Potential dangling ReadTheDocs DNS record",
}

urllib3.disable_warnings(InsecureRequestWarning)


def ensure_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"


def resolve_ips(target: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(target, None)
        return sorted({item[4][0] for item in infos})
    except socket.gaierror:
        return []


def check_dns_records(target: str) -> CheckResult:
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    evidence: dict[str, Any] = {}
    issues: list[str] = []

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype, lifetime=4.0)
            evidence[rtype] = [ans.to_text() for ans in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            evidence[rtype] = []
        except dns.exception.DNSException as exc:
            evidence[rtype] = [f"error: {exc}"]

    txt_records = " ".join(evidence.get("TXT", []))
    if "v=spf1" not in txt_records:
        issues.append("SPF record not detected")
    if "v=DMARC1" not in txt_records:
        issues.append("DMARC record not detected")

    status = "ok" if not issues else "warning"
    severity = "low" if issues else "info"
    details = "DNS records collected"
    if issues:
        details += "; " + ", ".join(issues)

    return CheckResult(
        name="dns_records",
        severity=severity,
        status=status,
        details=details,
        evidence=evidence,
        recommendations=[
            "Configure SPF, DKIM, and DMARC for domain email protection",
        ]
        if issues
        else [],
    )


def check_whois(target: str) -> CheckResult:
    try:
        data = whois.whois(target)
        expiration = data.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        evidence = {
            "domain_name": str(data.domain_name),
            "registrar": str(data.registrar),
            "creation_date": str(data.creation_date),
            "expiration_date": str(expiration),
            "name_servers": [str(x) for x in (data.name_servers or [])],
        }

        recommendations: list[str] = []
        status = "ok"
        severity = "info"
        details = "WHOIS data collected"

        if isinstance(expiration, datetime):
            days_left = (expiration.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            evidence["days_to_expiry"] = days_left
            if days_left < 30:
                status = "warning"
                severity = "medium"
                details = f"Domain expires in {days_left} days"
                recommendations.append("Renew domain registration immediately")

        return CheckResult(
            name="whois_info",
            severity=severity,
            status=status,
            details=details,
            evidence=evidence,
            recommendations=recommendations,
        )
    except Exception as exc:
        return CheckResult(
            name="whois_info",
            severity="low",
            status="error",
            details="WHOIS lookup failed",
            evidence={"error": str(exc)},
        )


def check_ssl_certificate(target: str) -> CheckResult:
    evidence: dict[str, Any] = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

        not_after = cert.get("notAfter")
        expiry = None
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

        evidence = {
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "version": cert.get("version"),
            "serialNumber": cert.get("serialNumber"),
            "notBefore": cert.get("notBefore"),
            "notAfter": cert.get("notAfter"),
            "cipher": cipher,
        }

        status = "ok"
        severity = "info"
        details = "SSL certificate is present"
        recommendations: list[str] = []

        if expiry is not None:
            days = (expiry - datetime.now(timezone.utc)).days
            evidence["days_to_expiry"] = days
            if days < 15:
                status = "warning"
                severity = "high"
                details = f"SSL certificate expires in {days} days"
                recommendations.append("Renew SSL certificate")

        return CheckResult(
            name="ssl_certificate",
            severity=severity,
            status=status,
            details=details,
            evidence=evidence,
            recommendations=recommendations,
        )
    except Exception as exc:
        return CheckResult(
            name="ssl_certificate",
            severity="medium",
            status="error",
            details="SSL inspection failed",
            evidence={"error": str(exc)},
            recommendations=["Ensure HTTPS is enabled and certificate is valid"],
        )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _http_session(timeout: int, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None) -> requests.Session:
    s = requests.Session()
    s.max_redirects = 5
    s.headers.update({"User-Agent": "VAPT-Tool/0.1"})
    if headers:
        s.headers.update(headers)
    if cookies:
        s.cookies.update(cookies)
    s.request = _wrap_with_timeout(s.request, timeout)
    return s


def _wrap_with_timeout(func, timeout: int):
    def call(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout)
        kwargs.setdefault("allow_redirects", True)
        return func(method, url, **kwargs)

    return call


def _request_with_tls_fallback(session: requests.Session, method: str, url: str):
    try:
        resp = session.request(method, url, verify=True)
        return resp, False
    except SSLError:
        # Some environments have incomplete trust stores; continue with explicit flag.
        resp = session.request(method, url, verify=False)
        return resp, True


def _safe_request(session: requests.Session, method: str, url: str):
    resp, insecure_tls = _request_with_tls_fallback(session, method, url)
    return resp, insecure_tls


def _normalize_url(url: str) -> str:
    return url.split("#", 1)[0]


def _same_host(url: str, base_host: str) -> bool:
    return urlparse(url).hostname == base_host


def _extract_links(html: str, base_url: str) -> list[str]:
    links: list[str] = []
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(["a", "link", "script", "img", "form"]):
        attr = "href" if tag.name in {"a", "link"} else "src"
        if tag.name == "form":
            attr = "action"
        value = tag.get(attr)
        if not value:
            continue
        value = unescape(value)
        if value.startswith("javascript:") or value.startswith("mailto:"):
            continue
        links.append(requests.compat.urljoin(base_url, value))
    return links


def crawl_endpoints(
    target: str,
    timeout: int,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    max_pages: int = 20,
    max_depth: int = 2,
) -> tuple[list[dict[str, Any]], bool]:
    url = ensure_url(target)
    base_host = urlparse(url).hostname
    if not base_host:
        return [], False

    session = _http_session(timeout, headers=headers, cookies=cookies)
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(url, 0)]
    results: list[dict[str, Any]] = []
    insecure_tls = False

    while queue and len(results) < max_pages:
        current, depth = queue.pop(0)
        normalized = _normalize_url(current)
        if normalized in seen or depth > max_depth:
            continue
        seen.add(normalized)

        try:
            resp, tls_bypassed = _safe_request(session, "GET", normalized)
            insecure_tls = insecure_tls or tls_bypassed
            results.append(
                {
                    "url": resp.url,
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get("Content-Type", ""),
                }
            )

            if resp.headers.get("Content-Type", "").startswith("text/html"):
                for link in _extract_links(resp.text, resp.url):
                    if _same_host(link, base_host):
                        queue.append((link, depth + 1))
        except Exception:
            continue

    return results, insecure_tls


def perform_auth_login(
    url: str,
    method: str,
    timeout: int,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    form: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
) -> tuple[dict[str, str], CheckResult]:
    session = _http_session(timeout, headers=headers, cookies=cookies)
    method_upper = method.upper()
    data = form or None
    payload = json_body if json_body else None

    try:
        resp, insecure_tls = _safe_request(session, method_upper, url)
        if method_upper in {"POST", "PUT", "PATCH"}:
            resp, insecure_tls = _request_with_tls_fallback(
                session,
                method_upper,
                url,
            )
            if payload is not None:
                resp = session.request(method_upper, url, json=payload, timeout=timeout, verify=not insecure_tls)
            elif data is not None:
                resp = session.request(method_upper, url, data=data, timeout=timeout, verify=not insecure_tls)

        cookie_jar = session.cookies.get_dict()
        status = "ok" if resp.status_code < 400 else "warning"
        severity = "info" if resp.status_code < 400 else "medium"
        details = f"Login request completed with status {resp.status_code}"
        recs: list[str] = []
        if insecure_tls:
            status = "warning"
            severity = "medium"
            details += "; TLS certificate verification could not be completed locally"
            recs.append("Fix local trust store and validate certificate chain")

        return (
            cookie_jar,
            CheckResult(
                name="auth_login",
                severity=severity,
                status=status,
                details=details,
                evidence={
                    "login_url": url,
                    "method": method_upper,
                    "status_code": resp.status_code,
                    "cookie_count": len(cookie_jar),
                    "tls_verification_bypassed": insecure_tls,
                },
                recommendations=recs,
            ),
        )
    except Exception as exc:
        return (
            {},
            CheckResult(
                name="auth_login",
                severity="low",
                status="error",
                details="Authenticated login request failed",
                evidence={"error": str(exc), "login_url": url},
            ),
        )


def check_http_security_headers(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> CheckResult:
    required_headers = {
        "Strict-Transport-Security": "Enable HSTS",
        "Content-Security-Policy": "Define a strict CSP",
        "X-Content-Type-Options": "Set to nosniff",
        "X-Frame-Options": "Set to DENY or SAMEORIGIN",
        "Referrer-Policy": "Define referrer policy",
        "Permissions-Policy": "Define browser feature policy",
    }

    url = ensure_url(target)
    missing: list[str] = []
    evidence: dict[str, Any] = {}

    try:
        session = _http_session(timeout, headers=headers, cookies=cookies)
        resp, insecure_tls = _request_with_tls_fallback(session, "GET", url)
        evidence["url"] = resp.url
        evidence["status_code"] = resp.status_code
        evidence["server"] = resp.headers.get("Server", "")
        evidence["powered_by"] = resp.headers.get("X-Powered-By", "")
        evidence["tls_verification_bypassed"] = insecure_tls
        evidence["headers"] = dict(resp.headers)

        for header in required_headers:
            if header not in resp.headers:
                missing.append(header)

        recommendations = [required_headers[h] for h in missing]
        if resp.headers.get("Server"):
            recommendations.append("Reduce server banner disclosure")
        if resp.headers.get("X-Powered-By"):
            recommendations.append("Remove X-Powered-By header")

        severity = "info"
        status = "ok"
        details = "HTTP security headers look good"

        if missing:
            severity = "medium"
            status = "warning"
            details = f"Missing security headers: {', '.join(missing)}"

        if resp.headers.get("X-Powered-By"):
            severity = "medium"
            status = "warning"

        if insecure_tls:
            severity = "medium"
            status = "warning"
            details += "; TLS certificate verification could not be completed locally"
            recommendations.append("Fix local trust store and validate certificate chain")

        return CheckResult(
            name="http_security_headers",
            severity=severity,
            status=status,
            details=details,
            evidence=evidence,
            recommendations=sorted(set(recommendations)),
        )
    except Exception as exc:
        return CheckResult(
            name="http_security_headers",
            severity="medium",
            status="error",
            details="HTTP header check failed",
            evidence={"error": str(exc), "url": url},
        )


def check_http_methods(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> CheckResult:
    url = ensure_url(target)
    try:
        session = _http_session(timeout, headers=headers, cookies=cookies)
        resp, insecure_tls = _request_with_tls_fallback(session, "OPTIONS", url)
        allow = resp.headers.get("Allow", "")
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        dangerous = sorted(m for m in methods if m in {"TRACE", "PUT", "DELETE", "CONNECT"})

        details = (
            f"Potentially dangerous methods enabled: {', '.join(dangerous)}"
            if dangerous
            else "No dangerous methods found in Allow header"
        )
        recs = ["Disable TRACE/PUT/DELETE/CONNECT where unnecessary"] if dangerous else []
        if insecure_tls:
            details += "; TLS certificate verification could not be completed locally"
            recs.append("Fix local trust store and validate certificate chain")

        return CheckResult(
            name="http_methods",
            severity="high" if dangerous else ("medium" if insecure_tls else "info"),
            status="warning" if (dangerous or insecure_tls) else "ok",
            details=details,
            evidence={
                "allow": allow,
                "status_code": resp.status_code,
                "tls_verification_bypassed": insecure_tls,
            },
            recommendations=sorted(set(recs)),
        )
    except Exception as exc:
        return CheckResult(
            name="http_methods",
            severity="low",
            status="error",
            details="HTTP methods check failed",
            evidence={"error": str(exc), "url": url},
        )


def check_common_paths(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> CheckResult:
    paths = [
        "/robots.txt",
        "/sitemap.xml",
        "/.git/HEAD",
        "/.env",
        "/phpinfo.php",
        "/server-status",
        "/admin",
        "/login",
    ]

    findings: list[dict[str, Any]] = []
    base = ensure_url(target).rstrip("/")
    session = _http_session(timeout, headers=headers, cookies=cookies)

    for path in paths:
        url = f"{base}{path}"
        try:
            resp = session.get(url)
            if resp.status_code < 400:
                findings.append(
                    {
                        "path": path,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "length": len(resp.text),
                    }
                )
        except Exception:
            continue

    sensitive = [x for x in findings if x["path"] in {"/.git/HEAD", "/.env", "/phpinfo.php", "/server-status"}]

    return CheckResult(
        name="common_paths",
        severity="high" if sensitive else ("low" if findings else "info"),
        status="warning" if findings else "ok",
        details=(
            f"Accessible paths discovered: {', '.join(x['path'] for x in findings)}"
            if findings
            else "No common paths exposed"
        ),
        evidence={"findings": findings},
        recommendations=[
            "Restrict access to sensitive paths like .git, .env, and server-status",
            "Place admin panels behind strong authentication and IP restrictions",
        ]
        if findings
        else [],
    )


def check_sensitive_paths(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> CheckResult:
    paths = [
        "/.git/HEAD",
        "/.env",
        "/.env.local",
        "/.env.backup",
        "/config.php",
        "/wp-config.php",
        "/composer.json",
        "/composer.lock",
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/.htaccess",
        "/.htpasswd",
        "/backup.zip",
        "/db.sql",
        "/phpinfo.php",
        "/server-status",
    ]

    findings: list[dict[str, Any]] = []
    base = ensure_url(target).rstrip("/")
    session = _http_session(timeout, headers=headers, cookies=cookies)
    insecure_tls = False

    for path in paths:
        url = f"{base}{path}"
        try:
            resp, tls_bypassed = _safe_request(session, "GET", url)
            insecure_tls = insecure_tls or tls_bypassed
            if resp.status_code < 400:
                findings.append(
                    {
                        "path": path,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "length": len(resp.text),
                    }
                )
        except Exception:
            continue

    severity = "high" if findings else "info"
    status = "warning" if findings else "ok"
    details = (
        f"Sensitive paths exposed: {', '.join(x['path'] for x in findings)}"
        if findings
        else "No sensitive paths exposed"
    )
    recommendations = [
        "Remove exposed configuration, backup, and repository files from web root",
        "Restrict admin endpoints and diagnostic pages",
    ]
    if insecure_tls:
        status = "warning"
        severity = "medium" if severity == "info" else severity
        details += "; TLS certificate verification could not be completed locally"
        recommendations.append("Fix local trust store and validate certificate chain")

    return CheckResult(
        name="sensitive_paths",
        severity=severity,
        status=status,
        details=details,
        evidence={"findings": findings, "tls_verification_bypassed": insecure_tls},
        recommendations=recommendations if findings or insecure_tls else [],
    )


def check_cors_and_cookies(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> CheckResult:
    url = ensure_url(target)
    session = _http_session(timeout, headers=headers, cookies=cookies)
    evidence: dict[str, Any] = {}

    try:
        resp, insecure_tls = _safe_request(session, "GET", url)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        set_cookie = resp.headers.get("Set-Cookie", "")

        missing_flags: list[str] = []
        if set_cookie:
            lowered = set_cookie.lower()
            if "secure" not in lowered:
                missing_flags.append("Secure")
            if "httponly" not in lowered:
                missing_flags.append("HttpOnly")
            if "samesite" not in lowered:
                missing_flags.append("SameSite")

        issues: list[str] = []
        if acao == "*" and acac.lower() == "true":
            issues.append("CORS allows any origin with credentials")
        if missing_flags:
            issues.append(f"Cookies missing flags: {', '.join(missing_flags)}")

        evidence.update(
            {
                "acao": acao,
                "acac": acac,
                "set_cookie_present": bool(set_cookie),
                "cookie_flag_gaps": missing_flags,
                "tls_verification_bypassed": insecure_tls,
            }
        )

        severity = "info"
        status = "ok"
        details = "CORS and cookie flags look reasonable"
        recommendations: list[str] = []

        if issues:
            severity = "high" if "CORS allows any origin" in " ".join(issues) else "medium"
            status = "warning"
            details = "; ".join(issues)
            recommendations.extend(
                [
                    "Restrict Access-Control-Allow-Origin to trusted origins",
                    "Avoid Access-Control-Allow-Credentials with wildcard origins",
                ]
            )
            if missing_flags:
                recommendations.append("Set Secure, HttpOnly, and SameSite on session cookies")

        if insecure_tls:
            status = "warning"
            severity = "medium" if severity == "info" else severity
            details += "; TLS certificate verification could not be completed locally"
            recommendations.append("Fix local trust store and validate certificate chain")

        return CheckResult(
            name="cors_cookies",
            severity=severity,
            status=status,
            details=details,
            evidence=evidence,
            recommendations=sorted(set(recommendations)),
        )
    except Exception as exc:
        return CheckResult(
            name="cors_cookies",
            severity="low",
            status="error",
            details="CORS/cookie checks failed",
            evidence={"error": str(exc)},
        )


def check_tls_versions(target: str) -> CheckResult:
    host = urlparse(ensure_url(target)).hostname or target
    supported: dict[str, bool] = {}
    evidence: dict[str, Any] = {"tested_host": host}
    versions = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]

    for name, version in versions:
        try:
            context = ssl.create_default_context()
            context.minimum_version = version
            context.maximum_version = version
            with socket.create_connection((host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    supported[name] = True
        except Exception:
            supported[name] = False

    evidence["supported_versions"] = supported
    weak = [k for k in ("TLSv1.0", "TLSv1.1") if supported.get(k)]

    severity = "info"
    status = "ok"
    details = "TLS protocol versions look modern"
    recommendations: list[str] = []

    if weak:
        severity = "medium"
        status = "warning"
        details = f"Deprecated TLS versions supported: {', '.join(weak)}"
        recommendations.append("Disable TLS 1.0/1.1 on the server")

    if not supported.get("TLSv1.2") and not supported.get("TLSv1.3"):
        severity = "high"
        status = "warning"
        details = "TLS 1.2/1.3 not detected"
        recommendations.append("Enable TLS 1.2 or TLS 1.3")

    return CheckResult(
        name="tls_versions",
        severity=severity,
        status=status,
        details=details,
        evidence=evidence,
        recommendations=recommendations,
    )


def check_tech_fingerprints(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> CheckResult:
    url = ensure_url(target)
    session = _http_session(timeout, headers=headers, cookies=cookies)
    evidence: dict[str, Any] = {}
    tech: set[str] = set()

    try:
        resp, insecure_tls = _safe_request(session, "GET", url)
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        if server:
            tech.add(server)
        if powered:
            tech.add(powered)

        if resp.headers.get("Content-Type", "").startswith("text/html"):
            soup = BeautifulSoup(resp.text, "html.parser")
            generator = soup.find("meta", attrs={"name": "generator"})
            if generator and generator.get("content"):
                tech.add(generator["content"])
            for script in soup.find_all("script"):
                src = script.get("src")
                if not src:
                    continue
                lowered = src.lower()
                if "wp-" in lowered or "wordpress" in lowered:
                    tech.add("WordPress")
                if "drupal" in lowered:
                    tech.add("Drupal")
                if "joomla" in lowered:
                    tech.add("Joomla")
                if "react" in lowered:
                    tech.add("React")
                if "vue" in lowered:
                    tech.add("Vue")
                if "angular" in lowered:
                    tech.add("Angular")
                if "jquery" in lowered:
                    tech.add("jQuery")

        evidence = {
            "server": server,
            "powered_by": powered,
            "detected": sorted(tech),
            "tls_verification_bypassed": insecure_tls,
        }

        details = "Technology fingerprinting completed"
        if tech:
            details += f": {', '.join(sorted(tech))}"

        return CheckResult(
            name="tech_fingerprints",
            severity="info",
            status="ok",
            details=details,
            evidence=evidence,
        )
    except Exception as exc:
        return CheckResult(
            name="tech_fingerprints",
            severity="low",
            status="error",
            details="Technology fingerprinting failed",
            evidence={"error": str(exc)},
        )


def check_endpoint_discovery(
    target: str,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    max_pages: int = 20,
    max_depth: int = 2,
) -> CheckResult:
    endpoints, insecure_tls = crawl_endpoints(
        target,
        timeout=timeout,
        headers=headers,
        cookies=cookies,
        max_pages=max_pages,
        max_depth=max_depth,
    )

    details = f"Discovered {len(endpoints)} endpoints from crawl"
    severity = "info"
    status = "ok"
    recommendations: list[str] = []

    if insecure_tls:
        status = "warning"
        severity = "medium"
        details += "; TLS certificate verification could not be completed locally"
        recommendations.append("Fix local trust store and validate certificate chain")

    return CheckResult(
        name="endpoint_discovery",
        severity=severity,
        status=status,
        details=details,
        evidence={"endpoints": endpoints, "tls_verification_bypassed": insecure_tls},
        recommendations=recommendations,
    )


def check_open_ports(target: str, timeout: float = 0.8) -> CheckResult:
    ips = resolve_ips(target)
    host = ips[0] if ips else target

    open_ports: list[int] = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()

    risky_ports = sorted(p for p in open_ports if p in {21, 23, 3306, 5432, 6379, 3389})

    return CheckResult(
        name="open_ports",
        severity="high" if risky_ports else ("medium" if open_ports else "info"),
        status="warning" if open_ports else "ok",
        details=(
            f"Open ports detected: {', '.join(str(p) for p in open_ports)}"
            if open_ports
            else "No common ports detected as open"
        ),
        evidence={"host": host, "open_ports": open_ports, "risky_ports": risky_ports},
        recommendations=[
            "Close unnecessary ports and restrict management ports with firewall rules",
            "Use VPN or bastion hosts for admin access",
        ]
        if open_ports
        else [],
    )


def check_subdomains_takeover(domain: str, timeout: int = 8) -> CheckResult:
    if _is_ip(domain):
        return CheckResult(
            name="subdomain_takeover",
            severity="info",
            status="ok",
            details="Subdomain enumeration skipped for IP target",
            evidence={"target_type": "ip"},
        )

    evidence: dict[str, Any] = {"enumerated_subdomains": [], "potential_takeovers": []}
    found: list[str] = []

    try:
        resp = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=timeout)
        if resp.ok:
            rows = resp.json()
            for row in rows:
                name_value = str(row.get("name_value", ""))
                for part in name_value.splitlines():
                    sub = part.strip().lower()
                    if sub.startswith("*."):
                        sub = sub[2:]
                    if sub.endswith("." + domain) or sub == domain:
                        found.append(sub)
        unique_subs = sorted(set(found))[:80]
        evidence["enumerated_subdomains"] = unique_subs

        potential: list[dict[str, str]] = []
        for sub in unique_subs[:40]:
            try:
                cname_answers = dns.resolver.resolve(sub, "CNAME", lifetime=3.5)
                cname = str(cname_answers[0].target).rstrip(".").lower()
                for hint, reason in TAKEOVER_CNAME_HINTS.items():
                    if hint in cname:
                        try:
                            dns.resolver.resolve(cname, "A", lifetime=3.5)
                        except Exception:
                            potential.append({"subdomain": sub, "cname": cname, "reason": reason})
            except Exception:
                continue

        evidence["potential_takeovers"] = potential
        if potential:
            return CheckResult(
                name="subdomain_takeover",
                severity="high",
                status="warning",
                details=f"Potential subdomain takeover indicators found: {len(potential)}",
                evidence=evidence,
                recommendations=[
                    "Remove dangling CNAME records for unclaimed third-party services",
                    "Claim or decommission external service endpoints referenced by DNS",
                ],
            )

        return CheckResult(
            name="subdomain_takeover",
            severity="info",
            status="ok",
            details=f"Enumerated {len(evidence['enumerated_subdomains'])} subdomains; no takeover indicators found",
            evidence=evidence,
        )
    except Exception as exc:
        return CheckResult(
            name="subdomain_takeover",
            severity="low",
            status="warning",
            details="Subdomain enumeration source unavailable; takeover check incomplete",
            evidence={"error": str(exc)},
            recommendations=["Retry scan later or use additional subdomain sources for confirmation"],
        )


def _extract_server_fingerprints(http_headers_result: CheckResult, open_ports_result: CheckResult) -> list[str]:
    fingerprints: list[str] = []
    server = str(http_headers_result.evidence.get("server", "")).strip()
    powered = str(http_headers_result.evidence.get("powered_by", "")).strip()
    if server:
        fingerprints.append(server)
    if powered:
        fingerprints.append(powered)

    for port in open_ports_result.evidence.get("open_ports", []):
        service = PORT_SERVICE_FINGERPRINTS.get(port)
        if service:
            fingerprints.append(service)

    # Keep stable order while removing duplicates.
    deduped: list[str] = []
    for item in fingerprints:
        if item not in deduped:
            deduped.append(item)
    return deduped[:8]


def _query_nvd_cves(keyword: str, timeout: int = 8) -> list[dict[str, Any]]:
    endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    resp = requests.get(endpoint, params=params, timeout=timeout)
    if not resp.ok:
        return []

    data = resp.json()
    out: list[dict[str, Any]] = []
    for row in data.get("vulnerabilities", []):
        cve = row.get("cve", {})
        cve_id = cve.get("id", "")
        metrics = cve.get("metrics", {})
        score = None
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss = entries[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity", severity)
                break
        out.append(
            {
                "cve_id": cve_id,
                "severity": severity,
                "score": score,
                "published": cve.get("published"),
                "source": "NVD",
            }
        )
    return out


def check_cve_enrichment(
    target: str,
    http_headers_result: CheckResult,
    open_ports_result: CheckResult,
    timeout: int = 8,
) -> CheckResult:
    fingerprints = _extract_server_fingerprints(http_headers_result, open_ports_result)
    evidence: dict[str, Any] = {"fingerprints": fingerprints, "matches": {}}

    if not fingerprints:
        return CheckResult(
            name="cve_enrichment",
            severity="info",
            status="ok",
            details="No service fingerprints available for CVE enrichment",
            evidence=evidence,
        )

    try:
        total = 0
        high_or_critical = 0
        for fp in fingerprints:
            cves = _query_nvd_cves(fp, timeout=timeout)
            evidence["matches"][fp] = cves
            total += len(cves)
            for c in cves:
                sev = str(c.get("severity", "")).upper()
                if sev in {"HIGH", "CRITICAL"}:
                    high_or_critical += 1

        if high_or_critical > 0:
            return CheckResult(
                name="cve_enrichment",
                severity="high",
                status="warning",
                details=f"Potential CVE matches found for {target}: {total} total, {high_or_critical} high/critical",
                evidence=evidence,
                recommendations=[
                    "Validate product/version fingerprint accuracy before remediation",
                    "Prioritize patching or mitigation for high and critical CVEs",
                    "Track exploitable CVEs through your vulnerability management process",
                ],
            )

        return CheckResult(
            name="cve_enrichment",
            severity="medium" if total else "info",
            status="warning" if total else "ok",
            details=(
                f"Potential CVE matches found for {target}: {total}"
                if total
                else "No CVE matches returned for identified fingerprints"
            ),
            evidence=evidence,
            recommendations=["Manually validate matched CVEs against exact software versions"] if total else [],
        )
    except Exception as exc:
        return CheckResult(
            name="cve_enrichment",
            severity="low",
            status="error",
            details="CVE enrichment lookup failed",
            evidence={"error": str(exc), **evidence},
        )


def check_nuclei_scan(
    target: str,
    enabled: bool = False,
    templates_path: str | None = None,
    severities: list[str] | None = None,
    tags: list[str] | None = None,
) -> CheckResult:
    if not enabled:
        return CheckResult(
            name="nuclei_scan",
            severity="info",
            status="ok",
            details="Nuclei scan not enabled",
            evidence={},
        )

    cmd = ["nuclei", "-u", target, "-json"]
    if templates_path:
        cmd.extend(["-t", templates_path])
    if severities:
        cmd.extend(["-severity", ",".join(severities)])
    if tags:
        cmd.extend(["-tags", ",".join(tags)])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if proc.returncode != 0:
            return CheckResult(
                name="nuclei_scan",
                severity="low",
                status="error",
                details="Nuclei scan failed",
                evidence={"stderr": proc.stderr.strip()},
            )

        findings = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        severity = "medium" if findings else "info"
        status = "warning" if findings else "ok"
        details = f"Nuclei findings: {len(findings)}" if findings else "No Nuclei findings"

        return CheckResult(
            name="nuclei_scan",
            severity=severity,
            status=status,
            details=details,
            evidence={"findings": findings},
            recommendations=["Review Nuclei findings and validate severity"] if findings else [],
        )
    except FileNotFoundError:
        return CheckResult(
            name="nuclei_scan",
            severity="low",
            status="error",
            details="Nuclei executable not found",
            evidence={},
            recommendations=["Install nuclei and ensure it is on PATH"],
        )
    except Exception as exc:
        return CheckResult(
            name="nuclei_scan",
            severity="low",
            status="error",
            details="Nuclei scan failed",
            evidence={"error": str(exc)},
        )


def check_zap_passive_alerts(target: str, base_url: str | None = None) -> CheckResult:
    if not base_url:
        return CheckResult(
            name="zap_passive",
            severity="info",
            status="ok",
            details="ZAP passive scan not enabled",
            evidence={},
        )

    try:
        endpoint = f"{base_url.rstrip('/')}/JSON/alert/view/alerts/"
        resp = requests.get(endpoint, params={"baseurl": ensure_url(target)}, timeout=10)
        if not resp.ok:
            return CheckResult(
                name="zap_passive",
                severity="low",
                status="error",
                details="Failed to fetch ZAP alerts",
                evidence={"status_code": resp.status_code, "body": resp.text[:200]},
            )

        data = resp.json()
        alerts = data.get("alerts", [])
        severity = "medium" if alerts else "info"
        status = "warning" if alerts else "ok"
        details = f"ZAP alerts found: {len(alerts)}" if alerts else "No ZAP alerts returned"

        return CheckResult(
            name="zap_passive",
            severity=severity,
            status=status,
            details=details,
            evidence={"alerts": alerts},
            recommendations=["Review ZAP passive alerts"] if alerts else [],
        )
    except Exception as exc:
        return CheckResult(
            name="zap_passive",
            severity="low",
            status="error",
            details="ZAP passive scan query failed",
            evidence={"error": str(exc)},
        )


def run_all_checks(
    target: str,
    timeout: int = 8,
    auth_headers: dict[str, str] | None = None,
    auth_cookies: dict[str, str] | None = None,
    auth_login_url: str | None = None,
    auth_login_method: str = "POST",
    auth_login_form: dict[str, str] | None = None,
    auth_login_json: dict[str, Any] | None = None,
    max_pages: int = 20,
    max_depth: int = 2,
    enable_nuclei: bool = False,
    nuclei_templates: str | None = None,
    nuclei_severities: list[str] | None = None,
    nuclei_tags: list[str] | None = None,
    zap_base_url: str | None = None,
    progress_cb=None,
    mode: str = "standard",
    workers: int = 8,
    rate_limit_rps: int = 15,
) -> list[CheckResult]:
    from vapt_tool.engine import ScanEngine, build_check_tasks, build_bounty_tasks

    host = urlparse(ensure_url(target)).hostname or target

    if progress_cb:
        progress_cb("start", "running", {"target": target, "mode": mode})

    auth_headers = auth_headers or {}
    auth_cookies = auth_cookies or {}
    auth_result = None
    if auth_login_url:
        if progress_cb:
            progress_cb("auth_login", "running", {})
        login_cookies, auth_result = perform_auth_login(
            auth_login_url,
            auth_login_method,
            timeout,
            headers=auth_headers,
            cookies=auth_cookies,
            form=auth_login_form,
            json_body=auth_login_json,
        )
        auth_cookies = {**auth_cookies, **login_cookies}
        if progress_cb:
            progress_cb("auth_login", "done", {"cookies": len(login_cookies)})

    # Build standard check tasks
    parallel_tasks, _ = build_check_tasks(
        target=target,
        host=host,
        timeout=timeout,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
        max_pages=max_pages,
        max_depth=max_depth,
        enable_nuclei=enable_nuclei,
        nuclei_templates=nuclei_templates,
        nuclei_severities=nuclei_severities,
        nuclei_tags=nuclei_tags,
        zap_base_url=zap_base_url,
    )

    # Run standard checks concurrently
    engine = ScanEngine(workers=workers, progress_cb=progress_cb)
    standard_results = engine.run_parallel(parallel_tasks)

    # Find results needed for dependent checks
    http_headers_result = None
    open_ports_result = None
    crawl_result = None
    for r in standard_results:
        if r.name == "http_security_headers":
            http_headers_result = r
        elif r.name == "open_ports":
            open_ports_result = r
        elif r.name == "endpoint_discovery":
            crawl_result = r

    # CVE enrichment depends on headers + ports results
    if http_headers_result and open_ports_result:
        if progress_cb:
            progress_cb("cve_enrichment", "running", {})
        cve_result = check_cve_enrichment(target, http_headers_result, open_ports_result, timeout=timeout)
        if progress_cb:
            progress_cb("cve_enrichment", "done", {})
    else:
        cve_result = CheckResult(
            name="cve_enrichment",
            severity="info",
            status="ok",
            details="CVE enrichment skipped (missing prerequisite data)",
            evidence={},
        )

    # Assemble standard results
    checks: list[CheckResult] = []
    if auth_result:
        checks.append(auth_result)
    checks.extend(standard_results)
    checks.append(cve_result)

    # Bug bounty mode: run additional checks
    if mode == "bounty":
        if progress_cb:
            progress_cb("bounty_checks", "running", {"phase": "starting"})

        crawled_endpoints = crawl_result.evidence.get("endpoints", []) if crawl_result else []

        bounty_tasks = build_bounty_tasks(
            target=target,
            timeout=timeout,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            crawled_endpoints=crawled_endpoints,
            rate_limit_rps=rate_limit_rps,
        )

        # Run most bounty checks in parallel, except dir bruteforce (rate-limited)
        parallel_bounty = [t for t in bounty_tasks if t[0] != "directory_bruteforce"]
        sequential_bounty = [t for t in bounty_tasks if t[0] == "directory_bruteforce"]

        bounty_results = engine.run_parallel(parallel_bounty)
        bounty_results.extend(engine.run_sequential(sequential_bounty))

        # Parameter discovery needs wayback results
        from vapt_tool.bb_checks import check_parameter_discovery
        wb_result = next((r for r in bounty_results if r.name == "wayback_urls"), None)
        wayback_params = wb_result.evidence.get("parameters_discovered", []) if wb_result else []

        if progress_cb:
            progress_cb("parameter_discovery", "running", {})
        param_result = check_parameter_discovery(
            target=target,
            crawled_endpoints=crawled_endpoints,
            wayback_params=wayback_params,
        )
        if progress_cb:
            progress_cb("parameter_discovery", "done", {})

        bounty_results.append(param_result)
        checks.extend(bounty_results)

        if progress_cb:
            progress_cb("bounty_checks", "done", {"total": len(bounty_results)})

    if progress_cb:
        progress_cb("complete", "done", {"timings": engine.timings})

    return checks
