from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from vapt_tool.models import TargetReport


def _summary_counts(report: TargetReport) -> dict[str, int]:
    by_status = {"ok": 0, "warning": 0, "error": 0}
    for result in report.results:
        by_status[result.status] = by_status.get(result.status, 0) + 1
    return by_status


def _risk_score(report: TargetReport) -> tuple[int, str, dict[str, int]]:
    weights = {"info": 1, "low": 2, "medium": 5, "high": 8, "critical": 13}
    severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    score = 0

    for result in report.results:
        sev = result.severity.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        score += weights.get(sev, 0)

    if score >= 50:
        level = "critical"
    elif score >= 30:
        level = "high"
    elif score >= 15:
        level = "medium"
    elif score >= 6:
        level = "low"
    else:
        level = "informational"

    return score, level, severity_counts


_DEFAULT_BOUNTY_RANGES: dict[str, str] = {
    "critical": "$1,000 – $10,000+",
    "high": "$500 – $3,000",
    "medium": "$100 – $1,000",
    "low": "$25 – $200",
    "info": "$0",
}

_FINDING_TITLES: dict[str, str] = {
    "js_secrets": "Sensitive Credentials Exposed in Client-Side JavaScript",
    "wayback_urls": "Historical URLs Reveal Hidden Endpoints / Sensitive Files",
    "open_redirect": "Open Redirect Vulnerability",
    "idor_patterns": "Insecure Direct Object Reference (IDOR) Indicators",
    "parameter_discovery": "Potentially Injectable Parameters Discovered",
    "info_harvester": "Information Disclosure — Internal Paths / Email Leakage",
    "cloud_buckets": "Publicly Accessible Cloud Storage Bucket",
    "directory_bruteforce": "Sensitive Files / Directories Exposed",
    "security_txt": "Security Disclosure Policy (security.txt)",
    "crlf_injection": "HTTP Header Injection (CRLF)",
    "subdomain_takeover": "Subdomain Takeover Vulnerability",
    "sensitive_paths": "Sensitive Files Publicly Accessible",
    "cors_cookies": "CORS Misconfiguration / Insecure Cookie Flags",
    "http_methods": "Dangerous HTTP Methods Enabled",
    "ssl_certificate": "SSL/TLS Certificate Issue",
    "tls_versions": "Deprecated TLS Protocol Versions",
    "cve_enrichment": "Known CVE Matches for Detected Technologies",
    "open_ports": "Sensitive Ports Exposed",
    "common_paths": "Common Sensitive Paths Accessible",
    "http_security_headers": "Missing HTTP Security Headers",
}

_IMPACT_TEMPLATES: dict[str, str] = {
    "js_secrets": "An attacker can extract hardcoded API keys and tokens from the application's JavaScript files, potentially gaining unauthorized access to backend services, third-party APIs, or user data.",
    "open_redirect": "An attacker can craft a URL that redirects users from the legitimate domain to a malicious site, enabling phishing attacks and credential theft while abusing the trust of the target domain.",
    "cloud_buckets": "An attacker can access, enumerate, and potentially download sensitive data from publicly accessible cloud storage buckets belonging to the organization.",
    "subdomain_takeover": "An attacker can claim an unclaimed subdomain and serve malicious content under the target's domain, enabling cookie theft, phishing, and CSP bypasses.",
    "crlf_injection": "An attacker can inject HTTP headers into the response, potentially enabling cache poisoning, XSS, or session fixation attacks.",
    "cors_cookies": "Misconfigured CORS allows unauthorized origins to read sensitive data via cross-origin requests. Missing cookie flags may allow session hijacking.",
    "sensitive_paths": "Exposed configuration files, backup archives, or repository data may contain credentials, internal architecture details, or application source code.",
    "directory_bruteforce": "Exposed sensitive files and directories may leak credentials, API documentation, admin access, or internal application details.",
    "idor_patterns": "Sequential numeric identifiers in URLs suggest resources may be accessible by modifying ID values, potentially allowing unauthorized access to other users' data.",
}


def build_report_payload(report: TargetReport) -> dict[str, object]:
    payload = asdict(report)
    payload["summary"] = _summary_counts(report)
    risk_score, risk_level, severity_counts = _risk_score(report)
    payload["risk"] = {
        "score": risk_score,
        "level": risk_level,
        "severity_counts": severity_counts,
    }
    return payload


def write_json_report(report: TargetReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_report_payload(report)
    output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def write_markdown_report(report: TargetReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary = _summary_counts(report)
    risk_score, risk_level, severity_counts = _risk_score(report)

    lines: list[str] = []
    lines.append(f"# VAPT Report: {report.target}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- OK checks: {summary.get('ok', 0)}")
    lines.append(f"- Warning checks: {summary.get('warning', 0)}")
    lines.append(f"- Error checks: {summary.get('error', 0)}")
    lines.append(f"- Risk score: {risk_score}")
    lines.append(f"- Risk level: {risk_level}")
    lines.append(f"- Severity distribution: {json.dumps(severity_counts)}")
    lines.append(f"- Resolved IPs: {', '.join(report.resolved_ips) if report.resolved_ips else 'N/A'}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")

    for result in report.results:
        lines.append(f"### {result.name}")
        lines.append("")
        lines.append(f"- Status: {result.status}")
        lines.append(f"- Severity: {result.severity}")
        lines.append(f"- Details: {result.details}")
        if result.recommendations:
            lines.append("- Recommendations:")
            for rec in result.recommendations:
                lines.append(f"  - {rec}")
        if result.evidence:
            lines.append("- Evidence:")
            lines.append("```json")
            lines.append(json.dumps(result.evidence, indent=2, default=str))
            lines.append("```")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_bounty_report(
    report: TargetReport,
    output_path: Path,
    program_name: str = "",
    bounty_table: dict[str, str] | None = None,
) -> None:
    """Generate a bug-bounty submission-ready markdown report.

    Groups findings by severity (critical first) and formats each as a
    standalone submission with Title, Severity, Impact, Steps to Reproduce,
    Evidence, and Remediation.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    bt = bounty_table or _DEFAULT_BOUNTY_RANGES
    risk_score, risk_level, severity_counts = _risk_score(report)

    lines: list[str] = []
    lines.append(f"# 🐛 Bug Bounty Report: {report.target}")
    if program_name:
        lines.append(f"**Program:** {program_name}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Target | `{report.target}` |")
    lines.append(f"| Risk Score | **{risk_score}** ({risk_level.upper()}) |")
    lines.append(f"| Total Findings | {len(report.results)} |")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count:
            bounty = bt.get(sev, "$0")
            lines.append(f"| {sev.upper()} | {count} finding(s) — est. {bounty} each |")
    lines.append("")

    # Filter to reportable findings (warnings/errors that aren't info severity)
    reportable = [r for r in report.results if r.status == "warning" and r.severity != "info"]
    if not reportable:
        lines.append("> **No actionable findings to report.** All checks passed or returned informational results only.")
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    reportable.sort(key=lambda r: sev_order.get(r.severity, 5))

    lines.append("---")
    lines.append("")
    lines.append("## Reportable Findings")
    lines.append("")

    for idx, result in enumerate(reportable, 1):
        title = _FINDING_TITLES.get(result.name, result.name.replace("_", " ").title())
        sev_upper = result.severity.upper()
        bounty = bt.get(result.severity, "$0")
        impact = _IMPACT_TEMPLATES.get(result.name, "This finding may allow an attacker to compromise the security posture of the application.")

        lines.append(f"### {idx}. {title}")
        lines.append("")
        lines.append(f"**Severity:** {sev_upper}  ")
        lines.append(f"**Estimated Bounty:** {bounty}  ")
        lines.append(f"**Check:** `{result.name}`")
        lines.append("")

        lines.append("#### Description")
        lines.append("")
        lines.append(result.details)
        lines.append("")

        lines.append("#### Impact")
        lines.append("")
        lines.append(impact)
        lines.append("")

        lines.append("#### Steps to Reproduce")
        lines.append("")
        lines.append(f"1. Navigate to `{report.target}`")
        lines.append(f"2. Run the VAPT scanner with `--mode bounty` against the target")
        lines.append(f"3. Observe the `{result.name}` check result")

        # Add specific reproduction steps based on evidence
        if result.name == "js_secrets" and result.evidence.get("findings"):
            finding = result.evidence["findings"][0]
            lines.append(f'4. Open browser DevTools → Sources → search for `{finding.get("type", "secret pattern")}`')
            lines.append(f'5. Secret found in: `{finding.get("source", "N/A")}`')
        elif result.name == "open_redirect" and result.evidence.get("vulnerable"):
            vuln = result.evidence["vulnerable"][0]
            lines.append(f'4. Visit: `{vuln.get("url", "N/A")}`')
            lines.append(f'5. Observe redirect to: `{vuln.get("redirect_to", "N/A")}`')
        elif result.name == "cloud_buckets" and result.evidence.get("open_buckets"):
            bucket = result.evidence["open_buckets"][0]
            lines.append(f'4. Visit: `{bucket.get("url", "N/A")}`')
            lines.append(f'5. Observe publicly listable bucket contents')
        elif result.name == "directory_bruteforce" and result.evidence.get("sensitive"):
            sens = result.evidence["sensitive"][0]
            lines.append(f'4. Visit: `{report.target}{sens.get("path", "")}`')
            lines.append(f'5. Observe status {sens.get("status", "200")} response with {sens.get("size", "N/A")} bytes')

        lines.append("")

        if result.evidence:
            lines.append("#### Evidence")
            lines.append("")
            lines.append("```json")
            # Truncate large evidence for readability
            ev = result.evidence
            ev_str = json.dumps(ev, indent=2, default=str)
            if len(ev_str) > 3000:
                ev_str = ev_str[:3000] + "\n... (truncated)"
            lines.append(ev_str)
            lines.append("```")
            lines.append("")

        if result.recommendations:
            lines.append("#### Remediation")
            lines.append("")
            for rec in result.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        lines.append("---")
        lines.append("")

    # Summary footer
    total_est = sum(1 for r in reportable if r.severity in ("critical", "high"))
    lines.append(f"**Total reportable findings:** {len(reportable)}  ")
    lines.append(f"**High-value findings (Critical+High):** {total_est}  ")
    lines.append("")
    lines.append("*Generated by VAPT Bug Bounty Toolkit*")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def generate_single_finding_report(result: Any, target: str) -> str:
    """Generate a copy-paste-ready submission for a single finding."""
    title = _FINDING_TITLES.get(result.name, result.name.replace("_", " ").title())
    impact = _IMPACT_TEMPLATES.get(result.name, "This finding may compromise application security.")

    lines = [
        f"## {title}",
        "",
        f"**Target:** {target}",
        f"**Severity:** {result.severity.upper()}",
        "",
        "### Summary",
        result.details,
        "",
        "### Impact",
        impact,
        "",
        "### Steps to Reproduce",
        f"1. Navigate to `{target}`",
        f"2. The `{result.name}` vulnerability was identified during automated scanning",
        "",
    ]

    if result.evidence:
        lines.extend([
            "### Proof of Concept",
            "```json",
            json.dumps(result.evidence, indent=2, default=str)[:2000],
            "```",
            "",
        ])

    if result.recommendations:
        lines.extend(["### Remediation"])
        for rec in result.recommendations:
            lines.append(f"- {rec}")

    return "\n".join(lines)

