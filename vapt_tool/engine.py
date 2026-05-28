"""Concurrent scanning engine using thread pools.

Runs independent checks in parallel to cut scan time by 3-5x.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable
from threading import Lock

from vapt_tool.models import CheckResult


class ScanEngine:
    """Thread-pool-based concurrent scanner with progress tracking."""

    def __init__(self, workers: int = 8, progress_cb: Callable | None = None):
        self.workers = workers
        self.progress_cb = progress_cb
        self._results: list[CheckResult] = []
        self._lock = Lock()
        self._timings: dict[str, float] = {}

    def _wrap(self, name: str, fn: Callable, **kwargs) -> CheckResult:
        """Wrap a check function with timing and progress callbacks."""
        if self.progress_cb:
            self.progress_cb(name, "running", {})

        start = time.monotonic()
        try:
            result = fn(**kwargs)
        except Exception as exc:
            result = CheckResult(
                name=name,
                severity="low",
                status="error",
                details=f"Check failed: {exc}",
                evidence={"error": str(exc)},
            )
        elapsed = time.monotonic() - start

        with self._lock:
            self._timings[name] = round(elapsed, 2)

        if self.progress_cb:
            self.progress_cb(name, "done", {"elapsed": round(elapsed, 2)})

        return result

    def run_parallel(self, tasks: list[tuple[str, Callable, dict[str, Any]]]) -> list[CheckResult]:
        """Run a list of (name, function, kwargs) tasks concurrently.

        Returns results in submission order.
        """
        results: dict[str, CheckResult] = {}
        order: list[str] = [t[0] for t in tasks]

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {}
            for name, fn, kwargs in tasks:
                future = pool.submit(self._wrap, name, fn, **kwargs)
                futures[future] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as exc:
                    results[name] = CheckResult(
                        name=name,
                        severity="low",
                        status="error",
                        details=f"Execution error: {exc}",
                        evidence={"error": str(exc)},
                    )

        # Return in original order
        return [results[name] for name in order if name in results]

    def run_sequential(self, tasks: list[tuple[str, Callable, dict[str, Any]]]) -> list[CheckResult]:
        """Run tasks sequentially (fallback / for dependent tasks)."""
        results: list[CheckResult] = []
        for name, fn, kwargs in tasks:
            result = self._wrap(name, fn, **kwargs)
            results.append(result)
        return results

    @property
    def timings(self) -> dict[str, float]:
        """Return per-check timing data."""
        with self._lock:
            return dict(self._timings)


def build_check_tasks(
    target: str,
    host: str,
    timeout: int,
    auth_headers: dict[str, str],
    auth_cookies: dict[str, str],
    max_pages: int,
    max_depth: int,
    enable_nuclei: bool,
    nuclei_templates: str | None,
    nuclei_severities: list[str] | None,
    nuclei_tags: list[str] | None,
    zap_base_url: str | None,
) -> tuple[list[tuple[str, Any, dict[str, Any]]], list[tuple[str, Any, dict[str, Any]]]]:
    """Build two task lists: parallel-safe and sequential (dependent) tasks.

    Returns (parallel_tasks, sequential_task_builders) where sequential
    tasks need results from parallel tasks.
    """
    from vapt_tool.checks import (
        check_dns_records,
        check_whois,
        check_ssl_certificate,
        check_http_security_headers,
        check_http_methods,
        check_common_paths,
        check_sensitive_paths,
        check_cors_and_cookies,
        check_tls_versions,
        check_tech_fingerprints,
        check_endpoint_discovery,
        check_open_ports,
        check_subdomains_takeover,
        check_nuclei_scan,
        check_zap_passive_alerts,
    )

    # Phase 1: Independent checks that can run in parallel
    parallel_tasks = [
        ("dns_records", check_dns_records, {"target": host}),
        ("whois_info", check_whois, {"target": host}),
        ("ssl_certificate", check_ssl_certificate, {"target": host}),
        ("http_security_headers", check_http_security_headers, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
        }),
        ("http_methods", check_http_methods, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
        }),
        ("common_paths", check_common_paths, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
        }),
        ("sensitive_paths", check_sensitive_paths, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
        }),
        ("cors_cookies", check_cors_and_cookies, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
        }),
        ("tls_versions", check_tls_versions, {"target": target}),
        ("tech_fingerprints", check_tech_fingerprints, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
        }),
        ("endpoint_discovery", check_endpoint_discovery, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
            "max_pages": max_pages, "max_depth": max_depth,
        }),
        ("open_ports", check_open_ports, {"target": host}),
        ("subdomain_takeover", check_subdomains_takeover, {
            "domain": host, "timeout": timeout,
        }),
        ("nuclei_scan", check_nuclei_scan, {
            "target": target, "enabled": enable_nuclei,
            "templates_path": nuclei_templates,
            "severities": nuclei_severities, "tags": nuclei_tags,
        }),
        ("zap_passive", check_zap_passive_alerts, {
            "target": target, "base_url": zap_base_url,
        }),
    ]

    return parallel_tasks, []


def build_bounty_tasks(
    target: str,
    timeout: int,
    auth_headers: dict[str, str],
    auth_cookies: dict[str, str],
    crawled_endpoints: list[dict[str, Any]] | None = None,
    rate_limit_rps: int = 15,
) -> list[tuple[str, Any, dict[str, Any]]]:
    """Build task list for bug-bounty-specific checks."""
    from vapt_tool.bb_checks import (
        check_js_secrets,
        check_wayback_urls,
        check_open_redirects,
        check_idor_patterns,
        check_info_harvester,
        check_cloud_buckets,
        check_directory_bruteforce,
        check_security_txt,
        check_crlf_injection,
    )

    tasks = [
        ("js_secrets", check_js_secrets, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
            "crawled_endpoints": crawled_endpoints,
        }),
        ("wayback_urls", check_wayback_urls, {"target": target, "timeout": 15}),
        ("open_redirect", check_open_redirects, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
        }),
        ("idor_patterns", check_idor_patterns, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
            "crawled_endpoints": crawled_endpoints,
        }),
        ("info_harvester", check_info_harvester, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
        }),
        ("cloud_buckets", check_cloud_buckets, {"target": target, "timeout": 5}),
        ("security_txt", check_security_txt, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
        }),
        ("crlf_injection", check_crlf_injection, {
            "target": target, "timeout": timeout,
            "headers": auth_headers, "cookies": auth_cookies,
        }),
    ]

    # Directory bruteforce runs sequentially (rate-limited)
    # We include it but it will be heavy on requests
    tasks.append(("directory_bruteforce", check_directory_bruteforce, {
        "target": target, "timeout": timeout,
        "headers": auth_headers, "cookies": auth_cookies,
        "rate_limit_rps": rate_limit_rps,
    }))

    return tasks
