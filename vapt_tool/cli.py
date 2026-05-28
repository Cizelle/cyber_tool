from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from vapt_tool.checks import resolve_ips, run_all_checks
from vapt_tool.models import TargetReport
from vapt_tool.reporting import write_json_report, write_markdown_report, write_bounty_report
from vapt_tool.scope import in_scope, normalize_target, parse_scope_file

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vapt-tool",
        description="Bug Bounty Power Toolkit — Authorization-first VAPT scanner with bounty-focused checks.",
    )

    # Target selection
    target_group = parser.add_argument_group("target selection")
    target_group.add_argument("--target", help="Single target (domain, IP, or URL)")
    target_group.add_argument("--targets-file", help="Path to file containing one target per line")
    target_group.add_argument(
        "--scope-file",
        help="Scope file. Lines are included targets; prefix with ! for exclusions.",
    )
    target_group.add_argument(
        "--strict-scope",
        action="store_true",
        help="Skip targets not present in --scope-file include list",
    )

    # Scan mode
    mode_group = parser.add_argument_group("scan mode")
    mode_group.add_argument(
        "--mode",
        choices=["standard", "bounty"],
        default="standard",
        help="Scan mode: 'standard' (baseline checks) or 'bounty' (extended bug bounty checks) (default: standard)",
    )
    mode_group.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of concurrent scan threads (default: 8)",
    )
    mode_group.add_argument(
        "--rate-limit",
        type=int,
        default=15,
        help="Max requests per second for bruteforce checks (default: 15)",
    )

    # Scan options
    scan_group = parser.add_argument_group("scan options")
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="HTTP timeout in seconds (default: 8)",
    )
    scan_group.add_argument(
        "--max-pages",
        type=int,
        default=20,
        help="Max pages to crawl for endpoint discovery (default: 20)",
    )
    scan_group.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Max crawl depth for endpoint discovery (default: 2)",
    )

    # Output
    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "--out-dir",
        default="reports",
        help="Output directory for generated reports (default: reports)",
    )
    output_group.add_argument(
        "--format",
        default="json,md",
        help="Report formats: comma-separated json,md,bounty (default: json,md)",
    )

    # Authentication
    auth_group = parser.add_argument_group("authentication")
    auth_group.add_argument(
        "--auth-header",
        action="append",
        default=[],
        help="Authenticated scan header in format Key:Value (can be used multiple times)",
    )
    auth_group.add_argument(
        "--cookie",
        action="append",
        default=[],
        help="Authenticated scan cookie in format key=value (can be used multiple times)",
    )
    auth_group.add_argument(
        "--bearer-token",
        help="Bearer token for authenticated scans (adds Authorization header)",
    )
    auth_group.add_argument(
        "--auth-login-url",
        help="Login URL for authenticated crawl/session initialization",
    )
    auth_group.add_argument(
        "--auth-login-method",
        default="POST",
        help="Login HTTP method (default: POST)",
    )
    auth_group.add_argument(
        "--auth-login-form",
        help="Login form payload (key=value&key2=value2)",
    )
    auth_group.add_argument(
        "--auth-login-json",
        help="Login JSON payload as string",
    )

    # Integrations
    int_group = parser.add_argument_group("integrations")
    int_group.add_argument(
        "--enable-nuclei",
        action="store_true",
        help="Enable Nuclei scan if nuclei is installed",
    )
    int_group.add_argument(
        "--nuclei-templates",
        help="Nuclei templates path",
    )
    int_group.add_argument(
        "--nuclei-severity",
        default="low,medium,high,critical",
        help="Nuclei severities (comma-separated)",
    )
    int_group.add_argument(
        "--nuclei-tags",
        help="Nuclei tags (comma-separated)",
    )
    int_group.add_argument(
        "--zap-base-url",
        help="ZAP API base URL (e.g. http://localhost:8080)",
    )

    # Program management
    prog_group = parser.add_argument_group("program management")
    prog_group.add_argument(
        "--scan-program",
        help="Scan all in-scope targets from a saved program",
    )
    prog_group.add_argument(
        "--add-program",
        action="store_true",
        help="Interactively add a new bug bounty program",
    )
    prog_group.add_argument(
        "--list-programs",
        action="store_true",
        help="List all saved bug bounty programs",
    )
    prog_group.add_argument(
        "--programs-file",
        default="programs.json",
        help="Path to programs database (default: programs.json)",
    )

    return parser


def load_targets(target: str | None, targets_file: str | None) -> list[str]:
    items: list[str] = []

    if target:
        items.append(target)

    if targets_file:
        path = Path(targets_file)
        if not path.exists():
            raise FileNotFoundError(f"Targets file not found: {targets_file}")
        for line in path.read_text(encoding="utf-8").splitlines():
            text = line.strip()
            if text and not text.startswith("#"):
                items.append(text)

    normalized = [normalize_target(x) for x in items if normalize_target(x)]
    deduped: list[str] = []
    for item in normalized:
        if item not in deduped:
            deduped.append(item)
    return deduped


def validate_authorization() -> None:
    console.print(
        Panel(
            "[bold yellow]⚠ AUTHORIZATION NOTICE[/]\n"
            "Use this tool [bold]only[/] on assets you own or have [bold]explicit written permission[/] to test.\n"
            "Unauthorized scanning is illegal and unethical.",
            border_style="yellow",
        )
    )


def _parse_header_list(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if ":" not in item:
            raise ValueError(f"Invalid --auth-header value: {item}. Expected Key:Value")
        key, value = item.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"Invalid --auth-header value: {item}. Header name cannot be empty")
        out[key] = value
    return out


def _parse_cookie_list(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Invalid --cookie value: {item}. Expected key=value")
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"Invalid --cookie value: {item}. Cookie name cannot be empty")
        out[key] = value
    return out


def scan_target(
    target: str,
    timeout: int,
    auth_headers: dict[str, str] | None = None,
    auth_cookies: dict[str, str] | None = None,
    max_pages: int = 20,
    max_depth: int = 2,
    enable_nuclei: bool = False,
    nuclei_templates: str | None = None,
    nuclei_severities: list[str] | None = None,
    nuclei_tags: list[str] | None = None,
    zap_base_url: str | None = None,
    auth_login_url: str | None = None,
    auth_login_method: str = "POST",
    auth_login_form: dict[str, str] | None = None,
    auth_login_json: dict[str, object] | None = None,
    mode: str = "standard",
    workers: int = 8,
    rate_limit_rps: int = 15,
) -> TargetReport:
    resolved_ips = resolve_ips(target)
    report = TargetReport(
        target=target,
        resolved_ips=resolved_ips,
        metadata={
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "tool": "vapt-tool",
            "version": "1.0.0",
            "mode": mode,
            "auth_mode": bool(auth_headers or auth_cookies),
            "auth_header_count": len(auth_headers or {}),
            "auth_cookie_count": len(auth_cookies or {}),
            "workers": workers,
        },
    )

    report.results = run_all_checks(
        target,
        timeout=timeout,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
        auth_login_url=auth_login_url,
        auth_login_method=auth_login_method,
        auth_login_form=auth_login_form,
        auth_login_json=auth_login_json,
        max_pages=max_pages,
        max_depth=max_depth,
        enable_nuclei=enable_nuclei,
        nuclei_templates=nuclei_templates,
        nuclei_severities=nuclei_severities,
        nuclei_tags=nuclei_tags,
        zap_base_url=zap_base_url,
        mode=mode,
        workers=workers,
        rate_limit_rps=rate_limit_rps,
    )
    return report


def print_summary(report: TargetReport, mode: str = "standard") -> None:
    table = Table(
        title=f"🔍 Scan Summary: {report.target}" + (" [BOUNTY MODE]" if mode == "bounty" else ""),
        title_style="bold cyan",
    )
    table.add_column("Check", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Details", max_width=60)

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    status_icons = {
        "ok": "[green]✓[/]",
        "warning": "[yellow]⚠[/]",
        "error": "[red]✗[/]",
    }

    for result in report.results:
        sev_style = severity_colors.get(result.severity, "white")
        status_icon = status_icons.get(result.status, result.status)
        table.add_row(
            result.name,
            status_icon,
            f"[{sev_style}]{result.severity.upper()}[/]",
            result.details[:60],
        )

    console.print(table)

    # Print high-value findings summary
    high_value = [r for r in report.results if r.status == "warning" and r.severity in ("critical", "high")]
    if high_value:
        console.print(f"\n[bold red]🔥 {len(high_value)} HIGH-VALUE FINDINGS:[/]")
        for r in high_value:
            console.print(f"  [red]•[/] [{severity_colors.get(r.severity, 'white')}]{r.severity.upper()}[/] — {r.name}: {r.details[:80]}")


def interactive_add_program() -> None:
    """Interactively add a new program via CLI prompts."""
    from vapt_tool.programs import Program, ProgramManager, BountyTable

    console.print(Panel("[bold cyan]Add Bug Bounty Program[/]", border_style="cyan"))

    name = console.input("[bold]Program name:[/] ").strip()
    if not name:
        console.print("[red]Name cannot be empty[/]")
        return

    platform = console.input("[bold]Platform[/] (hackerone/bugcrowd/intigriti/custom) [custom]: ").strip() or "custom"
    url = console.input("[bold]Program URL[/] (optional): ").strip()
    in_scope_text = console.input("[bold]In-scope domains[/] (comma-separated): ").strip()
    out_scope_text = console.input("[bold]Out-of-scope domains[/] (comma-separated, optional): ").strip()
    notes = console.input("[bold]Notes[/] (optional): ").strip()

    in_scope = [x.strip() for x in in_scope_text.split(",") if x.strip()]
    out_scope = [x.strip() for x in out_scope_text.split(",") if x.strip()] if out_scope_text else []

    program = Program(
        name=name,
        platform=platform,
        url=url,
        status="active",
        in_scope=in_scope,
        out_scope=out_scope,
        notes=notes,
    )

    manager = ProgramManager()
    manager.add_program(program)
    console.print(f"[green]✓ Program '{name}' saved with {len(in_scope)} in-scope target(s)[/]")


def list_programs_table(programs_file: str = "programs.json") -> None:
    """Display saved programs in a formatted table."""
    from vapt_tool.programs import ProgramManager

    manager = ProgramManager(Path(programs_file))
    programs = manager.list_programs()

    if not programs:
        console.print("[yellow]No programs saved. Use --add-program to add one.[/]")
        return

    table = Table(title="🏆 Bug Bounty Programs", title_style="bold cyan")
    table.add_column("Name", style="bold white")
    table.add_column("Platform", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("In-Scope", justify="right")
    table.add_column("URL")

    status_styles = {"active": "green", "paused": "yellow", "invited": "cyan"}
    for p in programs:
        style = status_styles.get(p.status, "white")
        table.add_row(
            p.name,
            p.platform,
            f"[{style}]{p.status}[/]",
            str(len(p.in_scope)),
            p.url[:50] if p.url else "—",
        )

    console.print(table)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Program management commands
    if args.add_program:
        interactive_add_program()
        return 0

    if args.list_programs:
        list_programs_table(args.programs_file)
        return 0

    # Scan from program
    if args.scan_program:
        from vapt_tool.programs import ProgramManager
        manager = ProgramManager(Path(args.programs_file))
        program = manager.get_program(args.scan_program)
        if not program:
            console.print(f"[red]Program '{args.scan_program}' not found. Use --list-programs to see saved programs.[/]")
            return 1

        console.print(f"[cyan]Scanning program:[/] {program.name} ({len(program.in_scope)} targets)")
        targets = program.in_scope
        # Force bounty mode for program scans
        args.mode = "bounty"
    elif not args.target and not args.targets_file:
        parser.error("Provide --target, --targets-file, or --scan-program")
        return 1
    else:
        targets = load_targets(args.target, args.targets_file)

    validate_authorization()

    auth_headers = _parse_header_list(args.auth_header)
    auth_cookies = _parse_cookie_list(args.cookie)
    if args.bearer_token:
        auth_headers["Authorization"] = f"Bearer {args.bearer_token}"

    include: set[str] = set()
    exclude: set[str] = set()
    if args.scope_file:
        scope_path = Path(args.scope_file)
        if not scope_path.exists():
            raise FileNotFoundError(f"Scope file not found: {args.scope_file}")
        include, exclude = parse_scope_file(scope_path)

    out_dir = Path(args.out_dir)
    formats = {x.strip().lower() for x in args.format.split(",") if x.strip()}

    # If bounty mode, auto-include bounty format
    if args.mode == "bounty" and "bounty" not in formats:
        formats.add("bounty")

    scanned = 0
    for t in targets:
        if args.strict_scope and not in_scope(t, include, exclude):
            console.print(f"[yellow]Skipping out-of-scope target:[/] {t}")
            continue

        mode_label = "[bold magenta]BOUNTY[/]" if args.mode == "bounty" else "[cyan]STANDARD[/]"
        console.print(f"\n{mode_label} [cyan]Scanning target:[/] {t} (workers={args.workers})")

        login_form = None
        if args.auth_login_form:
            login_form = dict(x.split("=", 1) for x in args.auth_login_form.split("&") if "=" in x)

        login_json = None
        if args.auth_login_json:
            login_json = json.loads(args.auth_login_json)

        report = scan_target(
            t,
            timeout=args.timeout,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            enable_nuclei=args.enable_nuclei,
            nuclei_templates=args.nuclei_templates,
            nuclei_severities=[x for x in args.nuclei_severity.split(",") if x],
            nuclei_tags=[x for x in (args.nuclei_tags or "").split(",") if x],
            zap_base_url=args.zap_base_url,
            auth_login_url=args.auth_login_url,
            auth_login_method=args.auth_login_method,
            auth_login_form=login_form,
            auth_login_json=login_json,
            mode=args.mode,
            workers=args.workers,
            rate_limit_rps=args.rate_limit,
        )
        print_summary(report, mode=args.mode)

        safe_name = t.replace(":", "_").replace("/", "_")
        if "json" in formats:
            write_json_report(report, out_dir / f"{safe_name}.json")
        if "md" in formats:
            write_markdown_report(report, out_dir / f"{safe_name}.md")
        if "bounty" in formats:
            program_name = args.scan_program or ""
            write_bounty_report(report, out_dir / f"{safe_name}_bounty.md", program_name=program_name)

        scanned += 1

    if scanned == 0:
        console.print("[red]No targets scanned. Check scope settings.[/]")
        return 1

    console.print(f"\n[green]✅ Completed.[/] {scanned} target(s) scanned. Reports written to: {out_dir}")
    if "bounty" in formats:
        console.print("[bold magenta]📋 Bounty submission reports generated (look for *_bounty.md files)[/]")
    return 0
