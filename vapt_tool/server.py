from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread, Lock
from time import time
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from vapt_tool.checks import resolve_ips, run_all_checks
from vapt_tool.models import TargetReport
from vapt_tool.reporting import (
    build_report_payload,
    write_json_report,
    write_bounty_report,
    generate_single_finding_report,
)

app = FastAPI(title="VAPT Bug Bounty Toolkit API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str = Field(..., description="Domain, IP, or URL")
    timeout: int = Field(8, ge=1, le=60)
    auth_headers: dict[str, str] = Field(default_factory=dict)
    auth_cookies: dict[str, str] = Field(default_factory=dict)
    bearer_token: str | None = None
    max_pages: int = Field(20, ge=1, le=200)
    max_depth: int = Field(2, ge=0, le=5)
    enable_nuclei: bool = False
    nuclei_templates: str | None = None
    nuclei_severities: list[str] = Field(default_factory=lambda: ["low", "medium", "high", "critical"])
    nuclei_tags: list[str] = Field(default_factory=list)
    zap_base_url: str | None = None
    auth_login_url: str | None = None
    auth_login_method: str = "POST"
    auth_login_form: dict[str, str] = Field(default_factory=dict)
    auth_login_json: dict[str, Any] = Field(default_factory=dict)
    write_report: bool = True
    out_dir: str = "reports"
    mode: str = Field("standard", description="Scan mode: standard or bounty")
    workers: int = Field(8, ge=1, le=32)
    rate_limit_rps: int = Field(15, ge=1, le=100)


class ScanResponse(BaseModel):
    report: dict[str, Any]
    saved_path: str | None = None


class ScanStartResponse(BaseModel):
    job_id: str
    estimate_seconds: int


class ScanStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: int
    current_step: str | None = None
    logs: list[dict[str, Any]] = []
    estimate_seconds: int
    elapsed_seconds: int
    report: dict[str, Any] | None = None
    saved_path: str | None = None


class ProgramModel(BaseModel):
    name: str
    platform: str = "custom"
    url: str = ""
    status: str = "active"
    in_scope: list[str] = Field(default_factory=list)
    out_scope: list[str] = Field(default_factory=list)
    bounty_table: dict[str, str] = Field(default_factory=lambda: {
        "critical": "$1000–$5000",
        "high": "$500–$2000",
        "medium": "$100–$500",
        "low": "$25–$100",
        "info": "$0",
    })
    notes: str = ""
    tags: list[str] = Field(default_factory=list)


class FindingReportRequest(BaseModel):
    target: str
    finding_name: str


JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = Lock()


def _estimate_seconds(request: ScanRequest) -> int:
    base = 18
    crawl = min(request.max_pages, 200) * 1
    depth_penalty = request.max_depth * 3
    nuclei = 60 if request.enable_nuclei else 0
    zap = 20 if request.zap_base_url else 0
    bounty = 90 if request.mode == "bounty" else 0
    concurrency_bonus = max(1, request.workers // 4)
    return int((base + crawl + depth_penalty + nuclei + zap + bounty) / concurrency_bonus)


def _build_report(
    target: str,
    timeout: int,
    auth_headers: dict[str, str],
    auth_cookies: dict[str, str],
    max_pages: int,
    max_depth: int,
    enable_nuclei: bool,
    nuclei_templates: str | None,
    nuclei_severities: list[str],
    nuclei_tags: list[str],
    zap_base_url: str | None,
    auth_login_url: str | None,
    auth_login_method: str,
    auth_login_form: dict[str, str],
    auth_login_json: dict[str, Any],
    mode: str = "standard",
    workers: int = 8,
    rate_limit_rps: int = 15,
    progress_cb=None,
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
        progress_cb=progress_cb,
    )
    return report


# ── Scan Endpoints ──────────────────────────────────────────

@app.post("/scan/start", response_model=ScanStartResponse)
def scan_start(request: ScanRequest) -> ScanStartResponse:
    job_id = str(uuid4())
    estimate = _estimate_seconds(request)

    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "queued",
            "progress": 0,
            "current_step": None,
            "logs": [],
            "estimate_seconds": estimate,
            "started_at": time(),
            "report": None,
            "saved_path": None,
        }

    def _progress_cb(step: str, state: str, meta: dict[str, Any]):
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return
            job["current_step"] = step
            job["logs"].append({"step": step, "state": state, "meta": meta, "ts": time()})
            job["progress"] = min(98, job.get("progress", 0) + 3)

    def _run():
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "running"

        headers = dict(request.auth_headers)
        if request.bearer_token:
            headers["Authorization"] = f"Bearer {request.bearer_token}"

        report = _build_report(
            request.target,
            request.timeout,
            headers,
            dict(request.auth_cookies),
            request.max_pages,
            request.max_depth,
            request.enable_nuclei,
            request.nuclei_templates,
            request.nuclei_severities,
            request.nuclei_tags,
            request.zap_base_url,
            request.auth_login_url,
            request.auth_login_method,
            dict(request.auth_login_form),
            dict(request.auth_login_json),
            mode=request.mode,
            workers=request.workers,
            rate_limit_rps=request.rate_limit_rps,
            progress_cb=_progress_cb,
        )
        payload = build_report_payload(report)

        saved_path = None
        if request.write_report:
            out_dir = Path(request.out_dir)
            safe_name = request.target.replace(":", "_").replace("/", "_")
            path = out_dir / f"{safe_name}.json"
            write_json_report(report, path)
            saved_path = str(path)

            # Also generate bounty report in bounty mode
            if request.mode == "bounty":
                bounty_path = out_dir / f"{safe_name}_bounty.md"
                write_bounty_report(report, bounty_path)

        with JOBS_LOCK:
            job = JOBS[job_id]
            job["status"] = "complete"
            job["progress"] = 100
            job["report"] = payload
            job["saved_path"] = saved_path

    Thread(target=_run, daemon=True).start()
    return ScanStartResponse(job_id=job_id, estimate_seconds=estimate)


@app.get("/scan/status/{job_id}", response_model=ScanStatusResponse)
def scan_status(job_id: str) -> ScanStatusResponse:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return ScanStatusResponse(
                job_id=job_id,
                status="missing",
                progress=0,
                current_step=None,
                logs=[],
                estimate_seconds=0,
                elapsed_seconds=0,
                report=None,
                saved_path=None,
            )
        elapsed = int(time() - job.get("started_at", time()))
        return ScanStatusResponse(
            job_id=job_id,
            status=job["status"],
            progress=job["progress"],
            current_step=job.get("current_step"),
            logs=job.get("logs", [])[-30:],
            estimate_seconds=job.get("estimate_seconds", 0),
            elapsed_seconds=elapsed,
            report=job.get("report"),
            saved_path=job.get("saved_path"),
        )


# ── Program Management Endpoints ────────────────────────────

@app.get("/programs")
def list_programs():
    from vapt_tool.programs import ProgramManager
    manager = ProgramManager()
    return manager.to_dict_list()


@app.post("/programs")
def add_program(program: ProgramModel):
    from vapt_tool.programs import Program, ProgramManager, BountyTable
    bt = BountyTable(**program.bounty_table) if program.bounty_table else BountyTable()
    p = Program(
        name=program.name,
        platform=program.platform,
        url=program.url,
        status=program.status,
        in_scope=program.in_scope,
        out_scope=program.out_scope,
        bounty_table=bt,
        notes=program.notes,
        tags=program.tags,
    )
    manager = ProgramManager()
    manager.add_program(p)
    return {"status": "ok", "name": program.name}


@app.delete("/programs/{name}")
def delete_program(name: str):
    from vapt_tool.programs import ProgramManager
    manager = ProgramManager()
    if manager.remove_program(name):
        return {"status": "ok", "deleted": name}
    raise HTTPException(status_code=404, detail=f"Program '{name}' not found")


# ── Report Generation Endpoints ─────────────────────────────

@app.post("/reports/finding")
def generate_finding_report(req: FindingReportRequest):
    """Generate a copy-paste submission report for a single finding from the last scan."""
    with JOBS_LOCK:
        for job_id in reversed(list(JOBS.keys())):
            job = JOBS[job_id]
            if job.get("status") == "complete" and job.get("report"):
                report_data = job["report"]
                if report_data.get("target") == req.target:
                    for result in report_data.get("results", []):
                        if result.get("name") == req.finding_name:
                            # Build a minimal result object
                            from types import SimpleNamespace
                            r = SimpleNamespace(
                                name=result["name"],
                                severity=result["severity"],
                                status=result["status"],
                                details=result["details"],
                                evidence=result.get("evidence", {}),
                                recommendations=result.get("recommendations", []),
                            )
                            md = generate_single_finding_report(r, req.target)
                            return {"markdown": md}

    raise HTTPException(status_code=404, detail="Finding not found in recent scans")
