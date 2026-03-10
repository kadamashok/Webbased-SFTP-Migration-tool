from __future__ import annotations

import shlex
from typing import Any

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.schemas import (
    ConnectivityResponse,
    DiscoveryRequest,
    JobLogsResponse,
    JobStartResponse,
    JobStatusResponse,
    MigrationRequest,
)
from app.services.connectivity_gate import connectivity_gate
from app.services.job_store import job_store
from app.services.migration_service import migration_service
from app.services.cron_script_discovery import (
    analyze_script_dependencies,
    discover_cron_jobs,
    discover_scripts,
    migrate_scripts,
    recreate_cron_jobs,
)
from app.services.discovery_engine import (
    get_last_report as get_discovery_last_report,
    report_to_csv as discovery_report_to_csv,
    run_full_discovery,
    set_last_report as set_discovery_last_report,
)
from app.services.ssh_client import (
    SSHAuthError,
    SSHCommandError,
    SSHConnectionError,
    SSHNetworkError,
)

router = APIRouter()


def _build_auth(payload: dict[str, Any], side: str):
    from app.models.schemas import SSHAuth

    host = str(payload.get("host", "")).strip()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    private_key = str(payload.get("private_key", "")).strip()
    sudo = bool(payload.get("sudo", True))

    if not host or " " in host:
        raise HTTPException(status_code=400, detail=f"Enter valid {side} IP or Hostname")
    if not username:
        raise HTTPException(status_code=400, detail=f"Enter {side} username")
    if not password and not private_key:
        raise HTTPException(status_code=400, detail=f"Enter {side} password or SSH key")

    try:
        port = int(payload.get("port", 22))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Enter valid {side} SSH port") from exc
    if port <= 0 or port > 65535:
        raise HTTPException(status_code=400, detail=f"Enter valid {side} SSH port")

    return SSHAuth(
        host=host,
        port=port,
        username=username,
        password=password or None,
        private_key=private_key or None,
        sudo=sudo,
    )


def _raise_friendly_ssh_error(exc: Exception) -> None:
    if isinstance(exc, HTTPException):
        raise exc
    if isinstance(exc, SSHAuthError):
        raise HTTPException(
            status_code=400,
            detail="Authentication failed. Invalid username or password.",
        ) from exc
    if isinstance(exc, SSHNetworkError):
        raise HTTPException(
            status_code=400,
            detail="Unable to reach server. Check network or firewall.",
        ) from exc
    if isinstance(exc, SSHConnectionError):
        raise HTTPException(status_code=400, detail="SSH connection failed.") from exc
    if isinstance(exc, SSHCommandError):
        if "sudo" in str(exc).lower() or "privilege" in str(exc).lower():
            raise HTTPException(
                status_code=400,
                detail="SSH access validation failed. Use root or passwordless sudo.",
            ) from exc
        raise HTTPException(status_code=400, detail="SSH connection failed.") from exc
    raise HTTPException(status_code=400, detail="SSH connection failed.") from exc


@router.post("/test/source", response_model=ConnectivityResponse)
def test_source_connectivity(req: dict[str, Any]) -> ConnectivityResponse:
    try:
        source_auth = _build_auth(req, "Source")
        data = migration_service.test_server_connectivity(source_auth)
        connectivity_gate.mark_source(source_auth)
        return ConnectivityResponse(**data)
    except Exception as exc:
        _raise_friendly_ssh_error(exc)


@router.post("/test/destination", response_model=ConnectivityResponse)
def test_destination_connectivity(req: dict[str, Any]) -> ConnectivityResponse:
    try:
        destination_auth = _build_auth(req, "Destination")
        data = migration_service.test_server_connectivity(destination_auth)
        connectivity_gate.mark_destination(destination_auth)
        return ConnectivityResponse(**data)
    except Exception as exc:
        _raise_friendly_ssh_error(exc)


@router.post("/migration/dry-run", response_model=JobStartResponse)
def dry_run(req: MigrationRequest) -> JobStartResponse:
    _build_auth(req.source.model_dump(), "Source")
    _build_auth(req.destination.model_dump(), "Destination")
    ok, reason = connectivity_gate.validate(req)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)
    job = job_store.create()
    migration_service.start_job(job.id, req, dry_run=True)
    return JobStartResponse(job_id=job.id)


@router.post("/migration/start", response_model=JobStartResponse)
def start(req: MigrationRequest) -> JobStartResponse:
    _build_auth(req.source.model_dump(), "Source")
    _build_auth(req.destination.model_dump(), "Destination")
    ok, reason = connectivity_gate.validate(req)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)
    job = job_store.create()
    migration_service.start_job(job.id, req, dry_run=False)
    return JobStartResponse(job_id=job.id)


@router.get("/migration/{job_id}/status", response_model=JobStatusResponse)
def status(job_id: str) -> JobStatusResponse:
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(
        job_id=job.id, status=job.status, progress=job.progress, detail=job.detail
    )


@router.get("/migration/{job_id}/logs", response_model=JobLogsResponse)
def logs(job_id: str) -> JobLogsResponse:
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobLogsResponse(job_id=job.id, logs=job.logs)


@router.get("/migration/logs", response_model=JobLogsResponse)
def logs_query(job_id: str) -> JobLogsResponse:
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobLogsResponse(job_id=job.id, logs=job.logs)


@router.get("/migration/{job_id}/report")
def report(job_id: str) -> dict:
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.report


@router.post("/scan-scripts")
def scan_scripts(req: MigrationRequest) -> dict:
    # Dry-run discovery: read-only operations on source.
    try:
        _build_auth(req.source.model_dump(), "Source")
        with SSHClientWrapper(**req.source.model_dump()) as src:
            cron_jobs, users = discover_cron_jobs(src, req.sftp_group, sudo=req.source.sudo)
            script_paths, scripts_from_cron, warnings = discover_scripts(
                src, cron_jobs=cron_jobs, users=users, sudo=req.source.sudo
            )
            analyses, keys_detected = analyze_script_dependencies(
                src, script_paths=script_paths, sudo=req.source.sudo
            )

            rows: list[dict] = []
            seen = set()
            for p, jobs in scripts_from_cron.items():
                ap = analyses.get(p)
                for j in jobs:
                    key = (p, j.schedule, j.command, j.owner, j.source)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append(
                        {
                            "script_path": p,
                            "owner": (ap.owner if ap else "unknown"),
                            "cron_schedule": j.schedule,
                            "command": j.command,
                            "dependencies": (ap.dependencies if ap else []),
                            "uses_ssh_sftp": (ap.uses_ssh_sftp if ap else False),
                            "uses_private_key": (ap.uses_private_key if ap else False),
                            "notes": (ap.notes if ap else f"From {j.source}"),
                        }
                    )

            # Include scripts found via directory scans but not tied to a cron entry.
            for p in script_paths:
                if p in scripts_from_cron:
                    continue
                ap = analyses.get(p)
                rows.append(
                    {
                        "script_path": p,
                        "owner": (ap.owner if ap else "unknown"),
                        "cron_schedule": "",
                        "command": "",
                        "dependencies": (ap.dependencies if ap else []),
                        "uses_ssh_sftp": (ap.uses_ssh_sftp if ap else False),
                        "uses_private_key": (ap.uses_private_key if ap else False),
                        "notes": (ap.notes if ap else "Found in common script directories"),
                    }
                )

            return {
                "dry_run": True,
                "cron_jobs_discovered": len(cron_jobs),
                "scripts_discovered": len(script_paths),
                "keys_detected": keys_detected,
                "warnings": warnings,
                "rows": rows,
            }
    except Exception as exc:
        _raise_friendly_ssh_error(exc)


@router.post("/migrate-scripts")
def migrate_scripts_and_cron(req: MigrationRequest) -> dict:
    try:
        _build_auth(req.source.model_dump(), "Source")
        _build_auth(req.destination.model_dump(), "Destination")
        ok, reason = connectivity_gate.validate(req)
        if not ok:
            raise HTTPException(status_code=400, detail=reason)

        with SSHClientWrapper(**req.source.model_dump()) as src, SSHClientWrapper(
            **req.destination.model_dump()
        ) as dst:
            cron_jobs, users = discover_cron_jobs(src, req.sftp_group, sudo=req.source.sudo)
            script_paths, _, warnings = discover_scripts(src, cron_jobs=cron_jobs, users=users, sudo=req.source.sudo)
            analyses, keys_detected = analyze_script_dependencies(src, script_paths=script_paths, sudo=req.source.sudo)

            # Copy ~/.ssh only when referenced in scripts.
            key_dirs: set[str] = set()
            for ap in analyses.values():
                for kp in ap.key_paths:
                    k = kp.strip()
                    if not k:
                        continue
                    if "/.ssh/" in k:
                        key_dirs.add(k.split("/.ssh/", 1)[0] + "/.ssh")
                    if k.startswith("/opt/keys/"):
                        key_dirs.add("/opt/keys")
                    if k.endswith(".pem") or k.endswith(".key"):
                        if k.startswith("/"):
                            key_dirs.add(k.rsplit("/", 1)[0])
            copied, copy_warnings = migrate_scripts(
                src, dst, req, script_paths=script_paths, key_dirs=sorted(key_dirs)
            )
            warnings.extend(copy_warnings)

            user_crons, system_files, cron_warnings = recreate_cron_jobs(
                src, dst, req, cron_jobs=cron_jobs, users=users
            )
            warnings.extend(cron_warnings)

            # Validation on destination
            validation_warnings: list[str] = []
            missing_deps: set[str] = set()
            for ap in analyses.values():
                if dst.run(f"test -f {shlex.quote(ap.script_path)}", sudo=req.destination.sudo, check=False).code != 0:
                    validation_warnings.append(f"Missing on destination: {ap.script_path}")
                    continue
                if dst.run(f"test -x {shlex.quote(ap.script_path)}", sudo=req.destination.sudo, check=False).code != 0:
                    validation_warnings.append(f"Not executable on destination: {ap.script_path}")
                for d in ap.dependencies:
                    if dst.run(f"command -v {shlex.quote(d)} >/dev/null 2>&1", sudo=req.destination.sudo, check=False).code != 0:
                        missing_deps.add(d)
            if missing_deps:
                validation_warnings.append("Missing dependencies on destination: " + ", ".join(sorted(missing_deps)))

            warnings.extend(validation_warnings)

            return {
                "dry_run": False,
                "cron_jobs_discovered": len(cron_jobs),
                "scripts_copied": copied,
                "keys_detected": keys_detected,
                "user_crontabs_updated": user_crons,
                "system_cron_files_written": system_files,
                "warnings": warnings,
            }
    except Exception as exc:
        _raise_friendly_ssh_error(exc)


@router.post("/discovery/run")
def discovery_run(req: DiscoveryRequest) -> dict:
    # Read-only discovery. Never writes to source.
    try:
        source_auth = _build_auth(req.source.model_dump(), "Source")
        report = run_full_discovery(
            source_auth,
            sftp_group=req.sftp_group,
            max_scripts=req.max_scripts,
        )
        set_discovery_last_report(report)
        return report
    except Exception as exc:
        _raise_friendly_ssh_error(exc)


@router.get("/discovery/report")
def discovery_report(format: str = "json") -> Response:
    report = get_discovery_last_report()
    if not report:
        raise HTTPException(status_code=404, detail="No discovery report available. Run discovery first.")

    ts = report.get("generated_at", "report").replace(":", "-")
    if format.lower() == "csv":
        csv_text = discovery_report_to_csv(report)
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename=\"discovery-report-{ts}.csv\"'},
        )

    # default json
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename=\"discovery-report-{ts}.json\"'},
    )
