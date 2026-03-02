from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app.models.schemas import (
    ConnectivityResponse,
    JobLogsResponse,
    JobStartResponse,
    JobStatusResponse,
    MigrationRequest,
)
from app.services.connectivity_gate import connectivity_gate
from app.services.job_store import job_store
from app.services.migration_service import migration_service
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
