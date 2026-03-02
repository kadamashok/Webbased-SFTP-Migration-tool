from __future__ import annotations

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

router = APIRouter()


@router.post("/test/source", response_model=ConnectivityResponse)
def test_source_connectivity(req: MigrationRequest) -> ConnectivityResponse:
    try:
        data = migration_service.test_server_connectivity(req.source)
        connectivity_gate.mark_source(req)
        return ConnectivityResponse(**data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/test/destination", response_model=ConnectivityResponse)
def test_destination_connectivity(req: MigrationRequest) -> ConnectivityResponse:
    try:
        data = migration_service.test_server_connectivity(req.destination)
        connectivity_gate.mark_destination(req)
        return ConnectivityResponse(**data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/migration/dry-run", response_model=JobStartResponse)
def dry_run(req: MigrationRequest) -> JobStartResponse:
    ok, reason = connectivity_gate.validate(req)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)
    job = job_store.create()
    migration_service.start_job(job.id, req, dry_run=True)
    return JobStartResponse(job_id=job.id)


@router.post("/migration/start", response_model=JobStartResponse)
def start(req: MigrationRequest) -> JobStartResponse:
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
