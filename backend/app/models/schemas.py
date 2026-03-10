from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class SSHAuth(BaseModel):
    host: str = ""
    port: int = Field(22, ge=1, le=65535)
    username: str = ""
    password: Optional[str] = None
    private_key: Optional[str] = None
    sudo: bool = True


class MigrationRequest(BaseModel):
    source: SSHAuth
    destination: SSHAuth
    sftp_group: str = "sftpusers"
    incremental: bool = True
    rsync_delete: bool = False
    sample_sftp_user: Optional[str] = None


class ConnectivityResponse(BaseModel):
    ok: bool
    os_release: str
    whoami: str
    disk_summary: str
    access: Literal["root", "sudo", "denied"]
    detail: str


class JobStartResponse(BaseModel):
    job_id: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: Literal["pending", "running", "completed", "failed"]
    progress: int
    detail: str


class JobLogsResponse(BaseModel):
    job_id: str
    logs: list[str]


class DiscoveryRequest(BaseModel):
    source: SSHAuth
    sftp_group: str = "sftpusers"
    max_scripts: int = Field(800, ge=50, le=5000)
