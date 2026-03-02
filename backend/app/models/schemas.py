from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


class SSHAuth(BaseModel):
    host: str = Field(..., min_length=1)
    port: int = Field(22, ge=1, le=65535)
    username: str = Field(..., min_length=1)
    password: Optional[str] = None
    private_key: Optional[str] = None
    sudo: bool = True

    @model_validator(mode="after")
    def validate_auth(self) -> "SSHAuth":
        if not self.password and not self.private_key:
            raise ValueError("Either password or private_key must be provided")
        return self


class MigrationRequest(BaseModel):
    source: SSHAuth
    destination: SSHAuth
    sftp_group: str = Field("sftpusers", min_length=1)
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
