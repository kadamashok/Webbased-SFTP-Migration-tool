from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Literal


JobState = Literal["pending", "running", "completed", "failed"]


@dataclass
class Job:
    id: str
    status: JobState = "pending"
    progress: int = 0
    detail: str = "Queued"
    logs: list[str] = field(default_factory=list)
    report: dict = field(default_factory=dict)


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self) -> Job:
        with self._lock:
            job_id = str(uuid.uuid4())
            job = Job(id=job_id)
            self._jobs[job_id] = job
            return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **kwargs) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for key, value in kwargs.items():
                setattr(job, key, value)

    def append_log(self, job_id: str, message: str) -> None:
        with self._lock:
            self._jobs[job_id].logs.append(message)


job_store = JobStore()
