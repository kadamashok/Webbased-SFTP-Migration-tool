from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass

from app.models.schemas import MigrationRequest, SSHAuth


@dataclass
class GateState:
    source_ok: bool = False
    destination_ok: bool = False
    source_ts: float = 0.0
    destination_ts: float = 0.0


class ConnectivityGate:
    def __init__(self, ttl_seconds: int = 1800) -> None:
        self._ttl = ttl_seconds
        self._state: dict[str, GateState] = {}
        self._lock = threading.Lock()

    def _fingerprint_auth(self, auth: SSHAuth) -> str:
        pwd = auth.password or ""
        key = auth.private_key or ""
        secret_hash = hashlib.sha256(f"{pwd}|{key}".encode("utf-8")).hexdigest()
        return f"{auth.host}:{auth.port}:{auth.username}:{auth.sudo}:{secret_hash}"

    def migration_key(self, req: MigrationRequest) -> str:
        src = self._fingerprint_auth(req.source)
        dst = self._fingerprint_auth(req.destination)
        return hashlib.sha256(f"{src}::{dst}".encode("utf-8")).hexdigest()

    def mark_source(self, req: MigrationRequest) -> None:
        self._mark(self.migration_key(req), "source")

    def mark_destination(self, req: MigrationRequest) -> None:
        self._mark(self.migration_key(req), "destination")

    def _mark(self, key: str, side: str) -> None:
        now = time.time()
        with self._lock:
            state = self._state.setdefault(key, GateState())
            if side == "source":
                state.source_ok = True
                state.source_ts = now
            else:
                state.destination_ok = True
                state.destination_ts = now

    def validate(self, req: MigrationRequest) -> tuple[bool, str]:
        key = self.migration_key(req)
        now = time.time()
        with self._lock:
            state = self._state.get(key)
            if not state:
                return False, "Connectivity tests missing for source and destination"

            if state.source_ok and now - state.source_ts > self._ttl:
                state.source_ok = False
            if state.destination_ok and now - state.destination_ts > self._ttl:
                state.destination_ok = False

            if not state.source_ok and not state.destination_ok:
                return False, "Both connectivity tests are required before migration"
            if not state.source_ok:
                return False, "Source connectivity test is required before migration"
            if not state.destination_ok:
                return False, "Destination connectivity test is required before migration"

            return True, "OK"


connectivity_gate = ConnectivityGate()
