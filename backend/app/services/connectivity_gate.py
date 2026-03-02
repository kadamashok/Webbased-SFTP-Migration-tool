from __future__ import annotations

import hashlib
import threading
import time

from app.models.schemas import MigrationRequest, SSHAuth


class ConnectivityGate:
    def __init__(self, ttl_seconds: int = 1800) -> None:
        self._ttl = ttl_seconds
        self._source_state: dict[str, float] = {}
        self._destination_state: dict[str, float] = {}
        self._lock = threading.Lock()

    def _fingerprint_auth(self, auth: SSHAuth) -> str:
        pwd = (auth.password or "").strip()
        key = (auth.private_key or "").strip()
        secret_hash = hashlib.sha256(f"{pwd}|{key}".encode("utf-8")).hexdigest()
        basis = f"{auth.host.strip()}:{auth.port}:{auth.username.strip()}:{auth.sudo}:{secret_hash}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()

    def mark_source(self, auth: SSHAuth) -> None:
        with self._lock:
            self._source_state[self._fingerprint_auth(auth)] = time.time()

    def mark_destination(self, auth: SSHAuth) -> None:
        with self._lock:
            self._destination_state[self._fingerprint_auth(auth)] = time.time()

    def _is_valid(self, state: dict[str, float], key: str, now: float) -> bool:
        ts = state.get(key)
        if ts is None:
            return False
        if now - ts > self._ttl:
            state.pop(key, None)
            return False
        return True

    def validate(self, req: MigrationRequest) -> tuple[bool, str]:
        now = time.time()
        source_key = self._fingerprint_auth(req.source)
        destination_key = self._fingerprint_auth(req.destination)
        with self._lock:
            source_ok = self._is_valid(self._source_state, source_key, now)
            destination_ok = self._is_valid(self._destination_state, destination_key, now)

            if not source_ok and not destination_ok:
                return False, "Both connectivity tests are required before migration"
            if not source_ok:
                return False, "Source connectivity test is required before migration"
            if not destination_ok:
                return False, "Destination connectivity test is required before migration"

            return True, "OK"


connectivity_gate = ConnectivityGate()
