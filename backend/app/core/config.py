from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_name: str = "SFTP Migration Tool"
    log_dir: Path = Path("backend/logs")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
