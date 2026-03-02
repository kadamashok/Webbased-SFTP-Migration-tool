from __future__ import annotations

import shutil
from pathlib import Path


def copy_logo() -> str:
    workspace = Path(__file__).resolve().parents[1]
    destination = workspace / "frontend" / "static" / "croma-logo.png"
    destination.parent.mkdir(parents=True, exist_ok=True)

    home = Path.home()
    candidates = [
        home / "Desktop" / "sftp1" / "logo.png",
        home / "Desktop" / "SFTP1" / "logo.png",
        workspace / "logo.png",
    ]

    source = next((path for path in candidates if path.exists()), None)
    if not source:
        raise FileNotFoundError(
            "Logo not found. Expected one of: "
            + ", ".join(str(path) for path in candidates)
        )

    shutil.copy2(source, destination)
    return f"Copied logo: {source} -> {destination}"


if __name__ == "__main__":
    print(copy_logo())
