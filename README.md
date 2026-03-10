# Croma - SFTP Migration Tool

Internal web tool to migrate SFTP workloads from Oracle Linux (source) to RHEL 9 (destination) using SSH-driven operations.

## Tech Stack

- Backend: Python, FastAPI, Uvicorn, Paramiko, Pydantic
- Frontend: single-page HTML/CSS/JavaScript (served via `python -m http.server`)
- Transport: SSH + rsync (optional `sshpass` for password-based rsync)

## What It Does

- Runs independent connectivity checks for source and destination.
- Blocks migration unless both checks pass.
- Migrates SFTP users, groups, UID/GID, password hashes, SSH keys, data, and SFTP/sshd configuration.
- Applies RHEL 9 SELinux adjustments and performs post-migration validation.
- Provides live migration status and logs in a single-page UI.
- Provides a read-only discovery engine to enumerate integrations (cron/scripts/systemd/external hosts) before migration.

## Key Features

- Croma-branded internal UI:
  - Header: `Croma - SFTP Migration Tool`
  - Local logo path: `/static/croma-logo.png`
  - Footer: `Developed by Ashok Kadam using AI`
- Separate server test buttons:
  - `Test Source Connectivity`
  - `Test Destination Connectivity`
- Connectivity test outputs:
  - SSH success/failure
  - OS details (`/etc/os-release`)
  - Access context (`root`/`sudo`)
  - Disk summary (`df -h`)
- Migration controls:
  - `Dry Run Migration`
  - `Start Migration` (disabled until both tests succeed)

## Scripts / Cron Jobs Discovery

The `Scripts / Cron Jobs` tab discovers and migrates automation components:

Dry run discovery (read-only on source):

- User crontabs via `crontab -l -u <user>`
- System cron via `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.daily/*`, `/etc/cron.hourly/*`
- Scripts referenced in cron commands (best-effort parsing)
- Common automation directories (bounded scan): `/opt`, `/usr/local/bin`, `/home/*/scripts`, `/data/scripts`
- Script analysis detects references to: `ssh`, `sftp`, `scp`, `ftp`, `curl`, `wget`
- Detects private key *paths* referenced in scripts (contents are never read or logged)
- Detects hard-coded IPv4 addresses and hostnames

Migration (writes only to destination):

- Copies discovered scripts to destination preserving permissions/ownership/timestamps (via `rsync -aHAX --numeric-ids`)
- Copies key directories if referenced (for example `~/.ssh/`, `/opt/keys/`)
- Recreates cron jobs on destination:
  - User crontabs are merged without duplicate lines
  - System cron is imported into `/etc/cron.d/croma_migrated_*` (does not overwrite `/etc/crontab`)
- Validates destination:
  - Script exists
  - Script is executable
  - Dependencies (`ssh`, `sftp`, `scp`, `curl`, `wget`) are present when referenced

## Discovery Engine (Read-Only)

The `Discovery` tab runs a full, read-only scan against the source server to provide visibility before any migration:

- Cron jobs (user + system)
- Scripts in common automation directories
- Script content analysis (ssh/sftp/scp/ftp/curl/wget)
- Key path references (paths only, never key contents)
- External hosts (IPs/hostnames)
- Systemd timers and services

## API

- `POST /test/source`
- `POST /test/destination`
- `POST /migration/dry-run`
- `POST /migration/start`
- `GET /migration/{job_id}/status`
- `GET /migration/logs?job_id=<id>`
- `GET /migration/{job_id}/report`
- `POST /scan-scripts`
- `POST /migrate-scripts`
- `POST /discovery/run`
- `GET /discovery/report?format=json|csv`
- `GET /health`

## Mandatory Connectivity Gate

Migration is blocked unless BOTH source and destination tests pass for the same submitted connection profile.

- Enforced server-side in memory
- No permanent credential storage

## Project Layout

- `backend/app/main.py` - FastAPI app entry
- `backend/app/routers/api.py` - API routes
- `backend/app/services/ssh_client.py` - Paramiko SSH wrapper
- `backend/app/services/migration_service.py` - main SFTP migration workflow
- `backend/app/services/cron_script_discovery.py` - scripts + cron discovery/migration
- `backend/app/services/connectivity_gate.py` - test gate enforcement
- `backend/app/services/job_store.py` - in-memory jobs/logs
- `frontend/index.html` - single-page UI
- `frontend/static/croma-logo.png` - runtime logo asset
- `scripts/setup_assets.py` - copies local logo into static path
- `scripts/run_local.ps1` - run backend+frontend (foreground)
- `scripts/run_detached.ps1` - run backend+frontend (detached)
- `scripts/stop_local.ps1` - stop backend+frontend by ports

## Prerequisites

- Python 3.10+
- SSH access from tool host to both servers
- Source/destination account with root or passwordless sudo
- `rsync` on source and destination
- `sshpass` on source only if destination password-based rsync is used

## Setup and Run

From project root:

```bash
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate          # Windows PowerShell
pip install -r backend/requirements.txt
python scripts/setup_assets.py
```

Run backend (manual):

```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

Run frontend (manual, new terminal):

```bash
cd frontend
python -m http.server 8080
```

Open UI:

- `http://127.0.0.1:8080`

### One-Command Run (Windows PowerShell)

Detached (recommended for local use):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_detached.ps1
```

Foreground (stops when you close the window):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_local.ps1
```

Stop:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop_local.ps1
```

## Logo Setup Details

`setup_assets.py` copies the first available logo file from:

1. `~/Desktop/sftp1/logo.png`
2. `~/Desktop/SFTP1/logo.png`
3. `<workspace>/logo.png`

to:

- `frontend/static/croma-logo.png`

## Security Notes

- Credentials are only processed in request memory.
- Secrets are masked in app logs.
- Temporary rsync key material (if used) is removed after transfer.
- Scripts/cron scanning reports key paths only; private key contents are never shown.
- Restrict backend access to internal admin networks only.

## Operational Notes

- `/etc/shadow` migration requires privileged access and policy approval.
- Dry run first, then production run during cutover.
- Review destination sshd config backup and apply change windows.
