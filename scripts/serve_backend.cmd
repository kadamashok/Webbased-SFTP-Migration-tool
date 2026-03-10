@echo off
setlocal

set "BIND_HOST=%~1"
set "PORT=%~2"

cd /d "%~dp0.."
cd backend

REM Keep this in a separate process so the server stays up.
REM Append logs (PowerShell runners already manage stop via ports).
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host %BIND_HOST% --port %PORT% 1>> ..\backend_stdout.log 2>> ..\backend_stderr.log
