@echo off
setlocal

set "BIND_HOST=%~1"
set "PORT=%~2"

cd /d "%~dp0.."
cd frontend

REM Append logs.
..\.venv\Scripts\python.exe -m http.server %PORT% --bind %BIND_HOST% 1>> ..\frontend_stdout.log 2>> ..\frontend_stderr.log
