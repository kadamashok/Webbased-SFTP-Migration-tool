from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Iterable

from app.models.schemas import MigrationRequest
from app.services.ssh_client import SSHClientWrapper


@dataclass(frozen=True)
class CronJob:
    scope: str  # "user" | "system"
    owner: str
    schedule: str
    command: str
    source: str  # e.g. "crontab:alice" or "/etc/cron.d/backup"


@dataclass(frozen=True)
class ScriptAnalysis:
    script_path: str
    owner: str
    dependencies: list[str]
    uses_ssh_sftp: bool
    uses_private_key: bool
    notes: str
    key_paths: list[str]


_CRON_SPECIAL_RE = re.compile(r"^\s*(@\w+)\s+(?P<cmd>.+?)\s*$")
_CRON_STD_RE = re.compile(
    r"^\s*(?P<m>[-\d*/,]+)\s+(?P<h>[-\d*/,]+)\s+(?P<dom>[-\d*/,]+)\s+(?P<mon>[-\d*/,]+)\s+(?P<dow>[-\d*/,]+)\s+(?P<rest>.+?)\s*$"
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")


def _discover_group_users(src: SSHClientWrapper, group: str, sudo: bool) -> list[str]:
    line = src.run(f"getent group {shlex.quote(group)}", sudo=sudo).stdout.strip()
    if not line:
        return []
    parts = line.split(":")
    gid = parts[2]
    listed = [m for m in parts[3].split(",") if m] if len(parts) > 3 else []
    primary = src.run(f"awk -F: '$4=={gid}{{print $1}}' /etc/passwd", sudo=sudo).stdout.splitlines()
    return sorted(set(listed + [u.strip() for u in primary if u.strip()]))


def _parse_user_crontab(user: str, text: str) -> list[CronJob]:
    jobs: list[CronJob] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line and line.split("=", 1)[0].strip().isidentifier():
            continue

        m = _CRON_SPECIAL_RE.match(line)
        if m:
            jobs.append(
                CronJob(
                    scope="user",
                    owner=user,
                    schedule=m.group(1),
                    command=m.group("cmd").strip(),
                    source=f"crontab:{user}",
                )
            )
            continue

        m = _CRON_STD_RE.match(line)
        if not m:
            continue
        schedule = " ".join([m.group("m"), m.group("h"), m.group("dom"), m.group("mon"), m.group("dow")])
        jobs.append(
            CronJob(
                scope="user",
                owner=user,
                schedule=schedule,
                command=m.group("rest").strip(),
                source=f"crontab:{user}",
            )
        )
    return jobs


def _parse_system_cron_file(path: str, text: str) -> tuple[list[CronJob], dict[str, str]]:
    jobs: list[CronJob] = []
    run_parts_schedules: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line and line.split("=", 1)[0].strip().isidentifier():
            continue

        m = _CRON_SPECIAL_RE.match(line)
        if m:
            # In system cron files, @reboot entries can still include a user field, but
            # it's inconsistent. Keep the full command and set owner="root" as safe default.
            cmd = m.group("cmd").strip()
            jobs.append(CronJob(scope="system", owner="root", schedule=m.group(1), command=cmd, source=path))
            continue

        m = _CRON_STD_RE.match(line)
        if not m:
            continue

        parts = m.group("rest").split(None, 1)
        if len(parts) < 2:
            continue
        owner = parts[0]
        cmd = parts[1].strip()
        schedule = " ".join([m.group("m"), m.group("h"), m.group("dom"), m.group("mon"), m.group("dow")])
        jobs.append(CronJob(scope="system", owner=owner, schedule=schedule, command=cmd, source=path))

        if "run-parts" in cmd:
            try:
                tokens = shlex.split(cmd)
            except ValueError:
                tokens = cmd.split()
            for i, t in enumerate(tokens):
                if t.endswith("run-parts") or t == "run-parts":
                    if i + 1 < len(tokens):
                        run_parts_schedules[tokens[i + 1]] = schedule
    return jobs, run_parts_schedules


def _extract_script_paths(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    out: list[str] = []

    # Handle interpreter style: bash /path/to/script
    for i, tok in enumerate(tokens):
        if tok in {"bash", "sh", "ksh", "zsh", "python", "python3", "/bin/bash", "/bin/sh"}:
            if i + 1 < len(tokens):
                nxt = tokens[i + 1]
                if nxt.startswith("/"):
                    out.append(nxt)

    for tok in tokens:
        if tok.startswith("-"):
            continue
        if tok.startswith("/"):
            # Heuristic: treat any absolute path as a candidate, even without an extension.
            out.append(tok)
        elif tok.startswith("~/"):
            out.append(tok)
        elif tok.startswith("./") or tok.startswith("../"):
            out.append(tok)

    # Filter obvious non-files (directories and placeholders are handled later by existence checks).
    return sorted(set(out))


def discover_cron_jobs(src: SSHClientWrapper, sftp_group: str, sudo: bool) -> tuple[list[CronJob], list[str]]:
    users = _discover_group_users(src, sftp_group, sudo=sudo)
    if "root" not in users:
        users.append("root")
    users = sorted(set(users))

    cron_jobs: list[CronJob] = []
    for u in users:
        res = src.run(f"crontab -l -u {shlex.quote(u)}", sudo=sudo, check=False)
        if res.code != 0 or not res.stdout.strip():
            continue
        cron_jobs.extend(_parse_user_crontab(u, res.stdout))

    run_parts_schedules: dict[str, str] = {}
    etc_crontab = src.run("cat /etc/crontab", sudo=sudo, check=False).stdout or ""
    jobs, rp = _parse_system_cron_file("/etc/crontab", etc_crontab)
    cron_jobs.extend(jobs)
    run_parts_schedules.update(rp)

    cron_d_list = src.run("ls -1 /etc/cron.d 2>/dev/null || true", sudo=sudo, check=False).stdout.splitlines()
    for f in [x.strip() for x in cron_d_list if x.strip()]:
        path = f"/etc/cron.d/{f}"
        text = src.run(f"cat {shlex.quote(path)}", sudo=sudo, check=False).stdout or ""
        jobs, rp = _parse_system_cron_file(path, text)
        cron_jobs.extend(jobs)
        run_parts_schedules.update(rp)

    # cron.{daily,hourly} contain scripts invoked via run-parts
    run_parts_dirs = ["/etc/cron.daily", "/etc/cron.hourly"]
    for d in run_parts_dirs:
        # List only regular files.
        files = src.run(
            f"find {shlex.quote(d)} -maxdepth 1 -type f -print 2>/dev/null || true",
            sudo=sudo,
            check=False,
        ).stdout.splitlines()
        schedule = run_parts_schedules.get(d, "")
        for p in [x.strip() for x in files if x.strip()]:
            cron_jobs.append(
                CronJob(
                    scope="system",
                    owner="root",
                    schedule=schedule,
                    command=p,
                    source=d,
                )
            )

    return cron_jobs, users


def discover_scripts(
    src: SSHClientWrapper,
    cron_jobs: list[CronJob],
    users: list[str],
    sudo: bool,
) -> tuple[list[str], dict[str, list[CronJob]], list[str]]:
    scripts_from_cron: dict[str, list[CronJob]] = {}
    for job in cron_jobs:
        for p in _extract_script_paths(job.command):
            scripts_from_cron.setdefault(p, []).append(job)

    candidates = set(scripts_from_cron.keys())
    warnings: list[str] = []

    # Common script directories (bounded scan depth to reduce load).
    find_cmds = [
        "find /opt -maxdepth 4 -type f \\( -name '*.sh' -o -name '*.py' -o -perm -111 \\ ) 2>/dev/null | head -n 2000",
        "find /usr/local/bin -maxdepth 3 -type f \\( -name '*.sh' -o -name '*.py' -o -perm -111 \\ ) 2>/dev/null | head -n 2000",
        "find /data/scripts -maxdepth 6 -type f \\( -name '*.sh' -o -name '*.py' -o -perm -111 \\ ) 2>/dev/null | head -n 2000",
        "find /home -maxdepth 4 -type f -path '*/scripts/*' \\( -name '*.sh' -o -name '*.py' -o -perm -111 \\ ) 2>/dev/null | head -n 2000",
    ]
    for cmd in find_cmds:
        out = src.run(cmd, sudo=sudo, check=False).stdout.splitlines()
        for line in out:
            p = line.strip()
            if p:
                candidates.add(p)

    # Expand ~/ paths for discovered users.
    expanded: set[str] = set()
    for p in list(candidates):
        if p.startswith("~/"):
            for u in users:
                home = src.run(f"getent passwd {shlex.quote(u)} | cut -d: -f6", sudo=sudo, check=False).stdout.strip()
                if home:
                    expanded.add(home.rstrip("/") + p[1:])
        else:
            expanded.add(p)

    # Filter to existing regular files on source.
    existing: list[str] = []
    for p in sorted(expanded):
        if not p.startswith("/"):
            # Relative paths can't be reliably resolved.
            warnings.append(f"Skipped non-absolute script path reference: {p}")
            continue
        if src.run(f"test -f {shlex.quote(p)}", sudo=sudo, check=False).code == 0:
            existing.append(p)

    return existing, scripts_from_cron, warnings


def analyze_script_dependencies(
    src: SSHClientWrapper, script_paths: Iterable[str], sudo: bool
) -> tuple[dict[str, ScriptAnalysis], int]:
    analyses: dict[str, ScriptAnalysis] = {}
    keys_detected = 0

    for p in script_paths:
        owner = src.run(f"stat -c '%U' {shlex.quote(p)} 2>/dev/null || echo unknown", sudo=sudo, check=False).stdout.strip()

        uses_ssh = src.run(
            f"grep -Eqi '\\b(ssh|sftp|scp|ftp)\\b' {shlex.quote(p)} 2>/dev/null",
            sudo=sudo,
            check=False,
        ).code == 0
        uses_curl = src.run(
            f"grep -Eqi '\\b(curl|wget)\\b' {shlex.quote(p)} 2>/dev/null",
            sudo=sudo,
            check=False,
        ).code == 0
        uses_key = src.run(
            f"grep -Eqi '(id_rsa|\\.pem\\b|/opt/keys/|~/?\\.ssh/|/\\.ssh/)' {shlex.quote(p)} 2>/dev/null",
            sudo=sudo,
            check=False,
        ).code == 0

        deps: list[str] = []
        if uses_ssh:
            deps.extend(["ssh", "sftp", "scp"])
        if uses_curl:
            deps.extend(["curl", "wget"])
        deps = sorted(set(deps))

        key_paths: list[str] = []
        if uses_key:
            raw = src.run(
                f"grep -Eo '(~/?\\.ssh/[^\\s\"\\x27]+)"
                f"|(/opt/keys/[^\\s\"\\x27]+)"
                f"|(/[^\\s\"\\x27]+\\.(pem|key))"
                f"|(/[^\\s\"\\x27]+/\\.ssh/[^\\s\"\\x27]+)"
                f"|(/[^\\s\"\\x27]+/id_rsa)' {shlex.quote(p)} 2>/dev/null | head -n 10",
                sudo=sudo,
                check=False,
            ).stdout.splitlines()
            key_paths = [x.strip() for x in raw if x.strip()]
            if key_paths:
                keys_detected += len(key_paths)

        ips = src.run(
            f"grep -Eo '(?:[0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' {shlex.quote(p)} 2>/dev/null | head -n 5",
            sudo=sudo,
            check=False,
        ).stdout.splitlines()
        hosts = src.run(
            f"grep -Eo '([A-Za-z0-9-]+\\.)+[A-Za-z]{{2,}}' {shlex.quote(p)} 2>/dev/null | head -n 5",
            sudo=sudo,
            check=False,
        ).stdout.splitlines()

        notes_parts: list[str] = []
        ip_list = [x.strip() for x in ips if _IPV4_RE.fullmatch(x.strip())]
        host_list = [x.strip() for x in hosts if _HOST_RE.fullmatch(x.strip())]
        if ip_list:
            notes_parts.append("IPs: " + ", ".join(sorted(set(ip_list))[:5]))
        if host_list:
            notes_parts.append("Hosts: " + ", ".join(sorted(set(host_list))[:5]))
        if key_paths:
            notes_parts.append("Key refs: " + ", ".join(key_paths[:3]))

        analyses[p] = ScriptAnalysis(
            script_path=p,
            owner=owner or "unknown",
            dependencies=deps,
            uses_ssh_sftp=uses_ssh,
            uses_private_key=uses_key,
            notes="; ".join(notes_parts),
            key_paths=key_paths,
        )

    return analyses, keys_detected


def migrate_scripts(
    src: SSHClientWrapper,
    dst: SSHClientWrapper,
    req: MigrationRequest,
    script_paths: list[str],
    key_dirs: list[str],
) -> tuple[int, list[str]]:
    copied = 0
    warnings: list[str] = []

    if req.destination.private_key:
        src.upload_text("/tmp/dst_mig_key", req.destination.private_key, mode=0o600)

    try:
        ssh_cmd = f"ssh -p {req.destination.port} -o StrictHostKeyChecking=no"
        if req.destination.private_key:
            ssh_cmd += " -i /tmp/dst_mig_key"

        rsync_opts = "-aHAX --numeric-ids"
        rsync_path = ""
        if req.destination.username != "root" and req.destination.sudo:
            rsync_path = "--rsync-path='sudo -n rsync'"

        def _sync_path(path: str) -> None:
            nonlocal copied
            dst_dir = path.rsplit("/", 1)[0]
            dst.run(f"mkdir -p {shlex.quote(dst_dir)}", sudo=req.destination.sudo)
            dst_ref = f"{req.destination.username}@{req.destination.host}:{path}"

            if req.destination.password:
                cmd = (
                    "command -v sshpass >/dev/null 2>&1 || "
                    "(echo 'sshpass missing on source' && exit 1); "
                    f"sshpass -p {shlex.quote(req.destination.password)} "
                    f"rsync {rsync_opts} {rsync_path} -e {shlex.quote(ssh_cmd)} "
                    f"{shlex.quote(path)} {shlex.quote(dst_ref)}"
                )
            else:
                cmd = (
                    f"rsync {rsync_opts} {rsync_path} -e {shlex.quote(ssh_cmd)} "
                    f"{shlex.quote(path)} {shlex.quote(dst_ref)}"
                )

            src.run(cmd, sudo=req.source.sudo)
            copied += 1

        for p in script_paths:
            _sync_path(p)

        for d in key_dirs:
            # rsync directory recursively
            dst.run(f"mkdir -p {shlex.quote(d)}", sudo=req.destination.sudo, check=False)
            dst_ref = f"{req.destination.username}@{req.destination.host}:{d}/"
            src_ref = f"{d}/"
            if req.destination.password:
                cmd = (
                    "command -v sshpass >/dev/null 2>&1 || "
                    "(echo 'sshpass missing on source' && exit 1); "
                    f"sshpass -p {shlex.quote(req.destination.password)} "
                    f"rsync {rsync_opts} {rsync_path} -e {shlex.quote(ssh_cmd)} "
                    f"{shlex.quote(src_ref)} {shlex.quote(dst_ref)}"
                )
            else:
                cmd = (
                    f"rsync {rsync_opts} {rsync_path} -e {shlex.quote(ssh_cmd)} "
                    f"{shlex.quote(src_ref)} {shlex.quote(dst_ref)}"
                )
            src.run(cmd, sudo=req.source.sudo)
    finally:
        src.run("rm -f /tmp/dst_mig_key", sudo=req.source.sudo, check=False)

    return copied, warnings


def recreate_cron_jobs(
    src: SSHClientWrapper,
    dst: SSHClientWrapper,
    req: MigrationRequest,
    cron_jobs: list[CronJob],
    users: list[str],
) -> tuple[int, int, list[str]]:
    warnings: list[str] = []
    installed_user_crons = 0
    installed_system_files = 0

    # User crontabs: merge (no duplicates)
    for u in users:
        src_tab = src.run(f"crontab -l -u {shlex.quote(u)}", sudo=req.source.sudo, check=False).stdout
        if not src_tab or not src_tab.strip():
            continue
        dst_tab = dst.run(f"crontab -l -u {shlex.quote(u)}", sudo=req.destination.sudo, check=False).stdout
        src_lines = [ln.rstrip() for ln in src_tab.splitlines() if ln.strip()]
        dst_lines = [ln.rstrip() for ln in (dst_tab or "").splitlines() if ln.strip()]

        merged: list[str] = []
        seen = set()
        for ln in dst_lines + src_lines:
            if ln not in seen:
                merged.append(ln)
                seen.add(ln)

        tmp = f"/tmp/croma_crontab_{u}.txt"
        dst.upload_text(tmp, "\n".join(merged) + "\n", mode=0o600)
        dst.run(f"crontab -u {shlex.quote(u)} {shlex.quote(tmp)}", sudo=req.destination.sudo)
        dst.run(f"rm -f {shlex.quote(tmp)}", sudo=req.destination.sudo, check=False)
        installed_user_crons += 1

    # System cron: import into /etc/cron.d (avoid overwriting /etc/crontab)
    cron_d_sources = sorted({j.source for j in cron_jobs if j.source.startswith("/etc/cron.d/")})
    for src_path in cron_d_sources:
        base = src_path.rsplit("/", 1)[-1]
        dst_path = f"/etc/cron.d/croma_migrated_{base}"
        src_txt = src.run(f"cat {shlex.quote(src_path)}", sudo=req.source.sudo, check=False).stdout or ""
        if not src_txt.strip():
            continue
        dst_txt = dst.run(f"cat {shlex.quote(dst_path)}", sudo=req.destination.sudo, check=False).stdout or ""
        if dst_txt == src_txt:
            continue
        tmp = f"/tmp/croma_{base}.cron"
        dst.upload_text(tmp, src_txt, mode=0o600)
        dst.run(f"cp {shlex.quote(tmp)} {shlex.quote(dst_path)}", sudo=req.destination.sudo)
        dst.run(f"chmod 644 {shlex.quote(dst_path)}", sudo=req.destination.sudo, check=False)
        dst.run(f"rm -f {shlex.quote(tmp)}", sudo=req.destination.sudo, check=False)
        installed_system_files += 1

    etc_crontab = src.run("cat /etc/crontab", sudo=req.source.sudo, check=False).stdout or ""
    lines: list[str] = []
    for raw in etc_crontab.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        if "=" in ln and ln.split("=", 1)[0].strip().isidentifier():
            continue
        m = _CRON_STD_RE.match(ln)
        if not m:
            continue
        rest = m.group("rest")
        if "run-parts" in rest:
            continue
        parts = rest.split(None, 1)
        if len(parts) < 2:
            continue
        lines.append(ln)

    if lines:
        dst_path = "/etc/cron.d/croma_migrated_system"
        header = "# Imported by Croma SFTP Migration Tool (system cron)\n"
        content = header + "\n".join(lines) + "\n"
        tmp = "/tmp/croma_migrated_system_cron"
        dst.upload_text(tmp, content, mode=0o600)
        dst.run(f"cp {shlex.quote(tmp)} {shlex.quote(dst_path)}", sudo=req.destination.sudo)
        dst.run(f"chmod 644 {shlex.quote(dst_path)}", sudo=req.destination.sudo, check=False)
        dst.run(f"rm -f {shlex.quote(tmp)}", sudo=req.destination.sudo, check=False)
        installed_system_files += 1

    return installed_user_crons, installed_system_files, warnings
