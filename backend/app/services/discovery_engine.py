from __future__ import annotations

import csv
import io
import re
import shlex
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable, Optional

from app.models.schemas import SSHAuth
from app.services.ssh_client import SSHClientWrapper

# Read-only, dry-run discovery engine.
# Do not add any write operations to the source host.


@dataclass(frozen=True)
class CronJob:
    scope: str  # user|system
    owner: str
    schedule: str
    command: str
    source: str


@dataclass(frozen=True)
class ScriptFinding:
    path: str
    owner: str
    schedule: str
    command: str
    uses_ssh: bool
    uses_sftp: bool
    uses_scp: bool
    uses_ftp: bool
    uses_curl: bool
    uses_wget: bool
    uses_key: bool
    external_hosts: list[str]
    key_paths: list[str]


_CRON_SPECIAL_RE = re.compile(r"^\s*(@\w+)\s+(?P<cmd>.+?)\s*$")
_CRON_STD_RE = re.compile(
    r"^\s*(?P<m>[-\d*/,]+)\s+(?P<h>[-\d*/,]+)\s+(?P<dom>[-\d*/,]+)\s+(?P<mon>[-\d*/,]+)\s+(?P<dow>[-\d*/,]+)\s+(?P<rest>.+?)\s*$"
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
            jobs.append(CronJob(scope="system", owner="root", schedule=m.group(1), command=m.group("cmd"), source=path))
            continue

        m = _CRON_STD_RE.match(line)
        if not m:
            continue

        rest = m.group("rest").strip()
        parts = rest.split(None, 1)
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
                if t == "run-parts" or t.endswith("/run-parts"):
                    if i + 1 < len(tokens):
                        run_parts_schedules[tokens[i + 1]] = schedule
    return jobs, run_parts_schedules


def _extract_script_paths(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    out: set[str] = set()

    for i, tok in enumerate(tokens):
        if tok in {"bash", "sh", "ksh", "zsh", "python", "python3", "/bin/bash", "/bin/sh"} and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            if nxt.startswith("/"):
                out.add(nxt)

    for tok in tokens:
        if tok.startswith("-"):
            continue
        if tok.startswith("/"):
            out.add(tok)
        elif tok.startswith("~/") or tok.startswith("./") or tok.startswith("../"):
            out.add(tok)

    return sorted(out)


def _discover_group_users(src: SSHClientWrapper, group: str, sudo: bool) -> list[str]:
    line = src.run(f"getent group {shlex.quote(group)}", sudo=sudo, check=False).stdout.strip()
    if not line:
        return []
    parts = line.split(":")
    gid = parts[2]
    listed = [m for m in parts[3].split(",") if m] if len(parts) > 3 else []
    primary = src.run(f"awk -F: '$4=={gid}{{print $1}}' /etc/passwd", sudo=sudo, check=False).stdout.splitlines()
    return sorted(set(listed + [u.strip() for u in primary if u.strip()]))


def discover_cron_jobs(src: SSHClientWrapper, sftp_group: str, sudo: bool) -> tuple[list[CronJob], list[str]]:
    users = _discover_group_users(src, sftp_group, sudo=sudo)
    if "root" not in users:
        users.append("root")
    users = sorted(set(users))

    cron_jobs: list[CronJob] = []
    for u in users:
        res = src.run(f"crontab -l -u {shlex.quote(u)}", sudo=sudo, check=False)
        if res.code == 0 and res.stdout.strip():
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

    for d in ["/etc/cron.daily", "/etc/cron.hourly"]:
        files = src.run(
            f"find {shlex.quote(d)} -maxdepth 1 -type f -print 2>/dev/null || true",
            sudo=sudo,
            check=False,
        ).stdout.splitlines()
        schedule = run_parts_schedules.get(d, "")
        for p in [x.strip() for x in files if x.strip()]:
            cron_jobs.append(CronJob(scope="system", owner="root", schedule=schedule, command=p, source=d))

    return cron_jobs, users


def discover_scripts(
    src: SSHClientWrapper,
    cron_jobs: list[CronJob],
    users: list[str],
    sudo: bool,
    max_scripts: int = 800,
) -> tuple[list[str], dict[str, list[CronJob]], list[str]]:
    scripts_from_cron: dict[str, list[CronJob]] = {}
    for job in cron_jobs:
        for p in _extract_script_paths(job.command):
            scripts_from_cron.setdefault(p, []).append(job)

    candidates: set[str] = set(scripts_from_cron.keys())
    warnings: list[str] = []

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

    expanded: set[str] = set()
    home_cache: dict[str, str] = {}
    for p in sorted(candidates):
        if p.startswith("~/"):
            for u in users:
                if u not in home_cache:
                    home_cache[u] = src.run(
                        f"getent passwd {shlex.quote(u)} | cut -d: -f6",
                        sudo=sudo,
                        check=False,
                    ).stdout.strip()
                home = home_cache.get(u, "")
                if home:
                    expanded.add(home.rstrip("/") + p[1:])
        else:
            expanded.add(p)

    existing: list[str] = []
    for p in sorted(expanded):
        if len(existing) >= max_scripts:
            warnings.append(f"Script cap reached ({max_scripts}); results truncated.")
            break
        if not p.startswith("/"):
            warnings.append(f"Skipped non-absolute script path reference: {p}")
            continue
        if src.run(f"test -f {shlex.quote(p)}", sudo=sudo, check=False).code == 0:
            existing.append(p)

    return existing, scripts_from_cron, warnings


def scan_script_content(
    src: SSHClientWrapper,
    script_paths: Iterable[str],
    sudo: bool,
    source_host: str,
) -> dict[str, dict]:
    paths = [p for p in script_paths if p and p.startswith("/")]
    if not paths:
        return {}

    # Parallel scan on the remote host using xargs -P (no temp files, read-only).
    here = "\n".join(paths)
    bash = (
        "SOURCE_HOST="
        + shlex.quote(source_host)
        + " "
        + "cat <<'EOF' | xargs -r -n 1 -P 6 bash -lc "
        + shlex.quote(
            r"""
f="$1"
owner="$(stat -c '%U' "$f" 2>/dev/null || echo unknown)"

grep -Eqi '\bssh\b' "$f" 2>/dev/null; uses_ssh=$?
grep -Eqi '\bsftp\b' "$f" 2>/dev/null; uses_sftp=$?
grep -Eqi '\bscp\b' "$f" 2>/dev/null; uses_scp=$?
grep -Eqi '\bftp\b' "$f" 2>/dev/null; uses_ftp=$?
grep -Eqi '\bcurl\b' "$f" 2>/dev/null; uses_curl=$?
grep -Eqi '\bwget\b' "$f" 2>/dev/null; uses_wget=$?

keys="$(grep -Eo '(~/?\.ssh/[^\s"'\''']+)|(/opt/keys/[^\s"'\''']+)|(/[^\s"'\''']+\.(pem|key))|(/[^\s"'\''']+/\.ssh/[^\s"'\''']+)|(/[^\s"'\''']+/id_rsa)' "$f" 2>/dev/null | head -n 10 | tr '\n' ',' | sed 's/,$//')"

hosts="$(grep -Eo '((?:[0-9]{1,3}\.){3}[0-9]{1,3})|(([A-Za-z0-9-]+\.)+[A-Za-z]{2,})' "$f" 2>/dev/null | head -n 50 | \
  grep -Ev '^(localhost|0\.0\.0\.0|127\.)' | tr '\n' ',' | sed 's/,$//')"

mentions_source=0
if [ -n "$SOURCE_HOST" ]; then
  echo "$hosts" | tr ',' '\n' | grep -Fxq "$SOURCE_HOST" && mentions_source=1
  if [ "$mentions_source" -eq 0 ]; then
    grep -Fq "$SOURCE_HOST" "$f" 2>/dev/null && mentions_source=1
  fi
fi

# exit codes are 0 when match found; invert into 1/0 flags
flag() { if [ "$1" -eq 0 ]; then echo 1; else echo 0; fi; }

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$f" "$owner" \
  "$(flag $uses_ssh)" "$(flag $uses_sftp)" "$(flag $uses_scp)" "$(flag $uses_ftp)" "$(flag $uses_curl)" "$(flag $uses_wget)" \
  "$mentions_source" "$keys" "$hosts"
"""
        )
        + " _"
        + "\nEOF\n"
        + here
        + "\nEOF\n"
    )

    out = src.run(bash, sudo=sudo, check=False).stdout.splitlines()
    findings: dict[str, dict] = {}
    for ln in out:
        parts = ln.split("\t")
        if len(parts) < 11:
            continue
        p = parts[0].strip()
        owner = parts[1].strip() or "unknown"
        uses_ssh = parts[2].strip() == "1"
        uses_sftp = parts[3].strip() == "1"
        uses_scp = parts[4].strip() == "1"
        uses_ftp = parts[5].strip() == "1"
        uses_curl = parts[6].strip() == "1"
        uses_wget = parts[7].strip() == "1"
        mentions_source = parts[8].strip() == "1"
        key_paths = [x for x in parts[9].split(",") if x]
        external_hosts = [x for x in parts[10].split(",") if x]

        # Normalize and filter hosts defensively
        norm_hosts: list[str] = []
        for h in external_hosts:
            v = h.strip()
            if not v:
                continue
            if v in {"localhost", "0.0.0.0"} or v.startswith("127."):
                continue
            if _IPV4_RE.fullmatch(v) or _HOST_RE.fullmatch(v):
                norm_hosts.append(v)

        findings[p] = {
            "owner": owner,
            "uses_ssh": uses_ssh,
            "uses_sftp": uses_sftp,
            "uses_scp": uses_scp,
            "uses_ftp": uses_ftp,
            "uses_curl": uses_curl,
            "uses_wget": uses_wget,
            "uses_key": bool(key_paths),
            "key_paths": sorted(set(key_paths)),
            "external_hosts": sorted(set(norm_hosts))[:50],
            "mentions_source_host": mentions_source,
        }

    return findings


def detect_private_keys(script_findings: dict[str, dict]) -> dict[str, list[str]]:
    keys: dict[str, set[str]] = {}
    for script_path, data in script_findings.items():
        for kp in data.get("key_paths", []) or []:
            keys.setdefault(kp, set()).add(script_path)
    return {k: sorted(v) for k, v in sorted(keys.items())}


def detect_external_hosts(script_findings: dict[str, dict]) -> dict[str, list[str]]:
    hosts: dict[str, set[str]] = {}
    for script_path, data in script_findings.items():
        for h in data.get("external_hosts", []) or []:
            hosts.setdefault(h, set()).add(script_path)
    return {h: sorted(v) for h, v in sorted(hosts.items())}


def discover_systemd_timers(src: SSHClientWrapper, sudo: bool) -> list[dict]:
    out = src.run("systemctl list-timers --all --no-pager 2>/dev/null || true", sudo=sudo, check=False).stdout
    lines = [ln.rstrip() for ln in out.splitlines() if ln.strip()]
    timers: list[dict] = []
    # Try to parse the table output; keep a raw line fallback.
    for ln in lines:
        if ln.lower().startswith("next") or ln.startswith(" "):
            continue
        if ln.endswith("timers listed.") or "loaded units listed" in ln.lower():
            continue
        parts = ln.split()
        if len(parts) >= 6 and parts[-2].endswith(".timer"):
            timers.append(
                {
                    "next": parts[0],
                    "left": parts[1],
                    "last": parts[2],
                    "passed": parts[3],
                    "unit": parts[4],
                    "activates": parts[5],
                }
            )
        else:
            timers.append({"raw": ln})
    return timers


def discover_running_services(src: SSHClientWrapper, sudo: bool) -> list[dict]:
    out = src.run(
        "systemctl list-units --type=service --no-pager 2>/dev/null || true",
        sudo=sudo,
        check=False,
    ).stdout
    services: list[dict] = []
    for ln in out.splitlines():
        s = ln.strip()
        if not s or s.lower().startswith("unit "):
            continue
        if s.endswith("loaded units listed.") or "units listed" in s.lower():
            continue
        parts = s.split(None, 4)
        if len(parts) >= 4 and parts[0].endswith(".service"):
            services.append(
                {
                    "unit": parts[0],
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": parts[4] if len(parts) == 5 else "",
                }
            )
    return services


def _flatten_dependencies(findings: dict[str, dict]) -> dict[str, list[str]]:
    deps: dict[str, set[str]] = {}
    for sp, d in findings.items():
        if d.get("uses_ssh") or d.get("uses_sftp") or d.get("uses_scp"):
            for n in ["ssh", "sftp", "scp"]:
                deps.setdefault(n, set()).add(sp)
        if d.get("uses_ftp"):
            deps.setdefault("ftp", set()).add(sp)
        if d.get("uses_curl"):
            deps.setdefault("curl", set()).add(sp)
        if d.get("uses_wget"):
            deps.setdefault("wget", set()).add(sp)
    return {k: sorted(v) for k, v in sorted(deps.items())}


def run_full_discovery(
    src_auth: SSHAuth,
    sftp_group: str = "sftpusers",
    max_scripts: int = 800,
) -> dict:
    with SSHClientWrapper(**src_auth.model_dump()) as src:
        cron_jobs, users = discover_cron_jobs(src, sftp_group=sftp_group, sudo=src_auth.sudo)
        script_paths, scripts_from_cron, warnings = discover_scripts(
            src, cron_jobs=cron_jobs, users=users, sudo=src_auth.sudo, max_scripts=max_scripts
        )
        content = scan_script_content(
            src,
            script_paths=script_paths,
            sudo=src_auth.sudo,
            source_host=src_auth.host,
        )
        timers = discover_systemd_timers(src, sudo=src_auth.sudo)
        services = discover_running_services(src, sudo=src_auth.sudo)

    # Join cron -> scripts for UI (schedule/command)
    script_rows: list[ScriptFinding] = []
    for p in script_paths:
        meta = content.get(p, {})
        owner = str(meta.get("owner", "unknown") or "unknown")
        jobs = scripts_from_cron.get(p, [])
        if jobs:
            for j in jobs:
                script_rows.append(
                    ScriptFinding(
                        path=p,
                        owner=owner,
                        schedule=j.schedule,
                        command=j.command,
                        uses_ssh=bool(meta.get("uses_ssh")),
                        uses_sftp=bool(meta.get("uses_sftp")),
                        uses_scp=bool(meta.get("uses_scp")),
                        uses_ftp=bool(meta.get("uses_ftp")),
                        uses_curl=bool(meta.get("uses_curl")),
                        uses_wget=bool(meta.get("uses_wget")),
                        uses_key=bool(meta.get("uses_key")),
                        external_hosts=list(meta.get("external_hosts", []) or []),
                        key_paths=list(meta.get("key_paths", []) or []),
                    )
                )
        else:
            script_rows.append(
                ScriptFinding(
                    path=p,
                    owner=owner,
                    schedule="",
                    command="",
                    uses_ssh=bool(meta.get("uses_ssh")),
                    uses_sftp=bool(meta.get("uses_sftp")),
                    uses_scp=bool(meta.get("uses_scp")),
                    uses_ftp=bool(meta.get("uses_ftp")),
                    uses_curl=bool(meta.get("uses_curl")),
                    uses_wget=bool(meta.get("uses_wget")),
                    uses_key=bool(meta.get("uses_key")),
                    external_hosts=list(meta.get("external_hosts", []) or []),
                    key_paths=list(meta.get("key_paths", []) or []),
                )
            )

    keys = detect_private_keys(content)
    hosts = detect_external_hosts(content)
    deps = _flatten_dependencies(content)

    report = {
        "ok": True,
        "dry_run": True,
        "generated_at": _now_iso(),
        "source": {"host": src_auth.host, "port": src_auth.port, "username": src_auth.username},
        "warnings": warnings,
        "cron_jobs": [asdict(j) for j in cron_jobs],
        "scripts": [asdict(s) for s in script_rows],
        "external_hosts": [{"host": h, "referenced_in": refs} for h, refs in hosts.items()],
        "ssh_keys": [{"path": k, "referenced_in": refs} for k, refs in keys.items()],
        "dependencies": [{"name": n, "referenced_in": refs} for n, refs in deps.items()],
        "systemd_timers": timers,
        "services": services,
        "counts": {
            "cron_jobs": len(cron_jobs),
            "unique_scripts": len(script_paths),
            "external_hosts": len(hosts),
            "ssh_keys": len(keys),
            "dependencies": len(deps),
            "systemd_timers": len(timers),
            "services": len(services),
        },
    }
    return report


def report_to_csv(report: dict) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "category",
            "path",
            "owner",
            "schedule",
            "command",
            "uses_ssh",
            "uses_sftp",
            "uses_key",
            "external_host",
            "notes",
        ]
    )

    for j in report.get("cron_jobs", []) or []:
        writer.writerow(
            [
                "cron_job",
                "",
                j.get("owner", ""),
                j.get("schedule", ""),
                j.get("command", ""),
                "",
                "",
                "",
                "",
                j.get("source", ""),
            ]
        )

    for s in report.get("scripts", []) or []:
        hosts = s.get("external_hosts", []) or []
        writer.writerow(
            [
                "script",
                s.get("path", ""),
                s.get("owner", ""),
                s.get("schedule", ""),
                s.get("command", ""),
                "yes" if s.get("uses_ssh") else "no",
                "yes" if s.get("uses_sftp") else "no",
                "yes" if s.get("uses_key") else "no",
                ",".join(hosts[:10]),
                ",".join((s.get("key_paths", []) or [])[:5]),
            ]
        )

    for h in report.get("external_hosts", []) or []:
        writer.writerow(["external_host", "", "", "", "", "", "", "", h.get("host", ""), ""])

    for k in report.get("ssh_keys", []) or []:
        writer.writerow(["ssh_key", k.get("path", ""), "", "", "", "", "", "", "", ""])

    for d in report.get("dependencies", []) or []:
        writer.writerow(["dependency", d.get("name", ""), "", "", "", "", "", "", "", ""])

    return output.getvalue()


# Simple in-memory cache (single-user/tool instance).
_LAST_REPORT: Optional[dict] = None


def set_last_report(report: dict) -> None:
    global _LAST_REPORT
    _LAST_REPORT = report


def get_last_report() -> Optional[dict]:
    return _LAST_REPORT
