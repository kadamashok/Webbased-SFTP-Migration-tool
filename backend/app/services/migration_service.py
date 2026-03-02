from __future__ import annotations

import logging
import re
import shlex
import threading
from dataclasses import dataclass

from app.models.schemas import MigrationRequest, SSHAuth
from app.services.job_store import job_store
from app.services.ssh_client import SSHClientWrapper, SSHCommandError

logger = logging.getLogger(__name__)


@dataclass
class UserRecord:
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    hash_value: str
    groups: list[str]


class MigrationService:
    _secret_patterns = [
        re.compile(r"sshpass -p\s+\S+"),
        re.compile(r"password\s*=\s*[^,\s]+", re.IGNORECASE),
        re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.DOTALL),
    ]

    def _mask_secrets(self, text: str) -> str:
        masked = text
        for pattern in self._secret_patterns:
            masked = pattern.sub("***REDACTED***", masked)
        return masked

    def _log(self, job_id: str, message: str) -> None:
        safe_message = self._mask_secrets(message)
        logger.info("job=%s %s", job_id, safe_message)
        job_store.append_log(job_id, safe_message)

    def _set_status(self, job_id: str, status: str, progress: int, detail: str) -> None:
        job_store.update(job_id, status=status, progress=progress, detail=detail)

    def test_server_connectivity(self, auth: SSHAuth) -> dict:
        with SSHClientWrapper(**auth.model_dump()) as cli:
            os_release = cli.run("cat /etc/os-release", sudo=False).stdout.strip()
            whoami = cli.run("whoami", sudo=False).stdout.strip()
            disk_summary = cli.run("df -h", sudo=False).stdout.strip()

            access = "denied"
            if whoami == "root":
                access = "root"
            elif auth.sudo and cli.run("sudo -n true", sudo=False, check=False).code == 0:
                access = "sudo"

            if access == "denied":
                raise SSHCommandError("Connected over SSH but root/sudo validation failed")

            os_line = next(
                (line for line in os_release.splitlines() if line.startswith("PRETTY_NAME=")),
                os_release.splitlines()[0] if os_release else "unknown",
            )

            return {
                "ok": True,
                "os_release": os_line,
                "whoami": whoami,
                "disk_summary": disk_summary,
                "access": access,
                "detail": "SSH connectivity and privilege checks passed",
            }

    def start_job(self, job_id: str, req: MigrationRequest, dry_run: bool = False) -> None:
        threading.Thread(target=self._run_job, args=(job_id, req, dry_run), daemon=True).start()

    def _run_job(self, job_id: str, req: MigrationRequest, dry_run: bool) -> None:
        self._set_status(job_id, "running", 5, "Starting")
        report = {"dry_run": dry_run, "users": [], "validation": {}}

        try:
            with SSHClientWrapper(**req.source.model_dump()) as src, SSHClientWrapper(
                **req.destination.model_dump()
            ) as dst:
                self._log(job_id, "Connected to source and destination")
                users = self._discover_sftp_users(src, req.sftp_group, req.source.sudo)
                if not users:
                    raise SSHCommandError(f"No users found in group {req.sftp_group}")
                self._set_status(job_id, "running", 15, "Exporting users")
                records = self._export_user_records(src, users, req.source.sudo)
                report["users"] = [r.username for r in records]
                self._log(job_id, f"Exported {len(records)} users")

                if not dry_run:
                    self._set_status(job_id, "running", 35, "Recreating users and groups")
                    self._recreate_groups_and_users(dst, records, req.destination.sudo)
                    self._copy_authorized_keys(src, dst, records, req.source.sudo, req.destination.sudo)
                    self._set_status(job_id, "running", 55, "Running rsync")
                    self._sync_data_rsync(src, records, req)
                    self._set_status(job_id, "running", 75, "Migrating sshd config")
                    self._migrate_sshd_config(src, dst, req.sftp_group, req.destination.sudo)
                    self._set_status(job_id, "running", 85, "Applying SELinux settings")
                    self._apply_selinux(dst, req.destination.sudo)
                else:
                    self._log(job_id, "Dry run mode: skipped write operations")

                self._set_status(job_id, "running", 95, "Validating")
                report["validation"] = self._validate(src, dst, records, req)
                job_store.update(job_id, report=report)
                self._set_status(job_id, "completed", 100, "Completed")
                self._log(job_id, "Migration completed")
        except Exception as exc:
            safe_error = self._mask_secrets(str(exc))
            self._set_status(job_id, "failed", 100, f"Failed: {safe_error}")
            self._log(job_id, f"ERROR: {safe_error}")

    def _discover_sftp_users(self, src: SSHClientWrapper, group: str, sudo: bool) -> list[str]:
        line = src.run(f"getent group {shlex.quote(group)}", sudo=sudo).stdout.strip()
        if not line:
            return []
        parts = line.split(":")
        gid = parts[2]
        listed = [m for m in parts[3].split(",") if m] if len(parts) > 3 else []
        primary = src.run(f"awk -F: '$4=={gid}{{print $1}}' /etc/passwd", sudo=sudo).stdout.splitlines()
        return sorted(set(listed + [u.strip() for u in primary if u.strip()]))

    def _export_user_records(self, src: SSHClientWrapper, users: list[str], sudo: bool) -> list[UserRecord]:
        out: list[UserRecord] = []
        for user in users:
            pline = src.run(f"getent passwd {shlex.quote(user)}", sudo=sudo).stdout.strip()
            if not pline:
                continue
            p = pline.split(":")
            shadow_hash = src.run(
                f"getent shadow {shlex.quote(user)} | cut -d: -f2", sudo=sudo
            ).stdout.strip()
            groups = src.run(f"id -Gn {shlex.quote(user)}", sudo=sudo).stdout.strip().split()
            out.append(
                UserRecord(
                    username=p[0],
                    uid=int(p[2]),
                    gid=int(p[3]),
                    home=p[5],
                    shell=p[6],
                    hash_value=shadow_hash,
                    groups=groups,
                )
            )
        return out

    def _recreate_groups_and_users(self, dst: SSHClientWrapper, recs: list[UserRecord], sudo: bool) -> None:
        for r in recs:
            for g in r.groups:
                if dst.run(f"getent group {shlex.quote(g)}", sudo=sudo, check=False).code != 0:
                    if g == r.groups[0]:
                        dst.run(f"groupadd -g {r.gid} {shlex.quote(g)}", sudo=sudo)
                    else:
                        dst.run(f"groupadd {shlex.quote(g)}", sudo=sudo)

            if dst.run(f"id {shlex.quote(r.username)}", sudo=sudo, check=False).code != 0:
                cmd = (
                    f"useradd -m -u {r.uid} -g {r.gid} -d {shlex.quote(r.home)} "
                    f"-s {shlex.quote(r.shell)} {shlex.quote(r.username)}"
                )
                dst.run(cmd, sudo=sudo)

            if r.hash_value and r.hash_value not in ("*", "!", "!!"):
                dst.run(f"usermod -p {shlex.quote(r.hash_value)} {shlex.quote(r.username)}", sudo=sudo)
            if len(r.groups) > 1:
                extras = ",".join(r.groups[1:])
                dst.run(f"usermod -aG {shlex.quote(extras)} {shlex.quote(r.username)}", sudo=sudo)

    def _copy_authorized_keys(
        self,
        src: SSHClientWrapper,
        dst: SSHClientWrapper,
        recs: list[UserRecord],
        src_sudo: bool,
        dst_sudo: bool,
    ) -> None:
        for r in recs:
            key_path = f"{r.home}/.ssh/authorized_keys"
            if src.run(f"test -f {shlex.quote(key_path)}", sudo=src_sudo, check=False).code != 0:
                continue
            keys = src.run(f"cat {shlex.quote(key_path)}", sudo=src_sudo).stdout
            dst.run(f"mkdir -p {shlex.quote(r.home)}/.ssh", sudo=dst_sudo)
            tmp = f"/tmp/{r.username}.authorized_keys"
            dst.upload_text(tmp, keys, mode=0o600)
            dst.run(f"cp {shlex.quote(tmp)} {shlex.quote(r.home)}/.ssh/authorized_keys", sudo=dst_sudo)
            dst.run(f"chown -R {shlex.quote(r.username)}:{r.gid} {shlex.quote(r.home)}/.ssh", sudo=dst_sudo)
            dst.run(f"chmod 700 {shlex.quote(r.home)}/.ssh && chmod 600 {shlex.quote(r.home)}/.ssh/authorized_keys", sudo=dst_sudo)
            dst.run(f"rm -f {shlex.quote(tmp)}", sudo=dst_sudo, check=False)

    def _sync_data_rsync(self, src: SSHClientWrapper, recs: list[UserRecord], req: MigrationRequest) -> None:
        if req.destination.private_key:
            src.upload_text("/tmp/dst_mig_key", req.destination.private_key, mode=0o600)
        try:
            for r in recs:
                opts = "-aHAX --numeric-ids --partial --append-verify"
                if req.incremental:
                    opts += " --inplace"
                if req.rsync_delete:
                    opts += " --delete"

                ssh_cmd = f"ssh -p {req.destination.port} -o StrictHostKeyChecking=no"
                if req.destination.private_key:
                    ssh_cmd += " -i /tmp/dst_mig_key"

                dst_ref = f"{req.destination.username}@{req.destination.host}:{r.home}/"
                src_ref = f"{r.home}/"

                if req.destination.password:
                    cmd = (
                        "command -v sshpass >/dev/null 2>&1 || "
                        "(echo 'sshpass missing on source' && exit 1); "
                        f"sshpass -p {shlex.quote(req.destination.password)} "
                        f"rsync {opts} -e {shlex.quote(ssh_cmd)} {shlex.quote(src_ref)} {shlex.quote(dst_ref)}"
                    )
                else:
                    cmd = f"rsync {opts} -e {shlex.quote(ssh_cmd)} {shlex.quote(src_ref)} {shlex.quote(dst_ref)}"

                src.run(cmd, sudo=req.source.sudo)
        finally:
            src.run("rm -f /tmp/dst_mig_key", sudo=req.source.sudo, check=False)

    def _migrate_sshd_config(self, src: SSHClientWrapper, dst: SSHClientWrapper, group: str, sudo: bool) -> None:
        cfg = src.run("cat /etc/ssh/sshd_config", sudo=True).stdout
        if "Subsystem sftp internal-sftp" not in cfg:
            cfg += "\nSubsystem sftp internal-sftp\n"
        if f"Match Group {group}" not in cfg:
            cfg += (
                f"\nMatch Group {group}\n"
                "    ChrootDirectory %h\n"
                "    ForceCommand internal-sftp\n"
                "    X11Forwarding no\n"
                "    AllowTcpForwarding no\n"
            )

        dst.upload_text("/tmp/sshd_config.migration", cfg, mode=0o600)
        dst.run("cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak_pre_migration", sudo=sudo)
        dst.run("cp /tmp/sshd_config.migration /etc/ssh/sshd_config", sudo=sudo)
        dst.run("sshd -t", sudo=sudo)
        dst.run("systemctl restart sshd && systemctl is-active --quiet sshd", sudo=sudo)

    def _apply_selinux(self, dst: SSHClientWrapper, sudo: bool) -> None:
        mode = dst.run("getenforce", sudo=sudo, check=False).stdout.strip()
        if mode in {"Enforcing", "Permissive"}:
            dst.run(
                "if getsebool -a | grep -q '^ssh_chroot_rw_homedirs'; then setsebool -P ssh_chroot_rw_homedirs on; fi",
                sudo=sudo,
                check=False,
            )
            dst.run("restorecon -Rv /home", sudo=sudo, check=False)

    def _validate(
        self,
        src: SSHClientWrapper,
        dst: SSHClientWrapper,
        recs: list[UserRecord],
        req: MigrationRequest,
    ) -> dict:
        checks = {"users": {}, "files": {}, "sftp": {"status": "skipped"}}
        for r in recs:
            checks["users"][r.username] = (
                dst.run(f"id {shlex.quote(r.username)}", sudo=req.destination.sudo, check=False).code == 0
            )
            sf = int(
                src.run(f"find {shlex.quote(r.home)} -type f 2>/dev/null | wc -l", sudo=req.source.sudo, check=False).stdout.strip() or 0
            )
            df = int(
                dst.run(f"find {shlex.quote(r.home)} -type f 2>/dev/null | wc -l", sudo=req.destination.sudo, check=False).stdout.strip() or 0
            )
            checks["files"][r.username] = {"source": sf, "destination": df, "match": sf == df}

        if req.sample_sftp_user:
            cmd = (
                f"sftp -P {req.destination.port} -o BatchMode=yes -o StrictHostKeyChecking=no "
                f"{shlex.quote(req.sample_sftp_user)}@localhost <<<'quit'"
            )
            rc = dst.run(cmd, sudo=req.destination.sudo, check=False).code
            checks["sftp"] = {"status": "passed" if rc == 0 else "failed", "code": rc}

        return checks


migration_service = MigrationService()
