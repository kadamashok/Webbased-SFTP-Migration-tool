from __future__ import annotations

import io
import shlex
import socket
from dataclasses import dataclass
from typing import Optional

import paramiko


class SSHCommandError(RuntimeError):
    pass


@dataclass
class SSHResult:
    code: int
    stdout: str
    stderr: str


class SSHClientWrapper:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        private_key: Optional[str],
        timeout: int = 15,
        **_: object,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        self.timeout = timeout
        self.client: Optional[paramiko.SSHClient] = None

    def __enter__(self) -> "SSHClientWrapper":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def connect(self) -> None:
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey = None
        if self.private_key:
            key_stream = io.StringIO(self.private_key)
            try:
                pkey = paramiko.RSAKey.from_private_key(key_stream)
            except paramiko.SSHException:
                key_stream.seek(0)
                pkey = paramiko.Ed25519Key.from_private_key(key_stream)

        try:
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                pkey=pkey,
                look_for_keys=False,
                allow_agent=False,
                timeout=self.timeout,
                banner_timeout=self.timeout,
            )
        except (paramiko.SSHException, socket.error) as exc:
            raise SSHCommandError(f"SSH connection failed to {self.host}:{self.port}: {exc}") from exc

    def run(self, command: str, sudo: bool = False, check: bool = True) -> SSHResult:
        if not self.client:
            raise SSHCommandError("SSH client is not connected")

        if sudo and self.username != "root":
            command = f"sudo -n bash -lc {shlex.quote(command)}"
        else:
            command = f"bash -lc {shlex.quote(command)}"

        _, stdout, stderr = self.client.exec_command(command)
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")

        result = SSHResult(code=code, stdout=out, stderr=err)
        if check and code != 0:
            raise SSHCommandError(
                f"Command failed on {self.host}: code={code}, stderr={err.strip()}"
            )
        return result

    def upload_text(self, remote_path: str, content: str, mode: int = 0o600) -> None:
        if not self.client:
            raise SSHCommandError("SSH client is not connected")
        with self.client.open_sftp() as sftp:
            with sftp.file(remote_path, "w") as remote_file:
                remote_file.write(content)
            sftp.chmod(remote_path, mode)

    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None
