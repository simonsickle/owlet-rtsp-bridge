"""Feed native H.264 video to the RTSP publisher."""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from . import db
from .settings import settings

Feeder = Callable[[asyncio.StreamWriter, asyncio.Event], Awaitable[None]]


class SourceUnavailable(RuntimeError):
    """Raised when a camera cannot be started; the message is shown in the UI."""


@dataclass
class Plan:
    input_args: list[str]
    feeder: Feeder
    note: str


def native_plan(camera: dict[str, Any]) -> Plan:
    ip = (camera.get("lan_ip") or "").strip()
    if not ip:
        raise SourceUnavailable("Set the camera's LAN IP")
    if not shutil.which("ffmpeg"):
        raise SourceUnavailable("ffmpeg is not installed")
    binary = shutil.which(settings.owlet_tutk_bin)
    if not binary:
        raise SourceUnavailable(f"native client not found: {settings.owlet_tutk_bin} (OWLET_TUTK_BIN)")
    uid = (camera.get("tutk_uid") or "").strip()
    password = camera.get("password")
    auth_key = camera.get("auth_key")
    if not uid or not password:
        raise SourceUnavailable("Sync the account to fetch the camera credentials")
    command = [
        binary, "stream", "--uid", uid, "--ip", ip, "--port", str(camera.get("lan_port") or "scan"),
        "--security", "dtls", "--resend", "--account", "admin", "--out", "-",
    ]
    if not camera.get("lan_port") and camera.get("seen_port"):
        command += ["--port-hint", str(camera["seen_port"])]
    cam_id = camera.get("id")

    async def feed(writer: asyncio.StreamWriter, stop: asyncio.Event) -> None:
        env = os.environ.copy()
        env["OWLET_TUTK_PASSWORD"] = password
        if auth_key:
            env["OWLET_TUTK_AUTHKEY"] = auth_key
        else:
            env.pop("OWLET_TUTK_AUTHKEY", None)
        proc = await asyncio.create_subprocess_exec(
            *command, env=env, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout and proc.stderr

        async def last_error(stream: asyncio.StreamReader) -> str:
            tail = ""
            async for line in stream:
                text = line.decode("utf-8", "replace").strip()
                found = re.fullmatch(r"device port (\d+)", text)
                if found and cam_id is not None:
                    db.remember_port(cam_id, int(found.group(1)))
                elif text:
                    tail = text
            for secret in (password, auth_key):
                if secret:
                    tail = tail.replace(secret, "[redacted]")
            return tail

        stderr = asyncio.create_task(last_error(proc.stderr))
        try:
            while not stop.is_set():
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    await proc.wait()
                    break
                writer.write(chunk)
                await writer.drain()
        finally:
            # A cancelled feeder can have a full stdout pipe. Drain it after
            # killing the child so the asyncio transport can finish wait().
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
            while await proc.stdout.read(65536):
                pass
            detail = await stderr
            rc = await proc.wait()
        if not stop.is_set():
            raise SourceUnavailable(detail or f"native client exited ({rc})")

    return Plan(input_args=["-f", "h264", "-r", "15", "-i", "pipe:0"],
                feeder=feed, note="Connecting. The first start can take 1 to 3 minutes while the camera port is found.")
