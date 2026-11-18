"""MediaMTX supervision and per-camera publisher workers."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from .settings import settings
from .sources import Plan, SourceUnavailable, native_plan

log = logging.getLogger(__name__)


def slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", value or "").strip("-").lower()
    return cleaned or "camera"


def path_for(camera: dict[str, Any]) -> str:
    return f"cam-{slug(str(camera.get('dsn') or camera.get('id') or ''))}"


def mediamtx_config() -> str:
    if bool(settings.rtsp_user) != bool(settings.rtsp_pass):
        raise ValueError("Set both RTSP_USER and RTSP_PASS")
    if settings.rtsp_user == "any" or ":" in settings.rtsp_user:
        raise ValueError("Choose an RTSP_USER other than 'any' and omit colons")
    read_pass = ""
    if settings.rtsp_pass:
        digest = hashlib.sha256(settings.rtsp_pass.encode()).digest()
        read_pass = "sha256:" + base64.b64encode(digest).decode("ascii")
    lines = [
        "logLevel: info",
        "readTimeout: 20s",
        "writeTimeout: 20s",
        "api: true",
        f"apiAddress: {settings.mediamtx_api}",
        "authInternalUsers:",
        "  - user: any",
        "    ips: [127.0.0.1, '::1']",
        "    permissions: [{action: api}, {action: publish}]",
        f"  - user: {json.dumps(settings.rtsp_user or 'any')}",
        f"    pass: {json.dumps(read_pass)}",
        "    permissions: [{action: read}]",
        "rtsp: true",
        f"rtspAddress: :{settings.rtsp_port}",
        "rtpAddress: :8100",
        "rtcpAddress: :8101",
        "srt: false",
        "rtmp: false",
        "moq: false",
        "hls: true",
        f"hlsAddress: :{settings.hls_port}",
        "hlsVariant: lowLatency",
        "hlsSegmentDuration: 1s",
        "hlsPartDuration: 200ms",
        "hlsAllowOrigins: ['*']",
        "webrtc: true",
        f"webrtcAddress: :{settings.webrtc_port}",
        "webrtcAllowOrigins: ['*']",
        "webrtcLocalUDPAddress: :8189",
        "webrtcIPsFromInterfaces: true",
    ]
    if settings.public_host:
        lines.append(f"webrtcAdditionalHosts: {json.dumps([settings.public_host])}")
    lines.append("pathDefaults:")
    lines.append("  source: publisher")
    lines.append("paths:")
    lines.append("  all_others:")
    return "\n".join(lines) + "\n"


class MediaServer:
    def __init__(self) -> None:
        self.proc: asyncio.subprocess.Process | None = None
        self.config_path = settings.data_dir.resolve() / "mediamtx.yml"
        self.log_path = settings.data_dir / "mediamtx.log"
        self.started_at: float | None = None
        self.error: str | None = None
        self.adopted = False
        self._watch: asyncio.Task[None] | None = None
        self._stopping = False

    async def _spawn(self) -> bool:
        binary = shutil.which(settings.mediamtx_bin) or settings.mediamtx_bin
        if not Path(binary).exists():
            self.error = f"MediaMTX binary not found ({settings.mediamtx_bin})"
            return False
        self.config_path.write_text(mediamtx_config(), encoding="utf-8")
        with self.log_path.open("ab", buffering=0) as handle:
            self.proc = await asyncio.create_subprocess_exec(
                binary, str(self.config_path), stdout=handle, stderr=handle, cwd=str(settings.data_dir)
            )
        self.started_at = time.time()
        for _ in range(50):
            if self.proc.returncode is not None:
                return False
            if await self.healthy():
                return True
            await asyncio.sleep(0.2)
        return False

    async def start(self) -> None:
        # An operator may run MediaMTX next to us; adopt it instead of fighting
        # over the RTSP/API ports.
        if await self.healthy():
            self.adopted = True
            self.error = None
            log.info("using the MediaMTX already listening on %s", settings.mediamtx_api)
            return
        if await self._spawn():
            self.error = None
            log.info("MediaMTX ready on %s", settings.mediamtx_api)
            self._watch = asyncio.create_task(self._supervise())
            return
        self.error = f"MediaMTX failed to start; see {self.log_path}"
        log.error(self.error)

    async def _supervise(self) -> None:
        backoff = 2.0
        while not self._stopping:
            proc = self.proc
            if proc is None:
                return
            rc = await proc.wait()
            self.proc = None
            self.error = f"MediaMTX exited ({rc}); retrying in {backoff:.0f}s"
            log.warning(self.error)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
            if self._stopping:
                return
            if await self.healthy():
                self.adopted = True
                self.error = None
                log.info("another MediaMTX took over; adopting it")
                return
            if await self._spawn():
                self.error = None
                backoff = 2.0
                log.info("MediaMTX restarted")

    async def healthy(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"http://{settings.mediamtx_api}/v3/config/global/get")
                return resp.status_code == 200
        except Exception:
            return False

    async def paths(self) -> dict[str, dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"http://{settings.mediamtx_api}/v3/paths/list")
                resp.raise_for_status()
                return {item["name"]: item for item in resp.json().get("items", [])}
        except Exception:
            return {}

    async def stop(self) -> None:
        self._stopping = True
        if self._watch:
            self._watch.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._watch
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.proc.kill()


@dataclass
class Worker:
    camera: dict[str, Any]
    path: str
    state: str = "idle"          # idle | starting | live | retrying | error | stopped
    detail: str = ""
    restarts: int = 0
    started_at: float | None = None
    proc: asyncio.subprocess.Process | None = None
    _stop: asyncio.Event = field(default_factory=asyncio.Event)
    _task: asyncio.Task[None] | None = None

    def stop(self) -> None:
        self._stop.set()

    def snapshot(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "state": self.state,
            "detail": self.detail,
            "restarts": self.restarts,
            "uptime": round(time.time() - self.started_at) if self.started_at else 0,
            "publisher_pid": self.proc.pid if self.proc and self.proc.returncode is None else None,
        }


class WorkerManager:
    def __init__(self, server: MediaServer) -> None:
        self.server = server
        self.workers: dict[int, Worker] = {}

    # -- planning -----------------------------------------------------

    def _ffmpeg_command(self, plan: Plan, path: str) -> list[str]:
        cmd = [
            shutil.which("ffmpeg") or "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "warning",
            "-fflags",
            "+genpts",
            *plan.input_args,
        ]
        cmd += [
            "-c",
            "copy",
            "-f",
            "rtsp",
            "-rtsp_transport",
            "tcp",
            f"rtsp://127.0.0.1:{settings.rtsp_port}/{path}",
        ]
        return cmd

    async def _run(self, worker: Worker) -> None:
        backoff = 2.0
        while not worker._stop.is_set():
            try:
                plan = native_plan(worker.camera)
            except SourceUnavailable as exc:
                worker.state = "error"
                worker.detail = str(exc)
                return
            except Exception as exc:  # pragma: no cover - defensive
                worker.state = "error"
                worker.detail = f"{type(exc).__name__}: {exc}"
                return

            if not worker.restarts:
                worker.detail = plan.note or ""
            worker.state = "retrying" if worker.restarts else "starting"
            cmd = self._ffmpeg_command(plan, worker.path)
            log.info("starting %s: %s", worker.path, " ".join(cmd[:8]) + " ...")
            try:
                worker.proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
            except Exception as exc:
                worker.state = "error"
                worker.detail = f"failed to spawn ffmpeg: {exc}"
                return

            worker.started_at = time.time()
            detail = await self._supervise_publisher(worker, plan)
            worker.proc = None
            worker.started_at = None
            if worker._stop.is_set():
                worker.state = "stopped"
                return
            worker.restarts += 1
            worker.state = "retrying"
            worker.detail = detail
            log.warning("%s: %s", worker.path, detail)
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(worker._stop.wait(), backoff)
            backoff = min(backoff * 2, 30.0)

    async def _supervise_publisher(self, worker: Worker, plan: Plan) -> str:
        proc = worker.proc
        assert proc and proc.stdin
        drain = asyncio.create_task(self._drain_stderr(worker))
        waiter = asyncio.create_task(proc.wait())
        stopping = asyncio.create_task(worker._stop.wait())
        feeder = asyncio.create_task(plan.feeder(proc.stdin, worker._stop))
        detail = ""
        try:
            await asyncio.wait([waiter, stopping, feeder], return_when=asyncio.FIRST_COMPLETED)
        finally:
            stopping.cancel()
            feeder.cancel()
            try:
                await feeder
            except (asyncio.CancelledError, BrokenPipeError, ConnectionResetError):
                pass
            except Exception as exc:
                detail = str(exc) or type(exc).__name__
            # EOF lets ffmpeg flush the last frames on a finite input. Bound
            # the wait if the publisher is stuck opening its input or output.
            proc.stdin.close()
            if worker._stop.is_set() and proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
            try:
                rc = await asyncio.wait_for(asyncio.shield(waiter), 2)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                rc = await waiter
            stderr_tail = await drain
        return detail or stderr_tail or f"publisher exited ({rc})"

    async def _drain_stderr(self, worker: Worker) -> str:
        assert worker.proc and worker.proc.stderr
        tail: list[str] = []
        while True:
            line = await worker.proc.stderr.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").strip()
            if text:
                tail.append(text)
                del tail[:-4]
        return " | ".join(tail)

    # -- lifecycle ----------------------------------------------------

    def ensure(self, camera: dict[str, Any]) -> None:
        cam_id = int(camera["id"])
        existing = self.workers.get(cam_id)
        if existing:
            return
        worker = Worker(camera=camera, path=path_for(camera))
        worker._task = asyncio.create_task(self._run(worker))
        self.workers[cam_id] = worker

    async def drop(self, cam_id: int) -> None:
        worker = self.workers.get(cam_id)
        if not worker:
            return
        worker.stop()
        if worker._task:
            await worker._task
        if self.workers.get(cam_id) is worker:
            del self.workers[cam_id]

    async def reconcile(self, cameras: list[dict[str, Any]]) -> None:
        wanted = {int(c["id"]) for c in cameras if int(c.get("enabled", 0))}
        for cam_id in self.workers.keys() - wanted:
            await self.drop(cam_id)
        for camera in cameras:
            if camera["id"] in wanted:
                worker = self.workers.get(camera["id"])
                if worker and worker.camera != camera:
                    await self.drop(camera["id"])
                self.ensure(camera)

    async def shutdown(self) -> None:
        for cam_id in list(self.workers):
            await self.drop(cam_id)

    async def status(self) -> list[dict[str, Any]]:
        live = await self.server.paths()
        out = []
        for cam_id, worker in self.workers.items():
            info = worker.snapshot()
            path_info = live.get(worker.path) or {}
            info["ready"] = bool(path_info.get("ready"))
            if worker.proc and info["ready"]:
                info.update(state="live", detail="")
            info["readers"] = len(path_info.get("readers") or [])
            info["bytes_received"] = path_info.get("bytesReceived") or 0
            tracks = path_info.get("tracks") or []
            info["codec"] = tracks[0].split("/")[0] if tracks else None
            out.append(info)
        return out
