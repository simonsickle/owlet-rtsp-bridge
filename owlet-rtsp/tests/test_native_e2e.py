"""Publish a finite H.264 clip through the native worker and a loopback DTLS camera."""

import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.media import MediaServer, WorkerManager  # noqa: E402
from app.settings import settings  # noqa: E402

BINARY = ROOT.parent / "owlet-tutk/target/release/owlet-tutk"
UID = "FAKECAM0000000000001"
PASSWORD = "native-camera-fixture"
WRONG_PASSWORD = "wrong-camera-fixture"
AUTH_KEY = "Auth4321"


async def wait_until(condition, timeout=20):
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.05)


def test_native_camera_stream(tmp_path, monkeypatch):
    if not os.access(BINARY, os.X_OK):
        pytest.skip(f"Missing release client at {BINARY}. Build owlet-tutk with --features dtls.")
    for tool in ("ffmpeg", "ffprobe"):
        if not shutil.which(tool):
            pytest.skip(f"The native stream test requires {tool} on PATH.")

    source = tmp_path / "source.h264"
    output = tmp_path / "received.mkv"
    subprocess.run([
        "ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc2=size=160x96:rate=15",
        "-frames:v", "36", "-c:v", "libx264", "-tune", "zerolatency", "-f", "h264", str(source),
    ], check=True, timeout=15)
    monkeypatch.setattr(settings, "owlet_tutk_bin", str(BINARY))

    manager = WorkerManager(MediaServer())
    publisher_command = manager._ffmpeg_command

    def file_output(plan, path):
        cmd = publisher_command(plan, path)
        assert cmd[-5:-1] == ["-f", "rtsp", "-rtsp_transport", "tcp"]
        assert cmd[cmd.index("-c") + 1] == "copy"
        return [*cmd[:-5], "-y", str(output)]

    monkeypatch.setattr(manager, "_ffmpeg_command", file_output)
    spawn = asyncio.create_subprocess_exec
    clients = []

    async def observe_spawn(*argv, **options):
        process = await spawn(*argv, **options)
        if argv[:2] == (str(BINARY), "stream"):
            clients.append((list(argv), process))
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", observe_spawn)

    async def run():
        camera = await spawn(
            str(BINARY), "fake-camera", "--ip", "127.0.0.1", "--port", "0",
            "--uid", UID, "--security", "dtls", "--start-on-login", "--h264", str(source),
            env={**os.environ, "OWLET_TUTK_PASSWORD": PASSWORD, "OWLET_TUTK_AUTHKEY": AUTH_KEY},
            stdout=asyncio.subprocess.PIPE,
        )
        try:
            ready = await asyncio.wait_for(camera.stdout.readline(), 5)
            assert ready.startswith(b"listening 127.0.0.1:"), "fake-camera did not bind to loopback"
            port = int(ready.rsplit(b":", 1)[1])
            row = {
                "id": 1, "dsn": "fake", "source": "native", "tutk_uid": UID,
                "lan_ip": "127.0.0.1", "lan_port": port,
                "password": PASSWORD, "auth_key": AUTH_KEY,
            }
            manager.ensure(row)
            worker = manager.workers[1]
            await wait_until(lambda: worker.restarts > 0)
            probe = subprocess.check_output([
                "ffprobe", "-v", "error", "-select_streams", "v:0", "-count_frames",
                "-show_entries", "stream=codec_name,width,height,nb_read_frames,r_frame_rate",
                "-of", "json", str(output),
            ], timeout=10)
            stream, = json.loads(probe)["streams"]
            frames = int(stream["nb_read_frames"])
            assert stream["codec_name"] == "h264"
            assert (stream["width"], stream["height"]) == (160, 96)
            assert stream["r_frame_rate"] == "15/1"
            assert frames > 20

            await wait_until(lambda: len(clients) == 2)
            assert clients[-1][1].returncode is None
            await asyncio.wait_for(manager.drop(1), 5)
            assert all(process.returncode is not None for _, process in clients)

            manager.ensure({**row, "password": WRONG_PASSWORD})
            worker = manager.workers[1]
            await wait_until(lambda: worker.restarts > 0)
            detail = worker.snapshot()["detail"]
            assert detail in {
                "owlet-tutk: DTLS password rejected (-20040)",
                "owlet-tutk: DTLS handshake timeout (-20011)",
                "owlet-tutk: peer closed before DTLS handshake completed (-20011)",
            }
            expected = [
                str(BINARY), "stream", "--uid", UID, "--ip", "127.0.0.1",
                "--port", str(port), "--security", "dtls", "--resend",
                "--account", "admin", "--out", "-",
            ]
            for command, _ in clients:
                for secret in (PASSWORD, WRONG_PASSWORD, AUTH_KEY):
                    assert all(secret not in arg for arg in command)
                assert command == expected
            return {
                "frame_count": frames,
                "resolution": [stream["width"], stream["height"]],
                "command": [BINARY.name, *clients[0][0][1:]],
                "wrong_password_detail": detail,
            }
        finally:
            try:
                await manager.shutdown()
            finally:
                if camera.returncode is None:
                    camera.kill()
                await camera.wait()

    report = asyncio.run(run())
    path = settings.data_dir / "native-e2e-report.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
