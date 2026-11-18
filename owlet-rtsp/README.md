# Portal development

See the [root README](../README.md) for Docker setup.

Build the Rust client with DTLS per the [client README](../owlet-tutk/README.md). Install FFmpeg and MediaMTX v1.21.4. Use Python 3.12 or later. Run these commands from this directory.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt pytest==8.3.4
DATA_DIR=/tmp/owlet-release-test .venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q app
```

The login tests use a fake Owlet backend. The native test needs UDP loopback, the release client, FFmpeg, and FFprobe. It writes `native-e2e-report.json` in `DATA_DIR`. The report records the decoded frame count, resolution, command, and client error.

Start the local portal with `scripts/deploy-local.sh`. The script uses the release client in the adjacent crate. Set `PY` to select another Python executable.
