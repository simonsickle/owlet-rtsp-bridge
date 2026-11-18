from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from .owlet_id import DEFAULT_API_KEY, DEFAULT_CERT, DEFAULT_PACKAGE


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _hostport(name: str, default: str) -> str:
    """Accept ``9997`` or ``127.0.0.1:9997``; both the client and MediaMTX need host:port."""
    value = (os.environ.get(name) or default).strip()
    return f"127.0.0.1:{value}" if value.isdigit() else value


@dataclass
class Settings:
    """Runtime configuration. Everything is env-driven so the image stays generic."""

    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("DATA_DIR", "/data")))
    public_host: str = field(default_factory=lambda: os.environ.get("PUBLIC_HOST", "").strip())

    rtsp_port: int = field(default_factory=lambda: _int("RTSP_PORT", 8554))
    webrtc_port: int = field(default_factory=lambda: _int("WEBRTC_PORT", 8889))
    hls_port: int = field(default_factory=lambda: _int("HLS_PORT", 8888))
    mediamtx_api: str = field(
        default_factory=lambda: _hostport("MEDIAMTX_API", "127.0.0.1:9997")
    )
    mediamtx_bin: str = field(default_factory=lambda: os.environ.get("MEDIAMTX_BIN", "mediamtx"))
    owlet_tutk_bin: str = field(default_factory=lambda: os.environ.get("OWLET_TUTK_BIN", "owlet-tutk"))

    # Optional read-side auth on the published RTSP paths.
    rtsp_user: str = field(default_factory=lambda: os.environ.get("RTSP_USER", ""))
    rtsp_pass: str = field(default_factory=lambda: os.environ.get("RTSP_PASS", ""))

    owlet_api_key: str = field(
        default_factory=lambda: os.environ.get("OWLET_API_KEY") or DEFAULT_API_KEY
    )
    owlet_accounts_base: str = field(
        default_factory=lambda: os.environ.get(
            "OWLET_ACCOUNTS_BASE", "https://accounts.owletdata.com"
        )
    )
    owlet_kms_base: str = field(
        default_factory=lambda: os.environ.get(
            "OWLET_KMS_BASE", "https://camera-kms.owletdata.com"
        )
    )
    owlet_package: str = field(
        default_factory=lambda: os.environ.get("OWLET_PACKAGE", DEFAULT_PACKAGE)
    )
    owlet_cert: str = field(
        default_factory=lambda: os.environ.get(
            "OWLET_CERT", DEFAULT_CERT
        )
    )

    session_cookie: str = "owletrtsp"

    @property
    def public_hostname(self) -> str:
        return self.public_host or "localhost"

    def rtsp_url(self, path: str) -> str:
        if self.rtsp_user and self.rtsp_pass:
            cred = f"{quote(self.rtsp_user, safe='')}:{quote(self.rtsp_pass, safe='')}@"
        else:
            cred = ""
        return f"rtsp://{cred}{self.public_hostname}:{self.rtsp_port}/{path}"

    def webrtc_base(self) -> str:
        return f"http://{self.public_hostname}:{self.webrtc_port}"

    def hls_base(self) -> str:
        return f"http://{self.public_hostname}:{self.hls_port}"


settings = Settings()
