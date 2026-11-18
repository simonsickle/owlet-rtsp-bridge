from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import db  # noqa: E402
from app import media  # noqa: E402
from app.settings import Settings, settings  # noqa: E402


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    db.close()
    db.init()
    yield tmp_path
    db.close()


# ------------------------------------------------------------------ settings


def test_rtsp_url_plain():
    s = Settings(public_host="box.lan", rtsp_port=8554, rtsp_user="", rtsp_pass="")
    assert s.rtsp_url("cam-a") == "rtsp://box.lan:8554/cam-a"


def test_rtsp_url_with_credentials():
    s = Settings(public_host="box.lan", rtsp_port=8554, rtsp_user="u", rtsp_pass="p")
    assert s.rtsp_url("cam-a") == "rtsp://u:p@box.lan:8554/cam-a"


def test_public_hostname_defaults_to_localhost():
    assert Settings(public_host="").public_hostname == "localhost"


# ------------------------------------------------------------------ media


@pytest.mark.parametrize(
    "value,expected",
    [
        ("OWL-CAM-001", "cam-owl-cam-001"),
        ("a b/c", "cam-a-b-c"),
        ("---", "cam-camera"),
        ("", "cam-camera"),
    ],
)
def test_path_for(value, expected):
    assert media.path_for({"dsn": value}) == expected


def test_mediamtx_config_core_keys():
    cfg = media.mediamtx_config()
    assert f"rtspAddress: :{settings.rtsp_port}" in cfg
    assert "webrtc: true" in cfg
    assert "paths:" in cfg
    assert "all_others:" in cfg


def test_mediamtx_config_rtsp_auth(monkeypatch):
    monkeypatch.setattr(settings, "rtsp_user", "viewer")
    monkeypatch.setattr(settings, "rtsp_pass", "s3cret")
    cfg = media.mediamtx_config()
    digest = base64.b64encode(hashlib.sha256(b"s3cret").digest()).decode()
    assert f'  - user: "viewer"\n    pass: "sha256:{digest}"\n    permissions: [{{action: read}}]' in cfg
    assert cfg.count("{action: read}") == 1


# ------------------------------------------------------------------ db


def test_account_roundtrip(data_dir):
    assert db.get_account() is None
    db.set_account("user@example.com", "fixture-account", "token", "refresh")
    account = db.get_account()
    assert account["email"] == "user@example.com"
    assert account["id_token"] == "token"
    db.unlink_account()
    assert db.get_account() is None


def test_camera_upsert_keeps_existing_secrets(data_dir):
    cam_id = db.sync_camera({"dsn": "D1", "name": "Camera A", "tutk_uid": "U", "auth_key": "K"})
    db.sync_camera({"dsn": "D1", "name": "Camera B"})
    camera = db.get_camera(cam_id)
    assert camera["name"] == "Camera A"
    assert camera["tutk_uid"] == "U"
    assert camera["auth_key"] == "K"


def test_camera_delete(data_dir):
    cam_id = db.sync_camera({"dsn": "D2", "name": "X"})
    db.delete_camera(cam_id)
    assert db.get_camera(cam_id) is None


def test_sessions(data_dir):
    db.add_session("t1")
    assert db.has_session("t1")
    db.drop_session("t1")
    assert not db.has_session("t1")
