"""Exercise the portal through HTTP with a fake Firebase, Owlet account and KMS."""

from __future__ import annotations

import sqlite3
import json
import sys
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import db, main  # noqa: E402
from app.media import WorkerManager  # noqa: E402
from app.owlet_id import DEFAULT_CERT, OwletIdClient  # noqa: E402
from app.settings import settings  # noqa: E402

UID = "fixture-account"
EMAIL = "user@example.com"
DSN = "OCC0000000000000"
OTHER_DSN = "OCC0000000000001"
TOKEN = "fixture-id-token"
SEEN: dict[str, object] = {}


def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if "identitytoolkit" in url:
        body = json.loads(request.content)
        SEEN["email"] = body.get("email")
        SEEN["package"] = request.headers.get("x-android-package")
        SEEN["cert"] = request.headers.get("x-android-cert")
        if body.get("password") != "correct-horse":
            return httpx.Response(400, json={"error": {"message": "INVALID_PASSWORD"}})
        return httpx.Response(
            200,
            json={
                "idToken": TOKEN,
                "localId": UID,
                "email": body["email"],
                "refreshToken": "refresh-1",
                "expiresIn": "3600",
            },
        )
    if "/kms/" in url:
        assert request.headers["authorization"] == TOKEN, "KMS uses the raw token"
        dsn = url.rsplit("/", 1)[-1]
        if dsn == OTHER_DSN:
            return httpx.Response(404, json={"title": "Not Found"})
        return httpx.Response(
            200, json={"password": "pw-abc", "tutkid": "ABCDEFGHJKLMNPRSTUVW", "authKey": "KEY-ABC"}
        )
    assert request.headers["authorization"] == f"Bearer {TOKEN}", url
    if url.endswith(f"/v2/accounts/{UID}/services"):
        return httpx.Response(
            200,
            json={
                "services": [
                    {
                        "name": f"accounts/{UID}/services/cam-1",
                        "serviceType": "SERVICE_TYPE_CAMERA",
                        "displayName": "Camera A",
                        "device": {
                            "dsn": DSN,
                            "deviceType": "DEVICE_TYPE_CAMERA2",
                            "firmwareVersion": "4.2.29",
                        },
                    },
                    {
                        "name": f"accounts/{UID}/services/cam-2",
                        "serviceType": "SERVICE_TYPE_CAMERA",
                        "displayName": "Camera B",
                        "device": {"dsn": OTHER_DSN, "deviceType": "DEVICE_TYPE_CAMERA2"},
                    },
                    {
                        "name": f"accounts/{UID}/services/band-1",
                        "serviceType": "SERVICE_TYPE_BAND",
                        "displayName": "Dream Band",
                        "device": {"dsn": "OB0000000", "deviceType": "DEVICE_TYPE_BAND"},
                    },
                ]
            },
        )
    if url.endswith(f"/v2/accounts/{UID}"):
        return httpx.Response(200, json={"name": f"accounts/{UID}", "email": EMAIL})
    return httpx.Response(404, json={"title": "Not Found"})


class FakeServer:
    def __init__(self) -> None:
        self.error = None
        self.adopted = False

    async def start(self) -> None: ...
    async def stop(self) -> None: ...

    async def healthy(self) -> bool:
        return False

    async def paths(self) -> dict:
        return {}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db.close()
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    monkeypatch.setattr(settings, "public_host", "localhost")
    monkeypatch.setattr(
        main,
        "owlet_id_client",
        lambda: OwletIdClient(
            api_key="stub-key",
            accounts_base="https://accounts.test",
            transport=httpx.MockTransport(handler),
        ),
    )
    SEEN.clear()

    fake = FakeServer()
    monkeypatch.setattr(main, "server", fake)
    monkeypatch.setattr(main, "manager", WorkerManager(fake))

    with TestClient(main.app) as test_client:
        yield test_client
    db.close()


def login(client):
    response = client.post("/login", data={"email": EMAIL, "password": "correct-horse"},
                           follow_redirects=False)
    assert response.status_code == 303, response.text
    return response


def test_login_imports_native_cameras(client):
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/state").status_code == 401
    assert client.post("/api/account/unlink").status_code == 401
    assert "HttpOnly" in login(client).headers["set-cookie"]
    assert SEEN == {"email": EMAIL, "package": "com.owletcare.sleep", "cert": DEFAULT_CERT}
    state = client.get("/api/state").json()
    assert state["account"] == {"email": EMAIL}
    cameras = {row["dsn"]: row for row in state["cameras"]}
    assert set(cameras) == {DSN, OTHER_DSN}
    cam = cameras[DSN]
    assert cam["source"] == "native" and cam["credentialed"] and cam["enabled"]
    assert cam["name"] == "Camera A" and cam["lan_ip"] is None
    assert not cameras[OTHER_DSN]["credentialed"]
    assert not {"password", "auth_key", "tutk_uid"}.intersection(cam)
    assert cam["rtsp_url"] == f"rtsp://localhost:8554/cam-{DSN.lower()}"
    assert cam["hls_url"].endswith(f"/cam-{DSN.lower()}/index.m3u8")
    assert cam["webrtc_url"].endswith(f"/cam-{DSN.lower()}")


def test_native_camera_settings_survive_sync(client):
    login(client)
    camera = client.get("/api/state").json()["cameras"][0]
    endpoint = f"/api/cameras/{camera['id']}"
    for invalid in ({"lan_port": 65536}, {"lan_ip": "not-an-address"}):
        assert client.patch(endpoint, json=invalid).status_code == 400
    changes = {"name": "Custom camera", "enabled": False, "lan_ip": "192.0.2.10", "lan_port": 31000}
    client.patch(endpoint, json=changes).raise_for_status()
    synced = client.post("/api/sync").json()["state"]["cameras"]
    assert len(synced) == 2
    assert {key: synced[0][key] for key in changes} == changes
    assert client.patch(endpoint, json={"name": "Renamed"}).json()["cameras"][0]["lan_port"] == 31000
    assert client.patch(endpoint, json={"lan_port": None}).json()["cameras"][0]["lan_port"] is None
    assert client.post(f"{endpoint}/restart").status_code == 200
    assert client.delete(endpoint).status_code == 200
    assert [c["dsn"] for c in client.get("/api/state").json()["cameras"]] == [OTHER_DSN]


def test_logout_and_unlink(client):
    login(client)
    old_cookie = client.cookies.get(settings.session_cookie)
    client.post("/logout")
    client.cookies.set(settings.session_cookie, old_cookie)
    assert client.get("/api/state").status_code == 401
    assert db.get_account()["email"] == EMAIL
    client.cookies.clear()
    login(client)
    assert client.post("/api/account/unlink").status_code == 200
    assert client.get("/api/state").status_code == 401
    assert db.get_account() is None and db.list_cameras() == []


def test_bad_password_surfaces_the_reason(client):
    response = client.post("/login", data={"email": EMAIL, "password": "wrong"})
    assert response.status_code == 400
    assert "email or password is incorrect" in response.text
    assert client.get("/api/state").status_code == 401


def test_refresh_token_keeps_the_account_alive(client, monkeypatch):
    login(client)

    def expired(request):
        if request.url.host == "securetoken.googleapis.com":
            assert b"refresh_token=refresh-1" in request.content
            return httpx.Response(200, json={"id_token": "fresh-token", "refresh_token": "refresh-2",
                                             "user_id": UID, "expires_in": "3600"})
        if request.headers["authorization"] == f"Bearer {TOKEN}":
            return httpx.Response(401)
        assert request.headers["authorization"] == "Bearer fresh-token"
        return httpx.Response(200, json={"services": []})

    monkeypatch.setattr(main, "owlet_id_client",
                        lambda: OwletIdClient(transport=httpx.MockTransport(expired)))
    assert client.post("/api/sync").status_code == 200
    account = db.get_account()
    assert (account["refresh_token"], account["id_token"], account["uid"]) == ("refresh-2", "fresh-token", UID)


def test_expired_session_is_reported(client, monkeypatch):
    def unauthorized(request):
        if "identitytoolkit" in str(request.url):
            return handler(request)
        return httpx.Response(401, json={"title": "Unauthorized"})

    monkeypatch.setattr(main, "owlet_id_client",
                        lambda: OwletIdClient(transport=httpx.MockTransport(unauthorized)))
    login(client)
    assert client.get("/api/state").json()["cameras"] == []
    assert client.post("/api/sync").status_code == 400


def test_upgrade_preserves_camera_and_refresh_token(tmp_path, monkeypatch):
    db.close()
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    with sqlite3.connect(db.db_path()) as old:
        old.executescript("""
            CREATE TABLE account (id INTEGER PRIMARY KEY, email TEXT, uid TEXT, id_token TEXT,
                                  ayla_refresh TEXT, updated_at REAL NOT NULL);
            INSERT INTO account VALUES (1,'user@example.com','fixture-account','id','old-refresh',0);
            CREATE TABLE cameras (id INTEGER PRIMARY KEY, dsn TEXT UNIQUE, name TEXT, source TEXT,
                                  tutk_uid TEXT, password TEXT, auth_key TEXT, bridge_port INTEGER,
                                  sort INTEGER, enabled INTEGER, created_at REAL);
            INSERT INTO cameras VALUES (1,'example','Example','demo',NULL,NULL,NULL,NULL,0,1,0);
            INSERT INTO cameras VALUES (2,'OCC0000000000000','Custom camera','bridge',
                                        NULL,'fixture',NULL,5000,0,0,0);
        """)
    try:
        for _ in range(2):
            db.init()
            camera, = db.list_cameras()
            assert (camera["id"], camera["name"], camera["enabled"]) == (2, "Custom camera", 0)
            assert camera["source"] == "native" and camera["password"] == "fixture"
            assert camera["lan_ip"] is None and camera["lan_port"] is None
            assert db.get_account()["refresh_token"] == "old-refresh"
    finally:
        db.close()
