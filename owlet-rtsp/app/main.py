from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from . import db
from .media import MediaServer, WorkerManager, path_for
from .owlet_id import OwletIdClient, OwletIdError, SessionExpired
from .settings import settings

log = logging.getLogger("owlet-rtsp")
logging.getLogger("httpx").setLevel(logging.WARNING)
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
server = MediaServer()
manager = WorkerManager(server)


async def reconcile() -> None:
    async with app.state.worker_lock:
        await manager.reconcile(db.list_cameras())


async def background_loop() -> None:
    while True:
        try:
            await reconcile()
        except Exception:
            log.exception("Camera worker update failed")
        await asyncio.sleep(5)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    app.state.account_lock = asyncio.Lock()
    app.state.worker_lock = asyncio.Lock()
    app.state.sync_error = None
    await server.start()
    task = asyncio.create_task(background_loop())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await manager.shutdown()
        await server.stop()
        db.close()


app = FastAPI(title="Owlet RTSP", lifespan=lifespan, docs_url=None, redoc_url=None)


def current_session(request: Request) -> str | None:
    token = request.cookies.get(settings.session_cookie)
    return token if token and db.has_session(token) else None


def require_auth(request: Request) -> None:
    if current_session(request) is None:
        raise HTTPException(status_code=401, detail="Sign in required")


def owlet_id_client() -> OwletIdClient:
    return OwletIdClient(
        api_key=settings.owlet_api_key, accounts_base=settings.owlet_accounts_base,
        kms_base=settings.owlet_kms_base, package=settings.owlet_package, cert=settings.owlet_cert,
    )


async def state() -> dict[str, Any]:
    statuses = {s["path"]: s for s in await manager.status()}
    items = []
    for camera in db.list_cameras():
        path = path_for(camera)
        items.append({
            "id": camera["id"], "dsn": camera["dsn"], "name": camera["name"],
            "source": camera["source"], "enabled": bool(camera["enabled"]),
            "credentialed": bool(camera["tutk_uid"] and camera["password"]),
            "lan_ip": camera["lan_ip"], "lan_port": camera["lan_port"],
            "path": path, "rtsp_url": settings.rtsp_url(path),
            "webrtc_url": f"{settings.webrtc_base()}/{path}",
            "hls_url": f"{settings.hls_base()}/{path}/index.m3u8",
            "status": statuses.get(path) or {
                "state": "idle" if camera["enabled"] else "disabled", "ready": False,
                "detail": "", "readers": 0, "bytes_received": 0,
                "uptime": 0, "restarts": 0, "codec": None,
            },
        })
    account = db.get_account()
    return {
        "account": {"email": account["email"]} if account else None,
        "cameras": items, "sync_error": app.state.sync_error,
        "media": {"healthy": await server.healthy(), "error": server.error},
    }


async def sync_cameras(account: dict[str, Any]) -> int:
    client = owlet_id_client()
    try:
        try:
            cameras = await client.cameras(account["uid"], account["id_token"])
        except SessionExpired:
            if not account.get("refresh_token"):
                raise
            fresh = await client.refresh(account["refresh_token"])
            db.set_account(account["email"], account["uid"], fresh["id_token"], fresh["refresh_token"])
            cameras = await client.cameras(account["uid"], fresh["id_token"])
    except (OwletIdError, httpx.HTTPError) as exc:
        app.state.sync_error = str(exc) if isinstance(exc, OwletIdError) else "Cannot reach Owlet. Try Sync again."
        raise OwletIdError(app.state.sync_error) from exc
    finally:
        await client.aclose()
    for camera in cameras:
        db.sync_camera(camera)
    app.state.sync_error = None
    await reconcile()
    return len(cameras)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> Response:
    if current_session(request) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "index.html")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    if current_session(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html")


@app.post("/login")
async def login_submit(request: Request, email: str = Form(...), password: str = Form(...)) -> Response:
    client = owlet_id_client()
    try:
        identity = await client.sign_in(email.strip(), password)
    except OwletIdError as exc:
        return templates.TemplateResponse(request, "login.html", {"error": str(exc)}, status_code=400)
    except httpx.HTTPError:
        return templates.TemplateResponse(
            request, "login.html", {"error": "Cannot reach Owlet sign-in."}, status_code=502
        )
    finally:
        await client.aclose()

    async with app.state.account_lock:
        linked = db.get_account()
        if linked:
            same_account = (linked["uid"] == identity["uid"] if linked["uid"] else
                            linked["email"].casefold() == identity["email"].casefold())
            if not same_account:
                return templates.TemplateResponse(
                    request, "login.html", {"error": "Sign in with the linked Owlet account."}, status_code=403
                )
        db.set_account(identity["email"], identity["uid"], identity["id_token"], identity["refresh_token"])
        with contextlib.suppress(OwletIdError):
            await sync_cameras(db.get_account())
        token = secrets.token_urlsafe(32)
        db.add_session(token)

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(settings.session_cookie, token, httponly=True, samesite="lax",
                        secure=request.url.scheme == "https", max_age=db.SESSION_AGE)
    return response


@app.post("/logout")
async def logout(request: Request) -> Response:
    if token := request.cookies.get(settings.session_cookie):
        db.drop_session(token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(settings.session_cookie)
    return response


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "media": await server.healthy(), "time": time.time()}


@app.get("/api/state", dependencies=[Depends(require_auth)])
async def api_state() -> dict[str, Any]:
    return await state()


@app.post("/api/sync")
async def api_sync(request: Request) -> dict[str, Any]:
    async with app.state.account_lock:
        require_auth(request)
        try:
            found = await sync_cameras(db.get_account())
        except OwletIdError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"imported": found, "state": await state()}


class CameraEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1)
    enabled: bool | None = None
    lan_ip: str | None = None
    lan_port: int | None = None


def require_camera(cam_id: int) -> None:
    if not db.get_camera(cam_id):
        raise HTTPException(status_code=404, detail="Camera not found")


@app.patch("/api/cameras/{cam_id}", dependencies=[Depends(require_auth)])
async def api_patch_camera(cam_id: int, edit: CameraEdit) -> dict[str, Any]:
    require_camera(cam_id)
    fields = edit.model_dump(exclude_unset=True)
    if "name" in fields and not (edit.name or "").strip():
        raise HTTPException(status_code=400, detail="Enter a camera name")
    if "enabled" in fields and edit.enabled is None:
        raise HTTPException(status_code=400, detail="Select a publish setting")
    if edit.lan_ip is not None:
        try:
            fields["lan_ip"] = str(IPv4Address(edit.lan_ip.strip())) if edit.lan_ip.strip() else None
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Enter an IPv4 address for the camera") from exc
    if edit.lan_port is not None and not 1 <= edit.lan_port <= 65535:
        raise HTTPException(status_code=400, detail="LAN port must be between 1 and 65535")
    db.edit_camera(cam_id, fields)
    await reconcile()
    return await state()


@app.delete("/api/cameras/{cam_id}", dependencies=[Depends(require_auth)])
async def api_delete_camera(cam_id: int) -> dict[str, bool]:
    require_camera(cam_id)
    db.delete_camera(cam_id)
    await reconcile()
    return {"ok": True}


@app.post("/api/cameras/{cam_id}/restart", dependencies=[Depends(require_auth)])
async def api_restart_camera(cam_id: int) -> dict[str, Any]:
    require_camera(cam_id)
    async with app.state.worker_lock:
        await manager.drop(cam_id)
        await manager.reconcile(db.list_cameras())
    return await state()


@app.post("/api/account/unlink")
async def api_unlink(request: Request) -> Response:
    async with app.state.account_lock:
        require_auth(request)
        db.unlink_account()
        app.state.sync_error = None
        await reconcile()
    response = JSONResponse({"ok": True})
    response.delete_cookie(settings.session_cookie)
    return response


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
