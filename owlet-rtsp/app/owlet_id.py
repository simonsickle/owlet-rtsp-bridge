"""Sign in with Firebase and fetch Owlet cameras and their LAN credentials."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

# The app's own public Firebase client key. Client keys are not secrets; they
# ship inside every APK and are restricted by package name + signing cert.
DEFAULT_API_KEY = "AIzaSyDlfp3urNTbyhCtHOCxZBOjHQf4WuN_Aws"

# Restrictions that make the key usable: the installed package and its cert.
DEFAULT_PACKAGE = "com.owletcare.sleep"
DEFAULT_CERT = "2A3BC26DB0B8B0792DBE28E6FFDC2598F9B12B74"

CAMERA_SERVICE = "SERVICE_TYPE_CAMERA"

_FIREBASE_MESSAGES = {
    "EMAIL_NOT_FOUND": "email or password is incorrect",
    "INVALID_PASSWORD": "email or password is incorrect",
    "INVALID_LOGIN_CREDENTIALS": "email or password is incorrect",
    "INVALID_EMAIL": "that is not a valid email address",
    "TOO_MANY_ATTEMPTS_TRY_LATER": "too many attempts; wait a few minutes",
    "API_KEY_INVALID": "the app's Firebase key was rejected",
    "OPERATION_NOT_ALLOWED": "password sign-in is disabled for this project",
}


class OwletIdError(RuntimeError):
    """A failure the user can act on (bad password, unreachable service, ...)."""


class SessionExpired(OwletIdError):
    """The server requires a fresh Firebase ID token."""


class OwletIdClient:
    """Firebase sign-in plus the Owlet account/service API."""

    def __init__(
        self,
        api_key: str = DEFAULT_API_KEY,
        accounts_base: str = "https://accounts.owletdata.com",
        kms_base: str = "https://camera-kms.owletdata.com",
        package: str = DEFAULT_PACKAGE,
        cert: str = DEFAULT_CERT,
        timeout: float = 25.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.api_key = api_key
        self.accounts_base = accounts_base.rstrip("/")
        self.kms_base = kms_base.rstrip("/")
        self.package = package
        self.cert = cert
        self._http = httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, transport=transport
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- auth ---------------------------------------------------------

    async def sign_in(self, email: str, password: str) -> dict[str, Any]:
        if not self.api_key:
            raise OwletIdError("OWLET_API_KEY is not set")
        payload = {"email": email, "password": password, "returnSecureToken": True}
        headers = {
            "X-Android-Package": self.package,
            "X-Android-Cert": self.cert,
            "Accept": "application/json",
        }
        resp = await self._http.post(
            "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword",
            params={"key": self.api_key},
            json=payload,
            headers=headers,
        )
        data = _json(resp) or {}
        if resp.status_code >= 400:
            message = ((data or {}).get("error") or {}).get("message", "")
            raise OwletIdError(
                _FIREBASE_MESSAGES.get(message) or f"sign-in failed: {message or resp.status_code}"
            )
        token = data.get("idToken")
        uid = data.get("localId")
        if not token or not uid:
            raise OwletIdError("sign-in returned no token")
        return {
            "uid": uid,
            "id_token": token,
            "email": data.get("email") or email,
            "refresh_token": data.get("refreshToken"),
            "expires_at": time.time() + float(data.get("expiresIn") or 3600),
        }

    async def refresh(self, refresh_token: str) -> dict[str, Any]:
        """Exchange a Firebase refresh token for a fresh idToken.

        The portal stores the refresh token at login, so the account does not go
        dark an hour later.
        """
        if not refresh_token:
            raise OwletIdError("no refresh token stored for this account")
        resp = await self._http.post(
            "https://securetoken.googleapis.com/v1/token",
            params={"key": self.api_key},
            headers={"X-Android-Package": self.package, "X-Android-Cert": self.cert},
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        )
        data = _json(resp) or {}
        if resp.status_code >= 400 or not data.get("id_token"):
            message = (data.get("error") or {}).get("message") if isinstance(data, dict) else ""
            raise OwletIdError(f"session refresh failed: {message or resp.status_code}")
        return {
            "id_token": data["id_token"],
            "refresh_token": data.get("refresh_token") or refresh_token,
            "uid": data.get("user_id"),
            "expires_at": time.time() + float(data.get("expires_in") or 3600),
        }

    # -- account ------------------------------------------------------

    def _headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    async def services(self, uid: str, token: str) -> list[dict[str, Any]]:
        resp = await self._http.get(
            f"{self.accounts_base}/v2/accounts/{uid}/services",
            headers=self._headers(token),
        )
        if resp.status_code == 401:
            raise SessionExpired("Your session expired. Sign in again.")
        if resp.status_code >= 400:
            raise OwletIdError(f"service list failed: HTTP {resp.status_code}")
        body = _json(resp) or {}
        return list(body.get("services") or [])

    async def cameras(self, uid: str, token: str) -> list[dict[str, Any]]:
        """Return one row for each camera on the account."""
        found: list[dict[str, Any]] = []
        for service in await self.services(uid, token):
            if service.get("serviceType") != CAMERA_SERVICE:
                continue
            device = service.get("device") or {}
            dsn = str(device.get("dsn") or "").strip()
            if not dsn:
                continue
            row = {
                "dsn": dsn,
                "name": str(service.get("displayName") or dsn).strip(),
                "tutk_uid": None,
                "password": None,
                "auth_key": None,
            }
            # Per-camera ThroughTek secrets live behind the camera KMS, keyed by
            # DSN and authorised by the same Firebase token.
            try:
                creds = await self.credentials(dsn, token)
            except SessionExpired:
                raise
            except OwletIdError as exc:
                log.warning("KMS lookup failed for %s: %s", dsn, exc)
                creds = {}
            row["tutk_uid"] = creds.get("tutkid") or creds.get("tutk_uid")
            row["password"] = creds.get("password")
            row["auth_key"] = creds.get("authKey") or creds.get("auth_key")
            found.append(row)
        return found

    async def credentials(self, dsn: str, token: str) -> dict[str, Any]:
        """``GET https://camera-kms.owletdata.com/kms/{dsn}``

        Mirrors ``CameraNetworker.retrievePassword`` in the APK: the token goes
        in as the raw ``Authorization`` value, not as ``Bearer``.
        """
        resp = await self._http.get(
            f"{self.kms_base}/kms/{dsn}", headers={"Authorization": token, "Accept": "application/json"}
        )
        if resp.status_code == 401:
            raise SessionExpired("Your session expired. Sign in again.")
        if resp.status_code == 404:
            raise OwletIdError(f"no camera credentials for {dsn}")
        if resp.status_code >= 400:
            raise OwletIdError(f"camera credentials failed: HTTP {resp.status_code}")
        body = _json(resp) or {}
        if not isinstance(body, dict) or not (body.get("tutkid") or body.get("password")):
            raise OwletIdError(f"camera credentials for {dsn} were empty")
        return body


def _json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None
