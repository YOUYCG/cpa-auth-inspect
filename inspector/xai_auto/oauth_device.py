"""xAI OAuth device-code grant (Grok CLI / CPA client).

Endpoints from https://auth.x.ai/.well-known/openid-configuration
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from .proxyutil import resolve_proxy

# Keep in sync with CLIProxyAPI internal/auth/xai/types.go
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
ISSUER = "https://auth.x.ai"
DEVICE_CODE_URL = "https://auth.x.ai/oauth2/device/code"
TOKEN_URL = "https://auth.x.ai/oauth2/token"
SCOPE = "openid profile email offline_access grok-cli:access api:access"

LogFn = Callable[[str], None]


def _noop_log(_: str) -> None:
    return None


def _proxy_handler(proxy: str | None = None) -> urllib.request.ProxyHandler | None:
    p = resolve_proxy(proxy)
    if not p:
        return None
    return urllib.request.ProxyHandler({"http": p, "https": p})


def _opener(proxy: str | None = None) -> urllib.request.OpenerDirector:
    handlers: list[Any] = []
    ph = _proxy_handler(proxy)
    if ph is not None:
        handlers.append(ph)
    return urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()


def _post_form(
    url: str,
    form: dict[str, str],
    timeout: float = 30.0,
    *,
    proxy: str | None = None,
) -> tuple[int, dict[str, Any] | str]:
    data = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "grok-reg-cpa-xai-minter/1.0",
        },
    )
    opener = _opener(proxy)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = getattr(resp, "status", 200) or 200
            try:
                return int(status), json.loads(body)
            except json.JSONDecodeError:
                return int(status), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return int(e.code), json.loads(body)
        except json.JSONDecodeError:
            return int(e.code), body


@dataclass
class DeviceCodeSession:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int
    raw: dict[str, Any]


@dataclass
class TokenResult:
    access_token: str
    refresh_token: str
    id_token: str | None
    token_type: str
    expires_in: int
    raw: dict[str, Any]


class OAuthDeviceError(RuntimeError):
    pass


def request_device_code(
    *,
    client_id: str = CLIENT_ID,
    scope: str = SCOPE,
    timeout: float = 30.0,
    proxy: str | None = None,
) -> DeviceCodeSession:
    status, body = _post_form(
        DEVICE_CODE_URL,
        {"client_id": client_id, "scope": scope},
        timeout=timeout,
        proxy=proxy,
    )
    if status != 200 or not isinstance(body, dict):
        raise OAuthDeviceError(f"device code request failed HTTP {status}: {body!r}")
    device_code = str(body.get("device_code") or "").strip()
    user_code = str(body.get("user_code") or "").strip()
    if not device_code or not user_code:
        raise OAuthDeviceError(f"device code response missing fields: {body}")
    vuri = str(body.get("verification_uri") or "https://accounts.x.ai/oauth2/device").strip()
    vcomplete = str(
        body.get("verification_uri_complete") or f"{vuri}?user_code={user_code}"
    ).strip()
    expires_in = int(body.get("expires_in") or 1800)
    interval = max(int(body.get("interval") or 5), 1)
    return DeviceCodeSession(
        device_code=device_code,
        user_code=user_code,
        verification_uri=vuri,
        verification_uri_complete=vcomplete,
        expires_in=expires_in,
        interval=interval,
        raw=body,
    )


def poll_device_token(
    device_code: str,
    *,
    client_id: str = CLIENT_ID,
    interval: int = 5,
    expires_in: int = 1800,
    timeout: float = 30.0,
    log: LogFn | None = None,
    cancel: Callable[[], bool] | None = None,
    proxy: str | None = None,
) -> TokenResult:
    """Poll token endpoint until authorized or expired."""
    log = log or _noop_log
    deadline = time.time() + max(expires_in - 5, 30)
    sleep_for = max(interval, 1)
    while time.time() < deadline:
        if cancel and cancel():
            raise OAuthDeviceError("cancelled")
        status, body = _post_form(
            TOKEN_URL,
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": client_id,
            },
            timeout=timeout,
            proxy=proxy,
        )
        if status == 200 and isinstance(body, dict) and body.get("access_token"):
            access = str(body["access_token"]).strip()
            refresh = str(body.get("refresh_token") or "").strip()
            if not refresh:
                raise OAuthDeviceError("token response missing refresh_token")
            return TokenResult(
                access_token=access,
                refresh_token=refresh,
                id_token=(str(body["id_token"]).strip() if body.get("id_token") else None),
                token_type=str(body.get("token_type") or "Bearer"),
                expires_in=int(body.get("expires_in") or 21600),
                raw=body,
            )
        err = ""
        desc = ""
        if isinstance(body, dict):
            err = str(body.get("error") or "")
            desc = str(body.get("error_description") or "")
        if err in ("authorization_pending", "slow_down"):
            if err == "slow_down":
                sleep_for = min(sleep_for + 5, 30)
            log(f"oauth poll: {err} (sleep {sleep_for}s)")
            time.sleep(sleep_for)
            continue
        if err in ("expired_token", "access_denied"):
            raise OAuthDeviceError(f"device auth failed: {err}: {desc}")
        if status == 400 and err:
            raise OAuthDeviceError(f"device auth token error: {err}: {desc or body}")
        log(f"oauth poll unexpected HTTP {status}: {body!r}")
        time.sleep(sleep_for)
    raise OAuthDeviceError("device auth timed out waiting for user approval")
