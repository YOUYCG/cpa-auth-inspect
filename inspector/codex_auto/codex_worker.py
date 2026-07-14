"""One-shot CLIProxyAPI-compatible Codex OAuth worker."""

from __future__ import annotations

import json
import sys
import threading
import time
from typing import Any

import httpx

from .browser_login import complete_codex_login

CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
TOKEN_URL = "https://auth.openai.com/oauth/token"
DEVICE_USER_CODE_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode"
DEVICE_TOKEN_URL = "https://auth.openai.com/api/accounts/deviceauth/token"
DEVICE_VERIFICATION_URL = "https://auth.openai.com/codex/device"
DEVICE_REDIRECT_URI = "https://auth.openai.com/deviceauth/callback"


def log(message: str) -> None:
    print(str(message), file=sys.stderr, flush=True)


class CodexOAuthError(RuntimeError):
    pass


def _client(payload: dict[str, Any], timeout: float = 30) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        proxy=payload.get("proxy") or None,
        headers={"Accept": "application/json"},
    )


def _token_result(body: dict[str, Any], *, mode: str) -> dict[str, Any]:
    access = str(body.get("access_token") or "")
    refresh = str(body.get("refresh_token") or "")
    if not access or not refresh:
        raise CodexOAuthError("codex_token_response_missing_tokens")
    return {
        "access_token": access,
        "refresh_token": refresh,
        "id_token": str(body.get("id_token") or ""),
        "token_type": str(body.get("token_type") or "Bearer"),
        "expires_in": int(body.get("expires_in") or 3600),
        "mode": mode,
    }


def refresh_tokens(payload: dict[str, Any]) -> dict[str, Any]:
    refresh = str(payload.get("refresh_token") or "")
    if not refresh:
        raise CodexOAuthError("missing_refresh_token")
    with _client(payload) as client:
        response = client.post(
            TOKEN_URL,
            data={
                "client_id": CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "scope": "openid profile email",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if response.status_code != 200:
        try:
            body = response.json()
            error = body.get("error") if isinstance(body, dict) else body
        except Exception:
            error = response.text[:300]
        raise CodexOAuthError(f"codex_refresh_http_{response.status_code}:{error}")
    return _token_result(response.json(), mode="refresh")


def _request_device_code(payload: dict[str, Any]) -> dict[str, Any]:
    with _client(payload) as client:
        response = client.post(DEVICE_USER_CODE_URL, json={"client_id": CLIENT_ID})
    if not 200 <= response.status_code < 300:
        raise CodexOAuthError(f"device_code_http_{response.status_code}:{response.text[:300]}")
    body = response.json()
    user_code = str(body.get("user_code") or body.get("usercode") or "").strip()
    device_auth_id = str(body.get("device_auth_id") or "").strip()
    if not user_code or not device_auth_id:
        raise CodexOAuthError("device_code_response_missing_fields")
    return {
        "user_code": user_code,
        "device_auth_id": device_auth_id,
        "interval": max(int(body.get("interval") or 5), 1),
    }


def _poll_device_code(
    payload: dict[str, Any], session: dict[str, Any], stop: threading.Event
) -> dict[str, Any]:
    deadline = time.time() + max(float(payload.get("browser_timeout_sec") or 240), 60)
    with _client(payload) as client:
        while time.time() < deadline:
            response = client.post(
                DEVICE_TOKEN_URL,
                json={
                    "device_auth_id": session["device_auth_id"],
                    "user_code": session["user_code"],
                },
            )
            if 200 <= response.status_code < 300:
                stop.set()
                return response.json()
            if response.status_code not in {403, 404}:
                raise CodexOAuthError(
                    f"device_poll_http_{response.status_code}:{response.text[:300]}"
                )
            time.sleep(session["interval"])
    raise CodexOAuthError("codex_device_authorization_timed_out")


def device_login(payload: dict[str, Any]) -> dict[str, Any]:
    email = str(payload.get("email") or "").strip()
    password = str(payload.get("password") or "")
    session_token = str(payload.get("session_token") or "")
    if (not email or not password) and not session_token:
        raise CodexOAuthError("refresh_failed_and_missing_password")
    session = _request_device_code(payload)
    log("Codex device code requested")
    stop = threading.Event()
    token_box: dict[str, Any] = {}
    error_box: dict[str, BaseException] = {}

    def poll() -> None:
        try:
            token_box["device"] = _poll_device_code(payload, session, stop)
        except BaseException as exc:  # noqa: BLE001
            error_box["error"] = exc
            stop.set()

    thread = threading.Thread(target=poll, name="codex-device-poll", daemon=True)
    thread.start()
    complete_codex_login(
        auth_url=DEVICE_VERIFICATION_URL,
        user_code=session["user_code"],
        email=email,
        password=password,
        session_token=session_token,
        proxy=payload.get("proxy") or None,
        headless=bool(payload.get("headless")),
        timeout_sec=float(payload.get("browser_timeout_sec") or 240),
        log=log,
        stop_event=stop,
    )
    thread.join(timeout=45)
    if "error" in error_box:
        raise error_box["error"]
    device = token_box.get("device")
    if not isinstance(device, dict):
        raise CodexOAuthError("device_poll_missing_result")
    code = str(device.get("authorization_code") or "")
    verifier = str(device.get("code_verifier") or "")
    if not code or not verifier:
        raise CodexOAuthError("device_poll_missing_exchange_fields")
    with _client(payload) as client:
        response = client.post(
            TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "redirect_uri": DEVICE_REDIRECT_URI,
                "code_verifier": verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if response.status_code != 200:
        raise CodexOAuthError(f"device_exchange_http_{response.status_code}:{response.text[:300]}")
    return _token_result(response.json(), mode="browser_device")


def run(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        result = refresh_tokens(payload)
        log("Codex refresh succeeded")
        return result
    except Exception as exc:
        log(f"Codex refresh failed: {type(exc).__name__}:{exc}")
    return device_login(payload)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("worker_request_must_be_object")
        result = run(payload)
        json.dump(result, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return 0
    except BaseException as exc:  # noqa: BLE001
        log(f"{type(exc).__name__}:{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
