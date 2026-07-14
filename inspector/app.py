"""Multi-provider auth-file inspector for CLIProxyAPI.

Supports selecting which providers to scan (xAI, Codex, …), local validation,
optional live upstream probes, and bulk disable/enable of auth files.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets
import signal
import shutil
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

AUTH_DIR = Path(os.environ.get("AUTH_DIR", "/auths"))
# Optional side archive from grok_bytao: sso-<email>.json with password + sso cookie.
SSO_AUTH_DIR = Path(os.environ.get("SSO_AUTH_DIR", "/sso_auths"))
DEFAULT_CONCURRENCY = int(os.environ.get("PROBE_CONCURRENCY", "8"))
DEFAULT_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "12"))
DEFAULT_XAI_MODEL = os.environ.get("PROBE_MODEL", "grok-3-mini")
HOST_BIND = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "18318"))
XAI_OAUTH_CLIENT_ID = os.environ.get(
    "XAI_OAUTH_CLIENT_ID", "b1a00492-073a-47ea-816f-4c329264a828"
)
XAI_DEVICE_CODE_URL = "https://auth.x.ai/oauth2/device/code"
XAI_TOKEN_URL = "https://auth.x.ai/oauth2/token"
XAI_OAUTH_SCOPE = "openid profile email offline_access grok-cli:access api:access"
# Auto reauth (browser device-consent). Defaults match grok_bytao mint flow.
XAI_REAUTH_AUTO = os.environ.get("XAI_REAUTH_AUTO", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
XAI_REAUTH_HEADLESS = os.environ.get("XAI_REAUTH_HEADLESS", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
XAI_REAUTH_PROXY = (
    os.environ.get("XAI_REAUTH_PROXY")
    or os.environ.get("HTTPS_PROXY")
    or os.environ.get("https_proxy")
    or os.environ.get("HTTP_PROXY")
    or os.environ.get("http_proxy")
    or ""
).strip()
XAI_REAUTH_TIMEOUT = float(os.environ.get("XAI_REAUTH_TIMEOUT", "240"))
XAI_REAUTH_CONCURRENCY = max(1, int(os.environ.get("XAI_REAUTH_CONCURRENCY", "1")))
app = FastAPI(title="CPA Auth Inspector", version="0.5.2")

# Allow embedding / probing from CPA management panel (different port).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_state_lock = asyncio.Lock()
_last_results: dict[str, Any] = {
    "scanned_at": None,
    "mode": None,
    "providers": [],
    "total": 0,
    "items": [],
    "summary": {},
    "by_provider": {},
}
_scan_running = False
_reauth_lock = asyncio.Lock()
_reauth_sessions: dict[str, dict[str, Any]] = {}
_reauth_tasks: dict[str, asyncio.Task[None]] = {}
_reauth_sem = asyncio.Semaphore(XAI_REAUTH_CONCURRENCY)
_batch_reauth_lock = asyncio.Lock()
_batch_reauth_job: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _b64url_json(segment: str) -> dict[str, Any] | None:
    try:
        pad = "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(segment + pad)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _parse_jwt_exp(token: str | None) -> tuple[datetime | None, dict[str, Any] | None]:
    if not token or not isinstance(token, str) or token.count(".") < 2:
        return None, None
    payload = _b64url_json(token.split(".")[1])
    if not payload:
        return None, payload
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return None, payload
    return datetime.fromtimestamp(exp, tz=timezone.utc), payload


def _local_status(
    *,
    disabled: bool,
    has_access: bool,
    has_refresh: bool,
    jwt_expired: bool,
    extra_reasons: list[str] | None = None,
) -> tuple[str, list[str]]:
    reasons = list(extra_reasons or [])
    if disabled:
        return "disabled", reasons + ["file_disabled"]
    if not has_access and not has_refresh:
        return "invalid", reasons + ["missing_tokens"]
    if not has_access and has_refresh:
        return "needs_refresh", reasons + ["missing_access_token"]
    if jwt_expired:
        return "token_expired", reasons + ["jwt_expired"]
    return "ok", reasons


def _public_item(item: dict[str, Any]) -> dict[str, Any]:
    drop = {"access_token", "refresh_token", "session_token", "id_token", "path", "raw_tokens"}
    return {k: v for k, v in item.items() if k not in drop}


# ---------------------------------------------------------------------------
# provider: xai
# ---------------------------------------------------------------------------

def detect_xai(path: Path, data: dict[str, Any]) -> bool:
    name = path.name.lower()
    if name.startswith("xai-") or name.startswith("account_xai"):
        return True
    t = str(data.get("type") or data.get("provider") or "").lower()
    if t == "xai":
        return True
    rec = data.get("oauth_record")
    if isinstance(rec, dict) and str(rec.get("type") or "").lower() == "xai":
        return True
    if ("xai" in name or "grok" in name) and (
        data.get("access_token") or data.get("oauth_access_token") or data.get("oauth_record")
    ):
        return True
    return False


def extract_xai(path: Path, data: dict[str, Any]) -> dict[str, Any]:
    email = data.get("email") or ""
    disabled = bool(data.get("disabled", False))
    access = data.get("access_token") or data.get("oauth_access_token") or ""
    refresh = data.get("refresh_token") or data.get("oauth_refresh_token") or ""
    base_url = (data.get("base_url") or "https://api.x.ai/v1").rstrip("/")
    token_endpoint = data.get("token_endpoint") or "https://auth.x.ai/oauth2/token"
    auth_kind = data.get("auth_kind") or "oauth"
    sub = data.get("sub") or ""
    file_expired = data.get("expired")
    last_refresh = data.get("last_refresh")
    error_field = data.get("error")

    rec = data.get("oauth_record")
    if isinstance(rec, dict):
        access = access or rec.get("access_token") or ""
        refresh = refresh or rec.get("refresh_token") or ""
        email = email or rec.get("email") or ""
        base_url = (rec.get("base_url") or base_url).rstrip("/")
        token_endpoint = rec.get("token_endpoint") or token_endpoint
        auth_kind = auth_kind or rec.get("auth_kind") or "oauth"
        sub = sub or rec.get("sub") or ""
        file_expired = file_expired or rec.get("expired")
        last_refresh = last_refresh or rec.get("last_refresh")

    jwt_exp, claims = _parse_jwt_exp(access if isinstance(access, str) else None)
    jwt_expired = bool(jwt_exp and jwt_exp <= _utc_now())
    status, reasons = _local_status(
        disabled=disabled,
        has_access=bool(access),
        has_refresh=bool(refresh),
        jwt_expired=jwt_expired,
        extra_reasons=[f"file_error:{error_field}"] if error_field else None,
    )
    return {
        "provider": "xai",
        "file": path.name,
        "path": str(path),
        "email": email,
        "sub": sub or ((claims or {}).get("sub") if claims else "") or "",
        "account_id": (claims or {}).get("team_id") if claims else None,
        "plan_type": None,
        "disabled": disabled,
        "auth_kind": auth_kind,
        "base_url": base_url,
        "token_endpoint": token_endpoint,
        "has_access_token": bool(access),
        "has_refresh_token": bool(refresh),
        "access_token": access if isinstance(access, str) else "",
        "refresh_token": refresh if isinstance(refresh, str) else "",
        "session_token": "",
        "file_expired_field": file_expired,
        "last_refresh": last_refresh,
        "jwt_exp": jwt_exp.isoformat() if jwt_exp else None,
        "jwt_expired": jwt_expired,
        "local_status": status,
        "local_reasons": reasons,
    }


async def refresh_xai(client: httpx.AsyncClient, cred: dict[str, Any]) -> tuple[bool, str]:
    refresh = cred.get("refresh_token") or ""
    if not refresh:
        return False, "no_refresh_token"
    endpoint = cred.get("token_endpoint") or "https://auth.x.ai/oauth2/token"
    try:
        resp = await client.post(
            endpoint,
            data={"grant_type": "refresh_token", "refresh_token": refresh},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except Exception as exc:
        return False, f"refresh_error:{exc}"
    if resp.status_code >= 400:
        return False, f"refresh_http_{resp.status_code}"
    try:
        body = resp.json()
    except Exception:
        return False, "refresh_bad_json"
    access = body.get("access_token")
    if not access:
        return False, "refresh_no_access_token"
    path = Path(cred["path"])
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if "access_token" in raw or raw.get("type") == "xai":
            raw["access_token"] = access
            if body.get("refresh_token"):
                raw["refresh_token"] = body["refresh_token"]
            if body.get("expires_in") is not None:
                raw["expires_in"] = body["expires_in"]
                exp_ts = int(time.time()) + int(body["expires_in"])
                raw["expired"] = datetime.fromtimestamp(exp_ts, tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            raw["last_refresh"] = _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            raw["oauth_access_token"] = access
            if body.get("refresh_token"):
                raw["oauth_refresh_token"] = body["refresh_token"]
            if isinstance(raw.get("oauth_record"), dict):
                raw["oauth_record"]["access_token"] = access
                if body.get("refresh_token"):
                    raw["oauth_record"]["refresh_token"] = body["refresh_token"]
        path.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        cred["access_token"] = access
        cred["has_access_token"] = True
        if body.get("refresh_token"):
            cred["refresh_token"] = body["refresh_token"]
            cred["has_refresh_token"] = True
    except Exception as exc:
        return False, f"refresh_persist_error:{exc}"
    return True, "refreshed"


async def probe_xai(
    client: httpx.AsyncClient,
    cred: dict[str, Any],
    *,
    live: bool,
    try_refresh: bool,
    model: str,
) -> dict[str, Any]:
    result = _base_result(cred)
    if not live:
        result["probe_status"] = "skipped"
        result["detail"] = "local_only"
        return result
    if cred["disabled"]:
        result["probe_status"] = "skipped"
        result["detail"] = "disabled"
        result["final"] = "disabled"
        return result

    if not cred["access_token"] and try_refresh and cred.get("refresh_token"):
        ok, msg = await refresh_xai(client, cred)
        result["detail"] = msg
        if not ok:
            result["probe_status"] = "refresh_failed"
            result["final"] = "invalid"
            return result

    if not cred["access_token"]:
        result["probe_status"] = "no_token"
        result["final"] = "invalid"
        result["detail"] = "missing_access_token"
        return result

    base = (cred.get("base_url") or "https://api.x.ai/v1").rstrip("/")
    headers = {"Authorization": f"Bearer {cred['access_token']}"}
    t0 = time.perf_counter()
    try:
        resp = await client.get(f"{base}/models", headers=headers)
        if resp.status_code in (404, 405):
            resp = await client.post(
                f"{base}/chat/completions",
                headers={**headers, "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                    "stream": False,
                },
            )
        if resp.status_code == 401 and try_refresh and cred.get("refresh_token"):
            ok, msg = await refresh_xai(client, cred)
            result["detail"] = msg
            if ok:
                headers = {"Authorization": f"Bearer {cred['access_token']}"}
                resp = await client.get(f"{base}/models", headers=headers)
    except Exception as exc:
        result["probe_status"] = "network_error"
        result["final"] = "error"
        result["detail"] = str(exc)
        result["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        return result

    return _classify_http(result, resp, t0)


# ---------------------------------------------------------------------------
# provider: codex
# ---------------------------------------------------------------------------

def detect_codex(path: Path, data: dict[str, Any]) -> bool:
    name = path.name.lower()
    t = str(data.get("type") or data.get("provider") or "").lower()
    if t == "codex":
        return True
    if data.get("auth_mode") == "chatgpt" and data.get("tokens"):
        return True
    if "codex" in name or name.endswith("_codex_auth.json"):
        return True
    if name.startswith("cpa_") and (data.get("access_token") or data.get("session_token")):
        # CPA export style often lacks type when incomplete; require plan_type or account_id
        if data.get("account_id") or data.get("plan_type") or data.get("session_token"):
            # avoid classifying xai-like files
            if t and t != "codex":
                return False
            if "xai" in name:
                return False
            # heuristic: cpa_* with session_token is typically codex
            if data.get("session_token") or data.get("plan_type"):
                return True
    return False


def extract_codex(path: Path, data: dict[str, Any]) -> dict[str, Any]:
    tokens = data.get("tokens") if isinstance(data.get("tokens"), dict) else {}
    access = data.get("access_token") or tokens.get("access_token") or ""
    refresh = data.get("refresh_token") or tokens.get("refresh_token") or ""
    id_token = data.get("id_token") or tokens.get("id_token") or ""
    session = data.get("session_token") or ""
    email = data.get("email") or ""
    account_id = data.get("account_id") or tokens.get("account_id") or ""
    plan_type = data.get("plan_type") or ""
    disabled = bool(data.get("disabled", False))
    file_expired = data.get("expired")
    last_refresh = data.get("last_refresh")
    auth_kind = data.get("auth_mode") or "chatgpt"

    # Prefer access_token JWT; fall back to id_token exp.
    jwt_exp, claims = _parse_jwt_exp(access if isinstance(access, str) else None)
    if not jwt_exp:
        jwt_exp, claims = _parse_jwt_exp(id_token if isinstance(id_token, str) else None)
    jwt_expired = bool(jwt_exp and jwt_exp <= _utc_now())

    # If file has expired field in the past, mark expired even if JWT missing.
    extra: list[str] = []
    if isinstance(file_expired, str) and file_expired:
        try:
            exp_dt = datetime.fromisoformat(file_expired.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt <= _utc_now():
                jwt_expired = True
                extra.append("file_expired_field")
        except Exception:
            pass

    # Email sometimes embedded in JWT claims.
    if not email and claims:
        email = str(claims.get("email") or claims.get("https://api.openai.com/profile", {}).get("email") or "")
        if not email and isinstance(claims.get("https://api.openai.com/profile"), dict):
            email = str(claims["https://api.openai.com/profile"].get("email") or "")

    status, reasons = _local_status(
        disabled=disabled,
        has_access=bool(access) or bool(session),
        has_refresh=bool(refresh),
        jwt_expired=jwt_expired and not session,  # session_token may still work if access JWT expired
        extra_reasons=extra,
    )
    # If only session present and not disabled, treat as ok locally.
    if status in ("invalid", "token_expired", "needs_refresh") and session and not disabled:
        if status == "token_expired" and session:
            status, reasons = "ok", ["has_session_token"]
        elif status == "invalid" and session:
            status, reasons = "ok", ["has_session_token"]

    return {
        "provider": "codex",
        "file": path.name,
        "path": str(path),
        "email": email,
        "sub": (claims or {}).get("sub") if claims else "",
        "account_id": account_id,
        "plan_type": plan_type,
        "disabled": disabled,
        "auth_kind": auth_kind,
        "base_url": "https://chatgpt.com",
        "token_endpoint": "",
        "has_access_token": bool(access),
        "has_refresh_token": bool(refresh),
        "access_token": access if isinstance(access, str) else "",
        "refresh_token": refresh if isinstance(refresh, str) else "",
        "session_token": session if isinstance(session, str) else "",
        "file_expired_field": file_expired,
        "last_refresh": last_refresh,
        "jwt_exp": jwt_exp.isoformat() if jwt_exp else None,
        "jwt_expired": jwt_expired,
        "local_status": status,
        "local_reasons": reasons,
    }


async def probe_codex(
    client: httpx.AsyncClient,
    cred: dict[str, Any],
    *,
    live: bool,
    try_refresh: bool,
    model: str,
) -> dict[str, Any]:
    result = _base_result(cred)
    if not live:
        result["probe_status"] = "skipped"
        result["detail"] = "local_only"
        return result
    if cred["disabled"]:
        result["probe_status"] = "skipped"
        result["detail"] = "disabled"
        result["final"] = "disabled"
        return result

    access = cred.get("access_token") or ""
    session = cred.get("session_token") or ""
    account_id = cred.get("account_id") or ""
    if not access and not session:
        result["probe_status"] = "no_token"
        result["final"] = "invalid"
        result["detail"] = "missing_access_and_session"
        return result

    headers: dict[str, str] = {
        "User-Agent": "CPA-Auth-Inspector/0.2",
        "Accept": "application/json",
    }
    if access:
        headers["Authorization"] = f"Bearer {access}"
    if session:
        # Some Codex/ChatGPT paths accept cookie-style session.
        headers["Cookie"] = f"__Secure-next-auth.session-token={session}"
    if account_id:
        headers["ChatGPT-Account-ID"] = str(account_id)

    # Lightweight endpoints used by community tools / dashboards.
    urls = [
        "https://chatgpt.com/backend-api/me",
        "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27",
        "https://chatgpt.com/backend-api/wham/usage",
    ]
    t0 = time.perf_counter()
    last_resp: httpx.Response | None = None
    try:
        for url in urls:
            resp = await client.get(url, headers=headers)
            last_resp = resp
            # 404/405 → try next shape; 401/403/402/429/2xx are decisive.
            if resp.status_code in (404, 405, 400):
                continue
            break
    except Exception as exc:
        result["probe_status"] = "network_error"
        result["final"] = "error"
        result["detail"] = str(exc)
        result["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        return result

    if last_resp is None:
        result["probe_status"] = "no_response"
        result["final"] = "error"
        result["detail"] = "empty_response"
        result["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        return result

    classified = _classify_http(result, last_resp, t0)
    # Enrich detail with plan/quota snippets when JSON.
    try:
        body = last_resp.json()
        if isinstance(body, dict):
            plan = (
                body.get("plan_type")
                or body.get("account_plan")
                or (body.get("account") or {}).get("plan_type")
            )
            if plan:
                classified["plan_type"] = plan
                classified["detail"] = f"{classified.get('detail','')}; plan={plan}".strip("; ")
    except Exception:
        pass
    return classified


# ---------------------------------------------------------------------------
# provider: claude
# ---------------------------------------------------------------------------

def detect_claude(path: Path, data: dict[str, Any]) -> bool:
    t = str(data.get("type") or data.get("provider") or "").lower()
    if t in {"claude", "anthropic"}:
        return True
    name = path.name.lower()
    # Only explicit filename prefixes — avoid false positives like Claudette@email
    if name.startswith("claude-") or name.startswith("anthropic-") or name.endswith("_claude.json"):
        return True
    return False


def extract_claude(path: Path, data: dict[str, Any]) -> dict[str, Any]:
    access = data.get("access_token") or ""
    refresh = data.get("refresh_token") or ""
    id_token = data.get("id_token") or ""
    email = data.get("email") or ""
    disabled = bool(data.get("disabled", False))
    file_expired = data.get("expired")
    last_refresh = data.get("last_refresh")

    jwt_exp, claims = _parse_jwt_exp(access if isinstance(access, str) else None)
    if not jwt_exp:
        jwt_exp, claims = _parse_jwt_exp(id_token if isinstance(id_token, str) else None)
    jwt_expired = bool(jwt_exp and jwt_exp <= _utc_now())

    extra: list[str] = []
    if isinstance(file_expired, str) and file_expired:
        try:
            exp_dt = datetime.fromisoformat(file_expired.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt <= _utc_now():
                jwt_expired = True
                extra.append("file_expired_field")
        except Exception:
            pass

    if not email and claims:
        email = str(claims.get("email") or claims.get("preferred_username") or "")

    status, reasons = _local_status(
        disabled=disabled,
        has_access=bool(access),
        has_refresh=bool(refresh),
        jwt_expired=jwt_expired,
        extra_reasons=extra,
    )
    return {
        "provider": "claude",
        "file": path.name,
        "path": str(path),
        "email": email,
        "sub": (claims or {}).get("sub") if claims else "",
        "account_id": (claims or {}).get("sub") if claims else "",
        "plan_type": None,
        "disabled": disabled,
        "auth_kind": "oauth",
        "base_url": "https://api.anthropic.com",
        "token_endpoint": "",
        "has_access_token": bool(access),
        "has_refresh_token": bool(refresh),
        "access_token": access if isinstance(access, str) else "",
        "refresh_token": refresh if isinstance(refresh, str) else "",
        "session_token": "",
        "file_expired_field": file_expired,
        "last_refresh": last_refresh,
        "jwt_exp": jwt_exp.isoformat() if jwt_exp else None,
        "jwt_expired": jwt_expired,
        "local_status": status,
        "local_reasons": reasons,
    }


async def probe_claude(
    client: httpx.AsyncClient,
    cred: dict[str, Any],
    *,
    live: bool,
    try_refresh: bool,
    model: str,
) -> dict[str, Any]:
    result = _base_result(cred)
    if not live:
        result["probe_status"] = "skipped"
        result["detail"] = "local_only"
        return result
    if cred["disabled"]:
        result["probe_status"] = "skipped"
        result["detail"] = "disabled"
        result["final"] = "disabled"
        return result
    access = cred.get("access_token") or ""
    if not access:
        result["probe_status"] = "no_token"
        result["final"] = "invalid"
        result["detail"] = "missing_access_token"
        return result

    headers = {
        "Authorization": f"Bearer {access}",
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
        "User-Agent": "CPA-Auth-Inspector/0.3",
    }
    # Claude Code OAuth often answers profile/usage first; models as fallback.
    attempts: list[tuple[str, str, dict | None]] = [
        ("GET", "https://api.anthropic.com/api/oauth/profile", None),
        ("GET", "https://api.anthropic.com/api/oauth/claude_cli/usage", None),
        ("GET", "https://api.anthropic.com/v1/models", None),
        (
            "POST",
            "https://api.anthropic.com/v1/messages",
            {
                "model": model if model.startswith("claude") else "claude-3-5-haiku-latest",
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "ping"}],
            },
        ),
    ]
    t0 = time.perf_counter()
    last_resp: httpx.Response | None = None
    try:
        for method, url, body in attempts:
            if method == "GET":
                resp = await client.get(url, headers=headers)
            else:
                resp = await client.post(url, headers=headers, json=body)
            last_resp = resp
            if resp.status_code in (404, 405, 400):
                continue
            break
    except Exception as exc:
        result["probe_status"] = "network_error"
        result["final"] = "error"
        result["detail"] = str(exc)
        result["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        return result

    if last_resp is None:
        result["probe_status"] = "no_response"
        result["final"] = "error"
        result["detail"] = "empty_response"
        result["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        return result
    return _classify_http(result, last_resp, t0)


# ---------------------------------------------------------------------------
# provider: gemini (gemini / gemini-cli / antigravity)
# ---------------------------------------------------------------------------

def detect_gemini(path: Path, data: dict[str, Any]) -> bool:
    t = str(data.get("type") or data.get("provider") or "").lower()
    if t in {"gemini", "gemini-cli", "antigravity", "google"}:
        return True
    name = path.name.lower()
    if (
        name.startswith("gemini-")
        or name.startswith("gemini_cli")
        or name.startswith("antigravity-")
        or name.endswith("_gemini.json")
        or name.endswith("_antigravity.json")
    ):
        return True
    # Google OAuth exports sometimes carry project_id + tokens without type.
    if data.get("project_id") and data.get("refresh_token") and data.get("access_token"):
        if t and t not in {"gemini", "gemini-cli", "antigravity", "google"}:
            return False
        return True
    return False


def extract_gemini(path: Path, data: dict[str, Any]) -> dict[str, Any]:
    t = str(data.get("type") or data.get("provider") or "gemini").lower() or "gemini"
    access = data.get("access_token") or data.get("token") or ""
    refresh = data.get("refresh_token") or ""
    email = data.get("email") or ""
    disabled = bool(data.get("disabled", False))
    file_expired = data.get("expired") or data.get("expiry") or data.get("expires_at")
    last_refresh = data.get("last_refresh")
    project_id = data.get("project_id") or ""
    project_ids = data.get("project_ids") if isinstance(data.get("project_ids"), list) else []
    if not project_id and project_ids:
        project_id = str(project_ids[0] or "")

    # Nested token dict (some Google client libraries)
    token_blob = data.get("token") if isinstance(data.get("token"), dict) else None
    if token_blob:
        access = access or token_blob.get("access_token") or ""
        refresh = refresh or token_blob.get("refresh_token") or ""
        file_expired = file_expired or token_blob.get("expiry")

    jwt_exp, claims = _parse_jwt_exp(access if isinstance(access, str) else None)
    jwt_expired = bool(jwt_exp and jwt_exp <= _utc_now())

    extra: list[str] = []
    if isinstance(file_expired, str) and file_expired:
        try:
            # Support RFC3339 and "YYYY-MM-DD HH:MM:SS"
            exp_raw = file_expired.replace("Z", "+00:00").replace(" ", "T")
            exp_dt = datetime.fromisoformat(exp_raw)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt <= _utc_now():
                jwt_expired = True
                extra.append("file_expired_field")
        except Exception:
            pass

    if not email and claims:
        email = str(claims.get("email") or "")

    status, reasons = _local_status(
        disabled=disabled,
        has_access=bool(access),
        has_refresh=bool(refresh),
        jwt_expired=jwt_expired,
        extra_reasons=extra,
    )
    return {
        "provider": "gemini",
        "file": path.name,
        "path": str(path),
        "email": email,
        "sub": (claims or {}).get("sub") if claims else "",
        "account_id": project_id,
        "plan_type": t,  # show storage subtype (gemini-cli / antigravity)
        "disabled": disabled,
        "auth_kind": t,
        "base_url": "https://cloudcode-pa.googleapis.com",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "has_access_token": bool(access),
        "has_refresh_token": bool(refresh),
        "access_token": access if isinstance(access, str) else "",
        "refresh_token": refresh if isinstance(refresh, str) else "",
        "session_token": "",
        "file_expired_field": file_expired,
        "last_refresh": last_refresh,
        "jwt_exp": jwt_exp.isoformat() if jwt_exp else None,
        "jwt_expired": jwt_expired,
        "local_status": status,
        "local_reasons": reasons,
        "project_id": project_id,
        "project_ids": project_ids,
    }


async def refresh_gemini(client: httpx.AsyncClient, cred: dict[str, Any]) -> tuple[bool, str]:
    refresh = cred.get("refresh_token") or ""
    if not refresh:
        return False, "no_refresh_token"
    # Google OAuth client used by Gemini CLI / Antigravity is installed-app style;
    # without client_id/secret we can only try a bare refresh (often fails).
    # Prefer probing with existing access_token; refresh is best-effort if file has client fields.
    path = Path(cred["path"])
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"read_error:{exc}"

    client_id = raw.get("client_id") or raw.get("clientId") or ""
    client_secret = raw.get("client_secret") or raw.get("clientSecret") or ""
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh,
    }
    if client_id:
        data["client_id"] = client_id
    if client_secret:
        data["client_secret"] = client_secret

    try:
        resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except Exception as exc:
        return False, f"refresh_error:{exc}"
    if resp.status_code >= 400:
        return False, f"refresh_http_{resp.status_code}"
    try:
        body = resp.json()
    except Exception:
        return False, "refresh_bad_json"
    access = body.get("access_token")
    if not access:
        return False, "refresh_no_access_token"
    try:
        raw["access_token"] = access
        if body.get("refresh_token"):
            raw["refresh_token"] = body["refresh_token"]
        if body.get("expires_in") is not None:
            exp_ts = int(time.time()) + int(body["expires_in"])
            raw["expired"] = datetime.fromtimestamp(exp_ts, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        raw["last_refresh"] = _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
        path.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        cred["access_token"] = access
        cred["has_access_token"] = True
    except Exception as exc:
        return False, f"refresh_persist_error:{exc}"
    return True, "refreshed"


async def probe_gemini(
    client: httpx.AsyncClient,
    cred: dict[str, Any],
    *,
    live: bool,
    try_refresh: bool,
    model: str,
) -> dict[str, Any]:
    result = _base_result(cred)
    if not live:
        result["probe_status"] = "skipped"
        result["detail"] = "local_only"
        return result
    if cred["disabled"]:
        result["probe_status"] = "skipped"
        result["detail"] = "disabled"
        result["final"] = "disabled"
        return result

    if not cred.get("access_token") and try_refresh and cred.get("refresh_token"):
        ok, msg = await refresh_gemini(client, cred)
        result["detail"] = msg
        if not ok:
            result["probe_status"] = "refresh_failed"
            result["final"] = "invalid"
            return result

    access = cred.get("access_token") or ""
    if not access:
        result["probe_status"] = "no_token"
        result["final"] = "invalid"
        result["detail"] = "missing_access_token"
        return result

    headers = {
        "Authorization": f"Bearer {access}",
        "Accept": "application/json",
        "User-Agent": "CPA-Auth-Inspector/0.3",
    }
    t0 = time.perf_counter()
    last_resp: httpx.Response | None = None
    try:
        # 1) Google userinfo — cheap identity check
        resp = await client.get("https://www.googleapis.com/oauth2/v2/userinfo", headers=headers)
        last_resp = resp
        if resp.status_code == 401 and try_refresh and cred.get("refresh_token"):
            ok, msg = await refresh_gemini(client, cred)
            result["detail"] = msg
            if ok:
                headers["Authorization"] = f"Bearer {cred['access_token']}"
                resp = await client.get(
                    "https://www.googleapis.com/oauth2/v2/userinfo", headers=headers
                )
                last_resp = resp

        # 2) If identity ok, optionally touch Cloud Code (gemini-cli / antigravity)
        if last_resp is not None and last_resp.status_code < 300:
            try:
                info = last_resp.json()
                if isinstance(info, dict) and info.get("email") and not result.get("email"):
                    result["email"] = info.get("email")
            except Exception:
                pass
            # light cloudcode probe when project present
            project = cred.get("project_id") or cred.get("account_id") or ""
            if project or (cred.get("auth_kind") or "").startswith("gemini") or cred.get("auth_kind") == "antigravity":
                body = {"metadata": {"ideType": "ANTIGRAVITY" if cred.get("auth_kind") == "antigravity" else "IDE"}}
                if project:
                    body["cloudaicompanionProject"] = project
                cc = await client.post(
                    "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
                    headers={**headers, "Content-Type": "application/json"},
                    json=body,
                )
                # Prefer cloudcode status if more specific than plain 200 userinfo
                if cc.status_code not in (404, 405):
                    last_resp = cc
    except Exception as exc:
        result["probe_status"] = "network_error"
        result["final"] = "error"
        result["detail"] = str(exc)
        result["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        return result

    if last_resp is None:
        result["probe_status"] = "no_response"
        result["final"] = "error"
        result["detail"] = "empty_response"
        result["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        return result
    return _classify_http(result, last_resp, t0)


# ---------------------------------------------------------------------------
# provider registry (extensible)
# ---------------------------------------------------------------------------

ProviderProbe = Callable[..., Any]

PROVIDERS: dict[str, dict[str, Any]] = {
    "xai": {
        "id": "xai",
        "label": "xAI / Grok",
        "description": "xAI OAuth / Free Build 认证",
        "detect": detect_xai,
        "extract": extract_xai,
        "probe": probe_xai,
        "supports_refresh": True,
        "supports_live": True,
    },
    "codex": {
        "id": "codex",
        "label": "Codex / ChatGPT",
        "description": "ChatGPT OAuth / Codex 认证",
        "detect": detect_codex,
        "extract": extract_codex,
        "probe": probe_codex,
        "supports_refresh": False,
        "supports_live": True,
    },
    "claude": {
        "id": "claude",
        "label": "Claude / Anthropic",
        "description": "Claude Code OAuth 认证",
        "detect": detect_claude,
        "extract": extract_claude,
        "probe": probe_claude,
        "supports_refresh": False,
        "supports_live": True,
    },
    "gemini": {
        "id": "gemini",
        "label": "Gemini / Antigravity",
        "description": "Gemini CLI / Antigravity / Google OAuth",
        "detect": detect_gemini,
        "extract": extract_gemini,
        "probe": probe_gemini,
        "supports_refresh": True,
        "supports_live": True,
    },
}

# Priority when multiple detectors match (first wins if we check ordered).
PROVIDER_ORDER = ["xai", "claude", "gemini", "codex"]


def _base_result(cred: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": cred.get("provider"),
        "file": cred.get("file"),
        "email": cred.get("email"),
        "sub": cred.get("sub"),
        "account_id": cred.get("account_id"),
        "plan_type": cred.get("plan_type"),
        "disabled": cred.get("disabled"),
        "local_status": cred.get("local_status"),
        "local_reasons": cred.get("local_reasons"),
        "jwt_exp": cred.get("jwt_exp"),
        "jwt_expired": cred.get("jwt_expired"),
        "has_access_token": cred.get("has_access_token"),
        "has_refresh_token": cred.get("has_refresh_token"),
        "auth_kind": cred.get("auth_kind"),
        "probe_status": None,
        "http_status": None,
        "latency_ms": None,
        "detail": "",
        "final": cred.get("local_status"),
    }


def _classify_http(result: dict[str, Any], resp: httpx.Response, t0: float) -> dict[str, Any]:
    result["latency_ms"] = int((time.perf_counter() - t0) * 1000)
    result["http_status"] = resp.status_code
    body_snip = (resp.text or "")[:240]
    code = resp.status_code
    if code < 300:
        result["probe_status"] = "alive"
        result["final"] = "ok"
        result["detail"] = result.get("detail") or "upstream_ok"
    elif code == 401:
        result["probe_status"] = "unauthorized"
        result["final"] = "invalid"
        result["detail"] = body_snip or "401"
    elif code == 402:
        result["probe_status"] = "payment_required"
        result["final"] = "no_quota"
        result["detail"] = body_snip or "402"
    elif code == 403:
        result["probe_status"] = "forbidden"
        result["final"] = "forbidden"
        result["detail"] = body_snip or "403"
    elif code == 429:
        result["probe_status"] = "rate_limited"
        result["final"] = "rate_limited"
        result["detail"] = body_snip or "429"
    else:
        result["probe_status"] = f"http_{code}"
        result["final"] = "error"
        result["detail"] = body_snip or f"http_{code}"
    return result


# ---------------------------------------------------------------------------
# xAI device OAuth reauthorization (auto browser approve + optional manual)
# ---------------------------------------------------------------------------

def _safe_auth_path(name: str) -> Path:
    safe = Path(name).name
    if safe != name or not re.match(r"^[\w.@+\-]+\.json$", safe):
        raise ValueError("invalid_auth_filename")
    path = AUTH_DIR / safe
    if not path.is_file():
        raise FileNotFoundError(safe)
    return path


def _sanitize_email_filename(email: str) -> str:
    out: list[str] = []
    for ch in (email or "").strip():
        if (
            ("a" <= ch <= "z")
            or ("A" <= ch <= "Z")
            or ("0" <= ch <= "9")
            or ch in {"@", ".", "_", "-"}
        ):
            out.append(ch)
        else:
            out.append("-")
    return "".join(out).strip("-.")


def _normalize_sso_token(raw: str) -> str:
    token = (raw or "").strip()
    if token.startswith("sso="):
        token = token[4:]
    return token.strip()


def _cookies_from_sso(sso: str, cookie_header: str = "") -> list[dict[str, Any]]:
    """Build browser cookie dicts for accounts.x.ai / auth.x.ai from SSO token."""
    token = _normalize_sso_token(sso)
    if not token and cookie_header:
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.lower().startswith("sso="):
                token = _normalize_sso_token(part)
                break
    if not token:
        return []
    cookies: list[dict[str, Any]] = []
    for name in ("sso", "sso-rw"):
        for domain in (".x.ai", "accounts.x.ai", ".accounts.x.ai", "auth.x.ai", ".auth.x.ai", "grok.com", ".grok.com"):
            cookies.append(
                {
                    "name": name,
                    "value": token,
                    "domain": domain,
                    "path": "/",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "None",
                }
            )
    return cookies


def _load_sso_sidecar(email: str) -> dict[str, Any] | None:
    """Load grok_bytao sso_auths/sso-<email>.json when present."""
    email = (email or "").strip()
    if not email or not SSO_AUTH_DIR.is_dir():
        return None
    safe = _sanitize_email_filename(email)
    candidates = [
        SSO_AUTH_DIR / f"sso-{safe}.json",
        SSO_AUTH_DIR / f"sso-{email}.json",
        SSO_AUTH_DIR / f"{safe}.json",
    ]
    seen: set[str] = set()

    def load_first(paths: list[Path]) -> dict[str, Any] | None:
        for path in paths:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            data_email = str(data.get("email") or "").strip().lower()
            if data_email and data_email != email.lower():
                # Accept filename match even if email field differs slightly.
                if safe.lower() not in path.name.lower() and email.lower() not in path.name.lower():
                    continue
            return data
        return None

    # The normal grok_bytao filename is exact. Check it before the expensive
    # case-insensitive directory fallback.
    direct = load_first(candidates)
    if direct is not None:
        return direct

    lowered = email.lower()
    fallback: list[Path] = []
    try:
        for path in SSO_AUTH_DIR.iterdir():
            if not path.is_file() or path.suffix.lower() != ".json":
                continue
            name = path.name.lower()
            if lowered in name or safe.lower() in name:
                fallback.append(path)
    except OSError:
        return None
    return load_first(fallback)


def _extract_login_credentials(raw: dict[str, Any], *, email_hint: str = "") -> dict[str, Any]:
    """Resolve email/password/sso for auto reauth from auth JSON + optional sso_auths sidecar.

    Returns dict: email, password, sso, cookies, source (auth|sso_sidecar|mixed|missing)
    """
    email = str(raw.get("email") or email_hint or "").strip()
    password = str(raw.get("password") or "").strip()
    sso = _normalize_sso_token(str(raw.get("sso") or ""))
    cookie_header = str(raw.get("cookie") or "")
    rec = raw.get("oauth_record")
    if isinstance(rec, dict):
        email = email or str(rec.get("email") or "").strip()
        password = password or str(rec.get("password") or "").strip()
        sso = sso or _normalize_sso_token(str(rec.get("sso") or ""))
        cookie_header = cookie_header or str(rec.get("cookie") or "")

    had_auth_secret = bool(password or sso)
    used_sidecar = False
    sidecar = _load_sso_sidecar(email) if email else None
    if sidecar:
        email = email or str(sidecar.get("email") or "").strip()
        if not password:
            side_pw = str(sidecar.get("password") or "").strip()
            if side_pw:
                password = side_pw
                used_sidecar = True
        if not sso:
            side_sso = _normalize_sso_token(str(sidecar.get("sso") or ""))
            if side_sso:
                sso = side_sso
                used_sidecar = True
        if not cookie_header:
            cookie_header = str(sidecar.get("cookie") or "")

    if had_auth_secret and used_sidecar:
        source = "mixed"
    elif used_sidecar:
        source = "sso_sidecar"
    elif had_auth_secret:
        source = "auth"
    else:
        source = "missing"

    cookies = _cookies_from_sso(sso, cookie_header)
    return {
        "email": email,
        "password": password,
        "sso": sso,
        "cookies": cookies,
        "source": source,
        "auto_capable": bool(email and password),
    }


def _public_reauth_session(session: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "id",
        "file",
        "email",
        "status",
        "mode",
        "user_code",
        "verification_uri",
        "verification_uri_complete",
        "created_at",
        "expires_at",
        "updated_at",
        "detail",
        "backup_file",
        "probe_final",
        "probe_http_status",
        "auto",
        "cred_source",
        "provider",
    }
    return {key: session.get(key) for key in allowed if key in session}


def _public_batch_job(job: dict[str, Any] | None) -> dict[str, Any] | None:
    if not job:
        return None
    allowed = {
        "id",
        "status",
        "total",
        "done",
        "ok",
        "failed",
        "skipped",
        "current_file",
        "current_status",
        "current_detail",
        "current_mode",
        "created_at",
        "updated_at",
        "detail",
        "results",
        "provider",
    }
    return {key: job.get(key) for key in allowed if key in job}


def _oauth_error_detail(body: Any, fallback: str) -> str:
    if isinstance(body, dict):
        error = str(body.get("error") or fallback)
        description = str(body.get("error_description") or "")
        return f"{error}: {description}".rstrip(": ")
    return fallback


def _persist_xai_reauth(path: Path, token: dict[str, Any]) -> str:
    """Atomically replace xAI OAuth tokens and keep a non-JSON backup."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not detect_xai(path, raw):
        raise ValueError("not_xai_auth_file")

    access = str(token.get("access_token") or "").strip()
    refresh = str(token.get("refresh_token") or "").strip()
    if not access or not refresh:
        raise ValueError("oauth_response_missing_tokens")

    now = _utc_now()
    expires_in = max(int(token.get("expires_in") or 21600), 1)
    expires_at = datetime.fromtimestamp(now.timestamp() + expires_in, tz=timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_name(f"{path.name}.{stamp}.bak")
    if backup.exists():
        backup = path.with_name(f"{path.name}.{stamp}-{secrets.token_hex(3)}.bak")
    shutil.copy2(path, backup)

    raw["type"] = "xai"
    raw["auth_kind"] = "oauth"
    raw["access_token"] = access
    raw["refresh_token"] = refresh
    raw["token_type"] = str(token.get("token_type") or "Bearer")
    raw["expires_in"] = expires_in
    raw["expired"] = expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    raw["last_refresh"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    if token.get("id_token"):
        raw["id_token"] = str(token["id_token"])
    # Keep alternate field names in sync for mixed-format CPA files.
    if "oauth_access_token" in raw:
        raw["oauth_access_token"] = access
    if "oauth_refresh_token" in raw:
        raw["oauth_refresh_token"] = refresh
    rec = raw.get("oauth_record")
    if isinstance(rec, dict):
        rec["access_token"] = access
        rec["refresh_token"] = refresh
        if token.get("id_token"):
            rec["id_token"] = str(token["id_token"])
        rec["expired"] = raw["expired"]
        rec["last_refresh"] = raw["last_refresh"]

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.stem}-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(raw, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            pass
        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return backup.name


def _persist_codex_reauth(path: Path, token: dict[str, Any]) -> str:
    """Atomically update a CPA Codex auth file while preserving its shape."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not detect_codex(path, raw):
        raise ValueError("not_codex_auth_file")
    access = str(token.get("access_token") or "").strip()
    refresh = str(token.get("refresh_token") or "").strip()
    if not access or not refresh:
        raise ValueError("codex_oauth_response_missing_tokens")

    now = _utc_now()
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_name(f"{path.name}.{stamp}.bak")
    if backup.exists():
        backup = path.with_name(f"{path.name}.{stamp}-{secrets.token_hex(3)}.bak")
    shutil.copy2(path, backup)

    raw["type"] = "codex"
    raw["access_token"] = access
    raw["refresh_token"] = refresh
    if token.get("id_token"):
        raw["id_token"] = str(token["id_token"])
    if token.get("account_id"):
        raw["account_id"] = str(token["account_id"])
    raw["last_refresh"] = str(token.get("last_refresh") or now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    access_exp, _ = _parse_jwt_exp(access)
    if access_exp:
        raw["expired"] = access_exp.strftime("%Y-%m-%dT%H:%M:%SZ")
    nested = raw.get("tokens")
    if isinstance(nested, dict):
        nested["access_token"] = access
        nested["refresh_token"] = refresh
        if token.get("id_token"):
            nested["id_token"] = str(token["id_token"])
        if token.get("account_id"):
            nested["account_id"] = str(token["account_id"])

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.stem}-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(raw, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            pass
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return backup.name


async def _update_result_after_reauth(path: Path) -> dict[str, Any]:
    raw = await asyncio.to_thread(lambda: json.loads(path.read_text(encoding="utf-8")))
    cred = extract_xai(path, raw)
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=True) as client:
        result = await probe_xai(
            client,
            cred,
            live=True,
            try_refresh=False,
            model=DEFAULT_XAI_MODEL,
        )
    public = _public_item(result)
    async with _state_lock:
        items = _last_results.get("items") or []
        for index, item in enumerate(items):
            if item.get("file") == path.name:
                items[index] = public
                break
        _last_results["summary"] = _summarize(items)
        _last_results["by_provider"] = _by_provider(items)
    return public


async def _update_codex_result_after_reauth(path: Path) -> dict[str, Any]:
    raw = await asyncio.to_thread(lambda: json.loads(path.read_text(encoding="utf-8")))
    cred = extract_codex(path, raw)
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=True) as client:
        result = await probe_codex(
            client,
            cred,
            live=True,
            try_refresh=False,
            model=DEFAULT_XAI_MODEL,
        )
    public = _public_item(result)
    async with _state_lock:
        items = _last_results.get("items") or []
        for index, item in enumerate(items):
            if item.get("file") == path.name:
                items[index] = public
                break
        _last_results["summary"] = _summarize(items)
        _last_results["by_provider"] = _by_provider(items)
    return public


async def _set_reauth_fields(flow_id: str, **fields: Any) -> None:
    async with _reauth_lock:
        session = _reauth_sessions.get(flow_id)
        if session is not None:
            session.update(fields)
            session["updated_at"] = _utc_now().isoformat()


def _session_cancelled(flow_id: str) -> bool:
    session = _reauth_sessions.get(flow_id)
    return bool(session and session.get("status") == "cancelled")


async def _stop_mint_worker(process: asyncio.subprocess.Process) -> None:
    """Stop a browser worker and its Chromium children without blocking the API."""
    if process.returncode is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except (ProcessLookupError, PermissionError):
        pass
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
        return
    except asyncio.TimeoutError:
        pass
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError):
        pass
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except asyncio.TimeoutError:
        pass


async def _auto_mint_tokens(
    *,
    email: str,
    password: str,
    flow_id: str,
    log_lines: list[str],
    cookies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Mint in an isolated process so Chromium cannot starve FastAPI's event loop."""
    payload = {
        "email": email,
        "password": password,
        "proxy": XAI_REAUTH_PROXY or None,
        "headless": XAI_REAUTH_HEADLESS,
        "browser_timeout_sec": XAI_REAUTH_TIMEOUT,
        "cookies": cookies or None,
    }
    command = [sys.executable, "-m", "xai_auto.mint_worker"]
    # accounts.x.ai commonly blocks true headless Chromium. In Linux containers
    # use a headed browser inside Xvfb so real clicks and Turnstile still work.
    if (
        not XAI_REAUTH_HEADLESS
        and os.name != "nt"
        and not os.environ.get("DISPLAY")
        and shutil.which("xvfb-run")
    ):
        command = [
            "xvfb-run",
            "-a",
            "--server-args=-screen 0 1280x900x24",
            *command,
        ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=os.name != "nt",
    )
    async with _reauth_lock:
        session = _reauth_sessions.get(flow_id)
        if session is not None:
            session["_worker_process"] = process
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(json.dumps(payload).encode("utf-8")),
            timeout=max(XAI_REAUTH_TIMEOUT, 60) + 90,
        )
    except asyncio.CancelledError:
        await asyncio.shield(_stop_mint_worker(process))
        raise
    except asyncio.TimeoutError as exc:
        await _stop_mint_worker(process)
        raise TimeoutError("auto_reauth_worker_timed_out") from exc
    finally:
        async with _reauth_lock:
            session = _reauth_sessions.get(flow_id)
            if session is not None:
                session.pop("_worker_process", None)

    for line in stderr.decode("utf-8", errors="replace").splitlines():
        if line.strip():
            log_lines.append(line.strip())
    if len(log_lines) > 80:
        del log_lines[:-60]
    if process.returncode != 0:
        detail = log_lines[-1] if log_lines else f"worker_exit_{process.returncode}"
        raise RuntimeError(detail)
    try:
        result = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("auto_reauth_worker_invalid_response") from exc
    if not isinstance(result, dict) or not result.get("access_token") or not result.get("refresh_token"):
        raise RuntimeError("auto_reauth_worker_missing_tokens")
    return result


async def _codex_mint_tokens(
    *,
    raw: dict[str, Any],
    email: str,
    password: str,
    flow_id: str,
    log_lines: list[str],
) -> dict[str, Any]:
    nested = raw.get("tokens") if isinstance(raw.get("tokens"), dict) else {}
    payload = {
        "email": email,
        "password": password,
        "access_token": raw.get("access_token") or nested.get("access_token") or "",
        "refresh_token": raw.get("refresh_token") or nested.get("refresh_token") or "",
        "id_token": raw.get("id_token") or nested.get("id_token") or "",
        "account_id": raw.get("account_id") or nested.get("account_id") or "",
        "session_token": raw.get("session_token") or "",
        "last_refresh": raw.get("last_refresh"),
        "proxy": XAI_REAUTH_PROXY or None,
        "headless": XAI_REAUTH_HEADLESS,
        "browser_timeout_sec": XAI_REAUTH_TIMEOUT,
    }
    command = [sys.executable, "-m", "codex_auto.codex_worker"]
    if (
        not XAI_REAUTH_HEADLESS
        and os.name != "nt"
        and not os.environ.get("DISPLAY")
        and shutil.which("xvfb-run")
    ):
        command = ["xvfb-run", "-a", "--server-args=-screen 0 1280x900x24", *command]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=os.name != "nt",
    )
    async with _reauth_lock:
        session = _reauth_sessions.get(flow_id)
        if session is not None:
            session["_worker_process"] = process
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(json.dumps(payload).encode("utf-8")),
            timeout=max(XAI_REAUTH_TIMEOUT, 60) + 120,
        )
    except asyncio.CancelledError:
        await asyncio.shield(_stop_mint_worker(process))
        raise
    except asyncio.TimeoutError as exc:
        await _stop_mint_worker(process)
        raise TimeoutError("codex_reauth_worker_timed_out") from exc
    finally:
        async with _reauth_lock:
            session = _reauth_sessions.get(flow_id)
            if session is not None:
                session.pop("_worker_process", None)
    for line in stderr.decode("utf-8", errors="replace").splitlines():
        if line.strip():
            log_lines.append(line.strip())
    if len(log_lines) > 100:
        del log_lines[:-80]
    if process.returncode != 0:
        detail = log_lines[-1] if log_lines else f"worker_exit_{process.returncode}"
        raise RuntimeError(detail)
    try:
        result = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("codex_reauth_worker_invalid_response") from exc
    if not isinstance(result, dict) or not result.get("access_token") or not result.get("refresh_token"):
        raise RuntimeError("codex_reauth_worker_missing_tokens")
    return result


async def _run_auto_reauth(flow_id: str) -> None:
    async with _reauth_lock:
        session = dict(_reauth_sessions[flow_id])
    path = AUTH_DIR / session["file"]
    email = str(session.get("email") or "")
    password = str(session.get("_password") or "")
    cookies = session.get("_cookies") or []
    cred_source = str(session.get("cred_source") or "")
    log_lines: list[str] = []
    try:
        await _set_reauth_fields(
            flow_id,
            status="browser_login",
            detail=f"auto_browser_login_and_consent source={cred_source or 'auth'}"
            + (f" cookies={len(cookies)}" if cookies else ""),
            mode="auto",
        )
        async with _reauth_sem:
            if _session_cancelled(flow_id):
                await _set_reauth_fields(flow_id, status="cancelled", detail="cancelled")
                return
            tokens = await _auto_mint_tokens(
                email=email,
                password=password,
                flow_id=flow_id,
                log_lines=log_lines,
                cookies=cookies if isinstance(cookies, list) else None,
            )
        if _session_cancelled(flow_id):
            await _set_reauth_fields(flow_id, status="cancelled", detail="cancelled")
            return
        await _set_reauth_fields(
            flow_id,
            status="persisting",
            detail="token_received_saving",
            user_code=tokens.get("user_code") or session.get("user_code"),
        )
        backup = await asyncio.to_thread(_persist_xai_reauth, path, tokens)
        probe = await _update_result_after_reauth(path)
        await _set_reauth_fields(
            flow_id,
            status="succeeded",
            detail="auto_reauthorized_and_saved; CPA should hot-load the updated file",
            backup_file=backup,
            probe_final=probe.get("final"),
            probe_http_status=probe.get("http_status"),
            mode="auto",
        )
    except asyncio.CancelledError:
        await _set_reauth_fields(flow_id, status="cancelled", detail="cancelled")
        raise
    except Exception as exc:
        detail = f"auto_reauth_error:{type(exc).__name__}:{exc}"
        if log_lines:
            trace = " <- ".join(log_lines[-8:])[-900:]
            detail = f"{detail} | trace={trace}"
        await _set_reauth_fields(flow_id, status="failed", detail=detail, mode="auto")
    finally:
        async with _reauth_lock:
            session = _reauth_sessions.get(flow_id)
            if session is not None:
                session.pop("_password", None)
                session.pop("_cookies", None)
                session.pop("_raw", None)
            _reauth_tasks.pop(flow_id, None)


async def _run_codex_reauth(flow_id: str) -> None:
    async with _reauth_lock:
        session = dict(_reauth_sessions[flow_id])
    path = AUTH_DIR / session["file"]
    raw = session.get("_raw") if isinstance(session.get("_raw"), dict) else {}
    log_lines: list[str] = []
    try:
        await _set_reauth_fields(
            flow_id,
            status="refreshing",
            detail="codex_official_refresh_then_browser_fallback",
            mode="auto",
        )
        async with _reauth_sem:
            tokens = await _codex_mint_tokens(
                raw=raw,
                email=str(session.get("email") or ""),
                password=str(session.get("_password") or ""),
                flow_id=flow_id,
                log_lines=log_lines,
            )
        if _session_cancelled(flow_id):
            await _set_reauth_fields(flow_id, status="cancelled", detail="cancelled")
            return
        await _set_reauth_fields(
            flow_id,
            status="persisting",
            detail=f"codex_token_received_saving mode={tokens.get('mode') or 'unknown'}",
        )
        backup = await asyncio.to_thread(_persist_codex_reauth, path, tokens)
        probe = await _update_codex_result_after_reauth(path)
        await _set_reauth_fields(
            flow_id,
            status="succeeded",
            detail=f"codex_reauthorized_and_saved mode={tokens.get('mode') or 'unknown'}",
            backup_file=backup,
            probe_final=probe.get("final"),
            probe_http_status=probe.get("http_status"),
            provider="codex",
        )
    except asyncio.CancelledError:
        await _set_reauth_fields(flow_id, status="cancelled", detail="cancelled")
        raise
    except Exception as exc:
        detail = f"codex_reauth_error:{type(exc).__name__}:{exc}"
        if log_lines:
            detail = f"{detail} | trace={' <- '.join(log_lines[-8:])[-900:]}"
        await _set_reauth_fields(flow_id, status="failed", detail=detail, mode="auto")
    finally:
        async with _reauth_lock:
            current = _reauth_sessions.get(flow_id)
            if current is not None:
                current.pop("_password", None)
                current.pop("_raw", None)
            _reauth_tasks.pop(flow_id, None)


async def _start_codex_reauth_for_file(file_name: str) -> dict[str, Any]:
    path = _safe_auth_path(file_name)
    raw = await asyncio.to_thread(lambda: json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(raw, dict) or not detect_codex(path, raw):
        raise HTTPException(status_code=400, detail="not_codex_auth_file")
    nested = raw.get("tokens") if isinstance(raw.get("tokens"), dict) else {}
    email = str(raw.get("email") or "").strip()
    if not email:
        _, claims = _parse_jwt_exp(str(raw.get("id_token") or nested.get("id_token") or ""))
        email = str((claims or {}).get("email") or "")
    password = str(raw.get("password") or "")
    refresh = str(raw.get("refresh_token") or nested.get("refresh_token") or "")
    session_token = str(raw.get("session_token") or "")
    if not refresh and not (email and password):
        raise HTTPException(status_code=400, detail="missing_codex_refresh_and_login_credentials")
    async with _reauth_lock:
        for existing in _reauth_sessions.values():
            if existing.get("file") == path.name and existing.get("status") in {
                "starting", "refreshing", "browser_login", "persisting"
            }:
                raise HTTPException(
                    status_code=409,
                    detail={"error": "reauth_already_running", "session": _public_reauth_session(existing)},
                )
        now = _utc_now()
        flow_id = secrets.token_urlsafe(18)
        session = {
            "id": flow_id,
            "file": path.name,
            "email": email,
            "provider": "codex",
            "status": "starting",
            "mode": "auto",
            "auto": True,
            "cred_source": "refresh_token" if refresh else ("session_token+password" if session_token else "password"),
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "expires_at": datetime.fromtimestamp(
                now.timestamp() + max(XAI_REAUTH_TIMEOUT, 60) + 180, tz=timezone.utc
            ).isoformat(),
            "detail": "codex_reauth_starting",
            "_password": password,
            "_raw": raw,
        }
        _reauth_sessions[flow_id] = session
        _reauth_tasks[flow_id] = asyncio.create_task(_run_codex_reauth(flow_id))
        return _public_reauth_session(session)


async def _poll_xai_reauth(flow_id: str) -> None:
    """Manual device-code poll (fallback when auto is disabled or no password)."""
    async with _reauth_lock:
        session = dict(_reauth_sessions[flow_id])
    interval = max(int(session["_interval"]), 1)
    deadline = float(session["_deadline"])
    path = AUTH_DIR / session["file"]
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            while time.time() < deadline:
                response = await client.post(
                    XAI_TOKEN_URL,
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": session["_device_code"],
                        "client_id": XAI_OAUTH_CLIENT_ID,
                    },
                    headers={"Accept": "application/json"},
                )
                try:
                    body: Any = response.json()
                except Exception:
                    body = None

                if response.status_code == 200 and isinstance(body, dict) and body.get("access_token"):
                    backup = await asyncio.to_thread(_persist_xai_reauth, path, body)
                    probe = await _update_result_after_reauth(path)
                    await _set_reauth_fields(
                        flow_id,
                        status="succeeded",
                        detail="reauthorized_and_saved; CPA should hot-load the updated file",
                        backup_file=backup,
                        probe_final=probe.get("final"),
                        probe_http_status=probe.get("http_status"),
                        mode="manual",
                    )
                    return

                error = str(body.get("error") or "") if isinstance(body, dict) else ""
                if error in {"authorization_pending", "slow_down"}:
                    if error == "slow_down":
                        interval = min(interval + 5, 30)
                    await _set_reauth_fields(flow_id, status="waiting_for_user", detail=error)
                    await asyncio.sleep(interval)
                    continue
                if error in {"expired_token", "access_denied"}:
                    await _set_reauth_fields(
                        flow_id,
                        status="failed",
                        detail=_oauth_error_detail(body, error),
                    )
                    return
                await _set_reauth_fields(
                    flow_id,
                    status="failed",
                    detail=_oauth_error_detail(body, f"token_http_{response.status_code}"),
                )
                return

        await _set_reauth_fields(flow_id, status="expired", detail="device_code_expired")
    except asyncio.CancelledError:
        await _set_reauth_fields(flow_id, status="cancelled", detail="cancelled")
        raise
    except Exception as exc:
        await _set_reauth_fields(
            flow_id,
            status="failed",
            detail=f"reauth_error:{type(exc).__name__}:{exc}",
        )
    finally:
        async with _reauth_lock:
            _reauth_tasks.pop(flow_id, None)


async def _run_batch_reauth(
    job_id: str, files: list[str], *, auto: bool, provider: str = "xai"
) -> None:
    global _batch_reauth_job
    try:
        for name in files:
            async with _batch_reauth_lock:
                if not _batch_reauth_job or _batch_reauth_job.get("id") != job_id:
                    return
                if _batch_reauth_job.get("status") == "cancelled":
                    _batch_reauth_job["detail"] = "cancelled"
                    _batch_reauth_job["updated_at"] = _utc_now().isoformat()
                    return
                _batch_reauth_job["current_file"] = name
                _batch_reauth_job["status"] = "running"
                _batch_reauth_job["updated_at"] = _utc_now().isoformat()
            try:
                if provider == "codex":
                    session = await _start_codex_reauth_for_file(name)
                else:
                    session = await _start_reauth_for_file(name, auto=auto, force_manual=not auto)
                # Wait until terminal; mirror live session fields onto the batch job.
                while True:
                    async with _reauth_lock:
                        cur = _reauth_sessions.get(session["id"])
                        status = (cur or {}).get("status")
                        detail = (cur or {}).get("detail")
                        mode = (cur or {}).get("mode")
                        probe_final = (cur or {}).get("probe_final")
                        backup_file = (cur or {}).get("backup_file")
                    async with _batch_reauth_lock:
                        if _batch_reauth_job and _batch_reauth_job.get("id") == job_id:
                            _batch_reauth_job["current_status"] = status
                            _batch_reauth_job["current_detail"] = detail
                            _batch_reauth_job["current_mode"] = mode
                            _batch_reauth_job["detail"] = f"{status or 'running'}: {detail or ''}".strip(": ")
                            _batch_reauth_job["updated_at"] = _utc_now().isoformat()
                            if _batch_reauth_job.get("status") == "cancelled":
                                status = "cancelled"
                                detail = "cancelled"
                    if status in {"succeeded", "failed", "expired", "cancelled"}:
                        break
                    await asyncio.sleep(1.5)
                ok = status == "succeeded"
                async with _batch_reauth_lock:
                    if not _batch_reauth_job or _batch_reauth_job.get("id") != job_id:
                        return
                    _batch_reauth_job["done"] = int(_batch_reauth_job.get("done") or 0) + 1
                    if ok:
                        _batch_reauth_job["ok"] = int(_batch_reauth_job.get("ok") or 0) + 1
                    else:
                        _batch_reauth_job["failed"] = int(_batch_reauth_job.get("failed") or 0) + 1
                    results = list(_batch_reauth_job.get("results") or [])
                    results.append(
                        {
                            "file": name,
                            "status": status,
                            "detail": detail,
                            "probe_final": probe_final,
                            "backup_file": backup_file,
                        }
                    )
                    _batch_reauth_job["results"] = results[-200:]
                    _batch_reauth_job["current_status"] = status
                    _batch_reauth_job["current_detail"] = detail
                    _batch_reauth_job["updated_at"] = _utc_now().isoformat()
            except Exception as exc:
                if isinstance(exc, HTTPException):
                    detail_obj = exc.detail
                    if isinstance(detail_obj, dict):
                        err = str(detail_obj.get("error") or detail_obj)
                    else:
                        err = str(detail_obj)
                else:
                    err = str(exc)
                async with _batch_reauth_lock:
                    if not _batch_reauth_job or _batch_reauth_job.get("id") != job_id:
                        return
                    _batch_reauth_job["done"] = int(_batch_reauth_job.get("done") or 0) + 1
                    err_l = err.lower()
                    if "missing_password" in err_l or ("password" in err_l and "missing" in err_l):
                        _batch_reauth_job["skipped"] = int(_batch_reauth_job.get("skipped") or 0) + 1
                        status_label = "skipped"
                    else:
                        _batch_reauth_job["failed"] = int(_batch_reauth_job.get("failed") or 0) + 1
                        status_label = "failed"
                    results = list(_batch_reauth_job.get("results") or [])
                    results.append({"file": name, "status": status_label, "detail": err})
                    _batch_reauth_job["results"] = results[-200:]
                    _batch_reauth_job["current_status"] = status_label
                    _batch_reauth_job["current_detail"] = err
                    _batch_reauth_job["updated_at"] = _utc_now().isoformat()
        async with _batch_reauth_lock:
            if _batch_reauth_job and _batch_reauth_job.get("id") == job_id:
                _batch_reauth_job["status"] = "finished"
                _batch_reauth_job["current_file"] = None
                _batch_reauth_job["detail"] = "batch_finished"
                _batch_reauth_job["updated_at"] = _utc_now().isoformat()
    except Exception as exc:
        async with _batch_reauth_lock:
            if _batch_reauth_job and _batch_reauth_job.get("id") == job_id:
                _batch_reauth_job["status"] = "failed"
                _batch_reauth_job["detail"] = f"batch_error:{exc}"
                _batch_reauth_job["updated_at"] = _utc_now().isoformat()


async def _start_reauth_for_file(
    file_name: str,
    *,
    auto: bool | None = None,
    force_manual: bool = False,
) -> dict[str, Any]:
    """Start one reauth session (auto browser or manual device OAuth)."""
    path = _safe_auth_path(file_name)
    raw = await asyncio.to_thread(lambda: json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(raw, dict) or not detect_xai(path, raw):
        raise HTTPException(status_code=400, detail="not_xai_auth_file")

    creds = await asyncio.to_thread(_extract_login_credentials, raw)
    email = str(creds.get("email") or "").strip()
    password = str(creds.get("password") or "").strip()
    cookies = creds.get("cookies") if isinstance(creds.get("cookies"), list) else []
    cred_source = str(creds.get("source") or "missing")
    want_auto = XAI_REAUTH_AUTO if auto is None else bool(auto)
    if force_manual:
        want_auto = False
    use_auto = bool(want_auto and email and password)
    # Explicit auto requests (batch / UI auto button) must not silently fall back
    # to a hanging manual wait when password is missing.
    if want_auto and not use_auto and auto is True:
        raise HTTPException(
            status_code=400,
            detail=(
                "missing_password_for_auto_reauth"
                f" (looked in auth JSON + SSO_AUTH_DIR={SSO_AUTH_DIR})"
            ),
        )

    async with _reauth_lock:
        for existing in _reauth_sessions.values():
            if existing.get("file") == path.name and existing.get("status") in {
                "starting",
                "refreshing",
                "waiting_for_user",
                "browser_login",
                "persisting",
            }:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "error": "reauth_already_running",
                        "session": _public_reauth_session(existing),
                    },
                )

    now = _utc_now()
    flow_id = secrets.token_urlsafe(18)

    if use_auto:
        session: dict[str, Any] = {
            "id": flow_id,
            "file": path.name,
            "email": email,
            "status": "starting",
            "mode": "auto",
            "auto": True,
            "cred_source": cred_source,
            "user_code": "",
            "verification_uri": "",
            "verification_uri_complete": "",
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "expires_at": datetime.fromtimestamp(
                now.timestamp() + max(XAI_REAUTH_TIMEOUT, 60) + 60, tz=timezone.utc
            ).isoformat(),
            "detail": f"auto_reauth_starting source={cred_source}",
            "_password": password,
            "_cookies": cookies,
        }
        async with _reauth_lock:
            _reauth_sessions[flow_id] = session
            _reauth_tasks[flow_id] = asyncio.create_task(_run_auto_reauth(flow_id))
        return _public_reauth_session(session)

    # Manual device OAuth path (open xAI page and confirm yourself).
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            response = await client.post(
                XAI_DEVICE_CODE_URL,
                data={"client_id": XAI_OAUTH_CLIENT_ID, "scope": XAI_OAUTH_SCOPE},
                headers={"Accept": "application/json"},
            )
        body = response.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"device_code_request_error:{exc}") from exc
    if response.status_code != 200 or not isinstance(body, dict):
        raise HTTPException(
            status_code=502,
            detail=_oauth_error_detail(body, f"device_code_http_{response.status_code}"),
        )

    device_code = str(body.get("device_code") or "").strip()
    user_code = str(body.get("user_code") or "").strip()
    if not device_code or not user_code:
        raise HTTPException(status_code=502, detail="device_code_response_missing_fields")
    verification_uri = str(
        body.get("verification_uri") or "https://accounts.x.ai/oauth2/device"
    ).strip()
    verification_uri_complete = str(
        body.get("verification_uri_complete") or f"{verification_uri}?user_code={user_code}"
    ).strip()
    expires_in = max(int(body.get("expires_in") or 1800), 30)
    interval = max(int(body.get("interval") or 5), 1)
    reason = "manual_requested"
    if want_auto and not password:
        reason = "missing_password_fallback_manual"
    session = {
        "id": flow_id,
        "file": path.name,
        "email": email,
        "status": "waiting_for_user",
        "mode": "manual",
        "auto": False,
        "cred_source": cred_source,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "expires_at": datetime.fromtimestamp(
            now.timestamp() + expires_in, tz=timezone.utc
        ).isoformat(),
        "detail": f"open_xai_authorization_page_and_confirm ({reason})",
        "_device_code": device_code,
        "_interval": interval,
        "_deadline": time.time() + expires_in,
    }
    async with _reauth_lock:
        _reauth_sessions[flow_id] = session
        _reauth_tasks[flow_id] = asyncio.create_task(_poll_xai_reauth(flow_id))
    return _public_reauth_session(session)


def _detect_provider(path: Path, data: dict[str, Any]) -> str | None:
    for pid in PROVIDER_ORDER:
        if PROVIDERS[pid]["detect"](path, data):
            return pid
    return None


def _candidate_paths(providers: set[str]) -> list[Path]:
    """Pick candidate auth files for the selected providers.

    xAI-only can use filename globs (fast on Windows bind mounts).
    Codex (and mixed multi-provider scans) must content-scan all JSON because
    many Codex files are named like email.json with no provider prefix.
    """
    # Providers that cannot be reliably discovered by filename alone.
    needs_full_scan = bool(providers - {"xai"})
    if needs_full_scan or not providers:
        return [p for p in AUTH_DIR.iterdir() if p.is_file() and p.suffix.lower() == ".json"]

    # Fast path: xAI only
    patterns = ["xai-*.json", "account_xai*.json", "*xai*.json", "*grok*.json"]
    seen: set[str] = set()
    out: list[Path] = []
    for pat in patterns:
        for p in AUTH_DIR.glob(pat):
            key = p.name.lower()
            if key in seen or not p.is_file():
                continue
            seen.add(key)
            out.append(p)
    return out


def _read_one(path: Path, providers: set[str]) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    pid = _detect_provider(path, data)
    if not pid or pid not in providers:
        return None
    return PROVIDERS[pid]["extract"](path, data)


def load_credentials(providers: list[str]) -> list[dict[str, Any]]:
    selected = {p for p in providers if p in PROVIDERS}
    if not selected:
        return []
    if not AUTH_DIR.is_dir():
        return []

    paths = _candidate_paths(selected)
    # Fallback: if pattern miss for a provider, do broader scan once.
    if not paths:
        paths = [p for p in AUTH_DIR.iterdir() if p.is_file() and p.suffix.lower() == ".json"]

    items: list[dict[str, Any]] = []
    workers = min(32, max(4, (os.cpu_count() or 4) * 4))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_read_one, p, selected): p for p in paths}
        for fut in as_completed(futs):
            item = fut.result()
            if item:
                items.append(item)
    items.sort(key=lambda x: (x.get("provider") or "", x.get("email") or "", x.get("file") or ""))
    return items


def count_by_provider_quick() -> dict[str, int]:
    """Best-effort counts for UI checkboxes (filename + light parse)."""
    counts = {pid: 0 for pid in PROVIDERS}
    if not AUTH_DIR.is_dir():
        return counts
    # Use same candidate sets; may slightly undercount exotic names.
    for pid in PROVIDERS:
        items = load_credentials([pid])
        counts[pid] = len(items)
    return counts


def _summarize(items: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {
        "total": len(items),
        "ok": 0,
        "disabled": 0,
        "invalid": 0,
        "token_expired": 0,
        "needs_refresh": 0,
        "no_quota": 0,
        "forbidden": 0,
        "rate_limited": 0,
        "error": 0,
        "other": 0,
    }
    for it in items:
        key = it.get("final") or it.get("local_status") or "other"
        if key in summary:
            summary[key] += 1
        else:
            summary["other"] += 1
    return summary


def _by_provider(items: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for it in items:
        groups.setdefault(it.get("provider") or "unknown", []).append(it)
    return {k: _summarize(v) for k, v in groups.items()}


async def run_scan(
    *,
    providers: list[str],
    live: bool,
    concurrency: int,
    timeout: float,
    model: str,
    try_refresh: bool,
    only_enabled: bool,
    limit: int | None,
) -> dict[str, Any]:
    global _scan_running, _last_results
    async with _state_lock:
        if _scan_running:
            raise HTTPException(status_code=409, detail="scan_already_running")
        _scan_running = True

    try:
        selected = [p for p in providers if p in PROVIDERS]
        if not selected:
            raise HTTPException(status_code=400, detail="no_providers_selected")

        creds = await asyncio.to_thread(load_credentials, selected)
        if only_enabled:
            creds = [c for c in creds if not c["disabled"]]
        if limit is not None and limit > 0:
            creds = creds[:limit]

        sem = asyncio.Semaphore(max(1, concurrency))

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:

            async def worker(cred: dict[str, Any]) -> dict[str, Any]:
                async with sem:
                    pid = cred["provider"]
                    probe = PROVIDERS[pid]["probe"]
                    return await probe(
                        client,
                        cred,
                        live=live,
                        try_refresh=try_refresh and PROVIDERS[pid].get("supports_refresh", False),
                        model=model,
                    )

            results = list(await asyncio.gather(*[worker(c) for c in creds]))

        public_items = [_public_item(r) for r in results]
        payload = {
            "scanned_at": _utc_now().isoformat(),
            "mode": "live" if live else "local",
            "providers": selected,
            "total": len(public_items),
            "items": public_items,
            "summary": _summarize(public_items),
            "by_provider": _by_provider(public_items),
            "auth_dir": str(AUTH_DIR),
            "concurrency": concurrency,
            "timeout": timeout,
            "model": model,
        }
        async with _state_lock:
            _last_results = payload
        return payload
    finally:
        async with _state_lock:
            _scan_running = False


# ---------------------------------------------------------------------------
# API models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    providers: list[str] = Field(default_factory=lambda: ["xai", "codex", "claude", "gemini"])
    live: bool = False
    concurrency: int = Field(default=DEFAULT_CONCURRENCY, ge=1, le=64)
    timeout: float = Field(default=DEFAULT_TIMEOUT, ge=2, le=60)
    model: str = DEFAULT_XAI_MODEL
    try_refresh: bool = True
    only_enabled: bool = False
    limit: int | None = Field(default=None, ge=1, le=5000)


class DisableRequest(BaseModel):
    files: list[str]
    disabled: bool = True


class ReauthStartRequest(BaseModel):
    file: str
    auto: bool | None = None
    manual: bool = False


class ReauthBatchRequest(BaseModel):
    files: list[str] = Field(default_factory=list)
    auto: bool = True
    only_candidates: bool = True
    limit: int | None = Field(default=None, ge=1, le=500)


def _set_disabled(path: Path, disabled: bool) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return False
        data["disabled"] = disabled
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "version": app.version,
        "auth_dir": str(AUTH_DIR),
        "auth_dir_exists": AUTH_DIR.is_dir(),
        "providers": list(PROVIDERS.keys()),
        "scan_running": _scan_running,
        "last_scanned_at": _last_results.get("scanned_at"),
    }


@app.get("/api/providers")
async def api_providers(count: bool = False) -> dict[str, Any]:
    items = []
    counts: dict[str, int] = {}
    if count:
        counts = await asyncio.to_thread(count_by_provider_quick)
    for pid, meta in PROVIDERS.items():
        items.append(
            {
                "id": pid,
                "label": meta["label"],
                "description": meta["description"],
                "supports_live": meta["supports_live"],
                "supports_refresh": meta["supports_refresh"],
                "count": counts.get(pid) if count else None,
            }
        )
    return {"providers": items}


@app.get("/api/status")
async def api_status() -> dict[str, Any]:
    async with _state_lock:
        return {
            "scan_running": _scan_running,
            "scanned_at": _last_results.get("scanned_at"),
            "mode": _last_results.get("mode"),
            "providers": _last_results.get("providers", []),
            "total": _last_results.get("total", 0),
            "summary": _last_results.get("summary", {}),
            "by_provider": _last_results.get("by_provider", {}),
        }


@app.get("/api/results")
async def api_results(
    final: str | None = None,
    provider: str | None = None,
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
) -> dict[str, Any]:
    async with _state_lock:
        items = list(_last_results.get("items") or [])
        meta = {
            "scanned_at": _last_results.get("scanned_at"),
            "mode": _last_results.get("mode"),
            "providers": _last_results.get("providers", []),
            "summary": _last_results.get("summary", {}),
            "by_provider": _last_results.get("by_provider", {}),
            "total_all": _last_results.get("total", 0),
        }
    if provider and provider != "all":
        items = [i for i in items if (i.get("provider") or "") == provider]
    if final and final != "all":
        items = [i for i in items if (i.get("final") or "") == final]
    if q:
        ql = q.lower()
        items = [
            i
            for i in items
            if ql in (i.get("email") or "").lower()
            or ql in (i.get("file") or "").lower()
            or ql in (i.get("sub") or "").lower()
            or ql in (i.get("account_id") or "").lower()
            or ql in (i.get("detail") or "").lower()
            or ql in (i.get("provider") or "").lower()
        ]
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        **meta,
        "filtered_total": total,
        "page": page,
        "page_size": page_size,
        "items": items[start:end],
    }


@app.post("/api/scan")
async def api_scan(req: ScanRequest) -> dict[str, Any]:
    return await run_scan(
        providers=req.providers,
        live=req.live,
        concurrency=req.concurrency,
        timeout=req.timeout,
        model=req.model,
        try_refresh=req.try_refresh,
        only_enabled=req.only_enabled,
        limit=req.limit,
    )


@app.post("/api/disable")
async def api_disable(req: DisableRequest) -> dict[str, Any]:
    if not req.files:
        raise HTTPException(status_code=400, detail="files_required")
    changed = 0
    failed: list[str] = []
    for name in req.files:
        safe = Path(name).name
        if not re.match(r"^[\w.@+\-]+\.json$", safe):
            failed.append(name)
            continue
        path = AUTH_DIR / safe
        if not path.is_file() or not _set_disabled(path, req.disabled):
            failed.append(name)
            continue
        changed += 1
        async with _state_lock:
            for it in _last_results.get("items") or []:
                if it.get("file") == safe:
                    it["disabled"] = req.disabled
                    if req.disabled:
                        it["final"] = "disabled"
                    break
    return {"ok": True, "changed": changed, "failed": failed, "disabled": req.disabled}


@app.get("/api/xai/reauth/config")
async def api_xai_reauth_config() -> dict[str, Any]:
    sso_exists = SSO_AUTH_DIR.is_dir()
    sso_count = 0
    if sso_exists:
        try:
            sso_count = await asyncio.to_thread(
                lambda: sum(1 for p in SSO_AUTH_DIR.glob("*.json") if p.is_file())
            )
        except OSError:
            sso_count = 0
    return {
        "auto_default": XAI_REAUTH_AUTO,
        "headless": XAI_REAUTH_HEADLESS,
        "proxy_configured": bool(XAI_REAUTH_PROXY),
        "timeout_sec": XAI_REAUTH_TIMEOUT,
        "concurrency": XAI_REAUTH_CONCURRENCY,
        "worker_isolation": "subprocess",
        "sso_auth_dir": str(SSO_AUTH_DIR),
        "sso_auth_dir_exists": sso_exists,
        "sso_auth_files": sso_count,
    }


def _enrich_xai_reauth_candidates(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for item in items:
        file_name = str(item.get("file") or "")
        has_password = False
        has_sso = False
        cred_source = "missing"
        email = str(item.get("email") or "")
        try:
            path = AUTH_DIR / Path(file_name).name
            if path.is_file():
                raw = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    creds = _extract_login_credentials(raw, email_hint=email)
                    email = email or str(creds.get("email") or "")
                    has_password = bool(creds.get("password"))
                    has_sso = bool(creds.get("sso"))
                    cred_source = str(creds.get("source") or "missing")
        except Exception:
            pass
        enriched.append(
            {
                "file": file_name,
                "email": email,
                "final": item.get("final"),
                "http_status": item.get("http_status"),
                "probe_status": item.get("probe_status"),
                "detail": item.get("detail"),
                "has_password": has_password,
                "has_sso": has_sso,
                "cred_source": cred_source,
                "auto_capable": bool(has_password and email),
            }
        )
    return enriched


@app.get("/api/xai/reauth/candidates")
async def api_xai_reauth_candidates() -> dict[str, Any]:
    async with _state_lock:
        items = [
            item
            for item in (_last_results.get("items") or [])
            if item.get("provider") == "xai"
            and item.get("final") in {"invalid", "token_expired", "needs_refresh"}
        ]
    enriched = await asyncio.to_thread(_enrich_xai_reauth_candidates, items)
    return {
        "total": len(enriched),
        "auto_capable": sum(1 for x in enriched if x.get("auto_capable")),
        "items": enriched,
    }


def _enrich_codex_reauth_candidates(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for item in items:
        file_name = str(item.get("file") or "")
        has_password = False
        has_refresh = bool(item.get("has_refresh_token"))
        has_session = False
        try:
            path = AUTH_DIR / Path(file_name).name
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                nested = raw.get("tokens") if isinstance(raw.get("tokens"), dict) else {}
                has_password = bool(raw.get("password"))
                has_refresh = bool(raw.get("refresh_token") or nested.get("refresh_token"))
                has_session = bool(raw.get("session_token"))
        except Exception:
            pass
        enriched.append(
            {
                "file": file_name,
                "email": item.get("email"),
                "final": item.get("final"),
                "http_status": item.get("http_status"),
                "probe_status": item.get("probe_status"),
                "detail": item.get("detail"),
                "has_password": has_password,
                "has_refresh": has_refresh,
                "has_session": has_session,
                "cred_source": "refresh_token" if has_refresh else (("session_token+password" if has_session else "password") if has_password else "missing"),
                "auto_capable": bool(has_refresh or has_password),
            }
        )
    return enriched


@app.get("/api/codex/reauth/candidates")
async def api_codex_reauth_candidates() -> dict[str, Any]:
    async with _state_lock:
        items = [
            item
            for item in (_last_results.get("items") or [])
            if item.get("provider") == "codex"
            and item.get("final") in {"invalid", "token_expired", "needs_refresh"}
        ]
    enriched = await asyncio.to_thread(_enrich_codex_reauth_candidates, items)
    return {
        "total": len(enriched),
        "auto_capable": sum(1 for item in enriched if item.get("auto_capable")),
        "items": enriched,
    }


@app.post("/api/codex/reauth/start")
async def api_codex_reauth_start(req: ReauthStartRequest) -> dict[str, Any]:
    try:
        return await _start_codex_reauth_for_file(req.file)
    except HTTPException:
        raise
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/xai/reauth/start")
async def api_xai_reauth_start(req: ReauthStartRequest) -> dict[str, Any]:
    try:
        return await _start_reauth_for_file(
            req.file,
            auto=False if req.manual else req.auto,
            force_manual=bool(req.manual),
        )
    except HTTPException:
        raise
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _create_batch_reauth_job(
    ordered: list[str], *, auto: bool, provider: str
) -> dict[str, Any]:
    global _batch_reauth_job
    async with _batch_reauth_lock:
        if _batch_reauth_job and _batch_reauth_job.get("status") in {"queued", "running"}:
            raise HTTPException(
                status_code=409,
                detail={"error": "batch_reauth_already_running", "job": _public_batch_job(_batch_reauth_job)},
            )
        job_id = secrets.token_urlsafe(12)
        now = _utc_now().isoformat()
        _batch_reauth_job = {
            "id": job_id,
            "provider": provider,
            "status": "queued",
            "total": len(ordered),
            "done": 0,
            "ok": 0,
            "failed": 0,
            "skipped": 0,
            "current_file": None,
            "created_at": now,
            "updated_at": now,
            "detail": "batch_queued",
            "results": [],
            "_task": None,
        }
        task = asyncio.create_task(
            _run_batch_reauth(job_id, ordered, auto=auto, provider=provider)
        )
        _batch_reauth_job["_task"] = task
        return _public_batch_job(_batch_reauth_job) or {}


@app.post("/api/xai/reauth/batch")
async def api_xai_reauth_batch(req: ReauthBatchRequest) -> dict[str, Any]:
    files = [Path(x).name for x in (req.files or []) if x]
    if not files and req.only_candidates:
        async with _state_lock:
            files = [
                str(item.get("file"))
                for item in (_last_results.get("items") or [])
                if item.get("provider") == "xai"
                and item.get("final") in {"invalid", "token_expired", "needs_refresh"}
                and item.get("file")
            ]
    # de-dupe preserve order
    seen: set[str] = set()
    ordered: list[str] = []
    for name in files:
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    if req.limit:
        ordered = ordered[: req.limit]
    if not ordered:
        raise HTTPException(status_code=400, detail="no_reauth_targets")

    return await _create_batch_reauth_job(ordered, auto=bool(req.auto), provider="xai")


@app.post("/api/codex/reauth/batch")
async def api_codex_reauth_batch(req: ReauthBatchRequest) -> dict[str, Any]:
    files = [Path(x).name for x in (req.files or []) if x]
    if not files and req.only_candidates:
        async with _state_lock:
            files = [
                str(item.get("file"))
                for item in (_last_results.get("items") or [])
                if item.get("provider") == "codex"
                and item.get("final") in {"invalid", "token_expired", "needs_refresh"}
                and item.get("file")
            ]
    ordered = list(dict.fromkeys(files))
    # Avoid launching hundreds of doomed browser jobs for files that contain
    # neither a refresh token nor reusable email/password credentials.
    candidate_rows = await asyncio.to_thread(
        _enrich_codex_reauth_candidates,
        [{"file": name} for name in ordered],
    )
    ordered = [str(row["file"]) for row in candidate_rows if row.get("auto_capable")]
    if req.limit:
        ordered = ordered[: req.limit]
    if not ordered:
        raise HTTPException(status_code=400, detail="no_reauth_targets")
    return await _create_batch_reauth_job(ordered, auto=True, provider="codex")


@app.get("/api/xai/reauth/batch")
async def api_xai_reauth_batch_status() -> dict[str, Any]:
    async with _batch_reauth_lock:
        job = _public_batch_job(_batch_reauth_job)
        return {"job": job}


@app.get("/api/codex/reauth/batch")
async def api_codex_reauth_batch_status() -> dict[str, Any]:
    return await api_xai_reauth_batch_status()


@app.post("/api/xai/reauth/batch/cancel")
async def api_xai_reauth_batch_cancel() -> dict[str, Any]:
    async with _batch_reauth_lock:
        if not _batch_reauth_job:
            raise HTTPException(status_code=404, detail="batch_job_not_found")
        _batch_reauth_job["status"] = "cancelled"
        _batch_reauth_job["detail"] = "cancel_requested"
        _batch_reauth_job["updated_at"] = _utc_now().isoformat()
        task = _batch_reauth_job.get("_task")
        if isinstance(task, asyncio.Task) and not task.done():
            task.cancel()
        return {"job": _public_batch_job(_batch_reauth_job)}


@app.post("/api/codex/reauth/batch/cancel")
async def api_codex_reauth_batch_cancel() -> dict[str, Any]:
    return await api_xai_reauth_batch_cancel()


@app.post("/api/xai/reauth/cancel-all")
async def api_xai_reauth_cancel_all() -> dict[str, Any]:
    """Force-cancel batch job + every in-flight single reauth session."""
    cancelled_sessions = 0
    async with _reauth_lock:
        for flow_id, session in list(_reauth_sessions.items()):
            if session.get("status") in {
                "starting",
                "waiting_for_user",
                "browser_login",
                "persisting",
            }:
                task = _reauth_tasks.get(flow_id)
                if task and not task.done():
                    task.cancel()
                session["status"] = "cancelled"
                session["detail"] = "cancelled_by_cancel_all"
                session.pop("_password", None)
                session.pop("_cookies", None)
                session["updated_at"] = _utc_now().isoformat()
                cancelled_sessions += 1
        # Drop finished session secrets if any linger.
        for session in _reauth_sessions.values():
            session.pop("_password", None)
            session.pop("_cookies", None)
            session.pop("_raw", None)

    batch_job = None
    async with _batch_reauth_lock:
        if _batch_reauth_job and _batch_reauth_job.get("status") in {"queued", "running"}:
            _batch_reauth_job["status"] = "cancelled"
            _batch_reauth_job["detail"] = "cancel_all_requested"
            _batch_reauth_job["updated_at"] = _utc_now().isoformat()
            task = _batch_reauth_job.get("_task")
            if isinstance(task, asyncio.Task) and not task.done():
                task.cancel()
        batch_job = _public_batch_job(_batch_reauth_job)

    # Best-effort: close reused mint browsers so next auto starts clean.
    try:
        from xai_auto import shutdown_mint_browsers

        await asyncio.to_thread(shutdown_mint_browsers)
    except Exception:
        pass

    return {
        "ok": True,
        "cancelled_sessions": cancelled_sessions,
        "job": batch_job,
    }


@app.get("/api/xai/reauth/{flow_id}")
async def api_xai_reauth_status(flow_id: str) -> dict[str, Any]:
    async with _reauth_lock:
        session = _reauth_sessions.get(flow_id)
        if session is None:
            raise HTTPException(status_code=404, detail="reauth_session_not_found")
        return _public_reauth_session(session)


@app.post("/api/xai/reauth/{flow_id}/cancel")
async def api_xai_reauth_cancel(flow_id: str) -> dict[str, Any]:
    async with _reauth_lock:
        session = _reauth_sessions.get(flow_id)
        if session is None:
            raise HTTPException(status_code=404, detail="reauth_session_not_found")
        task = _reauth_tasks.get(flow_id)
        if task and not task.done():
            task.cancel()
        session["status"] = "cancelled"
        session["detail"] = "cancelled"
        session.pop("_password", None)
        session.pop("_cookies", None)
        session.pop("_raw", None)
        session["updated_at"] = _utc_now().isoformat()
        return _public_reauth_session(session)


@app.get("/api/codex/reauth/{flow_id}")
async def api_codex_reauth_status(flow_id: str) -> dict[str, Any]:
    return await api_xai_reauth_status(flow_id)


@app.post("/api/codex/reauth/{flow_id}/cancel")
async def api_codex_reauth_cancel(flow_id: str) -> dict[str, Any]:
    return await api_xai_reauth_cancel(flow_id)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return STATUS_PAGE


STATUS_PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>认证巡检</title>
  <style>
    :root{color-scheme:light;--bg:#f4f6f8;--card:#fff;--text:#15202b;--muted:#667085;--line:#e4e7ec;--blue:#175cd3;--red:#b42318;--green:#067647;--amber:#b54708;--purple:#6941c6}
    *{box-sizing:border-box}body{margin:0;font:14px/1.45 Inter,system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--text)}
    header{background:#101828;color:#fff}.header-inner{max-width:1440px;margin:auto;padding:16px 20px;display:flex;justify-content:space-between;gap:16px;align-items:center}
    h1{margin:0;font-size:20px}.sub{color:#98a2b3;font-size:12px;margin-top:4px}
    main{max-width:1440px;margin:auto;padding:18px 20px 40px}
    .stats{display:grid;grid-template-columns:repeat(6,minmax(110px,1fr));gap:10px;margin-bottom:14px}
    .stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}.stat b{display:block;font-size:22px;margin-top:4px}.stat span{color:var(--muted);font-size:12px;font-weight:600}
    .panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;margin-bottom:12px}
    .row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
    .providers{display:flex;flex-wrap:wrap;gap:10px}
    .prov{display:flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:8px;padding:8px 12px;background:#fafbfc;cursor:pointer;user-select:none}
    .prov.active{border-color:#84adff;background:#eff4ff}
    .prov input{width:16px;height:16px}
    .prov .meta{display:flex;flex-direction:column;line-height:1.2}
    .prov .meta strong{font-size:13px}.prov .meta small{color:var(--muted);font-size:11px}
    input,select,button{height:34px;border:1px solid #d0d5dd;border-radius:6px;padding:0 10px;font:inherit;background:#fff}
    button{cursor:pointer;font-weight:600}button.primary{background:var(--blue);border-color:var(--blue);color:#fff}button.danger{color:var(--red);border-color:#fecdca}button:disabled{opacity:.45;cursor:not-allowed}
    label.chk{display:flex;align-items:center;gap:6px;color:var(--muted);white-space:nowrap}
    .msg{min-height:18px;color:var(--muted);font-size:12px;margin-top:8px}.msg.err{color:var(--red)}
    table{width:100%;border-collapse:collapse;min-width:1040px}th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{position:sticky;top:0;background:#f9fafb;font-size:12px;color:#475467;z-index:1}
    .wrap{overflow:auto;max-height:60vh;border:1px solid var(--line);border-radius:8px;background:var(--card)}
    code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700}
    .ok{background:#ecfdf3;color:var(--green)}.disabled{background:#f2f4f7;color:#475467}.invalid,.forbidden{background:#fef3f2;color:var(--red)}
    .no_quota,.token_expired,.needs_refresh{background:#fffaeb;color:var(--amber)}.rate_limited{background:#f4f3ff;color:var(--purple)}.error{background:#fef3f2;color:var(--red)}
    .pv-xai{background:#eef4ff;color:#3538cd}.pv-codex{background:#ecfdf3;color:#067647}
    .pv-claude{background:#fff6ed;color:#c4320a}.pv-gemini{background:#eef4ff;color:#175cd3}
    .pager{display:flex;justify-content:space-between;align-items:center;margin-top:10px;color:var(--muted)}
    @media(max-width:900px){.stats{grid-template-columns:repeat(3,1fr)}}
  </style>
</head>
<body>
<header><div class="header-inner">
  <div><h1>认证巡检</h1><div class="sub">勾选厂商 · 本地校验 · 可选上游实探 · 批量禁用</div></div>
  <div class="sub" id="sync">未扫描</div>
</div></header>
<main>
  <section class="panel">
    <div style="font-weight:700;margin-bottom:8px">选择要巡检的厂商</div>
    <div class="providers" id="providerBox"></div>
  </section>

  <section class="stats" id="stats"></section>

  <section class="panel">
    <div class="row">
      <label class="chk"><input type="checkbox" id="live"> 上游实探 (live)</label>
      <label class="chk"><input type="checkbox" id="tryRefresh" checked> 过期时尝试 refresh（xAI）</label>
      <label class="chk"><input type="checkbox" id="onlyEnabled"> 仅未禁用</label>
      <label>并发 <input id="concurrency" type="number" value="8" min="1" max="32" style="width:70px"></label>
      <label>超时秒 <input id="timeout" type="number" value="12" min="3" max="60" style="width:70px"></label>
      <label>limit <input id="limit" type="number" placeholder="全部" min="1" style="width:90px"></label>
      <button class="primary" id="btnScan" onclick="startScan()">开始巡检</button>
      <button onclick="loadResults()">刷新结果</button>
      <button onclick="loadProviders(true)">刷新厂商计数</button>
      <span style="flex:1"></span>
      <button id="btnDisable" class="danger" onclick="bulkDisable(true)" disabled>禁用已选</button>
      <button onclick="bulkDisable(false)" id="btnEnable" disabled>启用已选</button>
      <button class="danger" onclick="disableByFinal('invalid')">禁用全部 invalid</button>
      <button class="danger" onclick="disableByFinal('no_quota')">禁用全部 no_quota</button>
      <button class="danger" onclick="disableByFinal('forbidden')">禁用全部 forbidden</button>
    </div>
    <div class="row" style="margin-top:8px">
      <input id="q" type="search" placeholder="搜索 email / 文件名 / account / detail" style="min-width:280px;flex:1" oninput="state.page=1;render()">
      <select id="filterProvider" onchange="state.reauthOnly=false;state.page=1;render()">
        <option value="all">全部厂商</option>
      </select>
      <select id="filter" onchange="state.reauthOnly=false;state.page=1;render()">
        <option value="all">全部 final</option>
        <option value="ok">ok</option>
        <option value="disabled">disabled</option>
        <option value="invalid">invalid</option>
        <option value="token_expired">token_expired</option>
        <option value="needs_refresh">needs_refresh</option>
        <option value="no_quota">no_quota</option>
        <option value="forbidden">forbidden</option>
        <option value="rate_limited">rate_limited</option>
        <option value="error">error</option>
      </select>
      <button onclick="showInvalidProvider('xai')">待重授权 xAI</button>
      <button onclick="showInvalidProvider('codex')">待重授权 Codex/ChatGPT</button>
      <button class="primary" id="btnBatchReauth" onclick="batchReauthCurrent()">自动重授权当前筛选</button>
      <button id="btnCancelBatch" onclick="cancelBatchReauth()" disabled>取消批量</button>
      <button class="danger" id="btnCancelAllReauth" onclick="cancelAllReauth()">强制取消全部授权</button>
    </div>
    <div class="msg" id="msg">先勾选厂商，再点「开始巡检」。xAI 自动授权会读认证 JSON 或 sso_auths 的 password/sso；卡住时用「强制取消全部授权」。</div>
  </section>

  <section class="wrap">
    <table>
      <thead><tr>
        <th style="width:36px"><input type="checkbox" id="checkPage" onchange="togglePage(this.checked)"></th>
        <th>厂商</th><th>Email / 账号</th><th>文件</th><th>Final</th><th>HTTP</th><th>Probe</th><th>套餐</th><th>JWT 过期</th><th>延迟</th><th>Detail</th><th></th>
      </tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </section>
  <div class="pager">
    <div id="range">0</div>
    <div class="row">
      <button onclick="changePage(-1)">上一页</button>
      <span id="pageInfo">1/1</span>
      <button onclick="changePage(1)">下一页</button>
    </div>
  </div>
</main>
<script>
const state = {
  providersMeta: [],
  selectedProviders: new Set(['xai','codex','claude','gemini']),
  items: [], summary: {}, by_provider: {}, page: 1, pageSize: 50,
  selected: new Set(), reauthing: new Set(), reauthOnly: false,
  scanned_at: null, mode: null, providers: [],
  reauthConfig: {auto_default:true}, batchPoll: null
};
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function setMsg(text, err=false){ $('msg').textContent=text; $('msg').className='msg'+(err?' err':''); }
function badge(final){ return `<span class="badge ${esc(final)}">${esc(final||'-')}</span>`; }
function pbadge(p){ return `<span class="badge pv-${esc(p)}">${esc(p||'-')}</span>`; }

function renderProviderBox(){
  const box = $('providerBox');
  box.innerHTML = state.providersMeta.map(p => {
    const on = state.selectedProviders.has(p.id);
    const count = (p.count==null) ? '计数未加载' : (p.count.toLocaleString() + ' 个文件');
    return `<label class="prov ${on?'active':''}">
      <input type="checkbox" data-pid="${esc(p.id)}" ${on?'checked':''} onchange="toggleProvider('${esc(p.id)}', this.checked)">
      <span class="meta"><strong>${esc(p.label)}</strong><small>${esc(p.description)} · ${esc(count)}</small></span>
    </label>`;
  }).join('') || '<span class="sub">加载厂商列表中…</span>';

  // filter select
  const fp = $('filterProvider');
  const cur = fp.value || 'all';
  fp.innerHTML = '<option value="all">全部厂商</option>' + state.providersMeta.map(p => `<option value="${esc(p.id)}">${esc(p.label)}</option>`).join('');
  fp.value = [...fp.options].some(o => o.value===cur) ? cur : 'all';
}
function toggleProvider(id, on){
  on ? state.selectedProviders.add(id) : state.selectedProviders.delete(id);
  renderProviderBox();
}

function filtered(){
  const q = $('q').value.trim().toLowerCase();
  const f = $('filter').value;
  const fp = $('filterProvider').value;
  return state.items.filter(it => {
    if(state.reauthOnly && !(
      ['xai','codex'].includes(it.provider) && ['invalid','token_expired','needs_refresh'].includes(it.final)
    )) return false;
    if (fp !== 'all' && (it.provider||'') !== fp) return false;
    if (f !== 'all' && (it.final||'') !== f) return false;
    if (!q) return true;
    return [it.email,it.file,it.sub,it.account_id,it.detail,it.probe_status,it.provider,it.plan_type]
      .some(x => String(x||'').toLowerCase().includes(q));
  });
}

function renderStats(){
  const s = state.summary || {};
  const cards = [
    ['total','总数','本次巡检识别出的认证文件总数'],
    ['ok','正常','认证有效且上游探测通过，或本地检查未发现异常'],
    ['disabled','禁用','认证文件已被标记为 disabled'],
    ['token_expired','Token 过期','Access Token 的 JWT 到期时间已过'],
    ['needs_refresh','待刷新','Access Token 已过期，但存在可用 Refresh Token'],
    ['invalid','无效','上游返回 401，或认证内容缺失/不可用'],
    ['no_quota','无额度','账号额度或可用配额已耗尽'],
    ['forbidden','403','认证可能有效，但账号、模型、地区或 IP 没有访问权限'],
    ['rate_limited','429','请求频率过高、并发受限或触发上游限流'],
    ['error','错误','网络、超时、响应解析或其他探测异常'],
    ['other','其他','未归入上述分类的结果']
  ];
  $('stats').innerHTML = cards.map(([k,label,help]) => `<div class="stat" title="${esc(help)}"><span>${label}</span><b>${(s[k]??0).toLocaleString()}</b></div>`).join('');
  const prov = (state.providers||[]).join(',') || '-';
  $('sync').textContent = state.scanned_at
    ? `上次: ${new Date(state.scanned_at).toLocaleString('zh-CN',{hour12:false})} · ${state.mode||'-'} · ${prov}`
    : '未扫描';
}

function render(){
  renderStats();
  const list = filtered();
  const pages = Math.max(1, Math.ceil(list.length / state.pageSize));
  state.page = Math.min(state.page, pages);
  const start = (state.page-1)*state.pageSize;
  const rows = list.slice(start, start+state.pageSize);
  $('rows').innerHTML = rows.map(it => {
    const id = it.file;
    const account = it.email || it.account_id || '-';
    const canReauth = ['xai','codex'].includes(it.provider) && ['invalid','token_expired','needs_refresh'].includes(it.final);
    const reauthing = state.reauthing.has(id);
    return `<tr>
      <td><input type="checkbox" data-id="${esc(id)}" ${state.selected.has(id)?'checked':''} onchange="toggleOne('${esc(id)}',this.checked)"></td>
      <td>${pbadge(it.provider)}</td>
      <td>${esc(account)}</td>
      <td><code>${esc(it.file)}</code></td>
      <td>${badge(it.final)}</td>
      <td>${esc(it.http_status ?? '-')}</td>
      <td>${esc(it.probe_status ?? '-')}</td>
      <td>${esc(it.plan_type || '-')}</td>
      <td>${esc(it.jwt_exp ? new Date(it.jwt_exp).toLocaleString('zh-CN',{hour12:false}) : '-')}${it.jwt_expired?' ⚠':''}</td>
      <td>${esc(it.latency_ms ?? '-')}</td>
      <td style="max-width:260px;word-break:break-all;color:#475467">${esc(it.detail||'')}</td>
      <td><div class="row" style="gap:5px;flex-wrap:nowrap">
        ${canReauth?`<button class="primary" onclick="reauthProvider('${esc(id)}', '${esc(it.provider)}', true)" ${reauthing?'disabled':''}>${reauthing?'授权中…':'自动授权'}</button>
        ${it.provider==='xai'?`<button onclick="reauthProvider('${esc(id)}', 'xai', false)" ${reauthing?'disabled':''}>手动</button>`:''}`:''}
        <button onclick="disableFiles(['${esc(id)}'], true)">禁用</button>
      </div></td>
    </tr>`;
  }).join('') || `<tr><td colspan="12" style="text-align:center;color:#98a2b3;padding:40px">暂无数据：勾选厂商后点「开始巡检」</td></tr>`;
  $('range').textContent = `${list.length?start+1:0}-${Math.min(start+state.pageSize,list.length)} / ${list.length}`;
  $('pageInfo').textContent = `${state.page} / ${pages}`;
  $('btnDisable').disabled = state.selected.size===0;
  $('btnEnable').disabled = state.selected.size===0;
  $('checkPage').checked = rows.length>0 && rows.every(x => state.selected.has(x.file));
}

function toggleOne(id, on){ on?state.selected.add(id):state.selected.delete(id); render(); }
function togglePage(on){
  const list = filtered();
  const start = (state.page-1)*state.pageSize;
  for (const it of list.slice(start, start+state.pageSize)) on?state.selected.add(it.file):state.selected.delete(it.file);
  render();
}
function changePage(d){ state.page += d; if(state.page<1) state.page=1; render(); }
function showInvalidProvider(provider){
  $('filterProvider').value=provider;
  $('filter').value='all';
  state.reauthOnly=true;
  state.page=1;
  render();
}

function formatApiError(data, status){
  const d = (data && (data.detail ?? data.error)) ?? null;
  if(d == null || d === '') return 'HTTP ' + status;
  if(typeof d === 'string') return d;
  if(typeof d === 'object'){
    if(d.error === 'batch_reauth_already_running' && d.job){
      const j = d.job;
      return `批量任务已在进行：${j.done||0}/${j.total||0} · ${j.status} · current=${j.current_file||'-'} · job=${j.id||''}`;
    }
    if(d.error === 'reauth_already_running' && d.session){
      const s = d.session;
      return `该账号授权已在进行：${s.file||''} · ${s.status||''} · ${s.detail||''}`;
    }
    if(d.error) return String(d.error) + (d.detail ? (': ' + d.detail) : '');
    try{ return JSON.stringify(d); }catch(e){ return String(d); }
  }
  return String(d);
}
async function api(path, opts){
  const res = await fetch(path, Object.assign({cache:'no-store'}, opts||{}));
  const text = await res.text();
  let data; try{ data=JSON.parse(text);}catch{ throw new Error(text||('HTTP '+res.status)); }
  if(!res.ok) throw new Error(formatApiError(data, res.status));
  return data;
}

async function loadProviders(withCount=false){
  try{
    setMsg(withCount ? '正在统计各厂商认证数量（可能较慢）…' : '加载厂商列表…');
    const data = await api('/api/providers' + (withCount?'?count=true':''));
    state.providersMeta = data.providers || [];
    // keep selection only for known providers
    const known = new Set(state.providersMeta.map(p => p.id));
    state.selectedProviders = new Set([...state.selectedProviders].filter(x => known.has(x)));
    if (!state.selectedProviders.size && state.providersMeta.length) {
      state.providersMeta.forEach(p => state.selectedProviders.add(p.id));
    }
    renderProviderBox();
    setMsg(withCount ? '厂商计数已更新' : '已加载厂商列表（可点「刷新厂商计数」）');
  }catch(e){ setMsg(e.message,true); }
}

async function loadResults(){
  try{
    let page=1, all=[];
    while(true){
      const r = await api(`/api/results?page=${page}&page_size=200`);
      all = all.concat(r.items||[]);
      state.summary = r.summary||{};
      state.by_provider = r.by_provider||{};
      state.scanned_at = r.scanned_at;
      state.mode = r.mode;
      state.providers = r.providers||[];
      if(all.length >= (r.filtered_total||0) || !(r.items||[]).length) break;
      page++;
      if(page>100) break;
    }
    state.items = all;
    state.selected.clear();
    setMsg(all.length
      ? `已加载 ${all.length} 条结果${state.mode==='local'?'；当前是本地扫描，无额度 / 403 / 429 需勾选「上游实探」后重新巡检':''}`
      : '暂无历史结果，请先巡检');
    render();
  }catch(e){ setMsg(e.message,true); }
}

async function startScan(){
  const providers = [...state.selectedProviders];
  if(!providers.length){ setMsg('请至少勾选一个厂商', true); return; }
  const live = $('live').checked;
  if(live && !confirm(`将对 ${providers.join(', ')} 发起上游探测，可能耗额度/触发限流。确认？`)) return;
  $('btnScan').disabled = true;
  setMsg(live ? `正在上游实探：${providers.join(', ')} …` : `正在本地扫描：${providers.join(', ')} …`);
  try{
    const body = {
      providers,
      live,
      try_refresh: $('tryRefresh').checked,
      only_enabled: $('onlyEnabled').checked,
      concurrency: Number($('concurrency').value||8),
      timeout: Number($('timeout').value||12),
      limit: $('limit').value ? Number($('limit').value) : null,
    };
    const data = await api('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    state.items = data.items||[];
    state.summary = data.summary||{};
    state.by_provider = data.by_provider||{};
    state.scanned_at = data.scanned_at;
    state.mode = data.mode;
    state.providers = data.providers||[];
    state.selected.clear();
    state.page = 1;
    const bp = Object.entries(state.by_provider||{}).map(([k,v]) => `${k}:${v.total}`).join(' · ');
    setMsg(`巡检完成：共 ${data.total} 条（${bp || providers.join(',')}），mode=${data.mode}`
      + (data.mode==='local'?'；本地模式不请求上游，无额度 / 403 / 429 不会产生计数':'；已执行上游实探'));
    render();
  }catch(e){ setMsg(e.message,true); }
  finally{ $('btnScan').disabled=false; }
}

async function disableFiles(files, disabled){
  if(!files.length) return;
  if(!confirm((disabled?'禁用':'启用') + ` ${files.length} 个认证文件？`)) return;
  try{
    const r = await api('/api/disable', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({files, disabled})});
    setMsg(`已更新 ${r.changed} 个文件` + (r.failed?.length?`，失败 ${r.failed.length}`:''));
    for(const f of files){
      const it = state.items.find(x=>x.file===f);
      if(it){ it.disabled=disabled; if(disabled) it.final='disabled'; }
    }
    state.selected.clear();
    const summary = {total:state.items.length,ok:0,disabled:0,invalid:0,token_expired:0,needs_refresh:0,no_quota:0,forbidden:0,rate_limited:0,error:0,other:0};
    for(const it of state.items){ const k=it.final||'other'; if(summary[k]!==undefined) summary[k]++; else summary.other++; }
    state.summary = summary;
    render();
  }catch(e){ setMsg(e.message,true); }
}
function bulkDisable(disabled){ disableFiles([...state.selected], disabled); }
function disableByFinal(final){
  const files = filtered().filter(x=>x.final===final).map(x=>x.file);
  if(!files.length){ setMsg('当前筛选下没有匹配项'); return; }
  disableFiles(files, true);
}

async function reauthProvider(file, provider, auto=true){
  if(state.reauthing.has(file)) return;
  const providerLabel = provider==='codex' ? 'Codex/ChatGPT' : 'xAI';
  const modeLabel = provider==='codex'
    ? '优先刷新令牌，失败时使用 ChatGPT 登录凭据完成 Device OAuth'
    : (auto ? '自动浏览器授权（读取认证文件 password，打开 Chromium 完成登录/Turnstile/允许）' : '手动 Device OAuth（需你在 xAI 页面确认）');
  if(!confirm(`将为 ${file} 启动 ${providerLabel} 重新授权：${modeLabel}。继续？`)) return;
  let popup = null;
  state.reauthing.add(file);
  render();
  try{
    const session = await api(`/api/${provider}/reauth/start`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({file, auto: !!auto, manual: !auto})
    });
    if(session.mode==='manual' && session.verification_uri_complete){
      popup = window.open(session.verification_uri_complete, '_blank');
      setMsg(`已启动手动授权：${file} · 用户码 ${session.user_code||'-'} · ${session.detail||''}`);
    }else{
      setMsg(`已启动自动授权：${file} · ${session.detail||'browser_login'}`);
    }
    while(true){
      await new Promise(resolve=>setTimeout(resolve, 2500));
      const current = await api(`/api/${provider}/reauth/${encodeURIComponent(session.id)}`);
      if(['waiting_for_user','starting','refreshing','browser_login','persisting'].includes(current.status)){
        setMsg(`${current.mode==='auto'?'自动':'手动'}授权中：${file} · ${current.status} · ${current.detail||''}${current.user_code?(' · 码 '+current.user_code):''}`);
        continue;
      }
      if(current.status==='succeeded'){
        setMsg(`重新授权成功：${file} · mode=${current.mode||'-'} · 实探 ${current.probe_final||'-'} / HTTP ${current.probe_http_status??'-'} · 备份 ${current.backup_file||'-'}`);
        await loadResults();
      }else{
        setMsg(`重新授权未完成：${file} · ${current.status} · ${current.detail||''}`, true);
      }
      break;
    }
  }catch(e){
    if(popup) popup.close();
    setMsg(`重新授权失败：${file} · ${e.message}`, true);
  }finally{
    state.reauthing.delete(file);
    render();
  }
}

function startBatchPolling(){
  $('btnCancelBatch').disabled = false;
  if(state.batchPoll) clearInterval(state.batchPoll);
  state.batchPoll = setInterval(pollBatchReauth, 2500);
  pollBatchReauth();
}

async function batchReauthCurrent(){
  const visible = filtered().filter(x => ['xai','codex'].includes(x.provider) && ['invalid','token_expired','needs_refresh'].includes(x.final));
  const providers = [...new Set(visible.map(x => x.provider))];
  if(providers.length !== 1){ setMsg('请先选择 xAI 或 Codex/ChatGPT 厂商，并确保当前筛选有待授权账号', true); return; }
  const provider = providers[0];
  state.batchProvider = provider;
  // If a batch is already running, just attach progress instead of hard-failing.
  try{
    const existing = await api(`/api/${provider}/reauth/batch`);
    if(existing.job && ['queued','running'].includes(existing.job.status)){
      setMsg(`已有批量任务进行中：${existing.job.done||0}/${existing.job.total||0} · current=${existing.job.current_file||'-'}`);
      startBatchPolling();
      return;
    }
  }catch(e){ /* continue to start new */ }

  const files = visible.map(x=>x.file);
  if(!files.length){ setMsg('当前筛选下没有可自动重授权的账号', true); return; }
  const providerLabel = provider==='codex' ? 'Codex/ChatGPT' : 'xAI';
  if(!confirm(`将对当前筛选中的 ${files.length} 个 ${providerLabel} 账号执行自动重授权（串行）。继续？`)) return;
  try{
    const job = await api(`/api/${provider}/reauth/batch`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({files, auto:true, only_candidates:false})
    });
    setMsg(`批量自动重授权已启动：job=${job.id} total=${job.total}`);
    startBatchPolling();
  }catch(e){
    // 409 already-running: attach instead of opaque [object Object]
    if(String(e.message||'').includes('批量任务已在进行') || String(e.message||'').includes('batch_reauth_already_running')){
      setMsg(e.message, true);
      startBatchPolling();
      return;
    }
    setMsg(`批量重授权失败：${e.message}`, true);
  }
}

async function pollBatchReauth(){
  try{
    const provider = state.batchProvider || 'xai';
    const data = await api(`/api/${provider}/reauth/batch`);
    const job = data.job;
    if(!job){ return; }
    const last = (job.results && job.results.length) ? job.results[job.results.length-1] : null;
    const lastTxt = last ? ` · last=${last.file}:${last.status}` : '';
    setMsg(`批量重授权 ${job.status}: ${job.done||0}/${job.total||0} ok=${job.ok||0} fail=${job.failed||0} skip=${job.skipped||0} current=${job.current_file||'-'} · ${job.current_status||''} ${job.current_detail||job.detail||''}${lastTxt}`);
    $('btnCancelBatch').disabled = !['queued','running'].includes(job.status);
    if(['finished','failed','cancelled'].includes(job.status)){
      if(state.batchPoll){ clearInterval(state.batchPoll); state.batchPoll=null; }
      await loadResults();
    }
  }catch(e){ /* ignore transient */ }
}

async function cancelBatchReauth(){
  try{
    const provider = state.batchProvider || 'xai';
    await api(`/api/${provider}/reauth/batch/cancel`, {method:'POST'});
    setMsg('已请求取消批量重授权');
    startBatchPolling();
  }catch(e){ setMsg(e.message, true); }
}

async function cancelAllReauth(){
  if(!confirm('强制取消全部进行中的 xAI 自动/手动/批量授权？可清理 409 卡住状态。')) return;
  try{
    const r = await api('/api/xai/reauth/cancel-all', {method:'POST'});
    state.reauthing.clear();
    if(state.batchPoll){ clearInterval(state.batchPoll); state.batchPoll=null; }
    $('btnCancelBatch').disabled = true;
    setMsg(`已强制取消：sessions=${r.cancelled_sessions||0}` + (r.job?` · batch=${r.job.status}`:''));
    render();
  }catch(e){ setMsg(e.message, true); }
}

async function loadReauthConfig(){
  try{
    state.reauthConfig = await api('/api/xai/reauth/config');
    if(state.reauthConfig){
      const p = state.reauthConfig.proxy_configured ? 'proxy=on' : 'proxy=off';
      const sso = state.reauthConfig.sso_auth_dir_exists
        ? `sso_files=${state.reauthConfig.sso_auth_files||0}`
        : 'sso_dir=missing';
      // keep subtle; full message is set by later loaders
      state.reauthConfigHint = `${p} · ${sso} · headless=${state.reauthConfig.headless}`;
    }
  }catch(e){ /* optional */ }
}

async function resumeBatchIfAny(){
  try{
    const data = await api('/api/xai/reauth/batch');
    if(data.job && ['queued','running'].includes(data.job.status)){
      setMsg(`检测到进行中的批量重授权：${data.job.done||0}/${data.job.total||0} · current=${data.job.current_file||'-'}`);
      startBatchPolling();
    }
  }catch(e){ /* optional */ }
}

loadProviders(false)
  .then(() => loadReauthConfig())
  .then(() => loadResults())
  .then(() => resumeBatchIfAny())
  .catch(()=>{});
</script>
</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host=HOST_BIND, port=PORT, reload=False)
