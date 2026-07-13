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
DEFAULT_CONCURRENCY = int(os.environ.get("PROBE_CONCURRENCY", "8"))
DEFAULT_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "12"))
DEFAULT_XAI_MODEL = os.environ.get("PROBE_MODEL", "grok-3-mini")
HOST_BIND = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "18318"))

app = FastAPI(title="CPA Auth Inspector", version="0.3.0")

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
        "version": "0.3.0",
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
      <select id="filterProvider" onchange="state.page=1;render()">
        <option value="all">全部厂商</option>
      </select>
      <select id="filter" onchange="state.page=1;render()">
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
    </div>
    <div class="msg" id="msg">先勾选厂商，再点「开始巡检」。建议先本地扫描；live 先小 limit。</div>
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
  selected: new Set(), scanned_at: null, mode: null, providers: []
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
    ['total','总数'],['ok','正常'],['invalid','无效'],['no_quota','无额度'],['forbidden','403'],['rate_limited','429']
  ];
  $('stats').innerHTML = cards.map(([k,label]) => `<div class="stat"><span>${label}</span><b>${(s[k]??0).toLocaleString()}</b></div>`).join('');
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
      <td><button onclick="disableFiles(['${esc(id)}'], true)">禁用</button></td>
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

async function api(path, opts){
  const res = await fetch(path, Object.assign({cache:'no-store'}, opts||{}));
  const text = await res.text();
  let data; try{ data=JSON.parse(text);}catch{ throw new Error(text||('HTTP '+res.status)); }
  if(!res.ok) throw new Error(data.detail || data.error || ('HTTP '+res.status));
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
    setMsg(all.length ? `已加载 ${all.length} 条结果` : '暂无历史结果，请先巡检');
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
    setMsg(`巡检完成：共 ${data.total} 条（${bp || providers.join(',')}），mode=${data.mode}`);
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

loadProviders(false).then(() => loadResults()).catch(()=>{});
</script>
</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host=HOST_BIND, port=PORT, reload=False)
