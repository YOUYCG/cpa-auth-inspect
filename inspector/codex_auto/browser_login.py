"""Drive the official Codex browser login with Chromium."""

from __future__ import annotations

import time
import threading
from typing import Any, Callable

from xai_auto.browser_confirm import (
    _click_exact,
    _page_url,
    _visible_text,
    close_standalone,
    create_standalone_page,
)


class CodexBrowserLoginError(RuntimeError):
    pass


def _input_first(page: Any, selectors: list[str], value: str) -> bool:
    for selector in selectors:
        try:
            element = page.ele(selector, timeout=0.4)
            if not element:
                continue
            current = str(getattr(element, "value", "") or element.attr("value") or "")
            if current == value:
                return True
            # DrissionPage's separate clear() followed by input() can race with
            # React's controlled input and append on every polling iteration.
            element.input(value, clear=True)
            current = str(getattr(element, "value", "") or element.attr("value") or "")
            if current == value:
                return True
        except Exception:
            continue
    return False


def complete_codex_login(
    *,
    auth_url: str,
    email: str,
    password: str,
    proxy: str | None,
    headless: bool,
    timeout_sec: float,
    log: Callable[[str], None],
    user_code: str = "",
    session_token: str = "",
    stop_event: threading.Event | None = None,
) -> None:
    browser, page = create_standalone_page(proxy=proxy, headless=headless, log=log)
    try:
        if session_token:
            cookie_names = (
                "__Secure-next-auth.session-token",
                "__Secure-authjs.session-token",
            )
            cookies: list[dict[str, Any]] = []
            for name in cookie_names:
                chunks = [session_token[i : i + 3800] for i in range(0, len(session_token), 3800)]
                for domain in (".openai.com", ".chatgpt.com"):
                    for index, chunk in enumerate(chunks):
                        cookies.append(
                            {
                                "name": name if len(chunks) == 1 else f"{name}.{index}",
                                "value": chunk,
                                "domain": domain,
                                "path": "/",
                                "secure": True,
                                "httpOnly": True,
                            }
                        )
            try:
                page.set.cookies(cookies)
                log(f"injected existing ChatGPT session cookies={len(cookies)}")
            except Exception as exc:
                log(f"ChatGPT session cookie injection failed: {exc}")
        page.get(auth_url)
        deadline = time.time() + max(timeout_sec, 60)
        last_state = ""
        while time.time() < deadline:
            if stop_event is not None and stop_event.is_set():
                log("codex browser stopped by successful token poll")
                return
            url = _page_url(page)
            text = _visible_text(page)
            normalized = " ".join(text.split())
            state = f"url={url[:160]} text={normalized[:220]}"
            if state != last_state:
                log(state)
                last_state = state

            low = normalized.lower()
            if (
                "localhost:" in url
                and ("success" in low or "authenticated" in low or "codex" in low)
            ) or "you are now signed in" in low or "authentication complete" in low:
                log("codex browser login completed")
                return
            # Do not use a generic text input here: on the account login page
            # that field is the email box and would receive the device code.
            if user_code and _input_first(
                page,
                [
                    "css:input[name='user_code']",
                    "css:input[autocomplete='one-time-code']",
                    "css:input[placeholder*='code' i]",
                ],
                user_code,
            ):
                log("entered Codex device user code")
                user_code = ""
                _click_exact(page, ["Continue", "继续", "Next", "下一步"], log, real=True)
                time.sleep(1.2)
                continue
            if any(term in low for term in ("one-time code", "verification code", "security code")):
                raise CodexBrowserLoginError("mfa_or_email_code_required")

            if _input_first(
                page,
                [
                    "css:input[type='email']",
                    "css:input[name='username']",
                    "css:input[name='email']",
                ],
                email,
            ):
                _click_exact(page, ["Continue", "继续", "Next", "下一步"], log, real=True)
                time.sleep(1.2)
                continue
            if _input_first(
                page,
                ["css:input[type='password']", "css:input[name='password']"],
                password,
            ):
                _click_exact(
                    page,
                    ["Continue", "继续", "Sign in", "Log in", "登录"],
                    log,
                    real=True,
                )
                time.sleep(1.5)
                continue
            if _click_exact(
                page,
                ["Continue", "继续", "Allow", "允许", "Authorize", "同意"],
                log,
                real=True,
            ):
                time.sleep(1.2)
                continue
            time.sleep(0.8)
        raise CodexBrowserLoginError("codex_browser_login_timed_out")
    finally:
        close_standalone(browser)
