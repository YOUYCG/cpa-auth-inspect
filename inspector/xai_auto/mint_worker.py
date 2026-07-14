"""Isolated browser mint worker.

The parent sends one JSON request on stdin. Progress is written to stderr and
the token response is the only JSON value written to stdout.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .browser_confirm import mint_with_browser


def _log(message: str) -> None:
    print(str(message), file=sys.stderr, flush=True)


def main() -> int:
    try:
        payload: Any = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("worker_request_must_be_object")
        email = str(payload.get("email") or "").strip()
        password = str(payload.get("password") or "")
        if not email or not password:
            raise ValueError("worker_request_missing_credentials")
        tokens = mint_with_browser(
            email=email,
            password=password,
            page=None,
            proxy=payload.get("proxy") or None,
            headless=bool(payload.get("headless")),
            browser_timeout_sec=float(payload.get("browser_timeout_sec") or 240),
            force_standalone=True,
            cookies=payload.get("cookies") or None,
            # A subprocess is intentionally one-shot. Reusing Chromium here
            # would keep browser children alive after the worker exits.
            reuse_browser=False,
            poll_log=_log,
        )
        json.dump(tokens, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return 0
    except BaseException as exc:  # noqa: BLE001 - worker must report every failure
        print(f"{type(exc).__name__}:{exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
