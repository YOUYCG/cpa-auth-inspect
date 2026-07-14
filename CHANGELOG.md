# Changelog

## 0.5.2 - 2026-07-14

- Keep every summary category visible even when its count is zero.
- Add the `other` summary card and hover explanations for all result states.

## 0.5.1 - 2026-07-14

- Show disabled, expired, refresh-needed, and error counts in the summary cards.
- Explain in the UI that quota, 403, and 429 counts require an upstream live probe.

## 0.5.0 - 2026-07-14

- Add automatic Codex/ChatGPT reauthorization for CPA credential files.
- Try a refresh token first, then fall back to the Codex device-login flow with
  reusable email/password credentials, reusing a saved ChatGPT session when available.
- Add single-account and filtered batch UI/API actions; pre-filter files that
  have neither a refresh token nor browser login credentials.
- Back up and atomically update both flat and nested Codex token fields, then
  run an immediate upstream probe.
- Keep Codex passwords and refresh tokens out of worker process arguments.

## 0.4.3 - 2026-07-14

- Isolate Chromium auto-reauthorization in a one-shot subprocess so browser
  automation cannot starve the FastAPI event loop or freeze health/status APIs.
- Terminate the worker process group on cancel/timeout, including Chromium
  children, while keeping passwords out of process arguments.
- Avoid a full `sso_auths` directory scan when the exact sidecar exists and
  move candidate/config filesystem work off the FastAPI event loop.
- Run recommended headed Chromium inside Xvfb in Docker; true headless mode is
  commonly blocked by accounts.x.ai Turnstile and times out before consent.
- Enable Docker's init process so completed Chromium/Xvfb grandchildren are
  reaped instead of accumulating as zombie processes.

## 0.4.2 - 2026-07-14

- Wire `XAI_REAUTH_PROXY` to host proxy (`host.docker.internal:7897`) for accounts.x.ai access.
- Add `/api/xai/reauth/cancel-all` + UI button to clear stuck single/batch sessions (stops 409 loops).
- Batch progress exposes live `current_status` / `current_detail`; frontend formats object error details.

## 0.4.1 - 2026-07-14

- Resolve auto-reauth credentials from `SSO_AUTH_DIR` (`sso-<email>.json`) when CPA auth JSON has no password.
- Inject SSO cookies into Chromium before device consent (skip secondary login when possible).
- Mount grok_bytao `sso_auths` in compose; expose sidecar stats on `/api/xai/reauth/config`.

## 0.4.0 - 2026-07-14

- Auto xAI reauthorization via Chromium device-consent (ported from grok_bytao).
- Read `email`/`password` from auth JSON; fall back to manual Device OAuth when missing.
- Add batch auto-reauth API/UI with cancel and progress.
- Bundle `xai_auto` helpers + `turnstilePatch`; Docker image installs Chromium.
- Env knobs: `XAI_REAUTH_AUTO`, `XAI_REAUTH_HEADLESS`, `XAI_REAUTH_PROXY`, timeout/concurrency.

## 0.3.0 - 2026-07-14

- Filter xAI credentials that need reauthorization.
- Add manual xAI Device OAuth reauthorization from the inspector UI.
- Back up and atomically replace credential files after authorization.
- Re-probe updated credentials and refresh the in-memory scan result.
- Add regression tests for token redaction, safe paths, and atomic persistence.

## 0.2.0 - 2026-07-14

- Declare only the management API capability.
- Add complete host-required plugin metadata.
- Use canonical management resource registration keys.
- Add Go unit tests and a standalone ABI smoke test.
- Publish the FastAPI multi-provider inspector with Docker support.
