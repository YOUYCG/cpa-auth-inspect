import json
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app


class XaiReauthTests(unittest.TestCase):
    def test_public_session_never_exposes_device_code(self) -> None:
        public = app._public_reauth_session(
            {
                "id": "flow",
                "file": "xai-user@example.com.json",
                "status": "waiting_for_user",
                "mode": "auto",
                "user_code": "ABCD-EFGH",
                "_device_code": "secret-device-code",
                "_password": "secret-password",
                "access_token": "secret-access-token",
            }
        )
        self.assertEqual(public["id"], "flow")
        self.assertEqual(public["mode"], "auto")
        self.assertNotIn("_device_code", public)
        self.assertNotIn("_password", public)
        self.assertNotIn("access_token", public)

    def test_extract_login_credentials_from_nested_oauth_record(self) -> None:
        creds = app._extract_login_credentials(
            {
                "email": "",
                "oauth_record": {"email": "nested@example.com", "password": "p@ss"},
            }
        )
        self.assertEqual(creds["email"], "nested@example.com")
        self.assertEqual(creds["password"], "p@ss")
        self.assertTrue(creds["auto_capable"])

    def test_extract_login_credentials_from_sso_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sso_dir = Path(temp_dir)
            sso_path = sso_dir / "sso-user@example.com.json"
            sso_path.write_text(
                json.dumps(
                    {
                        "type": "sso",
                        "email": "user@example.com",
                        "password": "from-sso-archive",
                        "sso": "sso-token-value",
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(app, "SSO_AUTH_DIR", sso_dir):
                creds = app._extract_login_credentials(
                    {"email": "user@example.com", "access_token": "x", "refresh_token": "y"}
                )
            self.assertEqual(creds["password"], "from-sso-archive")
            self.assertEqual(creds["sso"], "sso-token-value")
            self.assertEqual(creds["source"], "sso_sidecar")
            self.assertTrue(creds["auto_capable"])
            self.assertTrue(creds["cookies"])

    def test_exact_sso_sidecar_does_not_scan_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sso_dir = Path(temp_dir)
            (sso_dir / "sso-user@example.com.json").write_text(
                json.dumps({"email": "user@example.com", "password": "pw"}),
                encoding="utf-8",
            )
            with (
                mock.patch.object(app, "SSO_AUTH_DIR", sso_dir),
                mock.patch.object(Path, "iterdir", side_effect=AssertionError("full scan")),
            ):
                sidecar = app._load_sso_sidecar("user@example.com")
            self.assertEqual(sidecar["password"], "pw")

    def test_reauth_persists_atomically_and_keeps_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "xai-user@example.com.json"
            original = {
                "type": "xai",
                "email": "user@example.com",
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "oauth_access_token": "old-access",
                "oauth_refresh_token": "old-refresh",
                "oauth_record": {"access_token": "old-access", "refresh_token": "old-refresh"},
                "disabled": False,
                "base_url": "https://cli-chat-proxy.grok.com/v1",
            }
            path.write_text(json.dumps(original), encoding="utf-8")

            backup_name = app._persist_xai_reauth(
                path,
                {
                    "access_token": "new-access",
                    "refresh_token": "new-refresh",
                    "id_token": "new-id",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

            updated = json.loads(path.read_text(encoding="utf-8"))
            backup = json.loads((path.parent / backup_name).read_text(encoding="utf-8"))
            self.assertEqual(updated["access_token"], "new-access")
            self.assertEqual(updated["refresh_token"], "new-refresh")
            self.assertEqual(updated["oauth_access_token"], "new-access")
            self.assertEqual(updated["oauth_record"]["access_token"], "new-access")
            self.assertEqual(updated["base_url"], original["base_url"])
            self.assertEqual(updated["auth_kind"], "oauth")
            self.assertEqual(backup, original)
            self.assertTrue(backup_name.endswith(".bak"))

    def test_safe_auth_path_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(app, "AUTH_DIR", Path(temp_dir)):
                with self.assertRaises(ValueError):
                    app._safe_auth_path("../xai-user.json")

    def test_public_batch_job_hides_task_handle(self) -> None:
        public = app._public_batch_job(
            {
                "id": "job1",
                "status": "running",
                "total": 2,
                "done": 1,
                "_task": object(),
            }
        )
        self.assertEqual(public["id"], "job1")
        self.assertNotIn("_task", public)

    def test_codex_reauth_persists_tokens_and_preserves_login_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "codex-user@example.com.json"
            original = {
                "type": "codex",
                "email": "user@example.com",
                "password": "reusable-login",
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "tokens": {
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                },
            }
            path.write_text(json.dumps(original), encoding="utf-8")
            backup_name = app._persist_codex_reauth(
                path,
                {
                    "access_token": "new-access",
                    "refresh_token": "new-refresh",
                    "id_token": "new-id",
                    "account_id": "acct-1",
                },
            )
            updated = json.loads(path.read_text(encoding="utf-8"))
            backup = json.loads((path.parent / backup_name).read_text(encoding="utf-8"))
            self.assertEqual(updated["access_token"], "new-access")
            self.assertEqual(updated["tokens"]["refresh_token"], "new-refresh")
            self.assertEqual(updated["password"], "reusable-login")
            self.assertEqual(updated["account_id"], "acct-1")
            self.assertEqual(backup, original)

    def test_codex_candidates_require_refresh_or_password(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            auth_dir = Path(temp_dir)
            (auth_dir / "refresh.json").write_text(
                json.dumps({"type": "codex", "refresh_token": "refresh"}),
                encoding="utf-8",
            )
            (auth_dir / "password.json").write_text(
                json.dumps({"type": "codex", "password": "password"}),
                encoding="utf-8",
            )
            (auth_dir / "missing.json").write_text(
                json.dumps({"type": "codex"}), encoding="utf-8"
            )
            (auth_dir / "session.json").write_text(
                json.dumps({"type": "codex", "session_token": "session"}), encoding="utf-8"
            )
            with mock.patch.object(app, "AUTH_DIR", auth_dir):
                rows = app._enrich_codex_reauth_candidates(
                    [{"file": name} for name in ("refresh.json", "password.json", "session.json", "missing.json")]
                )
            self.assertEqual([row["auto_capable"] for row in rows], [True, True, False, False])
            self.assertEqual(
                [row["cred_source"] for row in rows],
                ["refresh_token", "password", "missing", "missing"],
            )


class XaiReauthAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_candidate_disk_work_does_not_block_event_loop(self) -> None:
        events: list[str] = []

        async def tick() -> None:
            await asyncio.sleep(0.01)
            events.append("tick")

        def slow_enrich(items):
            import time

            time.sleep(0.05)
            events.append("enrich_done")
            return []

        with mock.patch.object(app, "_enrich_xai_reauth_candidates", slow_enrich):
            response, _ = await asyncio.gather(app.api_xai_reauth_candidates(), tick())
        self.assertEqual(events, ["tick", "enrich_done"])
        self.assertEqual(response["total"], 0)

    async def test_auto_mint_runs_in_subprocess_without_credentials_in_argv(self) -> None:
        class FakeProcess:
            pid = 1234
            returncode = 0

            async def communicate(self, data: bytes) -> tuple[bytes, bytes]:
                request = json.loads(data)
                self.request = request
                await asyncio.sleep(0.05)
                return (
                    json.dumps(
                        {"access_token": "access", "refresh_token": "refresh"}
                    ).encode(),
                    b"worker progress\n",
                )

        process = FakeProcess()
        app._reauth_sessions["flow"] = {"id": "flow", "status": "browser_login"}
        logs: list[str] = []
        ticked = False

        async def tick() -> None:
            nonlocal ticked
            await asyncio.sleep(0.01)
            ticked = True

        try:
            with mock.patch(
                "asyncio.create_subprocess_exec",
                new=mock.AsyncMock(return_value=process),
            ) as create:
                result, _ = await asyncio.gather(
                    app._auto_mint_tokens(
                        email="user@example.com",
                        password="secret-password",
                        flow_id="flow",
                        log_lines=logs,
                    ),
                    tick(),
                )
            argv = create.await_args.args
            self.assertTrue(
                any(
                    argv[index : index + 2] == ("-m", "xai_auto.mint_worker")
                    for index in range(len(argv) - 1)
                ),
                argv,
            )
            self.assertNotIn("secret-password", argv)
            self.assertTrue(ticked)
            self.assertEqual(result["access_token"], "access")
            self.assertEqual(process.request["password"], "secret-password")
            self.assertIn("worker progress", logs)
            self.assertNotIn("_worker_process", app._reauth_sessions["flow"])
        finally:
            app._reauth_sessions.pop("flow", None)

    async def test_codex_mint_keeps_credentials_off_argv(self) -> None:
        class FakeProcess:
            pid = 5678
            returncode = 0

            async def communicate(self, data: bytes) -> tuple[bytes, bytes]:
                self.request = json.loads(data)
                return (
                    json.dumps({"access_token": "access", "refresh_token": "refresh"}).encode(),
                    b"Codex refresh succeeded\n",
                )

        process = FakeProcess()
        app._reauth_sessions["codex-flow"] = {"id": "codex-flow", "status": "refreshing"}
        try:
            with mock.patch(
                "asyncio.create_subprocess_exec",
                new=mock.AsyncMock(return_value=process),
            ) as create:
                result = await app._codex_mint_tokens(
                    raw={"refresh_token": "secret-refresh"},
                    email="user@example.com",
                    password="secret-password",
                    flow_id="codex-flow",
                    log_lines=[],
                )
            argv = create.await_args.args
            self.assertIn("codex_auto.codex_worker", argv)
            self.assertNotIn("secret-password", argv)
            self.assertNotIn("secret-refresh", argv)
            self.assertEqual(process.request["password"], "secret-password")
            self.assertEqual(result["access_token"], "access")
        finally:
            app._reauth_sessions.pop("codex-flow", None)


if __name__ == "__main__":
    unittest.main()
