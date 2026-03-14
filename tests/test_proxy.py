"""Tests for ts3-query-proxy.

Unit tests mock the SSH layer; integration tests require a real TS6 instance.
Set TS6_TEST_HOST, TS6_TEST_SSH_PORT, TS6_TEST_USER, TS6_TEST_PASS env vars
to enable integration tests.
"""

import asyncio
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from proxy import TS3_BANNER, ClientHandler, Config, _sanitize

# ---------------------------------------------------------------------------
# Unit tests — _sanitize
# ---------------------------------------------------------------------------


class TestSanitize(unittest.TestCase):
    def test_hides_password(self):
        self.assertEqual(_sanitize("login serveradmin secret123"), "login serveradmin ***")

    def test_ignores_non_login(self):
        self.assertEqual(_sanitize("serverinfo"), "serverinfo")

    def test_short_login(self):
        self.assertEqual(_sanitize("login serveradmin"), "login serveradmin")

    def test_empty_string(self):
        self.assertEqual(_sanitize(""), "")

    def test_login_keyword_only(self):
        self.assertEqual(_sanitize("login"), "login")

    def test_case_insensitive(self):
        self.assertEqual(_sanitize("LOGIN serveradmin secret"), "login serveradmin ***")

    def test_password_with_spaces(self):
        self.assertEqual(
            _sanitize("login serveradmin pass word with spaces"),
            "login serveradmin ***",
        )


# ---------------------------------------------------------------------------
# Unit tests — Config
# ---------------------------------------------------------------------------


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = Config()
        self.assertEqual(cfg.ts6_host, "teamspeak6")
        self.assertEqual(cfg.ts6_ssh_port, 10022)
        self.assertEqual(cfg.listen_host, "0.0.0.0")
        self.assertEqual(cfg.listen_port, 10011)

    def test_from_env(self):
        env = {"TS6_HOST": "myhost", "TS6_SSH_PORT": "9999", "LISTEN_PORT": "5555"}
        with patch.dict(os.environ, env, clear=False):
            cfg = Config.from_env()
        self.assertEqual(cfg.ts6_host, "myhost")
        self.assertEqual(cfg.ts6_ssh_port, 9999)
        self.assertEqual(cfg.listen_port, 5555)

    def test_from_env_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            cfg = Config.from_env()
        self.assertEqual(cfg.ts6_host, "teamspeak6")
        self.assertEqual(cfg.ts6_ssh_port, 10022)

    def test_frozen(self):
        cfg = Config()
        with self.assertRaises(AttributeError):
            cfg.ts6_host = "other"


# ---------------------------------------------------------------------------
# Unit tests — Banner
# ---------------------------------------------------------------------------


class TestBanner(unittest.TestCase):
    def test_banner_starts_with_ts3(self):
        self.assertTrue(TS3_BANNER.startswith(b"TS3"))

    def test_banner_contains_help(self):
        self.assertIn(b"help", TS3_BANNER)

    def test_banner_ends_with_crlf(self):
        self.assertTrue(TS3_BANNER.endswith(b"\n\r"))


# ---------------------------------------------------------------------------
# Unit tests — ClientHandler
# ---------------------------------------------------------------------------


class TestClientHandlerUnit(unittest.IsolatedAsyncioTestCase):
    def _make_handler(self, input_lines: list[bytes]):
        reader = AsyncMock(spec=asyncio.StreamReader)
        reader.readline = AsyncMock(side_effect=input_lines)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 12345))
        handler = ClientHandler(reader, writer)
        return handler, writer

    def _get_writes(self, writer):
        return [call[0][0] for call in writer.write.call_args_list]

    # --- Banner ---

    async def test_sends_banner_on_connect(self):
        handler, writer = self._make_handler([b"quit\n"])
        await handler.handle()
        first_write = writer.write.call_args_list[0][0][0]
        self.assertEqual(first_write, TS3_BANNER)

    # --- Pre-auth commands ---

    async def test_quit_before_login(self):
        handler, writer = self._make_handler([b"quit\n"])
        await handler.handle()
        self.assertIn(b"error id=0 msg=ok\n\r", self._get_writes(writer))

    async def test_command_before_login_returns_not_logged_in(self):
        handler, writer = self._make_handler([b"serverinfo\n", b"quit\n"])
        await handler.handle()
        self.assertIn(b"error id=1794 msg=not\\slogged\\sin\n\r", self._get_writes(writer))

    async def test_multiple_commands_before_login(self):
        handler, writer = self._make_handler(
            [b"serverinfo\n", b"clientlist\n", b"quit\n"]
        )
        await handler.handle()
        writes = self._get_writes(writer)
        not_logged_in = b"error id=1794 msg=not\\slogged\\sin\n\r"
        count = writes.count(not_logged_in)
        self.assertEqual(count, 2, f"Expected 2 not-logged-in errors, got {count}")

    async def test_empty_line_ignored(self):
        handler, writer = self._make_handler([b"\n", b"quit\n"])
        await handler.handle()
        writes = self._get_writes(writer)
        self.assertIn(b"error id=0 msg=ok\n\r", writes)
        self.assertNotIn(b"error id=1794", b"".join(writes))

    # --- Disconnect ---

    async def test_empty_disconnect(self):
        handler, writer = self._make_handler([b""])
        await handler.handle()

    async def test_timeout_in_auth_loop(self):
        reader = AsyncMock(spec=asyncio.StreamReader)
        reader.readline = AsyncMock(side_effect=asyncio.TimeoutError)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 12345))
        handler = ClientHandler(reader, writer)
        await handler.handle()  # should not raise

    # --- Login ---

    async def test_login_incomplete_command(self):
        handler, writer = self._make_handler([b"login serveradmin\n", b"quit\n"])
        await handler.handle()
        self.assertIn(b"error id=256 msg=command\\snot\\sfound\n\r", self._get_writes(writer))

    @patch("proxy.asyncssh")
    async def test_login_bad_credentials(self, mock_asyncssh):
        import asyncssh as real_asyncssh

        mock_asyncssh.PermissionDenied = real_asyncssh.PermissionDenied
        mock_asyncssh.connect = AsyncMock(
            side_effect=real_asyncssh.PermissionDenied("bad password")
        )
        handler, writer = self._make_handler([b"login serveradmin wrongpw\n"])
        await handler.handle()
        self.assertIn(
            b"error id=520 msg=invalid\\sloginname\\sor\\spassword\n\r",
            self._get_writes(writer),
        )

    @patch("proxy.asyncssh")
    async def test_login_ssh_timeout(self, mock_asyncssh):
        import asyncssh as real_asyncssh

        mock_asyncssh.PermissionDenied = real_asyncssh.PermissionDenied
        mock_asyncssh.connect = AsyncMock(side_effect=asyncio.TimeoutError)
        handler, writer = self._make_handler([b"login serveradmin pass\n"])
        await handler.handle()
        self.assertIn(
            b"error id=520 msg=invalid\\sloginname\\sor\\spassword\n\r",
            self._get_writes(writer),
        )

    @patch("proxy.asyncssh")
    async def test_login_ssh_connection_refused(self, mock_asyncssh):
        import asyncssh as real_asyncssh

        mock_asyncssh.PermissionDenied = real_asyncssh.PermissionDenied
        mock_asyncssh.connect = AsyncMock(side_effect=OSError("Connection refused"))
        handler, writer = self._make_handler([b"login serveradmin pass\n"])
        await handler.handle()
        self.assertIn(
            b"error id=520 msg=invalid\\sloginname\\sor\\spassword\n\r",
            self._get_writes(writer),
        )

    @patch("proxy.asyncssh")
    async def test_login_case_insensitive(self, mock_asyncssh):
        """LOGIN (uppercase) should be handled the same as login."""
        import asyncssh as real_asyncssh

        mock_asyncssh.PermissionDenied = real_asyncssh.PermissionDenied
        mock_asyncssh.connect = AsyncMock(
            side_effect=real_asyncssh.PermissionDenied("bad")
        )
        handler, writer = self._make_handler([b"LOGIN serveradmin wrongpw\n"])
        await handler.handle()
        self.assertIn(
            b"error id=520 msg=invalid\\sloginname\\sor\\spassword\n\r",
            self._get_writes(writer),
        )

    # --- Proxy (bidirectional forwarding) ---

    @patch("proxy.asyncssh")
    async def test_proxy_forwards_command_to_ssh(self, mock_asyncssh):
        """After login, client commands should be forwarded to SSH stdin."""
        import asyncssh as real_asyncssh

        mock_asyncssh.PermissionDenied = real_asyncssh.PermissionDenied

        # Mock SSH process
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdin.write = MagicMock()
        mock_process.stdout = AsyncMock()
        mock_process.stdout.read = AsyncMock(
            side_effect=["TS3 banner help\n\r", ""]
        )
        mock_process.close = MagicMock()

        mock_conn = AsyncMock()
        mock_conn.create_process = AsyncMock(return_value=mock_process)
        mock_conn.close = MagicMock()

        mock_asyncssh.connect = AsyncMock(return_value=mock_conn)

        handler, writer = self._make_handler(
            [b"login serveradmin pass\n", b"serverinfo\n", b""]
        )
        await handler.handle()

        # Verify login success response
        self.assertIn(b"error id=0 msg=ok\n\r", self._get_writes(writer))

        # Verify command was forwarded to SSH stdin
        stdin_writes = [call[0][0] for call in mock_process.stdin.write.call_args_list]
        self.assertIn("serverinfo\n", stdin_writes)

    @patch("proxy.asyncssh")
    async def test_proxy_forwards_ssh_response_to_client(self, mock_asyncssh):
        """SSH stdout data should be forwarded to the TCP client."""
        import asyncssh as real_asyncssh

        mock_asyncssh.PermissionDenied = real_asyncssh.PermissionDenied

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdin.write = MagicMock()
        mock_process.stdout = AsyncMock()
        mock_process.stdout.read = AsyncMock(
            side_effect=[
                "TS3 banner help\n\r",
                "virtualserver_name=Test error id=0 msg=ok\n\r",
                "",
            ]
        )
        mock_process.close = MagicMock()

        mock_conn = AsyncMock()
        mock_conn.create_process = AsyncMock(return_value=mock_process)
        mock_conn.close = MagicMock()

        mock_asyncssh.connect = AsyncMock(return_value=mock_conn)

        handler, writer = self._make_handler(
            [b"login serveradmin pass\n", b""]
        )
        await handler.handle()

        writes = self._get_writes(writer)
        joined = b"".join(writes)
        self.assertIn(b"virtualserver_name=Test", joined)

    # --- Cleanup ---

    async def test_cleanup_with_no_ssh(self):
        """Cleanup should not raise when SSH was never established."""
        handler, writer = self._make_handler([b""])
        self.assertIsNone(handler.ssh_conn)
        self.assertIsNone(handler.ssh_process)
        await handler._cleanup()

    async def test_cleanup_when_writer_close_raises(self):
        """Cleanup should swallow exceptions from writer.close."""
        handler, writer = self._make_handler([b""])
        writer.wait_closed = AsyncMock(side_effect=OSError("already closed"))
        await handler._cleanup()  # should not raise


# ---------------------------------------------------------------------------
# Integration tests (only run when env vars are set)
# ---------------------------------------------------------------------------

TS6_TEST_HOST = os.environ.get("TS6_TEST_HOST")
TS6_TEST_SSH_PORT = int(os.environ.get("TS6_TEST_SSH_PORT", "10022"))
TS6_TEST_USER = os.environ.get("TS6_TEST_USER", "serveradmin")
TS6_TEST_PASS = os.environ.get("TS6_TEST_PASS")
PROXY_TEST_PORT = int(os.environ.get("PROXY_TEST_PORT", "19011"))


@unittest.skipUnless(
    TS6_TEST_HOST and TS6_TEST_PASS,
    "Set TS6_TEST_HOST and TS6_TEST_PASS to run integration tests",
)
class TestIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests that start a real proxy and connect through it."""

    async def asyncSetUp(self):
        config = Config(ts6_host=TS6_TEST_HOST, ts6_ssh_port=TS6_TEST_SSH_PORT)

        async def on_connect(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            handler = ClientHandler(reader, writer, config)
            await handler.handle()

        self.server = await asyncio.start_server(on_connect, "127.0.0.1", PROXY_TEST_PORT)

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def _connect(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", PROXY_TEST_PORT)
        banner = await asyncio.wait_for(reader.read(4096), timeout=5)
        self.assertIn(b"TS3", banner)
        return reader, writer

    async def _login_and_use(self):
        """Helper: connect, login, select virtual server."""
        reader, writer = await self._connect()
        writer.write(f"login {TS6_TEST_USER} {TS6_TEST_PASS}\n".encode())
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=10)
        writer.write(b"use sid=1\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=5)
        return reader, writer

    async def _send_cmd(self, reader, writer, cmd):
        """Send a command and return the full response including error line."""
        writer.write(f"{cmd}\n".encode())
        await writer.drain()
        data = b""
        for _ in range(20):
            chunk = await asyncio.wait_for(reader.readline(), timeout=5)
            data += chunk
            if b"error id=" in chunk:
                break
        return data

    async def test_login_and_version(self):
        reader, writer = await self._connect()
        writer.write(f"login {TS6_TEST_USER} {TS6_TEST_PASS}\n".encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout=10)
        self.assertIn(b"id=0", resp)

        writer.write(b"version\n")
        await writer.drain()
        data = b""
        for _ in range(10):
            chunk = await asyncio.wait_for(reader.readline(), timeout=5)
            data += chunk
            if b"error id=" in chunk:
                break
        self.assertIn(b"error id=0", data)

        writer.write(b"quit\n")
        await writer.drain()
        writer.close()

    async def test_login_wrong_password(self):
        reader, writer = await self._connect()
        writer.write(b"login serveradmin definitelywrong\n")
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout=10)
        self.assertIn(b"id=520", resp)
        writer.close()

    async def test_serverinfo(self):
        reader, writer = await self._connect()
        writer.write(f"login {TS6_TEST_USER} {TS6_TEST_PASS}\n".encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout=10)
        self.assertIn(b"id=0", resp)

        writer.write(b"serverinfo\n")
        await writer.drain()
        data = b""
        for _ in range(10):
            chunk = await asyncio.wait_for(reader.readline(), timeout=5)
            data += chunk
            if b"error id=" in chunk:
                break
        self.assertIn(b"virtualserver_name=", data)

        writer.write(b"quit\n")
        await writer.drain()
        writer.close()

    async def test_channellist_and_channelinfo(self):
        reader, writer = await self._login_and_use()

        data = await self._send_cmd(reader, writer, "channellist")
        self.assertIn(b"error id=0", data)
        self.assertIn(b"cid=", data)

        for part in data.decode(errors="replace").split("|")[0].split():
            if part.startswith("cid="):
                cid = part.split("=")[1]
                break

        data = await self._send_cmd(reader, writer, f"channelinfo cid={cid}")
        self.assertIn(b"error id=0", data)
        self.assertIn(b"channel_name=", data)

        writer.write(b"quit\n")
        await writer.drain()
        writer.close()

    async def test_ban_add_list_delete(self):
        reader, writer = await self._login_and_use()

        data = await self._send_cmd(
            reader, writer, "banadd ip=254.253.252.251 banreason=proxytest time=10"
        )
        self.assertIn(b"error id=0", data)
        self.assertIn(b"banid=", data)

        banid = None
        for part in data.decode(errors="replace").split():
            if part.startswith("banid="):
                banid = part.split("=")[1].strip()
                break

        data = await self._send_cmd(reader, writer, "banlist")
        self.assertIn(b"error id=0", data)
        self.assertIn(b"ip=254.253.252.251", data)

        data = await self._send_cmd(reader, writer, f"bandel banid={banid}")
        self.assertIn(b"error id=0", data)

        writer.write(b"quit\n")
        await writer.drain()
        writer.close()

    async def test_servergrouplist(self):
        reader, writer = await self._login_and_use()
        data = await self._send_cmd(reader, writer, "servergrouplist")
        self.assertIn(b"error id=0", data)
        self.assertIn(b"name=", data)
        writer.write(b"quit\n")
        await writer.drain()
        writer.close()

    async def test_whoami(self):
        reader, writer = await self._login_and_use()
        data = await self._send_cmd(reader, writer, "whoami")
        self.assertIn(b"error id=0", data)
        self.assertIn(b"virtualserver_id=1", data)
        writer.write(b"quit\n")
        await writer.drain()
        writer.close()

    async def test_clientlist(self):
        reader, writer = await self._login_and_use()
        data = await self._send_cmd(reader, writer, "clientlist")
        self.assertIn(b"error id=0", data)
        self.assertIn(b"client_nickname=", data)
        writer.write(b"quit\n")
        await writer.drain()
        writer.close()

    async def test_hostinfo(self):
        reader, writer = await self._login_and_use()
        data = await self._send_cmd(reader, writer, "hostinfo")
        self.assertIn(b"error id=0", data)
        self.assertIn(b"instance_uptime=", data)
        writer.write(b"quit\n")
        await writer.drain()
        writer.close()

    async def test_permissionlist(self):
        reader, writer = await self._login_and_use()
        data = await self._send_cmd(reader, writer, "permissionlist")
        self.assertIn(b"error id=0", data)
        self.assertIn(b"permname=", data)
        writer.write(b"quit\n")
        await writer.drain()
        writer.close()

    async def test_logview(self):
        reader, writer = await self._login_and_use()
        data = await self._send_cmd(reader, writer, "logview lines=3")
        self.assertIn(b"error id=0", data)
        self.assertIn(b"last_pos=", data)
        writer.write(b"quit\n")
        await writer.drain()
        writer.close()


if __name__ == "__main__":
    unittest.main()
