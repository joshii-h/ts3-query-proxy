"""Tests for ts3-query-proxy.

Unit tests mock the SSH layer; integration tests require a real TS6 instance.
Set TS6_TEST_HOST, TS6_TEST_SSH_PORT, TS6_TEST_USER, TS6_TEST_PASS env vars
to enable integration tests.
"""

import asyncio
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from proxy import ClientHandler, TS3_BANNER, _sanitize


class TestSanitize(unittest.TestCase):
    def test_hides_password(self):
        self.assertEqual(_sanitize("login serveradmin secret123"), "login serveradmin ***")

    def test_ignores_non_login(self):
        self.assertEqual(_sanitize("serverinfo"), "serverinfo")

    def test_short_login(self):
        self.assertEqual(_sanitize("login serveradmin"), "login serveradmin")


class TestBanner(unittest.TestCase):
    def test_banner_starts_with_ts3(self):
        self.assertTrue(TS3_BANNER.startswith(b"TS3"))

    def test_banner_contains_help(self):
        self.assertIn(b"help", TS3_BANNER)


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

    async def test_sends_banner_on_connect(self):
        handler, writer = self._make_handler([b"quit\n"])
        await handler.handle()
        first_write = writer.write.call_args_list[0][0][0]
        self.assertEqual(first_write, TS3_BANNER)

    async def test_quit_before_login(self):
        handler, writer = self._make_handler([b"quit\n"])
        await handler.handle()
        writes = [call[0][0] for call in writer.write.call_args_list]
        self.assertIn(b"error id=0 msg=ok\n\r", writes)

    async def test_command_before_login_returns_not_logged_in(self):
        handler, writer = self._make_handler([b"serverinfo\n", b"quit\n"])
        await handler.handle()
        writes = [call[0][0] for call in writer.write.call_args_list]
        self.assertIn(b"error id=1794 msg=not\\slogged\\sin\n\r", writes)

    async def test_empty_disconnect(self):
        handler, writer = self._make_handler([b""])
        await handler.handle()
        # Should not raise, just disconnect

    @patch("proxy.asyncssh")
    async def test_login_bad_credentials(self, mock_asyncssh):
        import asyncssh as real_asyncssh

        mock_asyncssh.PermissionDenied = real_asyncssh.PermissionDenied
        mock_asyncssh.connect = AsyncMock(
            side_effect=real_asyncssh.PermissionDenied("bad password")
        )
        handler, writer = self._make_handler([b"login serveradmin wrongpw\n"])
        await handler.handle()
        writes = [call[0][0] for call in writer.write.call_args_list]
        self.assertIn(
            b"error id=520 msg=invalid\\sloginname\\sor\\spassword\n\r", writes
        )

    async def test_login_incomplete_command(self):
        handler, writer = self._make_handler([b"login serveradmin\n", b"quit\n"])
        await handler.handle()
        writes = [call[0][0] for call in writer.write.call_args_list]
        self.assertIn(b"error id=256 msg=command\\snot\\sfound\n\r", writes)


# --- Integration tests (only run when env vars are set) ---

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
        os.environ["TS6_HOST"] = TS6_TEST_HOST
        os.environ["TS6_SSH_PORT"] = str(TS6_TEST_SSH_PORT)

        # Re-import to pick up env vars
        import importlib
        import proxy as proxy_mod

        importlib.reload(proxy_mod)

        self.server = await asyncio.start_server(
            proxy_mod.handle_client, "127.0.0.1", PROXY_TEST_PORT
        )

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def _connect(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", PROXY_TEST_PORT)
        # Read banner
        banner = await asyncio.wait_for(reader.read(4096), timeout=5)
        self.assertIn(b"TS3", banner)
        return reader, writer

    async def test_login_and_version(self):
        reader, writer = await self._connect()
        writer.write(f"login {TS6_TEST_USER} {TS6_TEST_PASS}\n".encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout=10)
        self.assertIn(b"id=0", resp)

        writer.write(b"version\n")
        await writer.drain()
        # version response + error line
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


if __name__ == "__main__":
    unittest.main()
