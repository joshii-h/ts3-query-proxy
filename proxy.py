import asyncio
import os
import logging
import sys

import asyncssh

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ts3query-proxy")

TS6_HOST = os.environ.get("TS6_HOST", "teamspeak6")
TS6_SSH_PORT = int(os.environ.get("TS6_SSH_PORT", "10022"))
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "10011"))

TS3_BANNER = (
    b"TS3\n\r"
    b"Welcome to the TeamSpeak 3 ServerQuery interface, "
    b'type "help" for a list of commands and "help <command>" '
    b"for information on a specific command.\n\r"
)


class ClientHandler:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.ssh_conn: asyncssh.SSHClientConnection | None = None
        self.ssh_process: asyncssh.SSHClientProcess | None = None
        self.addr = writer.get_extra_info("peername")

    async def handle(self) -> None:
        log.info("Client connected from %s", self.addr)
        try:
            self.writer.write(TS3_BANNER)
            await self.writer.drain()
            await self._auth_loop()
        except asyncio.TimeoutError:
            log.warning("Client %s timed out", self.addr)
        except (ConnectionResetError, BrokenPipeError):
            log.info("Client %s disconnected abruptly", self.addr)
        except Exception as e:
            log.error("Error handling %s: %s", self.addr, e)
        finally:
            await self._cleanup()

    async def _auth_loop(self) -> None:
        while True:
            line = await asyncio.wait_for(self.reader.readline(), timeout=30)
            if not line:
                return
            cmd = line.decode("utf-8", errors="replace").strip()
            if not cmd:
                continue

            log.info("Pre-auth from %s: %s", self.addr, _sanitize(cmd))

            if cmd.lower().startswith("login "):
                await self._handle_login(cmd)
                return
            elif cmd.lower() == "quit":
                self.writer.write(b"error id=0 msg=ok\n\r")
                await self.writer.drain()
                return
            else:
                self.writer.write(b"error id=1794 msg=not\\slogged\\sin\n\r")
                await self.writer.drain()

    async def _handle_login(self, cmd: str) -> None:
        parts = cmd.split(maxsplit=2)
        if len(parts) < 3:
            self.writer.write(b"error id=256 msg=command\\snot\\sfound\n\r")
            await self.writer.drain()
            return

        username, password = parts[1], parts[2]
        if await self._connect_ssh(username, password):
            self.writer.write(b"error id=0 msg=ok\n\r")
            await self.writer.drain()
            await self._proxy()
        else:
            self.writer.write(
                b"error id=520 msg=invalid\\sloginname\\sor\\spassword\n\r"
            )
            await self.writer.drain()

    async def _connect_ssh(self, username: str, password: str) -> bool:
        try:
            log.info("SSH connecting to %s:%d as %s", TS6_HOST, TS6_SSH_PORT, username)
            self.ssh_conn = await asyncio.wait_for(
                asyncssh.connect(
                    TS6_HOST,
                    TS6_SSH_PORT,
                    username=username,
                    password=password,
                    known_hosts=None,
                ),
                timeout=10,
            )
            self.ssh_process = await self.ssh_conn.create_process(term_type=None)

            # Read and discard the TS6 SSH banner
            banner = ""
            while True:
                try:
                    chunk = await asyncio.wait_for(
                        self.ssh_process.stdout.read(4096), timeout=3
                    )
                    if not chunk:
                        break
                    banner += chunk
                    if "help" in banner.lower():
                        break
                except asyncio.TimeoutError:
                    break

            log.info("SSH session established for %s", self.addr)
            return True
        except asyncssh.PermissionDenied:
            log.warning("SSH auth failed for %s (bad credentials)", self.addr)
            return False
        except Exception as e:
            log.error("SSH connection to %s:%d failed: %s", TS6_HOST, TS6_SSH_PORT, e)
            return False

    async def _proxy(self) -> None:
        log.info("Proxying traffic for %s", self.addr)

        async def client_to_ssh() -> None:
            try:
                while True:
                    line = await self.reader.readline()
                    if not line:
                        break
                    self.ssh_process.stdin.write(
                        line.decode("utf-8", errors="replace")
                    )
            except (ConnectionResetError, BrokenPipeError):
                pass

        async def ssh_to_client() -> None:
            try:
                while True:
                    data = await self.ssh_process.stdout.read(4096)
                    if not data:
                        break
                    raw = data.encode() if isinstance(data, str) else data
                    self.writer.write(raw)
                    await self.writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass

        tasks = [
            asyncio.create_task(client_to_ssh()),
            asyncio.create_task(ssh_to_client()),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        # Await cancelled tasks to suppress warnings
        for t in pending:
            try:
                await t
            except asyncio.CancelledError:
                pass

    async def _cleanup(self) -> None:
        try:
            if self.ssh_process:
                self.ssh_process.close()
            if self.ssh_conn:
                self.ssh_conn.close()
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        log.info("Client %s disconnected", self.addr)


def _sanitize(cmd: str) -> str:
    """Hide password in login commands for logging."""
    if cmd.lower().startswith("login "):
        parts = cmd.split(maxsplit=2)
        if len(parts) >= 3:
            return f"login {parts[1]} ***"
    return cmd


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    handler = ClientHandler(reader, writer)
    await handler.handle()


async def main() -> None:
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    log.info("TS3 Query Proxy listening on %s:%d", LISTEN_HOST, LISTEN_PORT)
    log.info("Forwarding to %s:%d (SSH Query)", TS6_HOST, TS6_SSH_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
