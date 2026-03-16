from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import sys
from dataclasses import dataclass

import asyncssh

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ts3query-proxy")


@dataclass(frozen=True)
class Config:
    ts6_host: str = "teamspeak6"
    ts6_ssh_port: int = 10022
    listen_host: str = "0.0.0.0"
    listen_port: int = 10011
    ssh_keepalive_interval: int = 30
    ssh_keepalive_count_max: int = 3

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            ts6_host=os.environ.get("TS6_HOST", "teamspeak6"),
            ts6_ssh_port=int(os.environ.get("TS6_SSH_PORT", "10022")),
            listen_port=int(os.environ.get("LISTEN_PORT", "10011")),
            ssh_keepalive_interval=int(os.environ.get("SSH_KEEPALIVE_INTERVAL", "30")),
            ssh_keepalive_count_max=int(os.environ.get("SSH_KEEPALIVE_COUNT_MAX", "3")),
        )

TS3_BANNER = (
    b"TS3\n\r"
    b"Welcome to the TeamSpeak 3 ServerQuery interface, "
    b'type "help" for a list of commands and "help <command>" '
    b"for information on a specific command.\n\r"
)


class ClientHandler:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        config: Config | None = None,
    ):
        self.reader = reader
        self.writer = writer
        self.config = config or Config()
        self.ssh_conn: asyncssh.SSHClientConnection | None = None
        self.ssh_process: asyncssh.SSHClientProcess | None = None
        self.addr: tuple[str, int] | None = writer.get_extra_info("peername")

    async def handle(self) -> None:
        log.info("Client connected from %s", self.addr)
        try:
            # Enable TCP keepalive on the client socket
            sock = self.writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            self.writer.write(TS3_BANNER)
            await self.writer.drain()
            await self._auth_loop()
        except TimeoutError:
            log.warning("Client %s timed out", self.addr)
        except (ConnectionResetError, BrokenPipeError):
            log.info("Client %s disconnected abruptly", self.addr)
        except Exception as e:
            log.error("Error handling %s: %s", self.addr, e)
        finally:
            await self._cleanup()

    async def _auth_loop(self) -> None:
        while True:
            line = await asyncio.wait_for(self.reader.readline(), timeout=300)
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
            log.info(
                "SSH connecting to %s:%d as %s",
                self.config.ts6_host,
                self.config.ts6_ssh_port,
                username,
            )
            self.ssh_conn = await asyncio.wait_for(
                asyncssh.connect(
                    self.config.ts6_host,
                    self.config.ts6_ssh_port,
                    username=username,
                    password=password,
                    known_hosts=None,
                    keepalive_interval=self.config.ssh_keepalive_interval,
                    keepalive_count_max=self.config.ssh_keepalive_count_max,
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
                except TimeoutError:
                    break

            log.info(
                "SSH session established for %s (keepalive=%ds)",
                self.addr,
                self.config.ssh_keepalive_interval,
            )
            return True
        except asyncssh.PermissionDenied:
            log.warning("SSH auth failed for %s (bad credentials)", self.addr)
            return False
        except Exception as e:
            log.error(
                "SSH connection to %s:%d failed: %s",
                self.config.ts6_host,
                self.config.ts6_ssh_port,
                e,
            )
            return False

    async def _proxy(self) -> None:
        assert self.ssh_process is not None
        log.info("Proxying traffic for %s", self.addr)
        ssh_process = self.ssh_process

        async def client_to_ssh() -> None:
            try:
                while True:
                    line = await self.reader.readline()
                    if not line:
                        break
                    ssh_process.stdin.write(
                        line.decode("utf-8", errors="replace")
                    )
            except (ConnectionResetError, BrokenPipeError):
                pass

        async def ssh_to_client() -> None:
            try:
                while True:
                    data = await ssh_process.stdout.read(4096)
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
        for t in pending:
            with contextlib.suppress(asyncio.CancelledError):
                await t

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
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: Config | None = None,
) -> None:
    handler = ClientHandler(reader, writer, config)
    await handler.handle()


async def main() -> None:
    config = Config.from_env()

    async def _on_connect(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await handle_client(reader, writer, config)

    server = await asyncio.start_server(
        _on_connect, config.listen_host, config.listen_port
    )
    log.info("TS3 Query Proxy listening on %s:%d", config.listen_host, config.listen_port)
    log.info("Forwarding to %s:%d (SSH Query)", config.ts6_host, config.ts6_ssh_port)
    log.info(
        "SSH keepalive: interval=%ds, max_count=%d",
        config.ssh_keepalive_interval,
        config.ssh_keepalive_count_max,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
