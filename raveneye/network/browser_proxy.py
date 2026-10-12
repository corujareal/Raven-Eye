"""Loopback SOCKS5 egress guard for optional Playwright rendering.

The browser keeps the original hostname for HTTP Host and TLS SNI, while this
proxy resolves and connects to a validated public IP itself. This closes the
DNS-rebinding gap that a Playwright URL route alone cannot close.
"""
from __future__ import annotations

import asyncio
import socket
import threading
from urllib.parse import urlsplit

from .domains import canonical_host, host_matches_rule
from .ssrf_guard import resolve_public_ips


class SafeSocksProxy:
    """Small no-auth SOCKS5 proxy bound to loopback and a fixed host scope."""

    def __init__(self, allowed_domains: set[str] | list[str], *, exact_hosts: set[str] | None = None,
                 max_connections: int = 64):
        self.allowed_domains = tuple(allowed_domains)
        self.exact_hosts = {canonical_host(host) for host in (exact_hosts or set())}
        self.max_connections = max(1, max_connections)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.AbstractServer | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self.port: int | None = None

    @property
    def url(self) -> str:
        if self.port is None:
            raise RuntimeError("Proxy local ainda não iniciado")
        return f"socks5://127.0.0.1:{self.port}"

    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._semaphore = asyncio.Semaphore(self.max_connections)
        try:
            self._server = loop.run_until_complete(
                asyncio.start_server(self._handle_client, "127.0.0.1", 0, limit=64 * 1024)
            )
            self.port = int(self._server.sockets[0].getsockname()[1])
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
            loop.close()
            return
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            if self._server:
                self._server.close()
                loop.run_until_complete(self._server.wait_closed())
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    def start(self, timeout: float = 5.0) -> "SafeSocksProxy":
        if self._thread and self._thread.is_alive():
            return self
        self._thread = threading.Thread(target=self._thread_main, name="raveneye-safe-browser-proxy", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            self.close()
            raise RuntimeError("Proxy local não iniciou dentro do prazo")
        if self._startup_error:
            raise RuntimeError("Falha ao iniciar proxy local") from self._startup_error
        return self

    def close(self) -> None:
        loop = self._loop
        thread = self._thread
        if loop and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if thread and thread.is_alive():
            thread.join(timeout=5)
        self._thread = None
        self._loop = None
        self._server = None
        self.port = None

    def allows_url(self, raw_url: str) -> bool:
        try:
            parsed = urlsplit(raw_url)
            if parsed.scheme.lower() not in {"http", "https", "ws", "wss"}:
                return False
            host = canonical_host(parsed.hostname or "")
            if not host or parsed.username is not None or parsed.password is not None:
                return False
            return host in self.exact_hosts or any(host_matches_rule(host, rule) for rule in self.allowed_domains)
        except (UnicodeError, ValueError):
            return False

    async def _reject(self, writer: asyncio.StreamWriter, status: int) -> None:
        # SOCKS5 reply: version, status, reserved, IPv4 bind address, port.
        writer.write(bytes((5, status, 0, 1, 0, 0, 0, 0, 0, 0)))
        await writer.drain()

    async def _pipe(self, source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
        while True:
            data = await source.read(64 * 1024)
            if not data:
                return
            destination.write(data)
            await destination.drain()

    async def _tunnel(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                      upstream_reader: asyncio.StreamReader, upstream_writer: asyncio.StreamWriter) -> None:
        tasks = {
            asyncio.create_task(self._pipe(client_reader, upstream_writer)),
            asyncio.create_task(self._pipe(upstream_reader, client_writer)),
        }
        try:
            _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except OSError:
                pass

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        semaphore = self._semaphore
        try:
            if semaphore is None or semaphore.locked():
                await self._reject(writer, 1)
                return
            async with semaphore:
                version, count = await asyncio.wait_for(reader.readexactly(2), timeout=5)
                if version != 5 or count < 1:
                    await self._reject(writer, 1)
                    return
                methods = await asyncio.wait_for(reader.readexactly(count), timeout=5)
                if 0 not in methods:
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    return
                writer.write(b"\x05\x00")
                await writer.drain()

                ver, command, _reserved, atyp = await asyncio.wait_for(reader.readexactly(4), timeout=5)
                if ver != 5 or command != 1:
                    await self._reject(writer, 7)
                    return
                if atyp == 1:
                    host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
                elif atyp == 4:
                    host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
                elif atyp == 3:
                    size = (await reader.readexactly(1))[0]
                    host = (await reader.readexactly(size)).decode("idna")
                else:
                    await self._reject(writer, 8)
                    return
                port = int.from_bytes(await reader.readexactly(2), "big")
                host = canonical_host(host)
                if not (1 <= port <= 65535) or not (
                    host in self.exact_hosts or any(host_matches_rule(host, rule) for rule in self.allowed_domains)
                ):
                    await self._reject(writer, 2)
                    return

                try:
                    ips = await asyncio.wait_for(resolve_public_ips(host, port), timeout=5)
                    # Resolve once, validate every answer, then connect directly
                    # to one of those pinned IPs. No second DNS lookup occurs.
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(ips[0], port), timeout=8
                    )
                except Exception:
                    await self._reject(writer, 5)
                    return

                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                await self._tunnel(reader, writer, upstream_reader, upstream_writer)
                upstream_writer = None
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError, UnicodeError, ValueError):
            pass
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                try:
                    await upstream_writer.wait_closed()
                except OSError:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
