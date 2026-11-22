# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""DNS forwarder for this device while Chameleon is enabled, routed through the tunnel.

chameleon-netctl redirects every DNS query of this device (port 53, any
destination) to this service and routes this service account's traffic only
through cham0. It has no direct fallback: an unavailable tunnel produces DNS
failure, never a query over the ordinary uplink. It listens on loopback and
answers loopback clients only, so it is never reachable from the network.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import signal
import socket


LOGGER = logging.getLogger(__name__)
MAX_DNS_MESSAGE = 4096
def _is_local_address(address: ipaddress.IPv4Address) -> bool:
    """True when the address belongs to this host (binding to it succeeds)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((str(address), 0))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _client_allowed(host: str) -> bool:
    # Redirected queries keep their original source: 127.0.0.1, the WSL DNS
    # stub on lo, or the address of the uplink the query would have left by.
    # Only this host's own addresses are answered.
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.version != 4:
        return False
    return address.is_loopback or _is_local_address(address)


def _upstreams() -> tuple[str, ...]:
    raw = os.getenv("CHAMELEON_DNS_UPSTREAMS", "1.1.1.1,9.9.9.9")
    result: list[str] = []
    for value in raw.split(","):
        candidate = value.strip()
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 4 and address.is_global and candidate not in result:
            result.append(candidate)
    if not result:
        raise RuntimeError("no valid public IPv4 DNS upstream configured")
    return tuple(result[:4])


async def _query_tcp(data: bytes, host: str, timeout: float) -> bytes:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, 53, family=socket.AF_INET), timeout=timeout
    )
    try:
        writer.write(len(data).to_bytes(2, "big") + data)
        await writer.drain()
        size = int.from_bytes(
            await asyncio.wait_for(reader.readexactly(2), timeout=timeout), "big"
        )
        if not 12 <= size <= 65535:
            raise ValueError("invalid upstream DNS response size")
        response = await asyncio.wait_for(reader.readexactly(size), timeout=timeout)
        if response[:2] != data[:2]:
            raise ValueError("upstream DNS transaction ID mismatch")
        return response
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def _query(
    data: bytes, upstreams: tuple[str, ...], timeout: float
) -> bytes | None:
    loop = asyncio.get_running_loop()
    for host in upstreams:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock, data, (host, 53))
            response, peer = await asyncio.wait_for(
                loop.sock_recvfrom(sock, MAX_DNS_MESSAGE), timeout=timeout
            )
            if peer[0] != host or len(response) < 12 or response[:2] != data[:2]:
                continue
            if int.from_bytes(response[2:4], "big") & 0x0200:
                return await _query_tcp(data, host, timeout)
            return response
        except (OSError, TimeoutError, asyncio.TimeoutError, ValueError):
            continue
        finally:
            sock.close()
    return None


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, upstreams: tuple[str, ...], timeout: float) -> None:
        self.upstreams = upstreams
        self.timeout = timeout
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        if _client_allowed(address[0]) and 12 <= len(data) <= MAX_DNS_MESSAGE:
            asyncio.create_task(self._reply(data, address))

    async def _reply(self, data: bytes, address: tuple[str, int]) -> None:
        response = await _query(data, self.upstreams, self.timeout)
        if response and self.transport:
            self.transport.sendto(response, address)


async def _handle_tcp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    upstreams: tuple[str, ...],
    timeout: float,
) -> None:
    try:
        peer = writer.get_extra_info("peername")
        if not peer or not _client_allowed(peer[0]):
            return
        size = int.from_bytes(await reader.readexactly(2), "big")
        if not 12 <= size <= MAX_DNS_MESSAGE:
            return
        data = await reader.readexactly(size)
        response = await _query(data, upstreams, timeout)
        if response:
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError, TimeoutError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def run() -> None:
    # REDIRECT of locally generated packets delivers to 127.0.0.1. The reply
    # must leave from that same address so conntrack restores the original
    # destination (for example 10.255.255.254:53, the WSL DNS stub that also
    # sits on lo); a wildcard socket would answer from the stub address and
    # port 15353, which the resolver drops.
    host = "127.0.0.1"
    port = int(os.getenv("CHAMELEON_DNS_PORT", "15353"))
    if not 1024 <= port <= 65535:
        raise RuntimeError("invalid Chameleon DNS port")
    timeout = min(10.0, max(0.25, float(os.getenv("CHAMELEON_DNS_TIMEOUT", "3"))))
    upstreams = _upstreams()
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: _UDPProtocol(upstreams, timeout), local_addr=(host, port)
    )
    tcp_server = await asyncio.start_server(
        lambda r, w: _handle_tcp(r, w, upstreams, timeout), host, port
    )
    LOGGER.info("Chameleon DNS proxy listening on port %d", port)
    try:
        await stop.wait()
    finally:
        udp_transport.close()
        tcp_server.close()
        await tcp_server.wait_closed()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    asyncio.run(run())


if __name__ == "__main__":
    main()
