"""
Serveur proxy SOCKS5 local (RFC 1928)
--------------------------------------
Écoute sur 127.0.0.1:1080.
Pour chaque connexion applicative :
  1. Handshake SOCKS5 (no-auth)
  2. Lecture destination (CONNECT)
  3. Délégation au TunnelClient WebSocket

Les applications configurées avec ce proxy (curl, browser, etc.)
ne voient qu'un proxy SOCKS5 standard — le chiffrement est transparent.
"""

import asyncio
import struct
import logging
from dataclasses import dataclass

logger = logging.getLogger("socks5")

SOCKS_VERSION   = 0x05
AUTH_NONE       = 0x00
CMD_CONNECT     = 0x01
ATYP_IPV4       = 0x01
ATYP_DOMAIN     = 0x03
ATYP_IPV6       = 0x04
REP_SUCCESS     = 0x00
REP_CMD_UNSUP   = 0x07
REP_ATYP_UNSUP  = 0x08


@dataclass
class ConnectRequest:
    host: str
    port: int
    atyp: int


class Socks5Server:
    def __init__(self, host="127.0.0.1", port=1080, tunnel_handler=None):
        self.host    = host
        self.port    = port
        self.handler = tunnel_handler
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(
            self._on_client, self.host, self.port
        )
        logger.info(f"[SOCKS5] En écoute sur {self.host}:{self.port}")

    async def serve_forever(self):
        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    # ------------------------------------------------------------------ #

    async def _on_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            req = await self._handshake(reader, writer)
            if req and self.handler:
                await self.handler(reader, writer, req)
        except Exception as exc:
            logger.debug(f"[SOCKS5] {peer}: {exc}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handshake(self, reader, writer) -> ConnectRequest | None:
        # Phase 1 : auth
        ver, nmethods = await reader.readexactly(2)
        if ver != SOCKS_VERSION:
            return None
        await reader.readexactly(nmethods)
        writer.write(bytes([SOCKS_VERSION, AUTH_NONE]))
        await writer.drain()

        # Phase 2 : commande CONNECT
        ver, cmd, _, atyp = await reader.readexactly(4)
        if cmd != CMD_CONNECT:
            writer.write(self._reply(REP_CMD_UNSUP))
            await writer.drain()
            return None

        host, port = await self._read_addr(reader, atyp)
        if host is None:
            writer.write(self._reply(REP_ATYP_UNSUP))
            await writer.drain()
            return None

        writer.write(self._reply(REP_SUCCESS))
        await writer.drain()
        logger.info(f"[SOCKS5] CONNECT → {host}:{port}")
        return ConnectRequest(host, port, atyp)

    async def _read_addr(self, reader, atyp) -> tuple[str | None, int]:
        host = None
        if atyp == ATYP_IPV4:
            raw  = await reader.readexactly(4)
            host = ".".join(str(b) for b in raw)
        elif atyp == ATYP_DOMAIN:
            n    = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode()
        elif atyp == ATYP_IPV6:
            import ipaddress
            raw  = await reader.readexactly(16)
            host = str(ipaddress.IPv6Address(raw))
        port_raw = await reader.readexactly(2)
        port = struct.unpack(">H", port_raw)[0]
        return host, port

    @staticmethod
    def _reply(rep: int) -> bytes:
        # VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
        return bytes([SOCKS_VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
