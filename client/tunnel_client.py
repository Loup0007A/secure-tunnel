"""
Client de tunnel WebSocket chiffré — websockets >= 14
"""
import asyncio, json, logging
from websockets.asyncio.client import connect
from secure_tunnel.crypto.engine import CryptoEngine
from secure_tunnel.obfuscation.obfuscator import Obfuscator
from secure_tunnel.proxy.socks5 import ConnectRequest
from secure_tunnel.utils.stats import tracker

logger  = logging.getLogger("tunnel.client")
CHUNK   = 8192
TIMEOUT = 10

class TunnelClient:
    def __init__(self, server_url: str, secret: bytes):
        self.server_url = server_url
        self.secret     = secret
        self.obfuscator = Obfuscator()

    async def handle(self, app_reader, app_writer, req: ConnectRequest):
        peer = app_writer.get_extra_info("peername")
        logger.info(f"[CLIENT] {peer} → {req.host}:{req.port}")
        tracker.connection_opened()
        try:
            await self._run_session(app_reader, app_writer, req)
        except Exception as exc:
            logger.warning(f"[CLIENT] Session error: {exc}")
            tracker.add_error()
        finally:
            tracker.connection_closed()
            try:
                app_writer.close()
                await app_writer.wait_closed()
            except Exception:
                pass

    async def _run_session(self, app_reader, app_writer, req):
        async with connect(self.server_url, open_timeout=TIMEOUT) as ws:
            crypto = CryptoEngine(self.secret)
            await ws.send(crypto.salt)

            msg    = json.dumps({"host": req.host, "port": req.port}).encode()
            padded = await self.obfuscator.prepare(msg)
            await ws.send(crypto.encrypt(padded))

            raw = await asyncio.wait_for(ws.recv(), timeout=TIMEOUT)
            raw = raw if isinstance(raw, bytes) else raw.encode()
            ack = json.loads(self.obfuscator.recover(crypto.decrypt(raw)))
            if ack.get("status") != "ok":
                raise ConnectionError(f"Serveur refusé: {ack}")

            logger.info(f"[CLIENT] ✓ Tunnel établi → {req.host}:{req.port}")
            await asyncio.gather(
                self._to_tunnel(app_reader, ws, crypto),
                self._from_tunnel(ws, app_writer, crypto),
                return_exceptions=True,
            )

    async def _to_tunnel(self, reader, ws, crypto):
        try:
            while True:
                data = await reader.read(CHUNK)
                if not data: break
                padded = await self.obfuscator.prepare(data)
                await ws.send(crypto.encrypt(padded))
                tracker.add_sent(len(data))
        except Exception as exc:
            logger.debug(f"[→TUNNEL] {exc}")

    async def _from_tunnel(self, ws, writer, crypto):
        try:
            async for message in ws:
                raw  = message if isinstance(message, bytes) else message.encode()
                data = self.obfuscator.recover(crypto.decrypt(raw))
                writer.write(data); await writer.drain()
                tracker.add_received(len(data))
        except Exception as exc:
            logger.debug(f"[TUNNEL→] {exc}")
