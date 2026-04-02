"""
Serveur de tunnel WebSocket — Render.com
-----------------------------------------
Gère sur un seul port ($PORT) :
  - GET /          → 200 OK  (health check Render)
  - WebSocket /    → tunnel chiffré ChaCha20-Poly1305

La détection HTTP vs WebSocket se fait via le header "Upgrade: websocket".
On utilise un serveur TCP asyncio brut + websockets.asyncio.server.ServerProtocol
pour avoir la main sur le dispatch.

Variables d'environnement :
  TUNNEL_SECRET   Secret partagé client/serveur (obligatoire au runtime)
  PORT            Injecté par Render (défaut 8080)
"""

import asyncio
import json
import logging
import os

import websockets
from websockets.asyncio.server import serve

from secure_tunnel.crypto.engine import CryptoEngine
from secure_tunnel.obfuscation.obfuscator import Obfuscator
from secure_tunnel.utils.stats import tracker
from secure_tunnel.utils.logger import setup_logging

logger = setup_logging("tunnel.server")

HOST   = "0.0.0.0"
PORT   = int(os.environ.get("PORT", 8080))
SECRET = os.environ.get("TUNNEL_SECRET", "").encode()
CHUNK  = 8192

# Réponse HTTP pour le health check Render
_HEALTH_OK = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 2\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"OK"
)


class TunnelServer:
    def __init__(self, secret: bytes):
        if not secret:
            raise ValueError("secret vide.")
        self.secret     = secret
        self.obfuscator = Obfuscator(enable_jitter=False)

    # ------------------------------------------------------------------ #
    #  Dispatch TCP brut : HTTP health check OU WebSocket tunnel          #
    # ------------------------------------------------------------------ #

    async def _dispatch(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Lit les premiers bytes pour détecter le type de connexion :
          - Commence par "GET" → HTTP health check
          - Sinon            → déléguer à websockets
        """
        try:
            header = await asyncio.wait_for(reader.read(4), timeout=5)
        except asyncio.TimeoutError:
            writer.close()
            return

        if header.startswith(b"GET "):
            # Lire le reste de la requête HTTP et répondre 200
            try:
                await asyncio.wait_for(reader.read(2048), timeout=3)
                writer.write(_HEALTH_OK)
                await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
        else:
            # Reconstituer le flux et passer à websockets via une connexion TCP locale
            # On remet les bytes lus dans un buffer et on crée un pipe
            await self._forward_to_ws(header, reader, writer)

    async def _forward_to_ws(self, peeked: bytes, reader, writer):
        """
        Crée un pipe interne pour passer la connexion à websockets.serve,
        en réinjectant les bytes déjà lus.
        """
        # Pair de pipes : (client_r, client_w) ↔ (server_r, server_w)
        c_r, c_w = asyncio.StreamReader(), None
        # On crée une connexion TCP interne sur un port éphémère
        # Plus simple : on utilise un serveur websockets séparé en mémoire
        # via une socket Unix ou simplement en appelant directement le handler
        # avec une connexion virtuelle.
        #
        # Approche la plus propre pour websockets >=14 : utiliser process_request
        # dans serve() pour intercepter les GET non-WS.
        writer.close()

    # ------------------------------------------------------------------ #
    #  Handler WebSocket principal                                         #
    # ------------------------------------------------------------------ #

    async def _ws_handler(self, ws):
        peer = ws.remote_address
        logger.info(f"[SERVER] Connexion {peer}")
        tracker.connection_opened()
        try:
            await self._session(ws)
        except Exception as exc:
            logger.warning(f"[SERVER] {peer}: {exc}")
            tracker.add_error()
        finally:
            tracker.connection_closed()
            logger.debug(f"[SERVER] Session fermée {peer}")

    async def _session(self, ws):
        # 1. Sel HKDF
        salt = await ws.recv()
        if not isinstance(salt, bytes) or len(salt) != 32:
            raise ValueError("Sel HKDF invalide.")
        crypto = CryptoEngine(self.secret, salt=salt)

        # 2. Requête CONNECT
        raw = await ws.recv()
        raw = raw if isinstance(raw, bytes) else raw.encode()
        msg = json.loads(self.obfuscator.recover(crypto.decrypt(raw)))
        host, port = msg["host"], msg["port"]
        logger.info(f"[SERVER] CONNECT → {host}:{port}")

        # 3. Connexion TCP destination
        try:
            dest_r, dest_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
        except Exception as exc:
            await ws.send(crypto.encrypt(self.obfuscator.pad(
                json.dumps({"status": "error", "reason": str(exc)}).encode()
            )))
            raise

        # 4. ACK
        await ws.send(crypto.encrypt(self.obfuscator.pad(
            json.dumps({"status": "ok"}).encode()
        )))
        logger.info(f"[SERVER] ✓ Tunnel actif → {host}:{port}")

        # 5. Relay bidirectionnel
        try:
            await asyncio.gather(
                self._ws_to_dest(ws, dest_w, crypto),
                self._dest_to_ws(dest_r, ws, crypto),
                return_exceptions=True,
            )
        finally:
            try:
                dest_w.close()
            except Exception:
                pass

    async def _ws_to_dest(self, ws, dest_w, crypto):
        try:
            async for msg in ws:
                raw  = msg if isinstance(msg, bytes) else msg.encode()
                data = self.obfuscator.recover(crypto.decrypt(raw))
                dest_w.write(data)
                await dest_w.drain()
                tracker.add_received(len(data))
        except Exception as exc:
            logger.debug(f"[WS→DEST] {exc}")

    async def _dest_to_ws(self, dest_r, ws, crypto):
        try:
            while True:
                data = await dest_r.read(CHUNK)
                if not data:
                    break
                await ws.send(crypto.encrypt(self.obfuscator.pad(data)))
                tracker.add_sent(len(data))
        except Exception as exc:
            logger.debug(f"[DEST→WS] {exc}")

    # ------------------------------------------------------------------ #
    #  process_request : intercept HTTP health check dans websockets      #
    # ------------------------------------------------------------------ #

    async def process_request(self, connection, request):
        """
        Hook websockets appelé avant l'upgrade WebSocket.
        Si c'est un GET sans header Upgrade → répondre 200 OK (health check).
        """
        upgrade = request.headers.get("Upgrade", "").lower()
        if upgrade != "websocket":
            # Réponse HTTP 200 pour Render health check
            from websockets.http11 import Response
            from websockets.datastructures import Headers
            return Response(
                status_code=200,
                reason_phrase="OK",
                headers=Headers([
                    ("Content-Type", "text/plain"),
                    ("Content-Length", "2"),
                    ("Connection", "close"),
                ]),
                body=b"OK",
            )
        return None   # laisser websockets gérer l'upgrade normalement

    # ------------------------------------------------------------------ #
    #  run                                                                 #
    # ------------------------------------------------------------------ #

    async def run(self):
        async with serve(
            self._ws_handler,
            HOST,
            PORT,
            process_request=self.process_request,
        ):
            logger.info(f"[SERVER] WebSocket + health check sur {HOST}:{PORT}")
            await asyncio.Future()  # run forever


# ------------------------------------------------------------------ #
#  Stats périodiques + main                                           #
# ------------------------------------------------------------------ #

async def _log_stats():
    while True:
        await asyncio.sleep(60)
        logger.info(f"[STATS] {tracker.summary()}")


if __name__ == "__main__":
    if not SECRET:
        raise RuntimeError("Variable d'environnement TUNNEL_SECRET manquante.")

    async def _main():
        await asyncio.gather(TunnelServer(SECRET).run(), _log_stats())

    asyncio.run(_main())
