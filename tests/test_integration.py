"""
Tests d'intégration — tunnel complet en local (websockets >= 16)

Le serveur TunnelServer relaie en boucle infinie (normal en prod).
Pour les tests, on utilise un serveur TCP "écho-et-ferme" qui répond
1 fois puis ferme → le relay _dest_to_ws se termine → test se conclut.
"""
import asyncio, json, os, pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from secure_tunnel.crypto.engine import CryptoEngine
from secure_tunnel.obfuscation.obfuscator import Obfuscator

SECRET = b"integration_test_secret_32bytes!"
OBF    = Obfuscator(enable_jitter=False)

# ── Serveur TCP écho-et-ferme ────────────────────────────────────────
async def _echo_once(reader, writer):
    """Lit un bloc, le renvoie, puis ferme la connexion."""
    data = await reader.read(65536)
    if data:
        writer.write(data)
        await writer.drain()
    writer.close()
    await writer.wait_closed()

# ── Handler serveur inline (sans la boucle infinie de prod) ─────────
def _make_handler(secret, obf):
    async def handler(ws):
        try:
            salt = await ws.recv()
            crypto = CryptoEngine(secret, salt=salt if isinstance(salt, bytes) else salt.encode())

            raw = await ws.recv()
            raw = raw if isinstance(raw, bytes) else raw.encode()
            msg = json.loads(obf.recover(crypto.decrypt(raw)))
            host, port = msg["host"], msg["port"]

            dest_r, dest_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

            await ws.send(crypto.encrypt(obf.pad(json.dumps({"status": "ok"}).encode())))

            # Relay jusqu'à fermeture de la connexion TCP destination
            async def ws_to_dest():
                async for m in ws:
                    raw = m if isinstance(m, bytes) else m.encode()
                    dest_w.write(obf.recover(crypto.decrypt(raw)))
                    await dest_w.drain()
                dest_w.close()

            async def dest_to_ws():
                buf = b""
                while True:
                    chunk = await dest_r.read(8192)
                    if not chunk:
                        break
                    buf += chunk
                if buf:
                    await ws.send(crypto.encrypt(obf.pad(buf)))

            await asyncio.gather(ws_to_dest(), dest_to_ws(), return_exceptions=True)
        except Exception as exc:
            pass  # connexion fermée normalement
    return handler

# ── Test 1 : aller-retour simple ────────────────────────────────────
@pytest.mark.asyncio
async def test_full_tunnel_roundtrip():
    echo_srv = await asyncio.start_server(_echo_once, "127.0.0.1", 19876)
    handler  = _make_handler(SECRET, OBF)

    async with serve(handler, "127.0.0.1", 19877):
        async with connect("ws://127.0.0.1:19877") as ws:
            crypto = CryptoEngine(SECRET)
            await ws.send(crypto.salt)
            await ws.send(crypto.encrypt(OBF.pad(
                json.dumps({"host": "127.0.0.1", "port": 19876}).encode()
            )))
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            raw = raw if isinstance(raw, bytes) else raw.encode()
            ack = json.loads(OBF.recover(crypto.decrypt(raw)))
            assert ack["status"] == "ok"

            payload = b"Hello from integration test!"
            await ws.send(crypto.encrypt(OBF.pad(payload)))

            raw   = await asyncio.wait_for(ws.recv(), timeout=5)
            raw   = raw if isinstance(raw, bytes) else raw.encode()
            reply = OBF.recover(crypto.decrypt(raw))
            assert reply == payload, f"Attendu {payload!r}, reçu {reply!r}"

    echo_srv.close()
    print("✓ test_full_tunnel_roundtrip")

# ── Test 2 : gros payload (32 KB) ────────────────────────────────────
@pytest.mark.asyncio
async def test_large_payload():
    BIG      = os.urandom(32 * 1024)
    echo_srv = await asyncio.start_server(_echo_once, "127.0.0.1", 19878)
    handler  = _make_handler(SECRET, OBF)

    async with serve(handler, "127.0.0.1", 19879):
        async with connect("ws://127.0.0.1:19879") as ws:
            crypto = CryptoEngine(SECRET)
            await ws.send(crypto.salt)
            await ws.send(crypto.encrypt(OBF.pad(
                json.dumps({"host": "127.0.0.1", "port": 19878}).encode()
            )))
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            raw = raw if isinstance(raw, bytes) else raw.encode()
            assert json.loads(OBF.recover(crypto.decrypt(raw)))["status"] == "ok"

            await ws.send(crypto.encrypt(OBF.pad(BIG)))
            raw   = await asyncio.wait_for(ws.recv(), timeout=10)
            raw   = raw if isinstance(raw, bytes) else raw.encode()
            reply = OBF.recover(crypto.decrypt(raw))
            assert reply == BIG, f"Taille: attendu {len(BIG)}, reçu {len(reply)}"

    echo_srv.close()
    print("✓ test_large_payload")

# ── Test 3 : mauvais secret → InvalidTag ────────────────────────────
@pytest.mark.asyncio
async def test_wrong_secret_rejected():
    WRONG    = b"wrong___secret_32bytes_padding!!"
    echo_srv = await asyncio.start_server(_echo_once, "127.0.0.1", 19880)
    handler  = _make_handler(SECRET, OBF)  # serveur utilise le bon secret

    async with serve(handler, "127.0.0.1", 19881):
        async with connect("ws://127.0.0.1:19881") as ws:
            bad_crypto = CryptoEngine(WRONG)
            await ws.send(bad_crypto.salt)
            await ws.send(bad_crypto.encrypt(OBF.pad(
                json.dumps({"host": "127.0.0.1", "port": 19880}).encode()
            )))
            # Serveur reçoit données chiffrées avec mauvais secret → InvalidTag → ferme WS
            with pytest.raises(Exception):
                raw = await asyncio.wait_for(ws.recv(), timeout=3)
                raw = raw if isinstance(raw, bytes) else raw.encode()
                bad_crypto.decrypt(raw)

    echo_srv.close()
    print("✓ test_wrong_secret_rejected")
