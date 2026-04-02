"""
Tests unitaires
---------------
Vérifie crypto, obfuscation et intégration client/serveur en local.
"""

import asyncio
import os
import pytest

from secure_tunnel.crypto.engine import CryptoEngine
from secure_tunnel.obfuscation.obfuscator import Obfuscator


# ------------------------------------------------------------------ #
#  Crypto                                                             #
# ------------------------------------------------------------------ #

class TestCryptoEngine:

    def test_encrypt_decrypt_roundtrip(self):
        key    = os.urandom(32)
        engine = CryptoEngine(key)
        plain  = b"Hello, tunnel!"
        assert engine.decrypt(engine.encrypt(plain)) == plain

    def test_different_nonces(self):
        key    = os.urandom(32)
        engine = CryptoEngine(key)
        plain  = b"same message"
        enc1   = engine.encrypt(plain)
        enc2   = engine.encrypt(plain)
        assert enc1 != enc2      # nonce aléatoire → ciphertext différent

    def test_same_salt_same_key(self):
        key    = b"shared_secret_1234567890123456"
        salt   = os.urandom(32)
        e1     = CryptoEngine(key, salt)
        e2     = CryptoEngine(key, salt)
        plain  = b"test"
        # e2 doit pouvoir déchiffrer ce qu'a chiffré e1
        assert e2.decrypt(e1.encrypt(plain)) == plain

    def test_tampered_message_rejected(self):
        from cryptography.exceptions import InvalidTag
        key     = os.urandom(32)
        engine  = CryptoEngine(key)
        enc     = bytearray(engine.encrypt(b"data"))
        enc[-1] ^= 0xFF            # altérer le tag
        with pytest.raises(InvalidTag):
            engine.decrypt(bytes(enc))

    def test_frame_read_frame(self):
        key    = os.urandom(32)
        engine = CryptoEngine(key)
        plain  = b"framed message"
        framed = engine.frame(plain)
        enc, rest = CryptoEngine.read_frame(framed)
        assert engine.decrypt(enc) == plain
        assert rest == b""

    def test_short_key_rejected(self):
        with pytest.raises(ValueError):
            CryptoEngine(b"short")


# ------------------------------------------------------------------ #
#  Obfuscation                                                        #
# ------------------------------------------------------------------ #

class TestObfuscator:

    def test_pad_unpad_roundtrip(self):
        ob   = Obfuscator()
        data = b"secret payload"
        assert ob.unpad(ob.pad(data)) == data

    def test_padding_changes_size(self):
        ob   = Obfuscator()
        data = b"x" * 100
        assert len(ob.pad(data)) > len(data)

    def test_padding_is_random(self):
        ob   = Obfuscator()
        data = b"same"
        assert ob.pad(data) != ob.pad(data)

    def test_jitter_disabled(self):
        ob = Obfuscator(enable_jitter=False)
        # Doit retourner immédiatement
        asyncio.run(ob.jitter())

    def test_prepare_recover(self):
        ob   = Obfuscator(enable_jitter=False)
        data = b"async pipeline"
        padded    = asyncio.run(ob.prepare(data))
        recovered = ob.recover(padded)
        assert recovered == data


# ------------------------------------------------------------------ #
#  Intégration : mini tunnel local                                    #
# ------------------------------------------------------------------ #

class TestLocalTunnel:
    """
    Simule un échange client ↔ serveur en mémoire :
      - Le client chiffre + obfusque un message
      - Le serveur déchiffre + désob flusque
      - Vérifie que les données sont identiques des deux côtés
    """

    def test_full_roundtrip(self):
        secret  = b"integration_test_secret_32bytes!"
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

        # Côté client
        client_engine = CryptoEngine(secret)
        ob             = Obfuscator(enable_jitter=False)
        padded         = ob.pad(payload)
        framed         = client_engine.frame(padded)

        # Côté serveur (reçoit le sel du client)
        server_engine = CryptoEngine(secret, salt=client_engine.salt)
        enc, _         = CryptoEngine.read_frame(framed)
        decrypted      = server_engine.decrypt(enc)
        recovered      = ob.recover(decrypted)

        assert recovered == payload
