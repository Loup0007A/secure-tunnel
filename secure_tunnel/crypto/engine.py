"""
Crypto Engine — ChaCha20-Poly1305 + HKDF
-----------------------------------------
- Chiffrement AEAD : confidentialité + intégrité en un seul passage
- Nonce 96 bits aléatoire à chaque message → pas de réutilisation
- HKDF-SHA256 pour dériver une clé 256 bits depuis un secret partagé
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

NONCE_SIZE  = 12
TAG_SIZE    = 16
HEADER_SIZE = 4
KEY_SIZE    = 32


class CryptoEngine:
    def __init__(self, master_key: bytes, salt: bytes | None = None):
        if len(master_key) < 16:
            raise ValueError("Clé maître : minimum 16 bytes.")
        self.salt    = salt if salt is not None else os.urandom(32)
        self._key    = self._derive_key(master_key, self.salt)
        self._chacha = ChaCha20Poly1305(self._key)

    def _derive_key(self, master_key: bytes, salt: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            info=b"secure_tunnel_v1",
            backend=default_backend(),
        ).derive(master_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Retourne [nonce 12B] + [ciphertext + tag 16B]"""
        nonce = os.urandom(NONCE_SIZE)
        return nonce + self._chacha.encrypt(nonce, plaintext, None)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < NONCE_SIZE + TAG_SIZE:
            raise ValueError("Données trop courtes.")
        return self._chacha.decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], None)

    def frame(self, plaintext: bytes) -> bytes:
        """Trame réseau : [longueur 4B] + encrypt(plaintext)"""
        enc = self.encrypt(plaintext)
        return struct.pack(">I", len(enc)) + enc

    @staticmethod
    def read_frame(data: bytes) -> tuple[bytes, bytes]:
        if len(data) < HEADER_SIZE:
            raise ValueError("Buffer incomplet.")
        length = struct.unpack(">I", data[:HEADER_SIZE])[0]
        total  = HEADER_SIZE + length
        if len(data) < total:
            raise ValueError(f"Trame incomplète : {len(data)}/{total}")
        return data[HEADER_SIZE:total], data[total:]
