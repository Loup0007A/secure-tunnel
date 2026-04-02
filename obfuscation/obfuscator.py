"""
Obfuscation du trafic
---------------------
1. Padding aléatoire  → masque la taille réelle des messages
2. Jitter temporel    → casse les patterns de timing inter-paquets

Format payload obfusqué : [real_len 4B] + [data] + [padding aléatoire]
"""

import os
import asyncio
import random
import struct


class Obfuscator:
    def __init__(
        self,
        max_padding: int  = 256,
        jitter_min_ms: float = 0.5,
        jitter_max_ms: float = 8.0,
        enable_jitter: bool  = True,
    ):
        self.max_padding   = max_padding
        self.jitter_min_ms = jitter_min_ms
        self.jitter_max_ms = jitter_max_ms
        self.enable_jitter = enable_jitter

    def pad(self, data: bytes) -> bytes:
        pad_len  = random.randint(16, self.max_padding)
        real_len = struct.pack(">I", len(data))
        return real_len + data + os.urandom(pad_len)

    def unpad(self, data: bytes) -> bytes:
        if len(data) < 4:
            raise ValueError("Payload trop court.")
        real_len = struct.unpack(">I", data[:4])[0]
        return data[4 : 4 + real_len]

    async def jitter(self):
        if self.enable_jitter:
            delay = random.uniform(self.jitter_min_ms, self.jitter_max_ms)
            await asyncio.sleep(delay / 1000.0)

    async def prepare(self, data: bytes) -> bytes:
        """Jitter + padding avant chiffrement."""
        await self.jitter()
        return self.pad(data)

    def recover(self, data: bytes) -> bytes:
        """Dépaddage après déchiffrement."""
        return self.unpad(data)
