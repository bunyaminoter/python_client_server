"""
Shared helpers for symmetric block cipher implementations (AES, DES).
"""

import base64
import hashlib
import os
from typing import Tuple


class _SymmetricCipherBase:
    """Shared helpers for block cipher implementations"""

    block_size = 16

    @staticmethod
    def _require_key(key: str, cipher_name: str) -> str:
        if not key:
            raise ValueError(f"{cipher_name} anahtarı boş olamaz")
        return key

    @classmethod
    def _derive_iv(cls, iv: str | None) -> bytes:
        if iv:
            digest = hashlib.md5(iv.encode('utf-8')).digest()
            return digest[:cls.block_size]
        return os.urandom(cls.block_size)

    @staticmethod
    def _encode_payload(iv: bytes, ciphertext: bytes) -> str:
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @classmethod
    def _decode_payload(cls, payload: str) -> Tuple[bytes, bytes]:
        raw = base64.b64decode(payload)
        if len(raw) < cls.block_size:
            raise ValueError("Şifreli veri geçersiz: IV eksik")
        return raw[:cls.block_size], raw[cls.block_size:]

    @classmethod
    def _pkcs7_pad(cls, data: bytes) -> bytes:
        pad_len = cls.block_size - (len(data) % cls.block_size)
        return data + bytes([pad_len] * pad_len)

    @classmethod
    def _pkcs7_unpad(cls, data: bytes) -> bytes:
        if not data:
            raise ValueError("Boş veri çözülemez")
        pad_len = data[-1]
        if pad_len <= 0 or pad_len > cls.block_size:
            raise ValueError("Geçersiz padding")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Padding doğrulaması başarısız")
        return data[:-pad_len]






