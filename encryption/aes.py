import hashlib
from typing import List

from .base import _SymmetricCipherBase


class AESCipher(_SymmetricCipherBase):
    """
    Pure Python AES-CBC implementation (supports 128/192/256-bit keys)
    S-box tabloları kullanmadan, dinamik hesaplama ile implementasyon
    """

    block_size = 16

    _R_CON = [
        0x00000000, 0x01000000, 0x02000000, 0x04000000,
        0x08000000, 0x10000000, 0x20000000, 0x40000000,
        0x80000000, 0x1B000000, 0x36000000, 0x6C000000,
        0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000
    ]

    # ---------------- GF(2^8) MATEMATİĞİ - S-box hesaplama için ----------------

    @staticmethod
    def _gf_mul(a: int, b: int) -> int:
        """Galois Field (2^8) çarpma işlemi"""
        res = 0
        for _ in range(8):
            if b & 1:
                res ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B  # İndirgenemez polinom x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return res

    @classmethod
    def _gf_inv(cls, a: int) -> int:
        """Galois Field (2^8) ters alma işlemi (multiplicative inverse)"""
        if a == 0:
            return 0
        # Extended Euclidean Algorithm kullanarak ters alma
        for i in range(1, 256):
            if cls._gf_mul(a, i) == 1:
                return i
        return 0

    @staticmethod
    def _affine_transform(b: int) -> int:
        """AES S-box için afin dönüşüm"""
        c = 0x63  # Sabit değer
        res = 0
        for i in range(8):
            bit = (
                ((b >> i) & 1) ^
                ((b >> ((i + 4) % 8)) & 1) ^
                ((b >> ((i + 5) % 8)) & 1) ^
                ((b >> ((i + 6) % 8)) & 1) ^
                ((b >> ((i + 7) % 8)) & 1) ^
                ((c >> i) & 1)
            )
            res |= bit << i
        return res

    @classmethod
    def _sbox(cls, byte: int) -> int:
        """S-box değerini dinamik olarak hesaplar: Affine(GF_inv(byte))"""
        inv = cls._gf_inv(byte)
        return cls._affine_transform(inv)

    @classmethod
    def _inv_sbox(cls, byte: int) -> int:
        """Inverse S-box değerini dinamik olarak hesaplar"""
        # Ters afin dönüşüm (inverse affine transformation)
        c = 0x05  # Ters afin için sabit değer
        b = 0
        for i in range(8):
            bit = (
                ((byte >> ((i + 2) % 8)) & 1) ^
                ((byte >> ((i + 5) % 8)) & 1) ^
                ((byte >> ((i + 7) % 8)) & 1) ^
                ((c >> i) & 1)
            )
            b |= bit << i
        # GF ters alma: GF_inv(b)
        return cls._gf_inv(b)

    @staticmethod
    def _derive_key(key) -> bytes:
        """Key'i bytes'a çevirir. String veya bytes kabul eder."""
        if isinstance(key, bytes):
            # Zaten bytes, direkt kullan (16 byte olmalı)
            if len(key) >= 16:
                return key[:16]
            # 16 byte'tan kısa ise hashle
            return hashlib.sha256(key).digest()[:16]
        elif isinstance(key, str):
            # String ise hashle
            if not key:
                raise ValueError("AES anahtarı boş olamaz")
            digest = hashlib.sha256(key.encode('utf-8')).digest()
            return digest[:16]  # AES-128
        else:
            raise ValueError("AES anahtarı string veya bytes olmalıdır")

    @staticmethod
    def _xtime(a: int) -> int:
        return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF

    @classmethod
    def _mix_column(cls, column: list[int]) -> list[int]:
        a = column
        b = [cls._xtime(c) for c in a]
        return [
            b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3],
            a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3],
            a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3],
            a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3],
        ]

    @classmethod
    def _inv_mix_column(cls, column: list[int]) -> list[int]:
        u = cls._xtime(cls._xtime(column[0] ^ column[2]))
        v = cls._xtime(cls._xtime(column[1] ^ column[3]))
        column[0] ^= u
        column[1] ^= v
        column[2] ^= u
        column[3] ^= v
        return cls._mix_column(column)

    @classmethod
    def _sub_bytes(cls, state: list[int]) -> None:
        """SubBytes: Her byte için S-box değerini dinamik hesapla"""
        for i in range(16):
            state[i] = cls._sbox(state[i])

    @classmethod
    def _inv_sub_bytes(cls, state: list[int]) -> None:
        """InvSubBytes: Her byte için Inverse S-box değerini dinamik hesapla"""
        for i in range(16):
            state[i] = cls._inv_sbox(state[i])

    @staticmethod
    def _shift_rows(state: list[int]) -> None:
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

    @staticmethod
    def _inv_shift_rows(state: list[int]) -> None:
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

    @classmethod
    def _mix_columns(cls, state: list[int]) -> None:
        for col in range(4):
            idx = col * 4
            column = state[idx:idx + 4]
            mixed = cls._mix_column(column)
            state[idx:idx + 4] = mixed

    @classmethod
    def _inv_mix_columns(cls, state: list[int]) -> None:
        for col in range(4):
            idx = col * 4
            column = state[idx:idx + 4]
            mixed = cls._inv_mix_column(column)
            state[idx:idx + 4] = mixed

    @classmethod
    def _add_round_key(cls, state: list[int], round_key: list[int]) -> None:
        for i in range(16):
            state[i] ^= round_key[i]

    @classmethod
    def _key_expansion(cls, key: bytes) -> list[list[int]]:
        key_symbols = list(key)
        key_size = len(key_symbols)
        if key_size not in (16, 24, 32):
            raise ValueError("AES anahtarı 16, 24 veya 32 bayt olmalıdır")

        Nk = key_size // 4
        Nr = {4: 10, 6: 12, 8: 14}[Nk]
        Nb = 4
        words: List[int] = [0] * (Nb * (Nr + 1))

        def word_from_bytes(b0, b1, b2, b3):
            return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

        def word_to_bytes(word):
            return [
                (word >> 24) & 0xFF,
                (word >> 16) & 0xFF,
                (word >> 8) & 0xFF,
                word & 0xFF,
            ]

        # İlk anahtar kelimeleri
        for i in range(Nk):
            words[i] = word_from_bytes(*key_symbols[4 * i: 4 * i + 4])

        for i in range(Nk, Nb * (Nr + 1)):
            temp = words[i - 1]
            if i % Nk == 0:
                temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF  # rot word
                temp = (
                    (cls._sbox((temp >> 24) & 0xFF) << 24) |
                    (cls._sbox((temp >> 16) & 0xFF) << 16) |
                    (cls._sbox((temp >> 8) & 0xFF) << 8) |
                    (cls._sbox(temp & 0xFF))
                )
                temp ^= cls._R_CON[i // Nk]
            elif Nk > 6 and i % Nk == 4:
                temp = (
                    (cls._sbox((temp >> 24) & 0xFF) << 24) |
                    (cls._sbox((temp >> 16) & 0xFF) << 16) |
                    (cls._sbox((temp >> 8) & 0xFF) << 8) |
                    (cls._sbox(temp & 0xFF))
                )
            words[i] = words[i - Nk] ^ temp

        round_keys: list[list[int]] = []
        for r in range(Nr + 1):
            round_key: list[int] = []
            for i in range(4):
                round_key.extend(word_to_bytes(words[r * 4 + i]))
            round_keys.append(round_key)
        return round_keys

    @classmethod
    def _cipher(cls, block: bytes, round_keys: list[list[int]]) -> bytes:
        state = list(block)
        Nr = len(round_keys) - 1
        cls._add_round_key(state, round_keys[0])

        for rnd in range(1, Nr):
            cls._sub_bytes(state)
            cls._shift_rows(state)
            cls._mix_columns(state)
            cls._add_round_key(state, round_keys[rnd])

        cls._sub_bytes(state)
        cls._shift_rows(state)
        cls._add_round_key(state, round_keys[Nr])
        return bytes(state)

    @classmethod
    def _inv_cipher(cls, block: bytes, round_keys: list[list[int]]) -> bytes:
        state = list(block)
        Nr = len(round_keys) - 1
        cls._add_round_key(state, round_keys[Nr])

        for rnd in range(Nr - 1, 0, -1):
            cls._inv_shift_rows(state)
            cls._inv_sub_bytes(state)
            cls._add_round_key(state, round_keys[rnd])
            cls._inv_mix_columns(state)

        cls._inv_shift_rows(state)
        cls._inv_sub_bytes(state)
        cls._add_round_key(state, round_keys[0])
        return bytes(state)

    @classmethod
    def encrypt(cls, text: str, key: str, iv: str | None = None) -> str:
        key_bytes = cls._derive_key(key)
        round_keys = cls._key_expansion(key_bytes)
        iv_bytes = cls._derive_iv(iv)
        padded = cls._pkcs7_pad(text.encode('utf-8'))

        blocks: list[bytes] = []
        prev = iv_bytes
        for i in range(0, len(padded), cls.block_size):
            block = padded[i:i + cls.block_size]
            xor_block = bytes(a ^ b for a, b in zip(block, prev))
            encrypted = cls._cipher(xor_block, round_keys)
            blocks.append(encrypted)
            prev = encrypted

        ciphertext = b''.join(blocks)
        return cls._encode_payload(iv_bytes, ciphertext)

    @classmethod
    def decrypt(cls, payload: str, key: str, iv: str | None = None) -> str:
        key_bytes = cls._derive_key(key)
        round_keys = cls._key_expansion(key_bytes)
        iv_bytes, ciphertext = cls._decode_payload(payload)

        blocks: list[bytes] = []
        prev = iv_bytes
        for i in range(0, len(ciphertext), cls.block_size):
            block = ciphertext[i:i + cls.block_size]
            decrypted = cls._inv_cipher(block, round_keys)
            plain_block = bytes(a ^ b for a, b in zip(decrypted, prev))
            blocks.append(plain_block)
            prev = block

        padded = b''.join(blocks)
        plaintext = cls._pkcs7_unpad(padded)
        return plaintext.decode('utf-8')









