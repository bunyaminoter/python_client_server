import hashlib
from typing import List

from .base import _SymmetricCipherBase


class AESCipher(_SymmetricCipherBase):
    """Pure Python AES-CBC implementation (supports 128/192/256-bit keys)"""

    block_size = 16

    # AES constants
    _S_BOX = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ]
    _INV_S_BOX = [0] * 256
    for idx, val in enumerate(_S_BOX):
        _INV_S_BOX[val] = idx

    _R_CON = [
        0x00000000, 0x01000000, 0x02000000, 0x04000000,
        0x08000000, 0x10000000, 0x20000000, 0x40000000,
        0x80000000, 0x1B000000, 0x36000000, 0x6C000000,
        0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000
    ]

    @staticmethod
    def _derive_key(key: str) -> bytes:
        _SymmetricCipherBase._require_key(key, "AES")
        # ECC'den gelen key zaten string formatında olabilir, yine de hashleyip kırpıyoruz
        digest = hashlib.sha256(key.encode('utf-8')).digest()
        return digest[:16]  # AES-128 #ilk 16 biti alarak 128 bite düşürdüm projede istenildiği için

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
        for i in range(16):
            state[i] = cls._S_BOX[state[i]]

    @classmethod
    def _inv_sub_bytes(cls, state: list[int]) -> None:
        for i in range(16):
            state[i] = cls._INV_S_BOX[state[i]]

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
                    (cls._S_BOX[(temp >> 24) & 0xFF] << 24) |
                    (cls._S_BOX[(temp >> 16) & 0xFF] << 16) |
                    (cls._S_BOX[(temp >> 8) & 0xFF] << 8) |
                    (cls._S_BOX[temp & 0xFF])
                )
                temp ^= cls._R_CON[i // Nk]
            elif Nk > 6 and i % Nk == 4:
                temp = (
                    (cls._S_BOX[(temp >> 24) & 0xFF] << 24) |
                    (cls._S_BOX[(temp >> 16) & 0xFF] << 16) |
                    (cls._S_BOX[(temp >> 8) & 0xFF] << 8) |
                    (cls._S_BOX[temp & 0xFF])
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







