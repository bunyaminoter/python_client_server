import hashlib

from .base import _SymmetricCipherBase


class DESCipher(_SymmetricCipherBase):
    """Pure Python DES-CBC implementation"""

    block_size = 8

    # DES constants (tables)
    _IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]
    _FP = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]
    _E = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    _P = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]
    _S_BOXES = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]
    _PC1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]
    _PC2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]
    _SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    @staticmethod
    def _derive_key(key: str) -> bytes:
        _SymmetricCipherBase._require_key(key, "DES")
        digest = hashlib.md5(key.encode('utf-8')).digest()
        return digest[:8]

    @staticmethod
    def _permute(block: int, table: list[int], bits: int) -> int:
        permuted = 0
        for position in table:
            permuted <<= 1
            permuted |= (block >> (bits - position)) & 1
        return permuted

    @classmethod
    def _generate_round_keys(cls, key: bytes) -> list[int]:
        key_int = int.from_bytes(key, 'big')
        permuted = cls._permute(key_int, cls._PC1, 64)
        c = (permuted >> 28) & 0xFFFFFFF
        d = permuted & 0xFFFFFFF
        round_keys: list[int] = []
        for shift in cls._SHIFT_SCHEDULE:
            c = ((c << shift) | (c >> (28 - shift))) & 0xFFFFFFF
            d = ((d << shift) | (d >> (28 - shift))) & 0xFFFFFFF
            cd = (c << 28) | d
            round_key = cls._permute(cd, cls._PC2, 56)
            round_keys.append(round_key)
        return round_keys

    @classmethod
    def _feistel(cls, right: int, round_key: int) -> int:
        expanded = cls._permute(right, cls._E, 32)
        xored = expanded ^ round_key
        output = 0
        for i in range(8):
            six_bits = (xored >> (42 - 6 * i)) & 0x3F
            row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01)
            col = (six_bits >> 1) & 0x0F
            output = (output << 4) | cls._S_BOXES[i][row][col]
        output = cls._permute(output, cls._P, 32)
        return output

    @classmethod
    def _process_block(cls, block: bytes, round_keys: list[int], decrypt: bool = False) -> bytes:
        block_int = int.from_bytes(block, 'big')
        permuted = cls._permute(block_int, cls._IP, 64)
        left = (permuted >> 32) & 0xFFFFFFFF
        right = permuted & 0xFFFFFFFF

        keys = reversed(round_keys) if decrypt else round_keys
        for round_key in keys:
            new_right = left ^ cls._feistel(right, round_key)
            left = right
            right = new_right

        pre_output = (right << 32) | left
        final = cls._permute(pre_output, cls._FP, 64)
        return final.to_bytes(8, 'big')

    @classmethod
    def encrypt(cls, text: str, key: str, iv: str | None = None) -> str:
        key_bytes = cls._derive_key(key)
        round_keys = cls._generate_round_keys(key_bytes)
        iv_bytes = cls._derive_iv(iv)
        padded = cls._pkcs7_pad(text.encode('utf-8'))

        prev = iv_bytes
        blocks: list[bytes] = []
        for i in range(0, len(padded), cls.block_size):
            block = padded[i:i + cls.block_size]
            xor_block = bytes(a ^ b for a, b in zip(block, prev))
            encrypted = cls._process_block(xor_block, round_keys, decrypt=False)
            blocks.append(encrypted)
            prev = encrypted

        ciphertext = b''.join(blocks)
        return cls._encode_payload(iv_bytes, ciphertext)

    @classmethod
    def decrypt(cls, payload: str, key: str, iv: str | None = None) -> str:
        key_bytes = cls._derive_key(key)
        round_keys = cls._generate_round_keys(key_bytes)
        iv_bytes, ciphertext = cls._decode_payload(payload)

        prev = iv_bytes
        blocks: list[bytes] = []
        for i in range(0, len(ciphertext), cls.block_size):
            block = ciphertext[i:i + cls.block_size]
            decrypted = cls._process_block(block, round_keys, decrypt=True)
            plain_block = bytes(a ^ b for a, b in zip(decrypted, prev))
            blocks.append(plain_block)
            prev = block

        padded = b''.join(blocks)
        plaintext = cls._pkcs7_unpad(padded)
        return plaintext.decode('utf-8')






