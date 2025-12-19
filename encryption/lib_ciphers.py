import base64
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad


class LibAESCipher:
    """PyCryptodome kütüphanesi kullanan AES Implementasyonu"""

    @staticmethod
    def _derive_key(key: str) -> bytes:
        # DEĞİŞİKLİK: Manuel modla uyum için ilk 16 byte (128-bit) alınıyor
        return hashlib.sha256(key.encode('utf-8')).digest()[:16]

    @staticmethod
    def encrypt(text: str, key: str, iv: str | None = None) -> str:
        key_bytes = LibAESCipher._derive_key(key)
        # IV varsa hashle, yoksa kütüphane üretsin (biz burada sabit 16 byte IV üretiyoruz uyum için)
        if iv:
            iv_bytes = hashlib.md5(iv.encode('utf-8')).digest()
        else:
            # Ödevde IV rastgele olsun deniyor ama kütüphane ile manuel uyumu için
            # şimdilik rastgele üretiyoruz
            cipher_temp = AES.new(key_bytes, AES.MODE_CBC)
            iv_bytes = cipher_temp.iv

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        padded_data = pad(text.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)

        # Format: IV + Ciphertext (Base64)
        return base64.b64encode(iv_bytes + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt(payload: str, key: str, iv: str | None = None) -> str:
        key_bytes = LibAESCipher._derive_key(key)
        raw = base64.b64decode(payload)

        # İlk 16 byte IV, gerisi ciphertext
        iv_bytes = raw[:16]
        ciphertext = raw[16:]

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        decrypted_padded = cipher.decrypt(ciphertext)
        return unpad(decrypted_padded, AES.block_size).decode('utf-8')


class LibDESCipher:
    """PyCryptodome kütüphanesi kullanan DES Implementasyonu"""

    @staticmethod
    def _derive_key(key: str) -> bytes:
        # DES için 8 byte anahtar (MD5 ile türetme)
        return hashlib.md5(key.encode('utf-8')).digest()[:8]

    @staticmethod
    def encrypt(text: str, key: str, iv: str | None = None) -> str:
        key_bytes = LibDESCipher._derive_key(key)

        if iv:
            iv_bytes = hashlib.md5(iv.encode('utf-8')).digest()[:8]
        else:
            cipher_temp = DES.new(key_bytes, DES.MODE_CBC)
            iv_bytes = cipher_temp.iv

        cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
        padded_data = pad(text.encode('utf-8'), DES.block_size)
        ciphertext = cipher.encrypt(padded_data)

        return base64.b64encode(iv_bytes + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt(payload: str, key: str, iv: str | None = None) -> str:
        key_bytes = LibDESCipher._derive_key(key)
        raw = base64.b64decode(payload)

        # İlk 8 byte IV
        iv_bytes = raw[:8]
        ciphertext = raw[8:]

        cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
        decrypted_padded = cipher.decrypt(ciphertext)
        return unpad(decrypted_padded, DES.block_size).decode('utf-8')