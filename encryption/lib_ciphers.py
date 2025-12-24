import base64
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad


class LibAESCipher:
    """PyCryptodome kütüphanesi kullanan AES Implementasyonu"""

    @staticmethod
    def _derive_key(key) -> bytes:
        """Key'i bytes'a çevirir. String (16 karakter) veya bytes kabul eder. Byte kontrolü yapar."""
        if isinstance(key, bytes):
            # Zaten bytes, byte kontrolü yap
            if len(key) != 16:
                raise ValueError(f"AES anahtarı tam olarak 16 byte olmalıdır, {len(key)} byte sağlandı")
            return key
        elif isinstance(key, str):
            # String ise 16 karakter olmalı
            if not key:
                raise ValueError("AES anahtarı boş olamaz")
            if len(key) != 16:
                raise ValueError(f"AES anahtarı tam olarak 16 karakter olmalıdır, {len(key)} karakter sağlandı")
            # String'i bytes'a çevir
            return key.encode('utf-8')
        else:
            raise ValueError("AES anahtarı string (16 karakter) veya bytes olmalıdır")

    @staticmethod
    def encrypt(text: str, key: str | bytes, iv: str | None = None) -> str:
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
    def decrypt(payload: str, key: str | bytes, iv: str | None = None) -> str:
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
    def _derive_key(key) -> bytes:
        """Key'i bytes'a çevirir. String (8 karakter) veya bytes kabul eder. Byte kontrolü yapar."""
        if isinstance(key, bytes):
            # Zaten bytes, byte kontrolü yap
            if len(key) != 8:
                raise ValueError(f"DES anahtarı tam olarak 8 byte olmalıdır, {len(key)} byte sağlandı")
            return key
        elif isinstance(key, str):
            # String ise 8 karakter olmalı
            if not key:
                raise ValueError("DES anahtarı boş olamaz")
            if len(key) != 8:
                raise ValueError(f"DES anahtarı tam olarak 8 karakter olmalıdır, {len(key)} karakter sağlandı")
            # String'i bytes'a çevir
            return key.encode('utf-8')
        else:
            raise ValueError("DES anahtarı string (8 karakter) veya bytes olmalıdır")

    @staticmethod
    def encrypt(text: str, key: str | bytes, iv: str | None = None) -> str:
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
    def decrypt(payload: str, key: str | bytes, iv: str | None = None) -> str:
        key_bytes = LibDESCipher._derive_key(key)
        raw = base64.b64decode(payload)

        # İlk 8 byte IV
        iv_bytes = raw[:8]
        ciphertext = raw[8:]

        cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
        decrypted_padded = cipher.decrypt(ciphertext)
        return unpad(decrypted_padded, DES.block_size).decode('utf-8')