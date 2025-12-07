"""
TÜM METOTLARI YÖNETEN MERKEZİ SINIF
"""

from __future__ import annotations
from typing import List

# Manuel Implementasyonlar
from .aes import AESCipher
from .affine import AffineCipher
from .caesar import CaesarCipher
from .columnar_transposition import ColumnarTranspositionCipher
from .des import DESCipher
from .hill import HillCipher
from .pigpen import PigpenCipher
from .polybius import PolybiusCipher
from .rail_fence import RailFenceCipher
from .route import RouteCipher
from .substitution import SubstitutionCipher
from .vigenere import VigenereCipher

# Kütüphane Implementasyonları (Yeni)
try:
    from .lib_ciphers import LibAESCipher, LibDESCipher
    LIBRARY_AVAILABLE = True
except ImportError:
    LIBRARY_AVAILABLE = False
    print("UYARI: pycryptodome kütüphanesi bulunamadı. Kütüphane modu çalışmayabilir.")

class EncryptionManager:

    def __init__(self):
        self.substitution_cipher = None
        self.affine_cipher = None
        self.polybius_cipher = None
        self.pigpen_cipher = None
        self.hill_cipher = None

    # ... (Setter metotları aynı kalıyor: set_substitution_key vb.) ...
    def set_substitution_key(self, key: str): self.substitution_cipher = SubstitutionCipher(key)
    def set_affine_keys(self, a: int, b: int): self.affine_cipher = AffineCipher(a, b)
    def set_polybius_alphabet(self, alphabet: str): self.polybius_cipher = PolybiusCipher(alphabet)
    def set_pigpen_cipher(self): self.pigpen_cipher = PigpenCipher()
    def set_hill_matrix(self, key_matrix: List[List[int]]): self.hill_cipher = HillCipher(key_matrix)

    def encrypt(self, text: str, method: str, use_lib: bool = False, **kwargs) -> str:
        """Encrypt text using specified method and mode"""

        # AES ve DES için Mod Kontrolü
        if method == "aes":
            if use_lib and LIBRARY_AVAILABLE:
                return LibAESCipher.encrypt(text, kwargs.get('key'), kwargs.get('iv'))
            return AESCipher.encrypt(text, kwargs.get('key'), kwargs.get('iv'))

        elif method == "des":
            if use_lib and LIBRARY_AVAILABLE:
                return LibDESCipher.encrypt(text, kwargs.get('key'), kwargs.get('iv'))
            return DESCipher.encrypt(text, kwargs.get('key'), kwargs.get('iv'))

        # Diğer metodlar sadece manuel
        elif method == "caesar": return CaesarCipher.encrypt(text, kwargs.get('shift', 3))
        elif method == "vigenere": return VigenereCipher.encrypt(text, kwargs.get('key', 'KEY'))
        elif method == "substitution": return self.substitution_cipher.encrypt(text)
        elif method == "rail_fence": return RailFenceCipher.encrypt(text, kwargs.get('rails', 3))
        elif method == "affine": return self.affine_cipher.encrypt(text)
        elif method == "route": return RouteCipher.encrypt(text, kwargs.get('rows', 3), kwargs.get('cols', 3), kwargs.get('route', 'spiral'))
        elif method == "columnar_transposition": return ColumnarTranspositionCipher.encrypt(text, kwargs.get('key', 'KEY'))
        elif method == "polybius":
            if not self.polybius_cipher: self.polybius_cipher = PolybiusCipher()
            return self.polybius_cipher.encrypt(text)
        elif method == "pigpen":
            if not self.pigpen_cipher: self.pigpen_cipher = PigpenCipher()
            return self.pigpen_cipher.encrypt(text)
        elif method == "hill": return self.hill_cipher.encrypt(text)
        else: raise ValueError(f"Unknown encryption method: {method}")

    def decrypt(self, text: str, method: str, use_lib: bool = False, **kwargs) -> str:
        """Decrypt text using specified method and mode"""

        if method == "aes":
            if use_lib and LIBRARY_AVAILABLE:
                return LibAESCipher.decrypt(text, kwargs.get('key'), kwargs.get('iv'))
            return AESCipher.decrypt(text, kwargs.get('key'), kwargs.get('iv'))

        elif method == "des":
            if use_lib and LIBRARY_AVAILABLE:
                return LibDESCipher.decrypt(text, kwargs.get('key'), kwargs.get('iv'))
            return DESCipher.decrypt(text, kwargs.get('key'), kwargs.get('iv'))

        # Diğerleri (Manuel)
        elif method == "caesar": return CaesarCipher.decrypt(text, kwargs.get('shift', 3))
        elif method == "vigenere": return VigenereCipher.decrypt(text, kwargs.get('key', 'KEY'))
        elif method == "substitution": return self.substitution_cipher.decrypt(text)
        elif method == "rail_fence": return RailFenceCipher.decrypt(text, kwargs.get('rails', 3))
        elif method == "affine": return self.affine_cipher.decrypt(text)
        elif method == "route": return RouteCipher.decrypt(text, kwargs.get('rows', 3), kwargs.get('cols', 3), kwargs.get('route', 'spiral'))
        elif method == "columnar_transposition": return ColumnarTranspositionCipher.decrypt(text, kwargs.get('key', 'KEY'))
        elif method == "polybius":
            if not self.polybius_cipher: self.polybius_cipher = PolybiusCipher()
            return self.polybius_cipher.decrypt(text)
        elif method == "pigpen":
            if not self.pigpen_cipher: self.pigpen_cipher = PigpenCipher()
            return self.pigpen_cipher.decrypt(text)
        elif method == "hill": return self.hill_cipher.decrypt(text)
        else: raise ValueError(f"Unknown encryption method: {method}")