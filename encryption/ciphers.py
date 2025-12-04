"""
TÜM METOTLARI İMPORT ETTİM
"""

from __future__ import annotations

from typing import List

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


class EncryptionManager:
    
    def __init__(self):
        self.substitution_cipher = None
        self.affine_cipher = None
        self.polybius_cipher = None
        self.pigpen_cipher = None
        self.hill_cipher = None
    
    def set_substitution_key(self, key: str):
        """Set substitution cipher key"""
        self.substitution_cipher = SubstitutionCipher(key)
    
    def set_affine_keys(self, a: int, b: int):
        """Set affine cipher keys"""
        self.affine_cipher = AffineCipher(a, b)
    
    def set_polybius_alphabet(self, alphabet: str):
        """Set Polybius cipher alphabet"""
        self.polybius_cipher = PolybiusCipher(alphabet)
    
    def set_pigpen_cipher(self):
        """Initialize Pigpen cipher"""
        self.pigpen_cipher = PigpenCipher()
    
    def set_hill_matrix(self, key_matrix: List[List[int]]):
        """Set Hill cipher key matrix"""
        self.hill_cipher = HillCipher(key_matrix)
    
    def encrypt(self, text: str, method: str, **kwargs) -> str:
        """Encrypt text using specified method"""
        if method == "caesar":
            shift = kwargs.get('shift', 3)
            return CaesarCipher.encrypt(text, shift)
        elif method == "aes":
            key = kwargs.get('key')
            iv = kwargs.get('iv')
            return AESCipher.encrypt(text, key, iv)
        elif method == "des":
            key = kwargs.get('key')
            iv = kwargs.get('iv')
            return DESCipher.encrypt(text, key, iv)
        elif method == "vigenere":
            key = kwargs.get('key', 'KEY')
            return VigenereCipher.encrypt(text, key)
        elif method == "substitution":
            if self.substitution_cipher is None:
                raise ValueError("Substitution cipher not initialized")
            return self.substitution_cipher.encrypt(text)
        elif method == "rail_fence":
            rails = kwargs.get('rails', 3)
            return RailFenceCipher.encrypt(text, rails)
        elif method == "affine":
            if self.affine_cipher is None:
                raise ValueError("Affine cipher not initialized")
            return self.affine_cipher.encrypt(text)
        elif method == "route":
            rows = kwargs.get('rows', 3)
            cols = kwargs.get('cols', 3)
            route = kwargs.get('route', 'spiral')
            return RouteCipher.encrypt(text, rows, cols, route)
        elif method == "columnar_transposition":
            key = kwargs.get('key', 'KEY')
            return ColumnarTranspositionCipher.encrypt(text, key)
        elif method == "polybius":
            if self.polybius_cipher is None:
                self.polybius_cipher = PolybiusCipher()
            return self.polybius_cipher.encrypt(text)
        elif method == "pigpen":
            if self.pigpen_cipher is None:
                self.pigpen_cipher = PigpenCipher()
            return self.pigpen_cipher.encrypt(text)
        elif method == "hill":
            if self.hill_cipher is None:
                raise ValueError("Hill cipher not initialized")
            return self.hill_cipher.encrypt(text)
        else:
            raise ValueError(f"Unknown encryption method: {method}")
    
    def decrypt(self, text: str, method: str, **kwargs) -> str:
        """Decrypt text using specified method"""
        if method == "caesar":
            shift = kwargs.get('shift', 3)
            return CaesarCipher.decrypt(text, shift)
        elif method == "aes":
            key = kwargs.get('key')
            iv = kwargs.get('iv')
            return AESCipher.decrypt(text, key, iv)
        elif method == "des":
            key = kwargs.get('key')
            iv = kwargs.get('iv')
            return DESCipher.decrypt(text, key, iv)
        elif method == "vigenere":
            key = kwargs.get('key', 'KEY')
            return VigenereCipher.decrypt(text, key)
        elif method == "substitution":
            if self.substitution_cipher is None:
                raise ValueError("Substitution cipher not initialized")
            return self.substitution_cipher.decrypt(text)
        elif method == "rail_fence":
            rails = kwargs.get('rails', 3)
            return RailFenceCipher.decrypt(text, rails)
        elif method == "affine":
            if self.affine_cipher is None:
                raise ValueError("Affine cipher not initialized")
            return self.affine_cipher.decrypt(text)
        elif method == "route":
            rows = kwargs.get('rows', 3)
            cols = kwargs.get('cols', 3)
            route = kwargs.get('route', 'spiral')
            return RouteCipher.decrypt(text, rows, cols, route)
        elif method == "columnar_transposition":
            key = kwargs.get('key', 'KEY')
            return ColumnarTranspositionCipher.decrypt(text, key)
        elif method == "polybius":
            if self.polybius_cipher is None:
                self.polybius_cipher = PolybiusCipher()
            return self.polybius_cipher.decrypt(text)
        elif method == "pigpen":
            if self.pigpen_cipher is None:
                self.pigpen_cipher = PigpenCipher()
            return self.pigpen_cipher.decrypt(text)
        elif method == "hill":
            if self.hill_cipher is None:
                raise ValueError("Hill cipher not initialized")
            return self.hill_cipher.decrypt(text)
        else:
            raise ValueError(f"Unknown encryption method: {method}")
