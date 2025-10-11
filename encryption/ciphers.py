"""
Encryption methods for client-server application
Includes: Caesar, Vigenere, Substitution, Rail Fence, and Affine ciphers
"""

import string
import math
from typing import Dict, List, Tuple


class CaesarCipher:
    """Caesar cipher implementation"""
    
    @staticmethod
    def encrypt(text: str, shift: int) -> str:
        """Encrypt text using Caesar cipher"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                shifted = (ord(char) - ascii_offset + shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        return result
    
    @staticmethod
    def decrypt(text: str, shift: int) -> str:
        """Decrypt text using Caesar cipher"""
        return CaesarCipher.encrypt(text, -shift)


class VigenereCipher:
    """Vigenere cipher implementation"""
    
    @staticmethod
    def encrypt(text: str, key: str) -> str:
        """Encrypt text using Vigenere cipher"""
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                key_char = ord(key[key_index % len(key)]) - 65
                shifted = (ord(char) - ascii_offset + key_char) % 26
                result += chr(shifted + ascii_offset)
                key_index += 1
            else:
                result += char
        return result
    
    @staticmethod
    def decrypt(text: str, key: str) -> str:
        """Decrypt text using Vigenere cipher"""
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                key_char = ord(key[key_index % len(key)]) - 65
                shifted = (ord(char) - ascii_offset - key_char) % 26
                result += chr(shifted + ascii_offset)
                key_index += 1
            else:
                result += char
        return result


class SubstitutionCipher:
    """Substitution cipher implementation"""
    
    def __init__(self, key: str = None):
        """Initialize with custom key or generate random key"""
        if key is None:
            self.key = self._generate_random_key()
        else:
            self.key = key.upper()
        self.alphabet = string.ascii_uppercase
        self._validate_key()
    
    def _generate_random_key(self) -> str:
        """Generate random substitution key"""
        import random
        chars = list(string.ascii_uppercase)
        random.shuffle(chars)
        return ''.join(chars)
    
    def _validate_key(self):
        """Validate that key contains all letters exactly once"""
        if len(self.key) != 26 or len(set(self.key)) != 26:
            raise ValueError("Key must contain all 26 letters exactly once")
    
    def encrypt(self, text: str) -> str:
        """Encrypt text using substitution cipher"""
        result = ""
        for char in text:
            if char.isalpha():
                index = ord(char.upper()) - 65
                encrypted_char = self.key[index]
                result += encrypted_char if char.isupper() else encrypted_char.lower()
            else:
                result += char
        return result
    
    def decrypt(self, text: str) -> str:
        """Decrypt text using substitution cipher"""
        result = ""
        for char in text:
            if char.isalpha():
                index = self.key.find(char.upper())
                decrypted_char = chr(index + 65)
                result += decrypted_char if char.isupper() else decrypted_char.lower()
            else:
                result += char
        return result


class RailFenceCipher:
    """Rail Fence cipher implementation"""
    
    @staticmethod
    def encrypt(text: str, rails: int) -> str:
        """Encrypt text using Rail Fence cipher"""
        if rails == 1:
            return text
        
        # Create rail pattern
        rail_pattern = []
        for i in range(rails):
            rail_pattern.append([])
        
        # Fill rails
        rail = 0
        direction = 1
        for char in text:
            rail_pattern[rail].append(char)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction = -direction
        
        # Read from rails
        result = ""
        for rail in rail_pattern:
            result += ''.join(rail)
        
        return result
    
    @staticmethod
    def decrypt(text: str, rails: int) -> str:
        """Decrypt text using Rail Fence cipher"""
        if rails == 1:
            return text
        
        # Calculate rail lengths
        rail_lengths = [0] * rails
        rail = 0
        direction = 1
        for _ in text:
            rail_lengths[rail] += 1
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction = -direction
        
        # Fill rails
        rail_pattern = []
        start = 0
        for length in rail_lengths:
            rail_pattern.append(list(text[start:start + length]))
            start += length
        
        # Read from rails
        result = ""
        rail = 0
        direction = 1
        for _ in text:
            result += rail_pattern[rail].pop(0)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction = -direction
        
        return result


class AffineCipher:
    """Affine cipher implementation"""
    
    def __init__(self, a: int, b: int):
        """Initialize with keys a and b"""
        self.a = a
        self.b = b
        self.m = 26  # Alphabet size
        self._validate_keys()
    
    def _validate_keys(self):
        """Validate that keys are valid for affine cipher"""
        if math.gcd(self.a, self.m) != 1:
            raise ValueError("Key 'a' must be coprime with 26")
        if not (0 <= self.b < self.m):
            raise ValueError("Key 'b' must be between 0 and 25")
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Calculate modular inverse"""
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        raise ValueError("Modular inverse does not exist")
    
    def encrypt(self, text: str) -> str:
        """Encrypt text using Affine cipher"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                x = ord(char) - ascii_offset
                encrypted = (self.a * x + self.b) % self.m
                result += chr(encrypted + ascii_offset)
            else:
                result += char
        return result
    
    def decrypt(self, text: str) -> str:
        """Decrypt text using Affine cipher"""
        result = ""
        a_inv = self._mod_inverse(self.a, self.m)
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                y = ord(char) - ascii_offset
                decrypted = (a_inv * (y - self.b)) % self.m
                result += chr(decrypted + ascii_offset)
            else:
                result += char
        return result


class EncryptionManager:
    """Manager class for all encryption methods"""
    
    def __init__(self):
        self.substitution_cipher = None
        self.affine_cipher = None
    
    def set_substitution_key(self, key: str):
        """Set substitution cipher key"""
        self.substitution_cipher = SubstitutionCipher(key)
    
    def set_affine_keys(self, a: int, b: int):
        """Set affine cipher keys"""
        self.affine_cipher = AffineCipher(a, b)
    
    def encrypt(self, text: str, method: str, **kwargs) -> str:
        """Encrypt text using specified method"""
        if method == "caesar":
            shift = kwargs.get('shift', 3)
            return CaesarCipher.encrypt(text, shift)
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
        else:
            raise ValueError(f"Unknown encryption method: {method}")
    
    def decrypt(self, text: str, method: str, **kwargs) -> str:
        """Decrypt text using specified method"""
        if method == "caesar":
            shift = kwargs.get('shift', 3)
            return CaesarCipher.decrypt(text, shift)
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
        else:
            raise ValueError(f"Unknown encryption method: {method}")

