import math


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






