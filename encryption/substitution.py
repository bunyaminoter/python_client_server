import string


class SubstitutionCipher:
    """Substitution cipher implementation"""

    def __init__(self, key: str | None = None):
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






