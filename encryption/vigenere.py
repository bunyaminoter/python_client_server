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






