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






