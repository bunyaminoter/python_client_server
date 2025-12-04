class PolybiusCipher:
    """Polybius cipher implementation"""

    def __init__(self, alphabet: str = "ABCDEFGHIKLMNOPQRSTUVWXYZ"):
        """Initialize with custom alphabet (I and J share same position)"""
        self.alphabet = alphabet.upper()
        if len(self.alphabet) != 25:
            raise ValueError("Alphabet must contain exactly 25 letters")

    def _char_to_coords(self, char: str) -> tuple[int, int] | None:
        """Convert character to Polybius coordinates"""
        char = char.upper()
        if char == 'J':
            char = 'I'  # I and J share same position

        if char in self.alphabet:
            index = self.alphabet.index(char)
            row = index // 5 + 1
            col = index % 5 + 1
            return (row, col)
        return None

    def _coords_to_char(self, row: int, col: int) -> str:
        """Convert Polybius coordinates to character"""
        if 1 <= row <= 5 and 1 <= col <= 5:
            index = (row - 1) * 5 + (col - 1)
            return self.alphabet[index]
        return ''

    def encrypt(self, text: str) -> str:
        """Encrypt text using Polybius cipher"""
        result: list[str] = []
        for char in text:
            if char.isalpha():
                coords = self._char_to_coords(char)
                if coords:
                    result.append(f"{coords[0]}{coords[1]}")
            elif char == ' ':
                result.append(' ')
        return ''.join(result)

    def decrypt(self, text: str) -> str:
        """Decrypt text using Polybius cipher"""
        result: list[str] = []
        i = 0
        while i < len(text):
            if text[i] == ' ':
                result.append(' ')
                i += 1
            elif text[i].isdigit() and i + 1 < len(text) and text[i + 1].isdigit():
                row = int(text[i])
                col = int(text[i + 1])
                char = self._coords_to_char(row, col)
                if char:
                    result.append(char)
                i += 2
            else:
                i += 1
        return ''.join(result)






