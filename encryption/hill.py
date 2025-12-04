import math
from typing import List


class HillCipher:
    """Hill cipher implementation"""

    def __init__(self, key_matrix: List[List[int]] | None = None):
        """Initialize with key matrix"""
        if key_matrix is None:
            # Default 2x2 key matrix (Det=9, Inv=3)
            self.key_matrix = [[3, 3], [2, 5]]
        else:
            self.key_matrix = key_matrix

        self.matrix_size = len(self.key_matrix)
        self.mod = 26

        # Anahtar kontrolü nesne oluşturulurken yapılmalı
        try:
            self._validate_key()
        except ValueError as e:
            # __init__ içinde hata fırlatmak daha doğrudur
            raise ValueError(f"Invalid key matrix: {e}")

    def _validate_key(self):
        """Validate that key matrix is invertible"""
        det = self._determinant(self.key_matrix)
        if math.gcd(det % self.mod, self.mod) != 1:
            raise ValueError(f"Key matrix determinant ({det}) must be coprime with 26")

    def _determinant(self, matrix: List[List[int]]) -> int:
        """Calculate determinant of matrix"""
        n = len(matrix)
        if n == 2:
            return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
        elif n == 3:
            return (matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) -
                    matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]) +
                    matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]))
        else:
            raise ValueError("Only 2x2 and 3x3 matrices are supported")

    def _mod_inverse(self, a: int, m: int) -> int:
        """Calculate modular inverse"""
        # Negatif sayıları pozitife çevir (örn: -17 % 26 = 9)
        a = a % m
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        raise ValueError(f"Modular inverse for {a} mod {m} does not exist")

    def _matrix_inverse(self, matrix: List[List[int]]) -> List[List[int]]:
        """Calculate modular inverse of matrix"""
        det = self._determinant(matrix)
        det_inv = self._mod_inverse(det, self.mod)

        inverse: List[List[int]] = []
        if len(matrix) == 2:
            # 2x2 matrix inverse: (1/det) * [[d, -b], [-c, a]]
            adj = [[matrix[1][1], -matrix[0][1]],
                   [-matrix[1][0], matrix[0][0]]]

            for i in range(2):
                row: List[int] = []
                for j in range(2):
                    # Python'da % operatörü negatif sayılarla doğru çalışır
                    # (örn: -3 % 26 = 23)
                    row.append((det_inv * adj[i][j]) % self.mod)
                inverse.append(row)

        elif len(matrix) == 3:
            # 3x3 matrix inverse: (1/det) * Adjugate(matrix)
            adj = [
                [matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1],
                 -(matrix[0][1] * matrix[2][2] - matrix[0][2] * matrix[2][1]),
                 matrix[0][1] * matrix[1][2] - matrix[0][2] * matrix[1][1]],

                [-(matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]),
                 matrix[0][0] * matrix[2][2] - matrix[0][2] * matrix[2][0],
                 -(matrix[0][0] * matrix[1][2] - matrix[0][2] * matrix[1][0])],

                [matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0],
                 -(matrix[0][0] * matrix[2][1] - matrix[0][1] * matrix[2][0]),
                 matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]]
            ]

            for i in range(3):
                row: List[int] = []
                for j in range(3):
                    row.append((det_inv * adj[i][j]) % self.mod)
                inverse.append(row)

        return inverse

    def _text_to_numbers(self, text: str) -> List[int]:
        """Convert text to numbers (A=0, B=1, ..., Z=25)"""
        return [ord(char.upper()) - 65 for char in text if char.isalpha()]

    def _numbers_to_text(self, numbers: List[int]) -> str:
        """Convert numbers to text"""
        return ''.join([chr(num + 65) for num in numbers])

    def _pad_text(self, text: str) -> str:
        """Pad text to be multiple of matrix size"""
        while len(text) % self.matrix_size != 0:
            text += 'X'
        return text

    def encrypt(self, text: str) -> str:
        """Encrypt text using Hill cipher"""
        # Clean and pad text
        clean_text = ''.join([char.upper() for char in text if char.isalpha()])
        padded_text = self._pad_text(clean_text)

        # Convert to numbers
        numbers = self._text_to_numbers(padded_text)

        # Encrypt in blocks
        result: List[int] = []
        for i in range(0, len(numbers), self.matrix_size):
            block = numbers[i:i + self.matrix_size]
            encrypted_block: List[int] = []
            for row in self.key_matrix:
                encrypted_value = sum(row[j] * block[j] for j in range(len(block))) % self.mod
                encrypted_block.append(encrypted_value)
            result.extend(encrypted_block)

        return self._numbers_to_text(result)

    def decrypt(self, text: str) -> str:
        """Decrypt text using Hill cipher"""
        # Get inverse matrix
        inverse_matrix = self._matrix_inverse(self.key_matrix)

        # Clean text
        clean_text = ''.join([char.upper() for char in text if char.isalpha()])

        # Convert to numbers
        numbers = self._text_to_numbers(clean_text)

        # Decrypt in blocks
        result: List[int] = []
        for i in range(0, len(numbers), self.matrix_size):
            block = numbers[i:i + self.matrix_size]
            decrypted_block: List[int] = []
            for row in inverse_matrix:
                decrypted_value = sum(row[j] * block[j] for j in range(len(block))) % self.mod
                decrypted_block.append(decrypted_value)
            result.extend(decrypted_block)

        decrypted_text = self._numbers_to_text(result)

        # Orijinal metinde 'X' olsaydı onu da sileceği için riskli olabilir,
        # ancak Hill cipher'da dolguyu kaldırmanın standart yolu budur.
        return decrypted_text.rstrip('X')






