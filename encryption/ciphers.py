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


class RouteCipher:
    """Route cipher implementation"""
    
    @staticmethod
    def encrypt(text: str, rows: int, cols: int, route: str = "spiral") -> str:
        """Encrypt text using Route cipher"""
        # Remove spaces and convert to uppercase
        text = text.replace(" ", "").upper()
        
        # Pad text to fill the grid
        total_chars = rows * cols
        if len(text) < total_chars:
            text += "X" * (total_chars - len(text))
        
        # Create grid
        grid = []
        for i in range(rows):
            start = i * cols
            end = start + cols
            grid.append(list(text[start:end]))
        
        # Extract characters based on route
        result = []
        if route == "spiral":
            result = RouteCipher._spiral_extract(grid, rows, cols)
        elif route == "row":
            result = RouteCipher._row_extract(grid, rows, cols)
        elif route == "column":
            result = RouteCipher._column_extract(grid, rows, cols)
        elif route == "diagonal":
            result = RouteCipher._diagonal_extract(grid, rows, cols)
        
        return ''.join(result)
    
    @staticmethod
    def decrypt(text: str, rows: int, cols: int, route: str = "spiral") -> str:
        """Decrypt text using Route cipher"""
        # Remove spaces and convert to uppercase
        text = text.replace(" ", "").upper()
        
        # Create empty grid
        grid = [['' for _ in range(cols)] for _ in range(rows)]
        
        # Fill grid based on route
        if route == "spiral":
            RouteCipher._spiral_fill(grid, text, rows, cols)
        elif route == "row":
            RouteCipher._row_fill(grid, text, rows, cols)
        elif route == "column":
            RouteCipher._column_fill(grid, text, rows, cols)
        elif route == "diagonal":
            RouteCipher._diagonal_fill(grid, text, rows, cols)
        
        # Read grid row by row
        result = ""
        for row in grid:
            result += ''.join(row)
        
        return result.rstrip('X')
    
    @staticmethod
    def _spiral_extract(grid, rows, cols):
        """Extract characters in spiral pattern"""
        result = []
        top, bottom = 0, rows - 1
        left, right = 0, cols - 1
        
        while top <= bottom and left <= right:
            # Top row
            for i in range(left, right + 1):
                result.append(grid[top][i])
            top += 1
            
            # Right column
            for i in range(top, bottom + 1):
                result.append(grid[i][right])
            right -= 1
            
            # Bottom row
            if top <= bottom:
                for i in range(right, left - 1, -1):
                    result.append(grid[bottom][i])
                bottom -= 1
            
            # Left column
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    result.append(grid[i][left])
                left += 1
        
        return result
    
    @staticmethod
    def _spiral_fill(grid, text, rows, cols):
        """Fill grid in spiral pattern"""
        text_index = 0
        top, bottom = 0, rows - 1
        left, right = 0, cols - 1
        
        while top <= bottom and left <= right and text_index < len(text):
            # Top row
            for i in range(left, right + 1):
                if text_index < len(text):
                    grid[top][i] = text[text_index]
                    text_index += 1
            top += 1
            
            # Right column
            for i in range(top, bottom + 1):
                if text_index < len(text):
                    grid[i][right] = text[text_index]
                    text_index += 1
            right -= 1
            
            # Bottom row
            if top <= bottom:
                for i in range(right, left - 1, -1):
                    if text_index < len(text):
                        grid[bottom][i] = text[text_index]
                        text_index += 1
                bottom -= 1
            
            # Left column
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    if text_index < len(text):
                        grid[i][left] = text[text_index]
                        text_index += 1
                left += 1
    
    @staticmethod
    def _row_extract(grid, rows, cols):
        """Extract characters row by row"""
        result = []
        for row in grid:
            result.extend(row)
        return result
    
    @staticmethod
    def _row_fill(grid, text, rows, cols):
        """Fill grid row by row"""
        text_index = 0
        for i in range(rows):
            for j in range(cols):
                if text_index < len(text):
                    grid[i][j] = text[text_index]
                    text_index += 1
    
    @staticmethod
    def _column_extract(grid, rows, cols):
        """Extract characters column by column"""
        result = []
        for j in range(cols):
            for i in range(rows):
                result.append(grid[i][j])
        return result
    
    @staticmethod
    def _column_fill(grid, text, rows, cols):
        """Fill grid column by column"""
        text_index = 0
        for j in range(cols):
            for i in range(rows):
                if text_index < len(text):
                    grid[i][j] = text[text_index]
                    text_index += 1
    
    @staticmethod
    def _diagonal_extract(grid, rows, cols):
        """Extract characters diagonally"""
        result = []
        # Extract diagonals from top-left to bottom-right
        for d in range(rows + cols - 1):
            for i in range(rows):
                j = d - i
                if 0 <= j < cols:
                    result.append(grid[i][j])
        return result
    
    @staticmethod
    def _diagonal_fill(grid, text, rows, cols):
        """Fill grid diagonally"""
        text_index = 0
        for d in range(rows + cols - 1):
            for i in range(rows):
                j = d - i
                if 0 <= j < cols and text_index < len(text):
                    grid[i][j] = text[text_index]
                    text_index += 1


class ColumnarTranspositionCipher:
    """Columnar Transposition cipher implementation"""
    
    @staticmethod
    def encrypt(text: str, key: str) -> str:
        """Encrypt text using Columnar Transposition cipher"""
        # Remove spaces and convert to uppercase
        text = text.replace(" ", "").upper()
        key = key.upper()
        
        # Create key mapping
        key_order = [(char, i) for i, char in enumerate(key)]
        key_order.sort()
        
        # Calculate number of rows needed
        cols = len(key)
        rows = (len(text) + cols - 1) // cols
        
        # Pad text if necessary
        padded_text = text + "X" * (rows * cols - len(text))
        
        # Create grid
        grid = []
        for i in range(rows):
            start = i * cols
            end = start + cols
            grid.append(list(padded_text[start:end]))
        
        # Read columns in key order
        result = ""
        for _, original_index in key_order:
            for row in grid:
                result += row[original_index]
        
        return result
    
    @staticmethod
    def decrypt(text: str, key: str) -> str:
        """Decrypt text using Columnar Transposition cipher"""
        # Remove spaces and convert to uppercase
        text = text.replace(" ", "").upper()
        key = key.upper()
        
        # Create key mapping
        key_order = [(char, i) for i, char in enumerate(key)]
        key_order.sort()
        
        # Calculate grid dimensions
        cols = len(key)
        rows = len(text) // cols
        
        # Create empty grid
        grid = [['' for _ in range(cols)] for _ in range(rows)]
        
        # Fill grid column by column in key order
        text_index = 0
        for _, original_index in key_order:
            for row in range(rows):
                if text_index < len(text):
                    grid[row][original_index] = text[text_index]
                    text_index += 1
        
        # Read grid row by row
        result = ""
        for row in grid:
            result += ''.join(row)
        
        return result.rstrip('X')


class PolybiusCipher:
    """Polybius cipher implementation"""
    
    def __init__(self, alphabet: str = "ABCDEFGHIKLMNOPQRSTUVWXYZ"):
        """Initialize with custom alphabet (I and J share same position)"""
        self.alphabet = alphabet.upper()
        if len(self.alphabet) != 25:
            raise ValueError("Alphabet must contain exactly 25 letters")
    
    def _char_to_coords(self, char: str) -> tuple:
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
        result = []
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
        result = []
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




class PigpenCipher:

    def __init__(self):
        # Tek satırlık Unicode sembol eşlemesi
        self.symbols = {
            # Izgara 1 (A-I)
            'A': '┘', 'B': '⊔', 'C': '└',
            'D': '⊐', 'E': '⊞', 'F': '⊏',
            'G': '┐', 'H': '⊤', 'I': '┌',

            # Izgara 2 (J-R, noktalı)
            'J': '⋅┘', 'K': '⋅⊔', 'L': '⋅└',
            'M': '⋅⊐', 'N': '⋅⊞', 'O': '⋅⊏',
            'P': '⋅┐', 'Q': '⋅⊤', 'R': '⋅┌',

            # Izgara 3 (S-V)
            'S': '∨', 'T': '>', 'U': '∧', 'V': '<',

            # Izgara 4 (W-Z, noktalı)
            'W': '⋅∨', 'X': '⋅>', 'Y': '⋅∧', 'Z': '⋅<',
        }

    def encrypt(self, text: str) -> str:

        text = text.upper()
        encrypted_message = []

        for char in text:
            if char == ' ':
                # Boşlukları 3 birimlik boşluk olarak koru
                encrypted_message.append('   ')
            elif char in self.symbols:
                # Sembolü sözlükten al
                encrypted_message.append(self.symbols[char])
            else:
                # Bilinmeyen karakterler (rakam, noktalama vb.)
                encrypted_message.append('?')

        # Tüm sembolleri aralarında birer boşluk bırakarak birleştir
        return ' '.join(encrypted_message)


class HillCipher:
    """Hill cipher implementation"""

    def __init__(self, key_matrix: List[List[int]] = None):
        """Initialize with key matrix"""
        if key_matrix is None:
            # Default 2x2 key matrix (Det=9, Inv=3)
            self.key_matrix = [[3, 3], [2, 5]]
        else:
            self.key_matrix = key_matrix

        self.matrix_size = len(self.key_matrix)
        self.mod = 26

        # --- DÜZELTME: Anahtar kontrolü nesne oluşturulurken yapılmalı ---
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

        inverse = []
        if len(matrix) == 2:
            # 2x2 matrix inverse: (1/det) * [[d, -b], [-c, a]]
            adj = [[matrix[1][1], -matrix[0][1]],
                   [-matrix[1][0], matrix[0][0]]]

            for i in range(2):
                row = []
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
                row = []
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
        result = []
        for i in range(0, len(numbers), self.matrix_size):
            block = numbers[i:i + self.matrix_size]
            encrypted_block = []
            for row in self.key_matrix:
                encrypted_value = sum(row[j] * block[j] for j in range(len(block))) % self.mod
                encrypted_block.append(encrypted_value)
            result.extend(encrypted_block)

        return self._numbers_to_text(result)

    def decrypt(self, text: str) -> str:
        """Decrypt text using Hill cipher"""
        # --- DÜZELTME: Doğrulama __init__ içine taşındı ---
        # self._validate_key() # Bu satır artık gereksiz

        # Get inverse matrix
        inverse_matrix = self._matrix_inverse(self.key_matrix)

        # Clean text
        clean_text = ''.join([char.upper() for char in text if char.isalpha()])

        # Convert to numbers
        numbers = self._text_to_numbers(clean_text)

        # Decrypt in blocks
        result = []
        for i in range(0, len(numbers), self.matrix_size):
            block = numbers[i:i + self.matrix_size]
            decrypted_block = []
            for row in inverse_matrix:
                decrypted_value = sum(row[j] * block[j] for j in range(len(block))) % self.mod
                decrypted_block.append(decrypted_value)
            result.extend(decrypted_block)

        decrypted_text = self._numbers_to_text(result)

        # Orijinal metinde 'X' olsaydı onu da sileceği için riskli olabilir,
        # ancak Hill cipher'da dolguyu kaldırmanın standart yolu budur.
        return decrypted_text.rstrip('X')


class EncryptionManager:
    """Manager class for all encryption methods"""
    
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

