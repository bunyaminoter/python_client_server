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
        grid: list[list[str]] = []
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
        grid: list[list[str]] = [['' for _ in range(cols)] for _ in range(rows)]

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






