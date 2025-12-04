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
        grid: list[list[str]] = []
        for i in range(rows):
            start = i * cols
            end = start + cols
            grid.append(list(text[start:end]))

        # Extract characters based on route
        result: list[str] = []
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
        grid: list[list[str]] = [['' for _ in range(cols)] for _ in range(rows)]

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
        result: list[str] = []
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
        result: list[str] = []
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
        result: list[str] = []
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
        result: list[str] = []
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






