class RailFenceCipher:
    """Rail Fence cipher implementation"""

    @staticmethod
    def encrypt(text: str, rails: int) -> str:
        """Encrypt text using Rail Fence cipher"""
        if rails == 1:
            return text

        # Create rail pattern
        rail_pattern: list[list[str]] = []
        for _ in range(rails):
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
        for r in rail_pattern:
            result += ''.join(r)

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
        rail_pattern: list[list[str]] = []
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






