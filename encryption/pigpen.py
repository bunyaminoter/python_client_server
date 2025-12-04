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
        encrypted_message: list[str] = []

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

    def decrypt(self, text: str) -> str:
        # Pigpen genellikle görsel bir şifreleme olduğu için,
        # burada ters map oluşturup sadece tam eşleşen semboller için çözüm yapılabilir.
        reverse_map = {v: k for k, v in self.symbols.items()}
        parts = text.split(' ')
        result: list[str] = []
        for part in parts:
            if part == '':
                continue
            if part in reverse_map:
                result.append(reverse_map[part])
            else:
                # Boşluk veya bilinmeyen
                if part.strip() == '':
                    result.append(' ')
                else:
                    result.append('?')
        return ''.join(result)






