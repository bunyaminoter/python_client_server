import random
import math


class RSACipher:
    """
    Basit RSA Implementasyonu (Eğitim Amaçlı)
    Ödev gereksinimi: Anahtar dağıtımı için kullanılacak.
    """

    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.generate_key_pair()

    def is_prime(self, n, k=5):
        if n < 2: return False
        if n == 2 or n == 3: return True
        if n % 2 == 0: return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_large_prime(self, bits):
        while True:
            num = random.getrandbits(bits)
            if num % 2 == 0: num += 1
            if self.is_prime(num):
                return num

    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def mod_inverse(self, a, m):
        m0, x0, x1 = m, 0, 1
        if m == 1: return 0
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0: x1 += m0
        return x1

    def generate_key_pair(self):
        # Basitlik adına biraz daha küçük asallar kullanılabilir hız için
        p = self.generate_large_prime(self.key_size // 2)
        q = self.generate_large_prime(self.key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        g = self.gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = self.gcd(e, phi)

        d = self.mod_inverse(e, phi)

        self.public_key = (e, n)
        self.private_key = (d, n)
        return self.public_key, self.private_key

    @staticmethod
    def encrypt(message_int_or_bytes, public_key):
        e, n = public_key
        # Mesajı sayıya çevir (basit yöntem)
        if isinstance(message_int_or_bytes, bytes):
            message_int = int.from_bytes(message_int_or_bytes, 'big')
        elif isinstance(message_int_or_bytes, str):
            message_int = int.from_bytes(message_int_or_bytes.encode('utf-8'), 'big')
        else:
            message_int = message_int_or_bytes

        if message_int >= n:
            raise ValueError("Mesaj boyutu RSA modülünden büyük olamaz!")

        cipher_int = pow(message_int, e, n)
        return cipher_int

    @staticmethod
    def decrypt(cipher_int, private_key):
        d, n = private_key
        decrypted_int = pow(cipher_int, d, n)

        # Sayıyı byte'a çevir - BYTES OLARAK DÖNDÜR (string'e çevirme!)
        byte_len = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes = decrypted_int.to_bytes(byte_len, 'big')
        return decrypted_bytes  # BYTES döndür, decode() yapma!