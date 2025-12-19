import random
import hashlib


class ECCCipher:
    """
    Basit ECDH (Elliptic Curve Diffie-Hellman) Implementasyonu.
    Eğri: secp256k1 (Bitcoin'in kullandığı eğri) parametreleri.
    Amaç: İki tarafın ortak bir gizli anahtar (session key) oluşturması.
    """

    # secp256k1 Parametreleri
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A = 0
    B = 7
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    def __init__(self):
        self.private_key = random.randrange(1, self.N)
        self.public_key = self.scalar_mult(self.private_key, self.G)

    def generate_shared_secret(self, other_public_key):
        """Karşı tarafın public key'i ile kendi private key'ini çarparak ortak sırrı üretir."""
        if other_public_key is None:
            raise ValueError("Karşı tarafın Public Key'i gerekli!")

        shared_point = self.scalar_mult(self.private_key, other_public_key)

        # Ortak sırrın x koordinatını alıp SHA-256 ile hashliyoruz
        # Böylece AES/DES için temiz bir byte dizisi elde ediyoruz.
        secret_bytes = shared_point[0].to_bytes(32, 'big')
        return hashlib.sha256(secret_bytes).hexdigest()  # String olarak döndür (32 byte hex -> 64 char)

    # --- Matematiksel Yardımcı Fonksiyonlar (Manuel Implementasyon) ---

    def point_add(self, p1, p2):
        if p1 is None: return p2
        if p2 is None: return p1

        x1, y1 = p1
        x2, y2 = p2

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            m = (3 * x1 * x1 + self.A) * pow(2 * y1, self.P - 2, self.P)
        else:
            m = (y1 - y2) * pow(x1 - x2, self.P - 2, self.P)

        m = m % self.P
        x3 = (m * m - x1 - x2) % self.P
        y3 = (m * (x1 - x3) - y1) % self.P
        return (x3, y3)

    def scalar_mult(self, k, point):
        """Double-and-add algoritması"""
        result = None
        addend = point

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result