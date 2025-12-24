import random
import hashlib


class ECCCipher:
    """
    Basit ECDH (Elliptic Curve Diffie-Hellman) Implementasyonu.
    Eğri: P-256 (secp256r1, NIST P-256) parametreleri.
    PyCryptodome ile uyumlu olması için P-256 kullanılıyor (secp256k1 desteklenmiyor).
    Amaç: İki tarafın ortak bir gizli anahtar (session key) oluşturması.
    """

    # P-256 (secp256r1) Parametreleri - PyCryptodome ile uyumlu
    # Prime modulus: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    # a = -3 (mod p)
    A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    # b parameter
    B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    # Generator point G
    G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
         0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
    # Order n
    N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

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
        return hashlib.sha256(secret_bytes).digest()  # BYTES olarak döndür (32 byte)

    # --- Matematiksel Yardımcı Fonksiyonlar (Manuel Implementasyon) ---

    def point_add(self, p1, p2):
        if p1 is None: return p2
        if p2 is None: return p1

        x1, y1 = p1
        x2, y2 = p2

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            # Point doubling: m = (3x^2 + a) / (2y) where a = -3 for P-256
            # So: m = (3x^2 - 3) / (2y) = 3(x^2 - 1) / (2y)
            m = ((3 * x1 * x1 - 3) % self.P) * pow(2 * y1, self.P - 2, self.P)
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