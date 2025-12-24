# Şifreli İstemci-Sunucu Uygulaması

Bu Python uygulaması, Tkinter GUI kullanarak modern bir arayüz sunar ve çeşitli şifreleme yöntemleri içerir.

- **Proje çıktı detayları için rapor.txt dosyasına bakınız.**

## Özellikler

- **GUI İstemci**: Tkinter ile modern, şık arayüz
- **Sunucu**: Socket tabanlı çoklu istemci desteği
- **Şifreleme Yöntemleri**:
  - Caesar Şifreleme
  - Vigenere Şifreleme
  - Substitution Şifreleme
  - Rail Fence Şifreleme
  - Affine Şifreleme
  - Route Şifreleme
  - Columnar Transposition Şifreleme
  - Polybius Şifreleme
  - Pigpen Şifreleme
  - Hill Şifreleme
  - **AES-128** (CBC, Manuel - S-box tabloları olmadan dinamik hesaplama)
  - **AES-128** (CBC, Kütüphane - PyCryptodome)
  - **AES-128 + RSA** (Anahtar dağıtımı için RSA)
  - **AES-128 + ECC** (Anahtar dağıtımı için ECC, sadece manuel)
  - **DES** (CBC, Manuel)
  - **DES** (CBC, Kütüphane - PyCryptodome)
  - **DES + RSA** (Anahtar dağıtımı için RSA)
  - **DES + ECC** (Anahtar dağıtımı için ECC, sadece manuel)
  - **RSA** (Anahtar dağıtımı - Manuel implementasyon, 1024-bit)
  - **ECC** (Anahtar dağıtımı - Manuel implementasyon, P-256 eğrisi, ECDH)

## Kurulum

1. Python 3.7+ gereklidir.
2. Tüm şifrelemeler standart kütüphaneleri kullanır. Herhangi bir kütüphane eklemenize gerek yoktur.

## Kullanım

### Sunucuyu Başlatma

```bash
cd python_client_server
python run_server.py
```

### İstemciyi Başlatma

```bash
cd python_client_server
python run_client.py
```

## Şifreleme Yöntemleri

### 1. Caesar Şifreleme
- **Parametre**: Kaydırma miktarı (shift)
- **Örnek**: Shift=3 için "ABC" → "DEF"

### 2. Vigenere Şifreleme
- **Parametre**: Anahtar kelime
- **Örnek**: Anahtar="KEY" ile "HELLO" → "RIJVS"

### 3. Substitution Şifreleme
- **Parametre**: 26 harflik alfabe karışımı
- **Örnek**: "QWERTYUIOPASDFGHJKLZXCVBNM" ile A→Q, B→W, vb.

### 4. Rail Fence Şifreleme
- **Parametre**: Ray sayısı
- **Örnek**: 3 ray ile "HELLO" → "HOEL L"

### 5. Affine Şifreleme
- **Parametreler**: 
  - A: 1-25 arası, 26 ile aralarında asal
  - B: 0-25 arası
- **Formül**: E(x) = (ax + b) mod 26

### 6. Route Şifreleme
- **Parametreler**: 
  - Satır sayısı
  - Sütun sayısı
  - Rota türü (spiral, row, column, diagonal)
- **Örnek**: 3x3 spiral ile "HELLO" → "HOEL L"

### 7. Columnar Transposition Şifreleme
- **Parametre**: Anahtar kelime
- **Örnek**: Anahtar="KEY" ile "HELLO" → "HOEL L"

### 8. Polybius Şifreleme
- **Parametre**: 25 harflik alfabe (I ve J aynı pozisyon)
- **Örnek**: "HELLO" → "23 15 31 31 34"

### 9. Pigpen Şifreleme
- **Parametre**: Otomatik (sembol tabanlı)
- **Örnek**: Her harf özel sembol ile temsil edilir

### 10. Hill Şifreleme
- **Parametre**: Anahtar matris (2x2 veya 3x3)
- **Örnek**: [[3,3],[2,5]] matrisi ile "HELLO" → "RIJVS"

### 11. AES Şifreleme
- **Mod**: CBC (IV mesaj içinde taşınır)
- **Parametreler**: Anahtar (serbest uzunlukta, SHA-256 ile 32 bayta türetilir), isteğe bağlı IV
- **Not**: IV girilmezse rastgele üretilir ve mesajın başına eklenir.
- **Özel Özellik**: S-box tabloları kullanmadan, dinamik hesaplama ile implementasyon
  - Galois Field (GF(2^8)) matematik işlemleri
  - Multiplicative inverse hesaplama
  - Affine transformation
  - Her byte için S-box değeri runtime'da hesaplanır

### 12. DES Şifreleme
- **Mod**: CBC
- **Parametreler**: Anahtar (en az 8 karakter, MD5 ile 8 bayta türetilir), isteğe bağlı IV
- **Not**: IV girilmezse rastgele üretilir ve mesajın başına eklenir.

### 13. RSA Şifreleme (Anahtar Dağıtımı)
- **Kullanım Amacı**: Oturum anahtarlarını (AES/DES anahtarları) güvenli şekilde dağıtmak için
- **Anahtar Boyutu**: 1024-bit (varsayılan)
- **Algoritma**: Manuel implementasyon
  - Asal sayı üretimi (Miller-Rabin testi)
  - Key pair oluşturma (p, q asallarından n = p*q, e, d hesaplama)
  - Public Key: (e, n) - Şifreleme için
  - Private Key: (d, n) - Çözme için
- **Şifreleme**: c = m^e mod n
- **Çözme**: m = c^d mod n
- **Not**: RSA sadece oturum anahtarlarını şifrelemek için kullanılır. Gerçek mesajlar AES veya DES ile şifrelenir.
- **Akış**:
  1. Sunucu RSA key pair üretir (public + private key)
  2. Sunucu public key'i istemciye gönderir
  3. İstemci AES/DES oturum anahtarını üretir
  4. İstemci oturum anahtarını RSA public key ile şifreler
  5. Şifrelenmiş anahtar sunucuya gönderilir
  6. Sunucu RSA private key ile anahtarı çözer
  7. Çözülen anahtar ile mesajlar AES/DES ile şifrelenir

### 14. ECC (Elliptic Curve Cryptography) - Anahtar Dağıtımı
- **Kullanım Amacı**: Oturum anahtarlarını (AES/DES anahtarları) güvenli şekilde dağıtmak için
- **Eğri**: P-256 (secp256r1, NIST P-256)
- **Algoritma**: ECDH (Elliptic Curve Diffie-Hellman) - Manuel implementasyon
- **Parametreler**:
  - Prime modulus: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
  - Curve equation: y² = x³ - 3x + b (mod p)
  - Generator point G: (x, y) koordinatları
  - Order n: Eğrinin mertebesi
- **Matematiksel İşlemler**:
  - Point addition: İki noktanın toplamı
  - Scalar multiplication: Bir noktanın bir sayı ile çarpımı (double-and-add algoritması)
- **Anahtar Üretimi**:
  1. Her taraf rastgele bir private key seçer (1 < d < n)
  2. Public key = d * G (scalar multiplication)
  3. Public key'ler karşılıklı olarak paylaşılır
- **Ortak Sır Üretimi (ECDH)**:
  - Shared secret = private_key * other_public_key
  - Shared secret'in x koordinatı alınır
  - SHA-256 hash ile 32 byte anahtar üretilir
  - Bu anahtar AES/DES oturum anahtarı olarak kullanılır
- **Not**: ECC sadece manuel modda kullanılabilir (kütüphane modu desteklenmez)
- **Not**: ECC sadece oturum anahtarlarını üretmek için kullanılır. Gerçek mesajlar AES veya DES ile şifrelenir.
- **Akış**:
  1. Sunucu ECC key pair üretir (private + public key)
  2. Sunucu public key'i istemciye gönderir
  3. İstemci kendi ECC key pair'ini üretir
  4. İstemci kendi public key'ini sunucuya gönderir
  5. Her iki taraf da karşı tarafın public key'i ile kendi private key'ini kullanarak ortak sır üretir
  6. Ortak sırdan AES/DES oturum anahtarı türetilir
  7. Bu anahtar ile mesajlar AES/DES ile şifrelenir

## Proje Yapısı

```
python_client_server/
├── client/
│   ├── __init__.py
│   └── client.py          # GUI istemci
├── server/
│   ├── __init__.py
│   └── server.py          # Sunucu
├── encryption/
│   ├── __init__.py
│   ├── ciphers.py         # Şifreleme yöntemleri
│   └── ...
├── requirements.txt
└── README.md
```

## Özellikler

- **Gerçek Zamanlı İletişim**: İstemci ve sunucu arasında anlık mesajlaşma
- **Çoklu Şifreleme Yöntemi**: Klasik ve modern şifreleme algoritmaları
- **Modern Arayüz**: Şık, göze hitap eden GUI tasarımı
- **Performans Analizi**: Her mesaj için şifreleme süresi ölçümü
- **Anahtar Dağıtımı**: RSA ve ECC ile güvenli anahtar değişimi
- **Manuel ve Kütüphane Modları**: AES ve DES için hem manuel hem kütüphane implementasyonları
- **S-box Olmadan AES**: S-box tabloları kullanmadan dinamik hesaplama
- **Hata Yönetimi**: Kapsamlı hata yakalama ve kullanıcı bildirimleri
- **Threading**: Arayüz donmadan çoklu işlem desteği
- **Parametrik Şifreleme**: Her şifreleme yöntemi için özelleştirilebilir parametreler
- **Otomatik Şifre Çözme**: Sunucu tarafında otomatik şifre çözme desteği

## Notlar

- Sunucu varsayılan olarak 127.0.0.1:8001 adresinde çalışır
- İstemci otomatik olarak sunucuya bağlanmaya çalışır
- Şifreleme parametreleri değiştirildiğinde otomatik olarak güncellenir
- Bağlantı durumu arayüzde görüntülenir
- Tüm şifreleme yöntemleri hem şifreleme hem de şifre çözme destekler
- Hill şifreleme için matris determinantı 26 ile aralarında asal olmalıdır
- Polybius şifrelemede I ve J harfleri aynı pozisyonu paylaşır
- Route şifreleme farklı rota türleri destekler (spiral, satır, sütun, diagonal)
- **AES Manuel Mod**: S-box tabloları kullanmaz, her byte için Galois Field matematik işlemleri ile dinamik hesaplama yapar
- **RSA Anahtar Dağıtımı**: Sadece oturum anahtarlarını şifrelemek için kullanılır, mesajlar AES/DES ile şifrelenir
- **ECC Anahtar Dağıtımı**: Sadece manuel modda kullanılabilir, ECDH ile ortak sır üretilir
- **Performans Ölçümü**: Her mesaj için şifreleme/çözme süresi milisaniye cinsinden gösterilir
