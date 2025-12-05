# Şifreli İstemci-Sunucu Uygulaması

Bu Python uygulaması, Tkinter GUI kullanarak modern bir arayüz sunar ve çeşitli şifreleme yöntemleri içerir.

- **Proje çıktı detayları için rapor.txt dosyasına bakınız.**

## Özellikler

- **GUI İstemci**: Tkinter ile modern arayüz
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
  - AES (CBC, 256-bit anahtar türetme)
  - DES (CBC, 64-bit anahtar türetme)

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

### 12. DES Şifreleme
- **Mod**: CBC
- **Parametreler**: Anahtar (en az 8 karakter, MD5 ile 8 bayta türetilir), isteğe bağlı IV
- **Not**: IV girilmezse rastgele üretilir ve mesajın başına eklenir.

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
- **12 Farklı Şifreleme Yöntemi**: Klasik ve modern şifreleme algoritmaları
- **Kullanıcı Dostu Arayüz**: Kolay kullanım için modern GUI
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
