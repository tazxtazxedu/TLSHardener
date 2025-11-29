# 🔐 TLSHardener

Windows sunucularda TLS/SSL güvenlik yapılandırmasını otomatik olarak sıkılaştıran PowerShell scripti.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2016%20|%202019%20|%202022%20|%202025-0078D6.svg)](https://www.microsoft.com/en-us/windows-server)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📋 İçindekiler

- [Özellikler](#-özellikler)
- [Gereksinimler](#-gereksinimler)
- [Kurulum](#-kurulum)
- [Kullanım](#-kullanım)
- [Yapılandırma Dosyaları](#-yapılandırma-dosyaları)
- [Güvenlik Ayarları](#-güvenlik-ayarları)
- [Uyumluluk](#-uyumluluk)
- [Sorun Giderme](#-sorun-giderme)
- [Katkıda Bulunma](#-katkıda-bulunma)

---

## ✨ Özellikler

| Özellik | Açıklama |
|---------|----------|
| 🔒 **Protokol Yönetimi** | SSL 2.0/3.0, TLS 1.0/1.1 devre dışı, TLS 1.2/1.3 etkin |
| 🛡️ **Cipher Suite Optimizasyonu** | Sadece GCM modlu güvenli cipher'lar |
| 🔑 **DH Key Size** | Minimum 3072-bit Diffie-Hellman anahtarı |
| #️⃣ **Hash Algoritmaları** | MD5/SHA1 kapalı, SHA256/384/512 açık |
| 📦 **Otomatik Yedekleme** | Registry değişikliklerinden önce yedek alır |
| 👁️ **Dry-Run Modu** | Değişiklik yapmadan önizleme (-WhatIf) |
| 🎯 **Profil Desteği** | strict/recommended/compatible profilleri |
| ✅ **Doğrulama Scripti** | Yapılandırma sonrası kontrol |
| 📝 **Detaylı Loglama** | Tüm işlemler loglanır |
| ⚙️ **JSON Yapılandırma** | Kolay özelleştirilebilir config dosyaları |

---

## 📦 Gereksinimler

### Sistem Gereksinimleri

| Gereksinim | Minimum |
|------------|---------|
| İşletim Sistemi | Windows Server 2016+ veya Windows 10+ |
| PowerShell | 5.1 veya üzeri |
| Yetki | Administrator |
| TLS 1.3 Desteği | Windows Server 2022+ / Windows 11+ |

### Ön Koşullar

```powershell
# PowerShell versiyonunu kontrol et
$PSVersionTable.PSVersion

# Administrator olarak çalıştığını doğrula
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
```

---

## 📥 Kurulum

### Yöntem 1: Git Clone

```powershell
git clone https://github.com/kullanici/TLSHardener.git
cd TLSHardener
```

### Yöntem 2: Manuel İndirme

1. Repository'yi ZIP olarak indirin
2. İstediğiniz klasöre çıkartın
3. PowerShell'i Administrator olarak açın

---

## 🚀 Kullanım

### Temel Kullanım

```powershell
# Standart çalıştırma (onay ister)
.\TLSHardener.ps1

# Onay istemeden çalıştır
.\TLSHardener.ps1 -BypassConfirmation

# .NET Strong Crypto ile çalıştır
.\TLSHardener.ps1 -EnableStrongCrypto

# Tüm parametrelerle
.\TLSHardener.ps1 -BypassConfirmation -EnableStrongCrypto
```

### 🎯 Profil Kullanımı

Farklı güvenlik seviyeleri için hazır profiller:

```powershell
# Strict profil - Maksimum güvenlik, sadece TLS 1.3
.\TLSHardener.ps1 -Profile strict

# Recommended profil - Dengeli güvenlik (varsayılan ayarlar)
.\TLSHardener.ps1 -Profile recommended

# Compatible profil - Eski sistemlerle uyumlu
.\TLSHardener.ps1 -Profile compatible

# Profil ile Dry-Run
.\TLSHardener.ps1 -Profile strict -WhatIf
```

#### Profil Karşılaştırması

| Özellik | Strict | Recommended | Compatible |
|---------|--------|-------------|------------|
| **TLS 1.2** | ❌ Kapalı | ✅ Açık | ✅ Açık |
| **TLS 1.3** | ✅ Açık | ✅ Açık | ✅ Açık |
| **CBC Cipher** | ❌ Yasak | ❌ Yasak | ✅ İzin |
| **DH Key Size** | 4096 bit | 3072 bit | 2048 bit |
| **AES-128** | ❌ Kapalı | ✅ Açık | ✅ Açık |
| **Cipher Sayısı** | 2 | 9 | 15 |
| **Uyumluluk** | Düşük | Orta | Yüksek |
| **Güvenlik** | Maksimum | Yüksek | Orta |

### Dry-Run Modu (Önizleme)

Hiçbir değişiklik yapmadan ne olacağını görmek için:

```powershell
.\TLSHardener.ps1 -WhatIf
```

Örnek çıktı:
```
╔════════════════════════════════════════════════════════════════╗
║                    DRY-RUN MODU AKTİF                          ║
║  Hiçbir değişiklik yapılmayacak, sadece önizleme gösterilecek  ║
╚════════════════════════════════════════════════════════════════╝

[DRY-RUN] PROTOKOL[Client] : TLS 1.0 -> DISABLED
[DRY-RUN] PROTOKOL[Client] : TLS 1.2 -> ENABLED
[DRY-RUN] CIPHER SUITES : TLS 1.3 ve TLS 1.2 -> 9 cipher suite yapılandırılacak
...
```

### Diğer Scriptler

```powershell
# Mevcut TLS yapılandırmasını raporla
.\TLSHardener-Report.ps1

# Yapılandırmayı temizle/sıfırla
.\TLSHardener-Clean.ps1

# Yapılandırmayı doğrula
.\TLSHardener-Verify.ps1

# Profil bazlı doğrulama
.\TLSHardener-Verify.ps1 -Profile recommended

# HTML rapor ile doğrulama
.\TLSHardener-Verify.ps1 -Profile strict -ExportReport
```

### 🔄 Rollback (Geri Alma)

Yapılandırmayı geri almak için esnek seçenekler:

```powershell
# İnteraktif mod - mevcut yedekleri listeler ve seçim yaparsınız
.\TLSHardener.ps1 -Rollback

# Belirli bir yedek dosyasını yükle
.\TLSHardener.ps1 -Rollback -BackupFile ".\backups\20251129_103045_SCHANNEL.reg"

# Windows varsayılanlarına dön (tüm TLS ayarlarını temizle)
.\TLSHardener.ps1 -Rollback -ToDefaults

# Onay istemeden rollback
.\TLSHardener.ps1 -Rollback -ToDefaults -BypassConfirmation
```

Rollback işlemi sırasında:
- Aynı zaman damgalı tüm yedek dosyaları gruplandırılır
- Seçilen yedek grubundaki tüm dosyalar birlikte yüklenir
- Yedek yoksa Windows varsayılanlarına dönme seçeneği sunulur

### 📋 Compliance Raporu (Uyumluluk Kontrolü)

Güvenlik standartlarına uyumluluğu kontrol edin:

```powershell
# Tüm standartları kontrol et
.\TLSHardener-Compliance.ps1

# Sadece belirli bir standart
.\TLSHardener-Compliance.ps1 -Standard PCI-DSS
.\TLSHardener-Compliance.ps1 -Standard NIST
.\TLSHardener-Compliance.ps1 -Standard HIPAA
.\TLSHardener-Compliance.ps1 -Standard CIS

# HTML rapor oluştur
.\TLSHardener-Compliance.ps1 -ExportReport

# HTML rapor oluştur ve tarayıcıda aç
.\TLSHardener-Compliance.ps1 -OpenReport

# Detaylı açıklamalar
.\TLSHardener-Compliance.ps1 -Detailed
```

Desteklenen standartlar:
| Standart | Açıklama |
|----------|----------|
| **PCI-DSS v4.0** | Payment Card Industry Data Security Standard |
| **NIST SP 800-52** | Guidelines for TLS Implementations |
| **HIPAA** | Health Insurance Portability and Accountability Act |
| **CIS Benchmark** | Center for Internet Security Windows Hardening |

HTML Rapor Özellikleri:
- 📊 Büyük ve okunabilir yazı boyutları
- 🎨 Modern dark theme tasarım
- 📋 Tıklanabilir genişleyebilir bölümler (Accordion)
- ✅❌⚠️ Renkli durum ikonları
- 💡 Başarısız kontroller için çözüm önerileri

Örnek çıktı:
```
╔════════════════════════════════════════════════════════════════════╗
║          🔐 TLSHardener COMPLIANCE RAPORU v1.0                     ║
╚════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════
  📋 PCI-DSS v4.0
═══════════════════════════════════════════════════════════════════════

  ✅ [4.2.1.a] SSL 2.0 devre dışı
  ✅ [4.2.1.b] SSL 3.0 devre dışı
  ✅ [4.2.1.c] TLS 1.0 devre dışı
  ❌ [4.2.1.f] Zayıf cipher suite'ler devre dışı

═══════════════════════════════════════════════════════════════════════
  📊 UYUMLULUK ÖZETİ
═══════════════════════════════════════════════════════════════════════

  ✅ PCI-DSS - 85.7% uyumlu (6 geçti, 1 başarısız, 0 uyarı)
  ✅ NIST - 100% uyumlu (6 geçti, 0 başarısız, 0 uyarı)
  
  TOPLAM: 92.3% uyumlu
```

### ✅ Doğrulama Scripti

Yapılandırma sonrası ayarların doğru uygulandığını kontrol edin:

```powershell
# Temel doğrulama
.\TLSHardener-Verify.ps1

# Profil bazlı doğrulama (hangi profili uyguladıysanız ona göre)
.\TLSHardener-Verify.ps1 -Profile recommended

# HTML rapor oluştur
.\TLSHardener-Verify.ps1 -Profile strict -ExportReport
```

Örnek çıktı:
```
╔════════════════════════════════════════════════════════════════════╗
║              🔐 TLSHardener DOĞRULAMA SCRIPTİ v1.1                  ║
╚════════════════════════════════════════════════════════════════════╝

======================================================================
  PROTOKOL AYARLARI
======================================================================
  ✅ TLS 1.0 [Server]              Beklenen: Kapalı    Mevcut: Kapalı
  ✅ TLS 1.2 [Server]              Beklenen: Açık      Mevcut: Açık
  ✅ TLS 1.3 [Server]              Beklenen: Açık      Mevcut: Açık

======================================================================
  DOĞRULAMA ÖZETİ
======================================================================
  Toplam Kontrol  : 35
  ✅ Başarılı      : 32
  ❌ Başarısız     : 0
  ⚠️ Uyarı         : 3
  Başarı Oranı    : 91.4%
```

---

## 📁 Yapılandırma Dosyaları

Tüm profil ayarları `config/` klasöründeki JSON dosyalarında tutulur:

```
config/
├── strict.json          # Maksimum güvenlik (TLS 1.3 only)
├── recommended.json     # Önerilen ayarlar (varsayılan)
├── compatible.json      # Legacy uyumluluk
└── custom.json          # Kullanıcı özelleştirmesi
```

### Profil Dosyaları

Her profil tüm güvenlik ayarlarını tek dosyada tanımlar:

#### strict.json
```json
{
    "name": "Strict",
    "description": "Sadece TLS 1.3 ve en güçlü cipher'lar",
    "protocols": {
        "TLS 1.2": false,
        "TLS 1.3": true
    },
    "cipherSuitesTls13": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
    ],
    "dhMinKeySize": 4096,
    "allowCBC": false
}
```

#### recommended.json (Varsayılan)
```json
{
    "name": "Recommended", 
    "description": "TLS 1.2/1.3 ve GCM cipher'lar",
    "protocols": {
        "TLS 1.2": true,
        "TLS 1.3": true
    },
    "dhMinKeySize": 3072,
    "allowCBC": false
}
```

#### compatible.json
```json
{
    "name": "Compatible",
    "description": "Eski sistemlerle uyumlu, CBC dahil",
    "protocols": {
        "TLS 1.2": true,
        "TLS 1.3": true
    },
    "dhMinKeySize": 2048,
    "allowCBC": true
}
```

#### custom.json
```json
{
    "name": "Custom",
    "description": "Kendi ihtiyaçlarınıza göre düzenleyin",
    // recommended.json kopyası - özgürce düzenleyebilirsiniz
}
```

### Örnek: protocols-server.json

```json
{
  "Multi-Protocol Unified Hello": false,
  "PCT 1.0": false,
  "SSL 2.0": false,
  "SSL 3.0": false,
  "TLS 1.0": false,
  "TLS 1.1": false,
  "TLS 1.2": true,
  "TLS 1.3": true
}
```

### Örnek: cipher-suites-tls12.json

```json
{
    "$12CipherSuites": [
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256"
    ]
}
```

---

## 🔒 Güvenlik Ayarları

### Protokoller

| Protokol | Durum | Açıklama |
|----------|-------|----------|
| SSL 2.0 | ❌ Kapalı | Ciddi güvenlik açıkları |
| SSL 3.0 | ❌ Kapalı | POODLE saldırısına açık |
| TLS 1.0 | ❌ Kapalı | BEAST saldırısına açık |
| TLS 1.1 | ❌ Kapalı | Zayıf cipher desteği |
| TLS 1.2 | ✅ Açık | Güvenli (GCM ile) |
| TLS 1.3 | ✅ Açık | En güvenli |

### Cipher Suite'ler

#### TLS 1.3 (3 cipher - değiştirilemez)
```
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
```

#### TLS 1.2 (6 cipher - sadece GCM)
```
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  ← En güvenli
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384          ← Uyumluluk için
TLS_RSA_WITH_AES_128_GCM_SHA256
```

### Devre Dışı Bırakılan Özellikler

| Kategori | Devre Dışı |
|----------|------------|
| Cipher'lar | RC4, DES, 3DES, NULL |
| Hash | MD5, SHA1 |
| Mod | CBC (tüm cipher'lar) |
| Key Exchange | RSA (sadece ECDHE/DHE önerilir) |

### DH Key Size

| Ayar | Değer |
|------|-------|
| ServerMinKeyBitLength | 3072 bit |
| ClientMinKeyBitLength | 3072 bit |

---

## ⚠️ Uyumluluk

### Desteklenen Sistemler

| Sistem | TLS 1.2 | TLS 1.3 |
|--------|---------|---------|
| Windows Server 2022+ | ✅ | ✅ |
| Windows Server 2019 | ✅ | ❌ |
| Windows Server 2016 | ✅ | ❌ |
| Windows 11 | ✅ | ✅ |
| Windows 10 (1903+) | ✅ | ✅ |

### ❌ Uyumsuz İstemciler

Bu yapılandırma aşağıdaki eski sistemlerle **çalışmaz**:

| Sistem/Uygulama | Neden |
|-----------------|-------|
| Windows XP | TLS 1.2 desteği yok |
| Windows Vista | TLS 1.2 varsayılan değil |
| Internet Explorer 10 ve altı | Eski cipher desteği |
| Android 4.3 ve altı | GCM desteği yok |
| Java 7 ve altı | TLS 1.2 desteği sınırlı |
| OpenSSL 0.9.8 | Eski sürüm |

### 📌 Önemli Notlar

1. **Yeniden Başlatma**: Değişikliklerin tam olarak uygulanması için sunucuyu yeniden başlatmanız gerekebilir.

2. **Test Edin**: Üretim ortamına uygulamadan önce test ortamında deneyin.

3. **Yedekleme**: Script otomatik yedek alır ancak manuel yedek de almanız önerilir.

4. **Eski Uygulamalar**: Eski .NET uygulamaları için `-EnableStrongCrypto` parametresini kullanın.

---

## 🔧 Sorun Giderme

### Yaygın Sorunlar

#### 1. "Erişim reddedildi" hatası
```powershell
# PowerShell'i Administrator olarak çalıştırın
Start-Process powershell -Verb runAs
```

#### 2. TLS 1.3 etkinleştirilemiyor
```powershell
# Windows sürümünü kontrol edin
[System.Environment]::OSVersion.Version
# TLS 1.3 için: Windows Server 2022+ veya Windows 11+ gerekli
```

#### 3. Uygulama bağlantı hatası
```powershell
# .NET uygulamaları için Strong Crypto etkinleştirin
.\TLSHardener.ps1 -EnableStrongCrypto
```

#### 4. Yedekten geri yükleme
```powershell
# backups/ klasöründeki .reg dosyasını çift tıklayın
# veya
reg import .\backups\Protocol_Script_YYYYMMDD_HHMMSS_SCHANNEL.reg
```

### Log Dosyaları

Loglar `logs/` klasöründe tutulur:
```
logs/TLSHardener_2025_11_29_1430.log
```

---

## 📊 Compliance (Uyumluluk Standartları)

Bu yapılandırma aşağıdaki standartlarla uyumludur:

| Standart | Durum | Notlar |
|----------|-------|--------|
| PCI-DSS 4.0 | ✅ | TLS 1.2+ zorunlu |
| NIST SP 800-52 Rev. 2 | ✅ | GCM cipher önerisi |
| HIPAA | ✅ | Güçlü şifreleme |
| GDPR | ✅ | Veri şifreleme |
| CIS Benchmark | ✅ | Windows Server hardening |

---

## 📂 Proje Yapısı

```
TLSHardener/
├── TLSHardener.ps1           # Ana script
├── TLSHardener-Verify.ps1    # Doğrulama scripti
├── TLSHardener-Compliance.ps1 # Uyumluluk raporu scripti
├── TLSHardener-Report.ps1    # Raporlama scripti
├── TLSHardener-Clean.ps1     # Temizleme scripti
├── README.md                 # Bu dosya
├── CHANGELOG.md              # Versiyon geçmişi
├── TODO.md                   # Yapılacaklar listesi
├── config/                   # Profil yapılandırma dosyaları
│   ├── strict.json           # Maksimum güvenlik (TLS 1.3 only)
│   ├── recommended.json      # Önerilen (varsayılan)
│   ├── compatible.json       # Legacy uyumluluk
│   └── custom.json           # Kullanıcı özelleştirmesi
├── assets/                   # Görseller
├── backups/                  # Otomatik yedekler
├── logs/                     # Log dosyaları
└── reports/                  # Doğrulama ve uyumluluk raporları
```

---

## 🤝 Katkıda Bulunma

1. Bu repository'yi fork edin
2. Feature branch oluşturun (`git checkout -b feature/YeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Yeni özellik eklendi'`)
4. Branch'inizi push edin (`git push origin feature/YeniOzellik`)
5. Pull Request açın

---

## 📜 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 📞 İletişim

- **Proje**: [GitHub Repository](https://github.com/kullanici/TLSHardener)
- **Sorunlar**: [Issues](https://github.com/kullanici/TLSHardener/issues)

---

## 🙏 Teşekkürler

- Microsoft TLS/SSL güvenlik dokümantasyonu
- NIST kriptografik standartları
- Açık kaynak topluluğu

---

<div align="center">

**⭐ Bu proje işinize yaradıysa yıldız vermeyi unutmayın! ⭐**

</div>
