# 🔐 TLSHardener

**Automated TLS/SSL Security Hardening for Windows Server**  
**Windows Sunucular için Otomatik TLS/SSL Güvenlik Sıkılaştırma**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2016%20|%202019%20|%202022%20|%202025-0078D6.svg)](https://www.microsoft.com/en-us/windows-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.6-orange.svg)](CHANGELOG.md)

---

## 🌍 Language / Dil

| 🇬🇧 English | 🇹🇷 Türkçe |
|:----------:|:----------:|
| [**📖 English Documentation**](EN/README.md) | [**📖 Türkçe Dokümantasyon**](TR/README.md) |
| [EN/TLSHardener.ps1](EN/TLSHardener.ps1) | [TR/TLSHardener.ps1](TR/TLSHardener.ps1) |

---

## 🔍 Keywords / Anahtar Kelimeler

### 🇬🇧 English Keywords
`TLS` `SSL` `Security` `Hardening` `Windows Server` `PowerShell` `SCHANNEL` `Cipher Suites` `PCI-DSS` `NIST` `HIPAA` `CIS` `TLS 1.3` `TLS 1.2` `Registry` `Compliance` `Encryption` `Certificate` `Protocol` `Vulnerability` `Security Audit` `Server Hardening` `Cryptography` `AES-GCM` `SHA256` `ECDHE` `Best Practices` `Windows Security` `Network Security` `SSL Disable` `TLS Enable` `Cipher Configuration`

### 🇹🇷 Türkçe Anahtar Kelimeler
`TLS` `SSL` `Güvenlik` `Sıkılaştırma` `Windows Sunucu` `PowerShell` `SCHANNEL` `Şifreleme Paketleri` `PCI-DSS` `NIST` `HIPAA` `CIS` `TLS 1.3` `TLS 1.2` `Registry` `Uyumluluk` `Şifreleme` `Sertifika` `Protokol` `Güvenlik Açığı` `Güvenlik Denetimi` `Sunucu Sıkılaştırma` `Kriptografi` `AES-GCM` `SHA256` `ECDHE` `En İyi Uygulamalar` `Windows Güvenliği` `Ağ Güvenliği` `SSL Devre Dışı` `TLS Etkinleştirme` `Cipher Yapılandırma`

---

## ⚠️ Important Warning / Önemli Uyarı

> **🇬🇧 ENGLISH:** Always create a system backup before running this script! Registry changes can cause irreversible issues. Test with `-WhatIf` parameter first.
>
> **🇹🇷 TÜRKÇE:** Bu scripti çalıştırmadan önce mutlaka sistem yedeği alın! Registry değişiklikleri geri alınamaz sorunlara yol açabilir. Önce `-WhatIf` parametresi ile test edin.

---

## ✨ Features / Özellikler

| 🇬🇧 Feature | 🇹🇷 Özellik |
|-------------|-------------|
| 🔒 Disable SSL 2.0/3.0, TLS 1.0/1.1 | 🔒 SSL 2.0/3.0, TLS 1.0/1.1 devre dışı |
| ✅ Enable TLS 1.2/1.3 | ✅ TLS 1.2/1.3 etkinleştirme |
| 🛡️ GCM-only cipher suites | 🛡️ Sadece GCM cipher suite'leri |
| 🔑 3072-bit DH key minimum | 🔑 Minimum 3072-bit DH anahtarı |
| 📊 PCI-DSS, NIST, HIPAA, CIS compliance | 📊 PCI-DSS, NIST, HIPAA, CIS uyumluluğu |
| 📦 Automatic backup before changes | 📦 Değişiklik öncesi otomatik yedekleme |
| 👁️ Dry-run mode (-WhatIf) | 👁️ Önizleme modu (-WhatIf) |
| 🔄 Rollback support | 🔄 Geri alma desteği |
| 🌐 Remote server support | 🌐 Uzak sunucu desteği |

---

## 📥 Quick Start / Hızlı Başlangıç

```powershell
# Clone repository
git clone https://github.com/tazxtazxedu/TLSHardener.git
cd TLSHardener

# 🇬🇧 English version
.\EN\TLSHardener.ps1 -WhatIf              # Preview
.\EN\TLSHardener.ps1 -Profile recommended  # Apply

# 🇹🇷 Türkçe versiyon
.\TR\TLSHardener.ps1 -WhatIf              # Önizleme
.\TR\TLSHardener.ps1 -Profile recommended  # Uygula
```

---

## 📂 Project Structure / Proje Yapısı

```
TLSHardener/
├── 📁 EN/                    # 🇬🇧 English scripts & docs
│   ├── TLSHardener.ps1
│   ├── TLSHardener-Verify.ps1
│   ├── TLSHardener-Compliance.ps1
│   ├── TLSHardener-Report.ps1
│   ├── TLSHardener-Clean.ps1
│   ├── README.md
│   ├── 📁 config/            # English profile configs
│   │   ├── strict.json
│   │   ├── recommended.json
│   │   ├── compatible.json
│   │   └── custom.json
│   └── 📁 assets/            # Icons & images
├── 📁 TR/                    # 🇹🇷 Türkçe scriptler & dokümanlar
│   ├── TLSHardener.ps1
│   ├── TLSHardener-Verify.ps1
│   ├── TLSHardener-Compliance.ps1
│   ├── TLSHardener-Report.ps1
│   ├── TLSHardener-Clean.ps1
│   ├── README.md
│   ├── 📁 config/            # Türkçe profil yapılandırmaları
│   │   ├── strict.json
│   │   ├── recommended.json
│   │   ├── compatible.json
│   │   └── custom.json
│   └── 📁 assets/            # Icons & images
├── 📄 README.md              # This file (bilingual)
├── 📄 LICENSE                # MIT License
├── 📄 CHANGELOG.md           # Version history
├── 📄 CONTRIBUTING.md        # Contribution guide
└── 📄 SECURITY.md            # Security policy
```

---

## 📊 Compliance Standards / Uyumluluk Standartları

| Standard | Status | Description |
|----------|:------:|-------------|
| **PCI-DSS v4.0** | ✅ | Payment Card Industry Data Security |
| **NIST SP 800-52** | ✅ | TLS Implementation Guidelines |
| **HIPAA** | ✅ | Healthcare Security Requirements |
| **CIS Benchmark** | ✅ | Windows Server Hardening |
| **GDPR** | ✅ | Data Protection (Encryption) |

---

## 📜 License / Lisans

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) for details.

Bu proje **MIT Lisansı** altında lisanslanmıştır - detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 🤝 Contributing / Katkıda Bulunma

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Katkı rehberi için [CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bakın.

---

## 📞 Contact / İletişim

- **GitHub**: [tazxtazxedu/TLSHardener](https://github.com/tazxtazxedu/TLSHardener)
- **Issues**: [Report a bug / Hata bildir](https://github.com/tazxtazxedu/TLSHardener/issues)

---

<div align="center">

**⭐ Star this repo if it helped you! / Yardımcı olduysa yıldız verin! ⭐**

Made with ❤️ for Windows Server Security

</div>
