# 📋 Changelog

Tüm önemli değişiklikler bu dosyada belgelenir.

Format [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) standardına uygundur,
ve bu proje [Semantic Versioning](https://semver.org/spec/v2.0.0.html) kullanır.

---

## [Yayınlanmamış]

### Planlanıyor
- Pester unit testleri
- CI/CD entegrasyonu

---

## [3.4.0] - 2025-11-29

### ✨ Eklendi
- **Uzak Sunucu Desteği**: Birden fazla sunucuyu tek komutla yapılandırma
  - `-ComputerName "Server01","Server02"` parametresi
  - `-Credential` ile kimlik bilgisi desteği
  - PowerShell Remoting (WinRM) kullanır
  - Bağlantı testi (Ping + WinRM)
  - Her sunucuda otomatik Registry yedekleme (`C:\TLSHardener-Backups\`)
  - CSV sonuç raporu (`.\reports\TLSHardener-Remote_*.csv`)
  - Dry-Run modu uzak sunucularda da çalışır
  - Profil desteği uzak sunucularda da çalışır
  - Tüm yapılandırma kategorileri: Protocols, Hashes, Ciphers, Key Exchange, DH Size, Cipher Suites, ECC Curves, FIPS, Strong Crypto
- **Compliance Raporu**: Güvenlik standartlarına uyumluluk kontrolü
  - `TLSHardener-Compliance.ps1` scripti
  - PCI-DSS v4.0 kontrolleri (SSL/TLS, cipher suite'ler, hash algoritmaları)
  - NIST SP 800-52 Rev.2 kontrolleri (TLS sürümleri, AEAD cipher'lar, key exchange)
  - HIPAA Technical Safeguards kontrolleri (şifreleme, iletim güvenliği)
  - CIS Benchmark kontrolleri (protokoller, NULL/RC4/DES cipher'lar)
  - `-Standard` parametresi: All, PCI-DSS, NIST, HIPAA, CIS
  - `-ExportReport` ile HTML rapor oluşturma
  - `-OpenReport` ile otomatik tarayıcıda açma
  - Accordion/collapsible bölümler ile modern HTML tasarım
  - Tek satır özet (Genel Uyumluluk + Başarılı/Uyarı/Başarısız)

### 🔄 Değişti
- Versiyon 3.3 → 3.4
- README.md güncellendi (Uzak Sunucu ve Compliance bölümleri)

---

## [3.3.0] - 2025-11-29

### ✨ Eklendi
- **Rollback Özelliği**: Esnek geri alma seçenekleri
  - `.\TLSHardener.ps1 -Rollback` → İnteraktif mod, yedekleri listeler
  - `.\TLSHardener.ps1 -Rollback -BackupFile "..."` → Belirli yedeği yükler
  - `.\TLSHardener.ps1 -Rollback -ToDefaults` → Windows varsayılanlarına döner
  - Aynı zaman damgalı yedek dosyaları gruplandırılır
  - Yedek yoksa Windows varsayılanlarına dönme seçeneği
- **custom.json** profili: Kullanıcı özelleştirmesi için şablon

### 🔄 Değişti
- Profil dosyaları `config/profiles/` → `config/` taşındı (basitleştirme)
- Ayrı JSON yapılandırma dosyaları kaldırıldı (tüm ayarlar profillerde)
- `Get-ConfigFromJson` fonksiyonu kaldırıldı (ölü kod temizliği)
- `UseProfile` değişkeni kaldırıldı (her zaman profil kullanılıyor)
- Tüm else blokları temizlendi (basitleştirme)

---

## [3.2.0] - 2025-11-29

### ✨ Eklendi
- **Profil Desteği**: Farklı güvenlik seviyeleri için hazır profiller
  - `strict.json`: Sadece TLS 1.3, maksimum güvenlik
  - `recommended.json`: TLS 1.2/1.3, dengeli güvenlik (varsayılan)
  - `compatible.json`: Eski sistemlerle uyumlu, CBC desteği
  - `-Profile "strict|recommended|compatible"` parametresi
  - Profil bilgisi konsol çıktısında gösterilir
- **TLSHardener-Verify.ps1**: Yapılandırma doğrulama scripti
  - Registry değerlerini kontrol eder
  - Beklenen değerlerle karşılaştırma
  - HTML rapor desteği (`-ExportReport`)
  - 0xFFFFFFFF değer okuma hatası düzeltildi (signed/unsigned int)

### 🔄 Değişti
- Tüm Set-* fonksiyonları profil desteği için güncellendi
- Profil aktifken profil ayarları kullanılır

---

## [3.1.0] - 2025-11-29

### ✨ Eklendi
- **Dry-Run (-WhatIf) Modu**: Değişiklik yapmadan önizleme
  - Tüm fonksiyonlara DryRun desteği eklendi
  - Renkli çıktı ile kolay okunabilirlik
  - `.\TLSHardener.ps1 -WhatIf` komutu ile kullanılabilir
- **README.md**: Kapsamlı dokümantasyon
  - Kurulum ve kullanım talimatları
  - Güvenlik ayarları açıklamaları
  - Uyumluluk tabloları
  - Sorun giderme rehberi
- **CHANGELOG.md**: Versiyon geçmişi takibi

### 🔒 Güvenlik İyileştirmeleri
- **DH Key Size artırıldı**: 2048 bit → 3072 bit
  - `ServerMinKeyBitLength` ve `ClientMinKeyBitLength` eklendi
  - Logjam saldırısına karşı koruma güçlendirildi
- **CBC Cipher Suite'leri kaldırıldı**: 10 adet güvensiz cipher silindi
  - BEAST/POODLE/Lucky13 saldırılarına karşı koruma
  - Sadece GCM modlu cipher'lar aktif
  - TLS 1.2 cipher sayısı: 18 → 6

### 🔄 Değişti
- Cipher suite sıralaması optimize edildi (ECDSA öncelikli)
- TLS 1.3 cipher sıralaması güncellendi (AES-256 önce)
- `key-exchange.json` dosyasına `DH-MinKeyBitLength` eklendi

---

## [3.0.0] - 2025-11-28

### 🎉 Büyük Değişiklikler
- **Proje yeniden adlandırıldı**: ProtocolConfig → **TLSHardener**
- **Dosya yapısı yenilendi**:
  - `jsons/` → `config/`
  - `icons/` → `assets/`
  - `ProtocolConfigV2.8.ps1` → `TLSHardener.ps1`
  - `CleanProtocolConfigVersion2.3.ps1` → `TLSHardener-Clean.ps1`
  - `GenerateProtocolConfigReportv1.9.ps1` → `TLSHardener-Report.ps1`

### 🔄 Değişti
- JSON dosyaları kebab-case formatına dönüştürüldü:
  - `protocolsClient.json` → `protocols-client.json`
  - `protocolsServer.json` → `protocols-server.json`
  - `tls12CipherSuites.json` → `cipher-suites-tls12.json`
  - `tls13CipherSuites.json` → `cipher-suites-tls13.json`
  - `hashAlgorithms.json` → `hashes.json`
  - `keyExchange.json` → `key-exchange.json`
  - `eccCurves.json` → `ecc-curves.json`
  - `encryptionAlgorithms.json` → `ciphers.json`
- Script header'ları ve versiyon numaraları güncellendi

### 🐛 Düzeltildi
- **TLS 1.1 Client tutarsızlığı**: `true` → `false` olarak düzeltildi
- **TLS 1.2 mantık hatası**: Her zaman `true` olacak şekilde düzeltildi

### 🗑️ Kaldırıldı
- `deepseekexamplereport.ps1` (gereksiz dosya)

---

## [2.8.0] - 2025-11-15

### ✨ Eklendi
- TLS 1.3 desteği (Windows Server 2022+ için)
- ECC Curves yapılandırması (NistP256, NistP384, NistP521)
- Dinamik OS versiyon kontrolü
- `-EnableStrongCrypto` parametresi (.NET Framework için)

### 🔄 Değişti
- Cipher suite'ler TLS 1.2 ve TLS 1.3 için ayrı dosyalara bölündü
- Log sistemi geliştirildi (renkli çıktı desteği)

---

## [2.7.0] - 2025-10-01

### ✨ Eklendi
- Otomatik registry yedekleme (`backups/` klasörü)
- `-BypassConfirmation` parametresi
- Detaylı loglama sistemi (`logs/` klasörü)

### 🔒 Güvenlik
- RC4, DES, 3DES, NULL cipher'lar devre dışı bırakıldı
- MD5 hash algoritması devre dışı bırakıldı

---

## [2.5.0] - 2025-08-15

### ✨ Eklendi
- JSON tabanlı yapılandırma sistemi
- FIPS Algorithm Policy ayarları
- Key Exchange algoritmaları yapılandırması

### 🔄 Değişti
- Hardcoded değerler JSON dosyalarına taşındı
- Fonksiyonlar modüler hale getirildi

---

## [2.0.0] - 2025-06-01

### 🎉 İlk Büyük Sürüm
- TLS 1.0 ve TLS 1.1 devre dışı bırakma
- TLS 1.2 etkinleştirme
- SSL 2.0 ve SSL 3.0 devre dışı bırakma
- Temel cipher suite yapılandırması
- Registry tabanlı yapılandırma

---

## Versiyon Numaralandırma

- **MAJOR** (X.0.0): Büyük değişiklikler, geriye uyumsuz
- **MINOR** (0.X.0): Yeni özellikler, geriye uyumlu
- **PATCH** (0.0.X): Hata düzeltmeleri

---

## Linkler

- [README](README.md)
- [TODO](TODO.md)
- [GitHub Repository](https://github.com/kullanici/TLSHardener)
