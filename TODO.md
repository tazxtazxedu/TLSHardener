# TLSHardener - Yapılacaklar Listesi

> Son Güncelleme: 2025-11-29
> Versiyon: 3.4

---

## ✅ Tamamlananlar

- [x] TLS 1.1 tutarsızlığı düzeltildi (Client'ta true idi → false yapıldı)
- [x] TLS 1.2 mantık hatası düzeltildi (artık her zaman `true`)
- [x] Proje yeniden adlandırıldı: **TLSHardener**
- [x] Dosya ve klasör yapısı düzenlendi:
  - `jsons/` → `config/`
  - `icons/` → `assets/`
  - `ProtocolConfigV2.8.ps1` → `TLSHardener.ps1`
  - `CleanProtocolConfigVersion2.3.ps1` → `TLSHardener-Clean.ps1`
  - `GenerateProtocolConfigReportv1.9.ps1` → `TLSHardener-Report.ps1`
- [x] Script header'ları ve versiyon numaraları güncellendi (v3.2)
- [x] Gereksiz dosya silindi (`deepseekexamplereport.ps1`)
- [x] **Yapılandırma basitleştirildi** ✅
  - Ayrı JSON dosyaları kaldırıldı (protocols, ciphers, hashes, key-exchange, ecc-curves)
  - Profil dosyaları config/ klasörüne taşındı
  - Varsayılan profil: "recommended"

---

## 🔐 Güvenlik İyileştirmeleri

- [x] **CBC Cipher Suite'leri kaldırıldı** (Öncelik: 🔴 Yüksek) ✅
  - BEAST/POODLE saldırılarına açık olan 10 CBC cipher kaldırıldı
  - Sadece GCM cipher'lar kullanılıyor
  - Sıralama optimize edildi: ECDSA > ECDHE-RSA > RSA

- [x] **DH Key Size artırıldı** (Öncelik: 🟡 Orta) ✅
  - Profillere göre: strict=4096, recommended=3072, compatible=2048
  - Hem Server hem Client için minimum key size ayarlandı

- [x] **Hash algoritmaları kontrolü** (Öncelik: 🟡 Orta) ✅
  - MD5 ve SHA1 kapalı (false)
  - SHA256, SHA384, SHA512 açık (true)

---

## ✨ Yeni Özellikler

- [x] **Dry-Run (-WhatIf) Modu** (Karmaşıklık: 🟢 Kolay) ✅
  - Değişiklik yapmadan önce ne yapılacağını gösterir
  - `.\TLSHardener.ps1 -WhatIf`
  - Tüm fonksiyonlara DryRun desteği eklendi

- [x] **Doğrulama Scripti oluşturuldu** (Karmaşıklık: 🟢 Kolay) ✅
  - Yapılandırma sonrası ayarların doğru uygulandığını test eder
  - Registry değerlerini okur ve beklenen değerlerle karşılaştırır
  - Profil bazlı doğrulama desteği
  - Renkli konsol çıktısı ve HTML rapor desteği
  - `.\TLSHardener-Verify.ps1` veya `.\TLSHardener-Verify.ps1 -ExportReport`

- [x] **Profil Desteği** (Karmaşıklık: 🟡 Orta) ✅
  - `config/` klasöründe profil dosyaları:
    - `strict.json` → TLS 1.3 only, maksimum güvenlik
    - `recommended.json` → TLS 1.2/1.3, dengeli güvenlik (varsayılan)
    - `compatible.json` → Eski sistemlerle uyumlu, CBC desteği
    - `custom.json` → Kullanıcı özelleştirmesi
  - `-Profile "strict|recommended|compatible|custom"` parametresi

- [x] **Rollback Özelliği** (Karmaşıklık: 🟡 Orta) ✅
  - Esnek rollback seçenekleri:
    - `.\TLSHardener.ps1 -Rollback` → Mevcut yedekleri listeler ve seçim yapılır
    - `.\TLSHardener.ps1 -Rollback -BackupFile "..."` → Belirli yedeği yükler
    - `.\TLSHardener.ps1 -Rollback -ToDefaults` → Windows varsayılanlarına döner
  - Aynı zaman damgalı tüm yedek dosyalarını gruplar ve birlikte yükler

- [x] **Uzak Sunucu Desteği** (Karmaşıklık: 🔴 Zor) ✅
  - `-ComputerName "Server01","Server02"` parametresi
  - `-Credential` ile kimlik bilgisi desteği
  - PowerShell Remoting (WinRM) kullanır
  - Toplu sunucu yapılandırması
  - Bağlantı testi ve hata yönetimi
  - CSV sonuç raporu

- [x] **Compliance Raporu** (Karmaşıklık: 🔴 Zor) ✅
  - `TLSHardener-Compliance.ps1` scripti oluşturuldu
  - PCI-DSS v4.0 uyumluluk kontrolü
  - NIST SP 800-52 Rev.2 kontrolü
  - HIPAA güvenlik gereksinimleri
  - CIS Benchmark kontrolleri
  - HTML rapor desteği (`-ExportReport`)
  - `.\TLSHardener-Compliance.ps1 -Standard All`

---

## 🛠️ Kod Kalitesi

- [x] **Tekrarlanan fonksiyonları birleştir** ✅
  - `Set-ProtocolsClients` ve `Set-ProtocolsServers` → `Set-Protocols -Type "Both"` olarak birleştirildi
  - ~40% kod azalması sağlandı

- [x] **Hata yönetimini geliştir** ✅
  - `$script:ErrorCodes` hashtable ile merkezi hata kodu sistemi eklendi
  - `Write-TLSError` fonksiyonu ile standart hata yönetimi
  - Kategorize hata kodları: Genel (1000-1099), Profil (1100-1199), Registry (1200-1299), Uzak Sunucu (1300-1399), Dosya (1400-1499), Yapılandırma (1500-1599)
  - Tüm yapılandırma fonksiyonlarına try-catch ve ErrorAction Stop eklendi

- [ ] **Pester testleri ekle**
  - Unit testler için `tests/` klasörü
  - CI/CD entegrasyonu

---

## 📚 Dokümantasyon

- [x] **README.md oluşturuldu** ✅
  - Kurulum talimatları
  - Kullanım örnekleri
  - Parametre açıklamaları
  - Uyumluluk notları
  - Sorun giderme

- [x] **CHANGELOG.md oluşturuldu** ✅
  - Versiyon geçmişi (v2.0 → v3.1)
  - Semantic Versioning formatı
  - Keep a Changelog standardı
  - Versiyon geçmişi
  - Yapılan değişiklikler

---

## 📝 Notlar

- Script Windows Server 2016, 2019, 2022, 2025 ile uyumlu
- TLS 1.3 sadece Windows Server 2022+ destekliyor
- Değişiklikler yeniden başlatma gerektirebilir

---

## 🏷️ Öncelik Açıklamaları

| Emoji | Anlam |
|-------|-------|
| 🔴 | Yüksek öncelik / Zor |
| 🟡 | Orta öncelik / Orta |
| 🟢 | Düşük öncelik / Kolay |
