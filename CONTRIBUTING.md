# 🤝 Katkıda Bulunma Rehberi

TLSHardener projesine katkıda bulunmak istediğiniz için teşekkürler! Bu rehber, projeye nasıl katkıda bulunabileceğinizi açıklar.

## 📋 İçindekiler

- [Davranış Kuralları](#davranış-kuralları)
- [Nasıl Katkıda Bulunabilirim?](#nasıl-katkıda-bulunabilirim)
- [Geliştirme Ortamı](#geliştirme-ortamı)
- [Kod Standartları](#kod-standartları)
- [Pull Request Süreci](#pull-request-süreci)

---

## 📜 Davranış Kuralları

Bu proje, saygılı ve kapsayıcı bir ortam sağlamayı amaçlar. Lütfen:

- Yapıcı eleştiri yapın
- Farklı görüşlere saygı gösterin
- Topluluk üyelerine karşı nazik olun
- Profesyonel bir dil kullanın

---

## 🚀 Nasıl Katkıda Bulunabilirim?

### 🐛 Hata Bildirimi

1. [Issues](https://github.com/kullanici/TLSHardener/issues) sayfasını kontrol edin
2. Aynı hata daha önce bildirilmemişse yeni bir issue açın
3. Şu bilgileri ekleyin:
   - Windows ve PowerShell sürümü
   - Adım adım tekrarlama yöntemi
   - Beklenen ve gerçekleşen davranış
   - Hata mesajları ve log çıktıları

### 💡 Özellik Önerisi

1. [Issues](https://github.com/kullanici/TLSHardener/issues) sayfasında "Feature Request" açın
2. Özelliğin amacını ve kullanım senaryosunu açıklayın
3. Mümkünse örnek kod veya tasarım ekleyin

### 🔧 Kod Katkısı

1. Repository'yi fork edin
2. Feature branch oluşturun: `git checkout -b feature/YeniOzellik`
3. Değişikliklerinizi yapın
4. Testlerinizi çalıştırın
5. Commit edin: `git commit -m 'Yeni özellik: Açıklama'`
6. Push edin: `git push origin feature/YeniOzellik`
7. Pull Request açın

---

## 🛠️ Geliştirme Ortamı

### Gereksinimler

- Windows 10/11 veya Windows Server 2016+
- PowerShell 5.1 veya PowerShell 7+
- VS Code (önerilen) + PowerShell extension
- Git

### Kurulum

```powershell
# Repository'yi klonlayın
git clone https://github.com/KULLANICI/TLSHardener.git
cd TLSHardener

# Test modunda çalıştırın
.\TLSHardener.ps1 -WhatIf
```

---

## 📝 Kod Standartları

### PowerShell Kuralları

```powershell
# ✅ Doğru: Açıklayıcı fonksiyon isimleri
function Set-TlsProtocol {
    param(
        [Parameter(Mandatory)]
        [string]$Protocol,
        
        [bool]$Enabled = $true
    )
}

# ❌ Yanlış: Kısa ve belirsiz isimler
function SetTls { }
```

### Yorum Standartları

```powershell
# Fonksiyonlar için Synopsis kullanın
<#
.SYNOPSIS
    Protokol yapılandırmasını ayarlar.

.DESCRIPTION
    TLS/SSL protokollerini etkinleştirir veya devre dışı bırakır.

.PARAMETER Protocol
    Yapılandırılacak protokol adı.

.EXAMPLE
    Set-TlsProtocol -Protocol "TLS 1.2" -Enabled $true
#>
```

### Loglama

```powershell
# Tüm önemli işlemler loglanmalı
Write-Log "İşlem başladı" -LogType Info
Write-Log "Hata oluştu: $_" -LogType Error
```

---

## 🔄 Pull Request Süreci

### PR Açmadan Önce

- [ ] Kod çalışıyor mu?
- [ ] `.\TLSHardener.ps1 -WhatIf` başarılı mı?
- [ ] Yeni özellik için dokümantasyon eklendi mi?
- [ ] CHANGELOG.md güncellendi mi?

### PR Açıklaması

```markdown
## Açıklama
Bu PR şunları ekler/düzeltir:
- ...

## Test
- [ ] Windows Server 2019'da test edildi
- [ ] Windows Server 2022'de test edildi
- [ ] Dry-Run modu test edildi

## İlgili Issue
Fixes #123
```

### Review Süreci

1. En az 1 reviewer onayı gerekli
2. Tüm CI testleri geçmeli
3. Merge conflict olmamalı

---

## 📞 Sorularınız mı var?

- [Discussions](https://github.com/kullanici/TLSHardener/discussions) sayfasında sorun
- Mevcut [Issues](https://github.com/kullanici/TLSHardener/issues) kontrol edin

---

Katkılarınız için teşekkürler! 🙏
