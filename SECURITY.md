# 🔒 Güvenlik Politikası

## Desteklenen Sürümler

| Sürüm | Destekleniyor |
|-------|---------------|
| 3.x   | ✅ Evet       |
| 2.x   | ❌ Hayır      |
| 1.x   | ❌ Hayır      |

## 🐛 Güvenlik Açığı Bildirimi

Eğer TLSHardener'da bir güvenlik açığı keşfettiyseniz, lütfen **herkese açık issue açmayın**.

### Bildirim Süreci

1. **E-posta gönderin**: Güvenlik açığını detaylı bir şekilde açıklayan e-posta gönderin
2. **Gizlilik**: Açık düzeltilene kadar güvenlik açığını herkese açık paylaşmayın
3. **48 saat**: İlk yanıtı 48 saat içinde almayı bekleyebilirsiniz

### Bildiriminize Şunları Ekleyin

- Güvenlik açığının açıklaması
- Tekrarlama adımları
- Potansiyel etki
- Varsa çözüm önerisi

## 🛡️ Güvenlik En İyi Uygulamaları

TLSHardener kullanırken:

1. **Yedekleme**: Script'i çalıştırmadan önce sistem yedeği alın
2. **Test Ortamı**: Üretim öncesi test ortamında deneyin
3. **Güncellemeler**: En son sürümü kullanın
4. **Loglar**: Log dosyalarını düzenli kontrol edin
5. **İzinler**: Script'i sadece Administrator olarak çalıştırın

## 📋 Güvenlik Denetim Listesi

Script çalıştırıldıktan sonra:

- [ ] `.\TLSHardener-Verify.ps1` ile doğrulama yapın
- [ ] `.\TLSHardener-Compliance.ps1` ile uyumluluk kontrolü yapın
- [ ] Kritik uygulamaların çalıştığını doğrulayın
- [ ] SSL Labs testi ile dış doğrulama yapın

---

Güvenlik endişeleriniz için teşekkürler! 🙏
