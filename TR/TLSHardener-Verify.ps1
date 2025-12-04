<#
.ScriptName: TLSHardener-Verify.ps1
.SYNOPSIS
TLSHardener yapılandırmasının doğru uygulandığını kontrol eden doğrulama scripti.

.DESCRIPTION
Bu script aşağıdaki kontrolleri yapar:
- Protokol ayarlarını doğrular (TLS 1.0/1.1 kapalı, TLS 1.2/1.3 açık)
- Cipher suite'leri kontrol eder
- Hash algoritmaları ayarlarını doğrular
- Key Exchange ayarlarını kontrol eder
- Şifreleme algoritmalarını doğrular
- Sonuçları renkli tablo olarak gösterir
- Profil bazlı doğrulama desteği

.PARAMETER ExportReport
Sonuçları HTML raporu olarak dışa aktarır

.PARAMETER ReportPath
HTML raporunun kaydedileceği yol

.PARAMETER Profile
Doğrulama için kullanılacak profil (strict, recommended, compatible)

.EXAMPLE
.\TLSHardener-Verify.ps1
Standart doğrulama - sonuçları ekrana yazdırır

.EXAMPLE
.\TLSHardener-Verify.ps1 -ExportReport
HTML raporu oluşturur

.EXAMPLE
.\TLSHardener-Verify.ps1 -Profile strict
Strict profil ayarlarına göre doğrulama yapar

.EXAMPLE
.\TLSHardener-Verify.ps1 -Profile compatible -ExportReport
Compatible profil ile doğrulama yapar ve HTML rapor oluşturur

.EXAMPLE
.\TLSHardener-Verify.ps1 -Profile custom
Custom profil ayarlarına göre doğrulama yapar

.NOTES
    Proje      : TLSHardener
    Versiyon   : 3.5
    Yazar      : TLSHardener Contributors
    Lisans     : MIT
    Tarih      : 2025
    
    Gereksinimler:
    - Administrator yetkisi
    - Windows Server 2016+ veya Windows 10+
    - PowerShell 5.1+

.LINK
    https://github.com/tazxtazxedu/TLSHardener
#>

param (
    [switch]$ExportReport,
    [string]$ReportPath = ".\reports\TLSHardener-Verify_$(Get-Date -Format 'yyyy-MM-dd_HHmm').html",
    [ValidateSet("strict", "recommended", "compatible", "custom")]
    [string]$Profile = "recommended"
)

# Konsol kodlamasını UTF-8 olarak ayarla
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Aktif profil
$script:ActiveProfile = $null
$script:ProfileName = "Varsayılan"

# Profil yükleme fonksiyonu
function Load-VerifyProfile {
    param ([string]$ProfileName)
    
    $profilePath = ".\config\$ProfileName.json"
    
    if (-not (Test-Path $profilePath)) {
        Write-Host "  ⚠️ Profil bulunamadı: $profilePath" -ForegroundColor Yellow
        Write-Host "  Varsayılan ayarlarla devam ediliyor..." -ForegroundColor Gray
        return $false
    }
    
    try {
        $script:ActiveProfile = Get-Content -Path $profilePath -Raw | ConvertFrom-Json
        $script:ProfileName = $script:ActiveProfile.name
        return $true
    }
    catch {
        Write-Host "  ❌ Profil yüklenirken hata: $_" -ForegroundColor Red
        return $false
    }
}

# Profilden protokol beklentilerini al
function Get-ExpectedProtocols {
    if ($script:ActiveProfile -and $script:ActiveProfile.protocols) {
        $result = @{}
        foreach ($protocol in $script:ActiveProfile.protocols.PSObject.Properties) {
            $result[$protocol.Name] = $protocol.Value
        }
        return $result
    }
    
    # Varsayılan (recommended)
    return @{
        "Multi-Protocol Unified Hello" = $false
        "PCT 1.0"                       = $false
        "SSL 2.0"                       = $false
        "SSL 3.0"                       = $false
        "TLS 1.0"                       = $false
        "TLS 1.1"                       = $false
        "TLS 1.2"                       = $true
        "TLS 1.3"                       = $true
    }
}

# Profilden cipher beklentilerini al
function Get-ExpectedCiphers {
    if ($script:ActiveProfile -and $script:ActiveProfile.ciphers) {
        $result = @{}
        foreach ($cipher in $script:ActiveProfile.ciphers.PSObject.Properties) {
            $result[$cipher.Name] = $cipher.Value
        }
        return $result
    }
    
    # Varsayılan (recommended)
    return @{
        "AES 128/128"    = $true
        "AES 256/256"    = $true
        "DES 56/56"      = $false
        "NULL"           = $false
        "RC2 128/128"    = $false
        "RC2 40/128"     = $false
        "RC2 56/128"     = $false
        "RC4 128/128"    = $false
        "RC4 40/128"     = $false
        "RC4 56/128"     = $false
        "RC4 64/128"     = $false
        "Triple DES 168" = $false
    }
}

# Profilden hash beklentilerini al
function Get-ExpectedHashes {
    if ($script:ActiveProfile -and $script:ActiveProfile.hashes) {
        $result = @{}
        foreach ($hash in $script:ActiveProfile.hashes.PSObject.Properties) {
            $result[$hash.Name] = $hash.Value
        }
        return $result
    }
    
    # Varsayılan (recommended)
    return @{
        "MD5"    = $false
        "SHA"    = $false
        "SHA256" = $true
        "SHA384" = $true
        "SHA512" = $true
    }
}

# Profilden key exchange beklentilerini al
function Get-ExpectedKeyExchange {
    if ($script:ActiveProfile -and $script:ActiveProfile.keyExchange) {
        $result = @{}
        foreach ($ke in $script:ActiveProfile.keyExchange.PSObject.Properties) {
            $result[$ke.Name] = $ke.Value
        }
        return $result
    }
    
    # Varsayılan (recommended)
    return @{
        "Diffie-Hellman" = $true
        "ECDH"           = $true
        "PKCS"           = $true
    }
}

# Profilden DH Key Size beklentisini al
function Get-ExpectedDHKeySize {
    if ($script:ActiveProfile -and $script:ActiveProfile.dhMinKeySize) {
        return $script:ActiveProfile.dhMinKeySize
    }
    return 3072  # Varsayılan
}

# Profilden beklenen cipher suite'leri al
function Get-ExpectedCipherSuites {
    $expected = @()
    
    if ($script:ActiveProfile) {
        if ($script:ActiveProfile.cipherSuitesTls13) {
            $expected += $script:ActiveProfile.cipherSuitesTls13
        }
        if ($script:ActiveProfile.cipherSuitesTls12) {
            $expected += $script:ActiveProfile.cipherSuitesTls12
        }
    }
    
    if ($expected.Count -eq 0) {
        # Varsayılan recommended cipher'lar
        $expected = @(
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_GCM_SHA256"
        )
    }
    
    return $expected
}

# Profilden CBC izin durumunu al
function Get-AllowCBC {
    if ($script:ActiveProfile -and $null -ne $script:ActiveProfile.allowCBC) {
        return $script:ActiveProfile.allowCBC
    }
    return $false  # Varsayılan: CBC izin verilmez
}

# Renk tanımları
$script:Colors = @{
    Pass    = "Green"
    Fail    = "Red"
    Warning = "Yellow"
    Info    = "Cyan"
    Header  = "Magenta"
}

# Sonuç sayaçları
$script:Results = @{
    Passed  = 0
    Failed  = 0
    Warning = 0
    Total   = 0
}

# Sonuç listesi (rapor için)
$script:ResultList = @()

# Başlık yazdırma fonksiyonu
function Write-Header {
    param ([string]$Title)
    
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor $script:Colors.Header
    Write-Host "  $Title" -ForegroundColor $script:Colors.Header
    Write-Host ("=" * 70) -ForegroundColor $script:Colors.Header
}

# Sonuç yazdırma fonksiyonu
function Write-Result {
    param (
        [string]$Category,
        [string]$Item,
        [string]$Expected,
        [string]$Actual,
        [ValidateSet("Pass", "Fail", "Warning")]
        [string]$Status
    )
    
    $script:Results.Total++
    
    $icon = switch ($Status) {
        "Pass"    { "✅"; $script:Results.Passed++ }
        "Fail"    { "❌"; $script:Results.Failed++ }
        "Warning" { "⚠️"; $script:Results.Warning++ }
    }
    
    $color = $script:Colors[$Status]
    
    # Formatlı çıktı
    $itemPadded = $Item.PadRight(35)
    $expectedPadded = $Expected.PadRight(15)
    $actualPadded = $Actual.PadRight(15)
    
    Write-Host "  $icon " -NoNewline -ForegroundColor $color
    Write-Host "$itemPadded " -NoNewline
    Write-Host "Beklenen: " -NoNewline -ForegroundColor Gray
    Write-Host "$expectedPadded " -NoNewline -ForegroundColor White
    Write-Host "Mevcut: " -NoNewline -ForegroundColor Gray
    Write-Host "$actualPadded" -ForegroundColor $color
    
    # Rapor için kaydet
    $script:ResultList += [PSCustomObject]@{
        Category = $Category
        Item     = $Item
        Expected = $Expected
        Actual   = $Actual
        Status   = $Status
    }
}

# Registry değerini güvenli okuma
function Get-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        $Default = $null
    )
    
    try {
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $value) {
                return $value.$Name
            }
        }
        return $Default
    }
    catch {
        return $Default
    }
}

# Enabled değerini kontrol etme (0xFFFFFFFF = -1 olarak okunabilir)
function Test-IsEnabled {
    param ($value)
    
    if ($null -eq $value) { return $null }
    
    # 0xFFFFFFFF signed olarak -1, unsigned olarak 4294967295
    # 1 de enabled anlamına gelir
    return ($value -eq -1 -or $value -eq 0xFFFFFFFF -or $value -eq 4294967295 -or $value -eq 1)
}

# Protokol doğrulama
function Test-Protocols {
    Write-Header "PROTOKOL AYARLARI"
    
    # Profilden veya varsayılan beklentileri al
    $protocols = Get-ExpectedProtocols
    
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    
    foreach ($protocol in $protocols.Keys) {
        $expected = $protocols[$protocol]
        
        # Server ayarını kontrol et
        $serverPath = "$basePath\$protocol\Server"
        $serverEnabled = Get-RegistryValue -Path $serverPath -Name "Enabled" -Default $null
        $serverDisabledByDefault = Get-RegistryValue -Path $serverPath -Name "DisabledByDefault" -Default $null
        
        # TLS 1.3 için özel kontrol (Windows Server 2022+ gerekli)
        if ($protocol -eq "TLS 1.3") {
            $os = Get-WmiObject -Class Win32_OperatingSystem
            if ([System.Version]$os.Version -lt [System.Version]'10.0.20348') {
                Write-Result -Category "Protokol" -Item "$protocol [Server]" -Expected "N/A" -Actual "OS Desteklemiyor" -Status "Warning"
                continue
            }
        }
        
        # Durumu belirle
        if ($null -eq $serverEnabled) {
            $actualStatus = "Tanımsız"
            $status = "Warning"
        }
        elseif ($expected -eq $true) {
            # Açık olması bekleniyor
            if ($serverEnabled -eq 1 -and $serverDisabledByDefault -eq 0) {
                $actualStatus = "Açık"
                $status = "Pass"
            }
            else {
                $actualStatus = "Kapalı"
                $status = "Fail"
            }
        }
        else {
            # Kapalı olması bekleniyor
            if ($serverEnabled -eq 0 -or $serverDisabledByDefault -eq 1) {
                $actualStatus = "Kapalı"
                $status = "Pass"
            }
            else {
                $actualStatus = "Açık"
                $status = "Fail"
            }
        }
        
        $expectedStr = if ($expected) { "Açık" } else { "Kapalı" }
        Write-Result -Category "Protokol" -Item "$protocol [Server]" -Expected $expectedStr -Actual $actualStatus -Status $status
    }
}

# Cipher algoritmaları doğrulama
function Test-Ciphers {
    Write-Header "ŞİFRELEME ALGORİTMALARI"
    
    # Profilden veya varsayılan beklentileri al
    $ciphers = Get-ExpectedCiphers
    
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
    
    foreach ($cipher in $ciphers.Keys) {
        $expected = $ciphers[$cipher]
        $cipherPath = "$basePath\$cipher"
        
        $enabled = Get-RegistryValue -Path $cipherPath -Name "Enabled" -Default $null
        $isEnabled = Test-IsEnabled -value $enabled
        
        if ($null -eq $enabled) {
            $actualStatus = "Tanımsız"
            $status = "Warning"
        }
        elseif ($expected -eq $true) {
            if ($isEnabled) {
                $actualStatus = "Açık"
                $status = "Pass"
            }
            else {
                $actualStatus = "Kapalı"
                $status = "Fail"
            }
        }
        else {
            if ($enabled -eq 0) {
                $actualStatus = "Kapalı"
                $status = "Pass"
            }
            else {
                $actualStatus = "Açık"
                $status = "Fail"
            }
        }
        
        $expectedStr = if ($expected) { "Açık" } else { "Kapalı" }
        Write-Result -Category "Cipher" -Item $cipher -Expected $expectedStr -Actual $actualStatus -Status $status
    }
}

# Hash algoritmaları doğrulama
function Test-Hashes {
    Write-Header "HASH ALGORİTMALARI"
    
    # Profilden veya varsayılan beklentileri al
    $hashes = Get-ExpectedHashes
    
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"
    
    foreach ($hash in $hashes.Keys) {
        $expected = $hashes[$hash]
        $hashPath = "$basePath\$hash"
        
        $enabled = Get-RegistryValue -Path $hashPath -Name "Enabled" -Default $null
        $isEnabled = Test-IsEnabled -value $enabled
        
        if ($null -eq $enabled) {
            $actualStatus = "Tanımsız"
            $status = "Warning"
        }
        elseif ($expected -eq $true) {
            if ($isEnabled) {
                $actualStatus = "Açık"
                $status = "Pass"
            }
            else {
                $actualStatus = "Kapalı"
                $status = "Fail"
            }
        }
        else {
            if ($enabled -eq 0) {
                $actualStatus = "Kapalı"
                $status = "Pass"
            }
            else {
                $actualStatus = "Açık"
                $status = "Fail"
            }
        }
        
        $expectedStr = if ($expected) { "Açık" } else { "Kapalı" }
        Write-Result -Category "Hash" -Item $hash -Expected $expectedStr -Actual $actualStatus -Status $status
    }
}

# Key Exchange doğrulama
function Test-KeyExchange {
    Write-Header "ANAHTAR DEĞİŞİM ALGORİTMALARI"
    
    # Profilden veya varsayılan beklentileri al
    $keyExchanges = Get-ExpectedKeyExchange
    $expectedDHKeySize = Get-ExpectedDHKeySize
    
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"
    
    foreach ($ke in $keyExchanges.Keys) {
        $expected = $keyExchanges[$ke]
        $kePath = "$basePath\$ke"
        
        $enabled = Get-RegistryValue -Path $kePath -Name "Enabled" -Default $null
        $isEnabled = Test-IsEnabled -value $enabled
        
        if ($null -eq $enabled) {
            $actualStatus = "Tanımsız"
            $status = "Warning"
        }
        elseif ($expected -eq $true) {
            if ($isEnabled) {
                $actualStatus = "Açık"
                $status = "Pass"
            }
            else {
                $actualStatus = "Kapalı"
                $status = "Fail"
            }
        }
        else {
            if ($enabled -eq 0) {
                $actualStatus = "Kapalı"
                $status = "Pass"
            }
            else {
                $actualStatus = "Açık"
                $status = "Fail"
            }
        }
        
        $expectedStr = if ($expected) { "Açık" } else { "Kapalı" }
        Write-Result -Category "KeyExchange" -Item $ke -Expected $expectedStr -Actual $actualStatus -Status $status
    }
    
    # DH Key Size kontrolü - sadece DH açıksa kontrol et
    $dhExpected = $keyExchanges['Diffie-Hellman']
    $dhPath = "$basePath\Diffie-Hellman"
    $serverMinKey = Get-RegistryValue -Path $dhPath -Name "ServerMinKeyBitLength" -Default $null
    $clientMinKey = Get-RegistryValue -Path $dhPath -Name "ClientMinKeyBitLength" -Default $null
    
    # DH kapalıysa MinKeyBitLength kontrolü yapma
    if ($dhExpected -eq $false) {
        Write-Result -Category "KeyExchange" -Item "DH ServerMinKeyBitLength" -Expected "N/A" -Actual "DH Kapalı" -Status "Pass"
        Write-Result -Category "KeyExchange" -Item "DH ClientMinKeyBitLength" -Expected "N/A" -Actual "DH Kapalı" -Status "Pass"
    }
    else {
        # Server Min Key
        if ($null -eq $serverMinKey) {
            Write-Result -Category "KeyExchange" -Item "DH ServerMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "Tanımsız" -Status "Warning"
        }
        elseif ($serverMinKey -ge $expectedDHKeySize) {
            Write-Result -Category "KeyExchange" -Item "DH ServerMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "$serverMinKey" -Status "Pass"
        }
        else {
            Write-Result -Category "KeyExchange" -Item "DH ServerMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "$serverMinKey" -Status "Fail"
        }
        
        # Client Min Key
        if ($null -eq $clientMinKey) {
            Write-Result -Category "KeyExchange" -Item "DH ClientMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "Tanımsız" -Status "Warning"
        }
        elseif ($clientMinKey -ge $expectedDHKeySize) {
            Write-Result -Category "KeyExchange" -Item "DH ClientMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "$clientMinKey" -Status "Pass"
        }
        else {
            Write-Result -Category "KeyExchange" -Item "DH ClientMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "$clientMinKey" -Status "Fail"
        }
    }
}

# Cipher Suites doğrulama
function Test-CipherSuites {
    Write-Header "CIPHER SUITES"
    
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    $currentSuites = Get-RegistryValue -Path $regPath -Name "Functions" -Default ""
    
    if ([string]::IsNullOrEmpty($currentSuites)) {
        Write-Result -Category "CipherSuites" -Item "Cipher Suite Yapılandırması" -Expected "Yapılandırılmış" -Actual "Tanımsız" -Status "Warning"
        return
    }
    
    $suiteArray = $currentSuites -split ','
    
    # Profilden beklenen cipher'ları al
    $expectedSuites = Get-ExpectedCipherSuites
    $allowCBC = Get-AllowCBC
    
    # Güvensiz cipher'lar (olmaması gereken) - CBC kontrolü profile göre değişir
    $unsafeSuites = @(
        "_RC4_",
        "_DES_",
        "_NULL_",
        "_EXPORT_",
        "_MD5"
    )
    
    # CBC kontrolü (profil izin vermiyorsa)
    if (-not $allowCBC) {
        $unsafeSuites += "_CBC_"
    }
    
    Write-Host "`n  Toplam Cipher Suite: $($suiteArray.Count)" -ForegroundColor $script:Colors.Info
    if ($allowCBC) {
        Write-Host "  ⚠️ CBC Cipher'lar: İZİN VERİLİYOR (Profil: $script:ProfileName)" -ForegroundColor $script:Colors.Warning
    } else {
        Write-Host "  🔒 CBC Cipher'lar: YASAKLI" -ForegroundColor $script:Colors.Info
    }
    
    # Güvensiz cipher kontrolü
    $hasUnsafe = $false
    foreach ($suite in $suiteArray) {
        foreach ($unsafe in $unsafeSuites) {
            if ($suite -like "*$unsafe*") {
                Write-Result -Category "CipherSuites" -Item $suite -Expected "Olmamalı" -Actual "Mevcut" -Status "Fail"
                $hasUnsafe = $true
            }
        }
    }
    
    if (-not $hasUnsafe) {
        Write-Result -Category "CipherSuites" -Item "Güvensiz Cipher Kontrolü" -Expected "Yok" -Actual "Yok" -Status "Pass"
    }
    
    # GCM cipher kontrolü
    $gcmCount = ($suiteArray | Where-Object { $_ -like "*_GCM_*" }).Count
    if ($gcmCount -gt 0) {
        Write-Result -Category "CipherSuites" -Item "GCM Cipher Sayısı" -Expected ">0" -Actual "$gcmCount" -Status "Pass"
    }
    else {
        Write-Result -Category "CipherSuites" -Item "GCM Cipher Sayısı" -Expected ">0" -Actual "0" -Status "Fail"
    }
}

# FIPS Policy doğrulama
function Test-FIPSPolicy {
    Write-Header "FIPS POLİTİKASI"
    
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
    $enabled = Get-RegistryValue -Path $regPath -Name "Enabled" -Default $null
    
    if ($null -eq $enabled) {
        Write-Result -Category "FIPS" -Item "FIPS Algorithm Policy" -Expected "0 (Kapalı)" -Actual "Tanımsız" -Status "Warning"
    }
    elseif ($enabled -eq 0) {
        Write-Result -Category "FIPS" -Item "FIPS Algorithm Policy" -Expected "0 (Kapalı)" -Actual "0 (Kapalı)" -Status "Pass"
    }
    else {
        Write-Result -Category "FIPS" -Item "FIPS Algorithm Policy" -Expected "0 (Kapalı)" -Actual "$enabled (Açık)" -Status "Warning"
    }
}

# .NET Strong Crypto doğrulama
function Test-DotNetCrypto {
    Write-Header ".NET FRAMEWORK AYARLARI"
    
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    )
    
    foreach ($regPath in $regPaths) {
        $pathName = if ($regPath -like "*Wow6432Node*") { ".NET 4.x (32-bit)" } else { ".NET 4.x (64-bit)" }
        
        $strongCrypto = Get-RegistryValue -Path $regPath -Name "SchUseStrongCrypto" -Default $null
        $systemTls = Get-RegistryValue -Path $regPath -Name "SystemDefaultTlsVersions" -Default $null
        
        # SchUseStrongCrypto
        if ($null -eq $strongCrypto) {
            Write-Result -Category ".NET" -Item "$pathName - StrongCrypto" -Expected "1" -Actual "Tanımsız" -Status "Warning"
        }
        elseif ($strongCrypto -eq 1) {
            Write-Result -Category ".NET" -Item "$pathName - StrongCrypto" -Expected "1" -Actual "1" -Status "Pass"
        }
        else {
            Write-Result -Category ".NET" -Item "$pathName - StrongCrypto" -Expected "1" -Actual "$strongCrypto" -Status "Fail"
        }
        
        # SystemDefaultTlsVersions
        if ($null -eq $systemTls) {
            Write-Result -Category ".NET" -Item "$pathName - SystemDefaultTls" -Expected "1" -Actual "Tanımsız" -Status "Warning"
        }
        elseif ($systemTls -eq 1) {
            Write-Result -Category ".NET" -Item "$pathName - SystemDefaultTls" -Expected "1" -Actual "1" -Status "Pass"
        }
        else {
            Write-Result -Category ".NET" -Item "$pathName - SystemDefaultTls" -Expected "1" -Actual "$systemTls" -Status "Fail"
        }
    }
}

# Özet yazdırma
function Write-Summary {
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor $script:Colors.Header
    Write-Host "  DOĞRULAMA ÖZETİ" -ForegroundColor $script:Colors.Header
    Write-Host ("=" * 70) -ForegroundColor $script:Colors.Header
    
    $total = $script:Results.Total
    $passed = $script:Results.Passed
    $failed = $script:Results.Failed
    $warning = $script:Results.Warning
    
    $passRate = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }
    
    Write-Host "`n  Toplam Kontrol  : " -NoNewline
    Write-Host "$total" -ForegroundColor White
    
    Write-Host "  ✅ Başarılı      : " -NoNewline
    Write-Host "$passed" -ForegroundColor $script:Colors.Pass
    
    Write-Host "  ❌ Başarısız     : " -NoNewline
    Write-Host "$failed" -ForegroundColor $script:Colors.Fail
    
    Write-Host "  ⚠️ Uyarı         : " -NoNewline
    Write-Host "$warning" -ForegroundColor $script:Colors.Warning
    
    Write-Host "`n  Başarı Oranı    : " -NoNewline
    
    if ($passRate -ge 90) {
        Write-Host "$passRate%" -ForegroundColor $script:Colors.Pass
    }
    elseif ($passRate -ge 70) {
        Write-Host "$passRate%" -ForegroundColor $script:Colors.Warning
    }
    else {
        Write-Host "$passRate%" -ForegroundColor $script:Colors.Fail
    }
    
    # Genel durum
    Write-Host "`n" -NoNewline
    if ($failed -eq 0 -and $warning -eq 0) {
        Write-Host "  🎉 TÜM KONTROLLER BAŞARILI!" -ForegroundColor $script:Colors.Pass
    }
    elseif ($failed -eq 0) {
        Write-Host "  ✅ Kritik sorun yok, bazı uyarılar mevcut." -ForegroundColor $script:Colors.Warning
    }
    else {
        Write-Host "  ⚠️ DİKKAT: $failed adet başarısız kontrol var!" -ForegroundColor $script:Colors.Fail
        Write-Host "  Lütfen TLSHardener.ps1 scriptini çalıştırın." -ForegroundColor $script:Colors.Info
    }
    
    Write-Host "`n" -NoNewline
}

# HTML Rapor oluşturma
function Export-HtmlReport {
    if (-not $ExportReport) { return }
    
    # Klasör oluştur
    $reportDir = Split-Path $ReportPath
    if (-not (Test-Path $reportDir)) {
        New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    }
    
    $passRate = if ($script:Results.Total -gt 0) { 
        [math]::Round(($script:Results.Passed / $script:Results.Total) * 100, 1) 
    } else { 0 }
    
    $statusColor = if ($passRate -ge 90) { "#28a745" } elseif ($passRate -ge 70) { "#ffc107" } else { "#dc3545" }
    
    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLSHardener Doğrulama Raporu</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { text-align: center; color: #00d4ff; margin-bottom: 30px; }
        .summary { display: flex; justify-content: center; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }
        .summary-card { background: #16213e; padding: 20px 40px; border-radius: 10px; text-align: center; }
        .summary-card h2 { font-size: 2.5em; margin-bottom: 5px; }
        .summary-card p { color: #888; }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .warning { color: #ffc107; }
        .rate { color: $statusColor; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #16213e; color: #00d4ff; }
        tr:hover { background: #16213e; }
        .status-pass { color: #28a745; font-weight: bold; }
        .status-fail { color: #dc3545; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .footer { text-align: center; margin-top: 30px; color: #666; }
        .category-header { background: #0f3460 !important; color: #00d4ff; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 TLSHardener Doğrulama Raporu</h1>
        
        <div class="summary">
            <div class="summary-card">
                <h2>$($script:Results.Total)</h2>
                <p>Toplam Kontrol</p>
            </div>
            <div class="summary-card">
                <h2 class="pass">$($script:Results.Passed)</h2>
                <p>Başarılı</p>
            </div>
            <div class="summary-card">
                <h2 class="fail">$($script:Results.Failed)</h2>
                <p>Başarısız</p>
            </div>
            <div class="summary-card">
                <h2 class="warning">$($script:Results.Warning)</h2>
                <p>Uyarı</p>
            </div>
            <div class="summary-card">
                <h2 class="rate">%$passRate</h2>
                <p>Başarı Oranı</p>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Kategori</th>
                    <th>Öğe</th>
                    <th>Beklenen</th>
                    <th>Mevcut</th>
                    <th>Durum</th>
                </tr>
            </thead>
            <tbody>
"@

    $currentCategory = ""
    foreach ($result in $script:ResultList) {
        $statusClass = "status-$($result.Status.ToLower())"
        $statusText = switch ($result.Status) {
            "Pass" { "✅ Başarılı" }
            "Fail" { "❌ Başarısız" }
            "Warning" { "⚠️ Uyarı" }
        }
        
        $html += @"
                <tr>
                    <td>$($result.Category)</td>
                    <td>$($result.Item)</td>
                    <td>$($result.Expected)</td>
                    <td>$($result.Actual)</td>
                    <td class="$statusClass">$statusText</td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
        
        <div class="footer">
            <p>Rapor Tarihi: $(Get-Date -Format "dd.MM.yyyy HH:mm:ss")</p>
            <p>Profil: $script:ProfileName</p>
            <p>TLSHardener v3.2 | Doğrulama Scripti v1.1</p>
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
    
    Write-Host "`n  📄 HTML Raporu oluşturuldu: " -NoNewline -ForegroundColor $script:Colors.Info
    Write-Host $ReportPath -ForegroundColor White
}

# Ana fonksiyon
function Invoke-Verification {
    Clear-Host
    
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor $script:Colors.Header
    Write-Host "║              🔐 TLSHardener DOĞRULAMA SCRIPTİ v1.1                  ║" -ForegroundColor $script:Colors.Header
    Write-Host "║                    Yapılandırma Kontrol Aracı                       ║" -ForegroundColor $script:Colors.Header
    Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor $script:Colors.Header
    
    Write-Host "`n  Tarih: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" -ForegroundColor Gray
    Write-Host "  Bilgisayar: $env:COMPUTERNAME" -ForegroundColor Gray
    
    # Profil yükleme (varsayılan: recommended)
    if (Load-VerifyProfile -ProfileName $Profile) {
        Write-Host "`n" -NoNewline
        Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║                        PROFİL BİLGİSİ                               ║" -ForegroundColor Cyan
        Write-Host "╠════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host ("║  Profil: {0,-58}║" -f $script:ActiveProfile.name) -ForegroundColor Cyan
        $descShort = if ($script:ActiveProfile.description.Length -gt 56) { 
            $script:ActiveProfile.description.Substring(0, 53) + "..." 
        } else { 
            $script:ActiveProfile.description 
        }
        Write-Host ("║  Açıklama: {0,-55}║" -f $descShort) -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    }
    
    # Tüm testleri çalıştır
    Test-Protocols
    Test-Ciphers
    Test-Hashes
    Test-KeyExchange
    Test-CipherSuites
    Test-FIPSPolicy
    Test-DotNetCrypto
    
    # Özet ve rapor
    Write-Summary
    Export-HtmlReport
}

# Script'i çalıştır
Invoke-Verification
