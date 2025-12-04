<#
.ScriptName: TLSHardener-Compliance.ps1
.SYNOPSIS
TLS/SSL yapılandırmasının güvenlik standartlarına uyumluluğunu kontrol eder.

.DESCRIPTION
Bu script aşağıdaki standartlara göre uyumluluk kontrolü yapar:
- PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
- NIST SP 800-52 Rev.2 (Guidelines for TLS Implementations)
- HIPAA (Health Insurance Portability and Accountability Act)
- CIS Benchmark (Center for Internet Security)

.PARAMETER Standard
Kontrol edilecek standart: All, PCI-DSS, NIST, HIPAA, CIS

.PARAMETER ExportReport
HTML rapor dosyası oluşturur

.PARAMETER OpenReport
HTML rapor oluşturur ve otomatik olarak tarayıcıda açar

.PARAMETER Detailed
Detaylı açıklamalar gösterir

.EXAMPLE
.\TLSHardener-Compliance.ps1
Tüm standartlara göre kontrol yapar

.EXAMPLE
.\TLSHardener-Compliance.ps1 -Standard PCI-DSS
Sadece PCI-DSS uyumluluğunu kontrol eder

.EXAMPLE
.\TLSHardener-Compliance.ps1 -ExportReport
HTML rapor oluşturur

.EXAMPLE
.\TLSHardener-Compliance.ps1 -OpenReport
HTML rapor oluşturur ve tarayıcıda açar

.NOTES
    Proje      : TLSHardener
    Versiyon   : 3.5
    Yazar      : TLSHardener Contributors
    Lisans     : MIT
    Tarih      : 2025
    
    Desteklenen Standartlar:
    - PCI-DSS v4.0 (Payment Card Industry)
    - NIST SP 800-52 Rev.2 (TLS Guidelines)
    - HIPAA (Healthcare Security)
    - CIS Benchmark (Windows Hardening)

.LINK
    https://github.com/tazxtazxedu/TLSHardener
#>

param (
    [ValidateSet("All", "PCI-DSS", "NIST", "HIPAA", "CIS")]
    [string]$Standard = "All",
    [switch]$ExportReport,
    [switch]$OpenReport,
    [switch]$Detailed
)

# Konsol kodlamasını UTF-8 olarak ayarla
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ============================================================================
# GLOBAL DEĞİŞKENLER
# ============================================================================

$script:ComplianceResults = @{
    "PCI-DSS" = @{ Passed = 0; Failed = 0; Warnings = 0; Checks = @() }
    "NIST" = @{ Passed = 0; Failed = 0; Warnings = 0; Checks = @() }
    "HIPAA" = @{ Passed = 0; Failed = 0; Warnings = 0; Checks = @() }
    "CIS" = @{ Passed = 0; Failed = 0; Warnings = 0; Checks = @() }
}

$script:TotalPassed = 0
$script:TotalFailed = 0
$script:TotalWarnings = 0

# ============================================================================
# YARDIMCI FONKSİYONLAR
# ============================================================================

function Write-ComplianceHeader {
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║          🔐 TLSHardener COMPLIANCE RAPORU v1.0                     ║" -ForegroundColor Cyan
    Write-Host "║          Güvenlik Standartları Uyumluluk Kontrolü                  ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Tarih: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "  Bilgisayar: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host ""
}

function Write-StandardHeader {
    param([string]$StandardName, [string]$Description)
    
    Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "  📋 $StandardName" -ForegroundColor Cyan
    Write-Host "  $Description" -ForegroundColor Gray
    Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ""
}

function Add-ComplianceCheck {
    param(
        [string]$Standard,
        [string]$CheckId,
        [string]$CheckName,
        [string]$Status,  # PASS, FAIL, WARN
        [string]$Current,
        [string]$Expected,
        [string]$Remediation = ""
    )
    
    $check = @{
        Id = $CheckId
        Name = $CheckName
        Status = $Status
        Current = $Current
        Expected = $Expected
        Remediation = $Remediation
    }
    
    $script:ComplianceResults[$Standard].Checks += $check
    
    switch ($Status) {
        "PASS" { 
            $script:ComplianceResults[$Standard].Passed++
            $script:TotalPassed++
            $icon = "✅"
            $color = "Green"
        }
        "FAIL" { 
            $script:ComplianceResults[$Standard].Failed++
            $script:TotalFailed++
            $icon = "❌"
            $color = "Red"
        }
        "WARN" { 
            $script:ComplianceResults[$Standard].Warnings++
            $script:TotalWarnings++
            $icon = "⚠️"
            $color = "Yellow"
        }
    }
    
    Write-Host "  $icon [$CheckId] $CheckName" -ForegroundColor $color
    if ($Detailed -or $Status -ne "PASS") {
        Write-Host "      Mevcut: $Current" -ForegroundColor Gray
        Write-Host "      Beklenen: $Expected" -ForegroundColor Gray
        if ($Status -eq "FAIL" -and $Remediation) {
            Write-Host "      Çözüm: $Remediation" -ForegroundColor Yellow
        }
    }
}

function Get-ProtocolStatus {
    param([string]$Protocol, [string]$Type)
    
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\$Type"
    
    if (Test-Path $regPath) {
        try {
            $enabled = Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue
            $disabled = Get-ItemProperty -Path $regPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue
            
            if ($null -ne $enabled -and $enabled.Enabled -eq 0) {
                return "Disabled"
            }
            if ($null -ne $disabled -and $disabled.DisabledByDefault -eq 1) {
                return "Disabled"
            }
            if ($null -ne $enabled -and ($enabled.Enabled -eq 1 -or $enabled.Enabled -eq -1)) {
                return "Enabled"
            }
        } catch { }
    }
    
    # Varsayılan durumlar
    switch ($Protocol) {
        "SSL 2.0" { return "Disabled (Default)" }
        "SSL 3.0" { return "Disabled (Default)" }
        "TLS 1.0" { return "Enabled (Default)" }
        "TLS 1.1" { return "Enabled (Default)" }
        "TLS 1.2" { return "Enabled (Default)" }
        "TLS 1.3" { return "Enabled (Default)" }
        default { return "Unknown" }
    }
}

function Get-CipherSuites {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    
    try {
        $ciphers = Get-ItemProperty -Path $regPath -Name "Functions" -ErrorAction SilentlyContinue
        if ($null -ne $ciphers) {
            return $ciphers.Functions -split ','
        }
    } catch { }
    
    # Sistem varsayılanlarını al
    try {
        $tlsCiphers = Get-TlsCipherSuite -ErrorAction SilentlyContinue
        if ($null -ne $tlsCiphers) {
            return $tlsCiphers | ForEach-Object { $_.Name }
        }
    } catch { }
    
    # Fallback - boş dizi döndür
    return @()
}

function Get-HashAlgorithmStatus {
    param([string]$Algorithm)
    
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$Algorithm"
    
    if (Test-Path $regPath) {
        try {
            $enabled = Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue
            if ($null -ne $enabled) {
                if ($enabled.Enabled -eq 0) { return "Disabled" }
                if ($enabled.Enabled -eq -1 -or $enabled.Enabled -eq 0xFFFFFFFF) { return "Enabled" }
            }
        } catch { }
    }
    
    return "Enabled (Default)"
}

function Get-KeyExchangeStatus {
    param([string]$Algorithm)
    
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$Algorithm"
    
    if (Test-Path $regPath) {
        try {
            $enabled = Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue
            if ($null -ne $enabled) {
                if ($enabled.Enabled -eq 0) { return "Disabled" }
                if ($enabled.Enabled -eq -1 -or $enabled.Enabled -eq 0xFFFFFFFF) { return "Enabled" }
            }
        } catch { }
    }
    
    return "Enabled (Default)"
}

function Get-DHKeySize {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman"
    
    try {
        $keyLength = Get-ItemProperty -Path $regPath -Name "ServerMinKeyBitLength" -ErrorAction SilentlyContinue
        if ($null -ne $keyLength) {
            return $keyLength.ServerMinKeyBitLength
        }
    } catch { }
    
    return 1024  # Windows varsayılanı
}

# ============================================================================
# PCI-DSS v4.0 KONTROLLER
# ============================================================================

function Test-PCIDSS {
    Write-StandardHeader "PCI-DSS v4.0" "Payment Card Industry Data Security Standard"
    
    # Req 4.2.1 - SSL/Early TLS kullanımı yasak
    $ssl2 = Get-ProtocolStatus -Protocol "SSL 2.0" -Type "Server"
    $ssl3 = Get-ProtocolStatus -Protocol "SSL 3.0" -Type "Server"
    $tls10 = Get-ProtocolStatus -Protocol "TLS 1.0" -Type "Server"
    $tls11 = Get-ProtocolStatus -Protocol "TLS 1.1" -Type "Server"
    
    # SSL 2.0 kontrolü
    $status = if ($ssl2 -match "Disabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "PCI-DSS" -CheckId "4.2.1.a" -CheckName "SSL 2.0 devre dışı" `
        -Status $status -Current $ssl2 -Expected "Disabled" `
        -Remediation ".\TLSHardener.ps1 -Profile recommended"
    
    # SSL 3.0 kontrolü
    $status = if ($ssl3 -match "Disabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "PCI-DSS" -CheckId "4.2.1.b" -CheckName "SSL 3.0 devre dışı" `
        -Status $status -Current $ssl3 -Expected "Disabled" `
        -Remediation ".\TLSHardener.ps1 -Profile recommended"
    
    # TLS 1.0 kontrolü
    $status = if ($tls10 -match "Disabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "PCI-DSS" -CheckId "4.2.1.c" -CheckName "TLS 1.0 devre dışı" `
        -Status $status -Current $tls10 -Expected "Disabled" `
        -Remediation ".\TLSHardener.ps1 -Profile recommended"
    
    # TLS 1.1 kontrolü
    $status = if ($tls11 -match "Disabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "PCI-DSS" -CheckId "4.2.1.d" -CheckName "TLS 1.1 devre dışı" `
        -Status $status -Current $tls11 -Expected "Disabled" `
        -Remediation ".\TLSHardener.ps1 -Profile recommended"
    
    # TLS 1.2 veya üstü aktif mi?
    $tls12 = Get-ProtocolStatus -Protocol "TLS 1.2" -Type "Server"
    $tls13 = Get-ProtocolStatus -Protocol "TLS 1.3" -Type "Server"
    $status = if ($tls12 -match "Enabled" -or $tls13 -match "Enabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "PCI-DSS" -CheckId "4.2.1.e" -CheckName "TLS 1.2 veya üstü aktif" `
        -Status $status -Current "TLS 1.2: $tls12, TLS 1.3: $tls13" -Expected "En az biri Enabled" `
        -Remediation ".\TLSHardener.ps1 -Profile recommended"
    
    # Req 4.2.1 - Güçlü cipher suite'ler
    $cipherSuites = Get-CipherSuites
    $weakCiphers = $cipherSuites | Where-Object { 
        $_ -match "NULL|EXPORT|DES|RC4|MD5|ANON|CBC" -and $_ -notmatch "GCM"
    }
    
    $status = if ($weakCiphers.Count -eq 0) { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "PCI-DSS" -CheckId "4.2.1.f" -CheckName "Zayıf cipher suite'ler devre dışı" `
        -Status $status -Current "Zayıf cipher: $($weakCiphers.Count)" -Expected "0 zayıf cipher" `
        -Remediation "CBC/NULL/RC4/DES cipher'ları kaldırın"
    
    # Req 2.2.7 - MD5 hash devre dışı
    $md5 = Get-HashAlgorithmStatus -Algorithm "MD5"
    $status = if ($md5 -match "Disabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "PCI-DSS" -CheckId "2.2.7.a" -CheckName "MD5 hash algoritması devre dışı" `
        -Status $status -Current $md5 -Expected "Disabled" `
        -Remediation ".\TLSHardener.ps1 -Profile recommended"
    
    Write-Host ""
}

# ============================================================================
# NIST SP 800-52 Rev.2 KONTROLLER
# ============================================================================

function Test-NIST {
    Write-StandardHeader "NIST SP 800-52 Rev.2" "Guidelines for the Selection, Configuration, and Use of TLS"
    
    # 3.1 - TLS sürüm gereksinimleri
    $tls12 = Get-ProtocolStatus -Protocol "TLS 1.2" -Type "Server"
    $tls13 = Get-ProtocolStatus -Protocol "TLS 1.3" -Type "Server"
    
    $status = if ($tls12 -match "Enabled" -or $tls13 -match "Enabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "NIST" -CheckId "3.1.1" -CheckName "TLS 1.2 veya 1.3 destekleniyor" `
        -Status $status -Current "TLS 1.2: $tls12, TLS 1.3: $tls13" -Expected "En az biri aktif"
    
    # TLS 1.3 önerisi
    $status = if ($tls13 -match "Enabled") { "PASS" } else { "WARN" }
    Add-ComplianceCheck -Standard "NIST" -CheckId "3.1.2" -CheckName "TLS 1.3 aktif (önerilen)" `
        -Status $status -Current $tls13 -Expected "Enabled"
    
    # 3.3.1 - Cipher suite gereksinimleri
    $cipherSuites = Get-CipherSuites
    
    # GCM cipher kontrolü
    $gcmCiphers = $cipherSuites | Where-Object { $_ -match "GCM" }
    $status = if ($gcmCiphers.Count -gt 0) { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "NIST" -CheckId "3.3.1.a" -CheckName "AEAD cipher suite'ler (GCM) mevcut" `
        -Status $status -Current "$($gcmCiphers.Count) GCM cipher" -Expected "En az 1 GCM cipher"
    
    # ECDHE key exchange
    $ecdheCiphers = $cipherSuites | Where-Object { $_ -match "ECDHE" }
    $status = if ($ecdheCiphers.Count -gt 0) { "PASS" } else { "WARN" }
    Add-ComplianceCheck -Standard "NIST" -CheckId "3.3.1.b" -CheckName "ECDHE key exchange mevcut" `
        -Status $status -Current "$($ecdheCiphers.Count) ECDHE cipher" -Expected "ECDHE cipher'lar mevcut"
    
    # 3.4 - Key exchange gereksinimleri
    $dhKeySize = Get-DHKeySize
    $status = if ($dhKeySize -ge 2048) { "PASS" } elseif ($dhKeySize -ge 1024) { "WARN" } else { "FAIL" }
    Add-ComplianceCheck -Standard "NIST" -CheckId "3.4.1" -CheckName "DH key size >= 2048 bit" `
        -Status $status -Current "$dhKeySize bit" -Expected ">= 2048 bit (3072 önerilen)"
    
    # SHA-1 kullanımı
    $sha1 = Get-HashAlgorithmStatus -Algorithm "SHA"
    $status = if ($sha1 -match "Disabled") { "PASS" } else { "WARN" }
    Add-ComplianceCheck -Standard "NIST" -CheckId "3.5.1" -CheckName "SHA-1 devre dışı (önerilen)" `
        -Status $status -Current $sha1 -Expected "Disabled"
    
    # SHA-256+ kullanımı
    $sha256 = Get-HashAlgorithmStatus -Algorithm "SHA256"
    $sha384 = Get-HashAlgorithmStatus -Algorithm "SHA384"
    $status = if ($sha256 -match "Enabled" -or $sha384 -match "Enabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "NIST" -CheckId "3.5.2" -CheckName "SHA-256 veya üstü aktif" `
        -Status $status -Current "SHA256: $sha256, SHA384: $sha384" -Expected "En az biri aktif"
    
    Write-Host ""
}

# ============================================================================
# HIPAA KONTROLLER
# ============================================================================

function Test-HIPAA {
    Write-StandardHeader "HIPAA" "Health Insurance Portability and Accountability Act - Technical Safeguards"
    
    # 164.312(e)(1) - Transmission Security
    $tls12 = Get-ProtocolStatus -Protocol "TLS 1.2" -Type "Server"
    $tls13 = Get-ProtocolStatus -Protocol "TLS 1.3" -Type "Server"
    
    $status = if ($tls12 -match "Enabled" -or $tls13 -match "Enabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "HIPAA" -CheckId "164.312.e" -CheckName "Güçlü şifreleme ile iletim güvenliği" `
        -Status $status -Current "TLS 1.2: $tls12, TLS 1.3: $tls13" -Expected "TLS 1.2+ aktif"
    
    # Eski protokollerin kapalı olması
    $ssl2 = Get-ProtocolStatus -Protocol "SSL 2.0" -Type "Server"
    $ssl3 = Get-ProtocolStatus -Protocol "SSL 3.0" -Type "Server"
    $tls10 = Get-ProtocolStatus -Protocol "TLS 1.0" -Type "Server"
    
    $status = if ($ssl2 -match "Disabled" -and $ssl3 -match "Disabled" -and $tls10 -match "Disabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "HIPAA" -CheckId "164.312.e.2" -CheckName "Güvensiz protokoller devre dışı" `
        -Status $status -Current "SSL2: $ssl2, SSL3: $ssl3, TLS1.0: $tls10" -Expected "Hepsi Disabled"
    
    # 164.312(a)(2)(iv) - Encryption and decryption
    $cipherSuites = Get-CipherSuites
    $aesCiphers = $cipherSuites | Where-Object { $_ -match "AES" }
    
    $status = if ($aesCiphers.Count -gt 0) { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "HIPAA" -CheckId "164.312.a" -CheckName "AES şifreleme kullanımı" `
        -Status $status -Current "$($aesCiphers.Count) AES cipher" -Expected "AES cipher'lar aktif"
    
    # Zayıf algoritmaların kapalı olması
    $md5 = Get-HashAlgorithmStatus -Algorithm "MD5"
    $status = if ($md5 -match "Disabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "HIPAA" -CheckId "164.312.c" -CheckName "Zayıf hash algoritmaları (MD5) devre dışı" `
        -Status $status -Current $md5 -Expected "Disabled"
    
    Write-Host ""
}

# ============================================================================
# CIS BENCHMARK KONTROLLER
# ============================================================================

function Test-CIS {
    Write-StandardHeader "CIS Benchmark" "Center for Internet Security - Windows Server Hardening"
    
    # SSL 2.0
    $ssl2Server = Get-ProtocolStatus -Protocol "SSL 2.0" -Type "Server"
    $ssl2Client = Get-ProtocolStatus -Protocol "SSL 2.0" -Type "Client"
    $status = if ($ssl2Server -match "Disabled" -and $ssl2Client -match "Disabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "CIS" -CheckId "18.4.1" -CheckName "SSL 2.0 tamamen devre dışı" `
        -Status $status -Current "Server: $ssl2Server, Client: $ssl2Client" -Expected "Disabled"
    
    # SSL 3.0
    $ssl3Server = Get-ProtocolStatus -Protocol "SSL 3.0" -Type "Server"
    $ssl3Client = Get-ProtocolStatus -Protocol "SSL 3.0" -Type "Client"
    $status = if ($ssl3Server -match "Disabled" -and $ssl3Client -match "Disabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "CIS" -CheckId "18.4.2" -CheckName "SSL 3.0 tamamen devre dışı" `
        -Status $status -Current "Server: $ssl3Server, Client: $ssl3Client" -Expected "Disabled"
    
    # TLS 1.0
    $tls10Server = Get-ProtocolStatus -Protocol "TLS 1.0" -Type "Server"
    $tls10Client = Get-ProtocolStatus -Protocol "TLS 1.0" -Type "Client"
    $status = if ($tls10Server -match "Disabled" -and $tls10Client -match "Disabled") { "PASS" } else { "WARN" }
    Add-ComplianceCheck -Standard "CIS" -CheckId "18.4.3" -CheckName "TLS 1.0 devre dışı (önerilen)" `
        -Status $status -Current "Server: $tls10Server, Client: $tls10Client" -Expected "Disabled"
    
    # TLS 1.1
    $tls11Server = Get-ProtocolStatus -Protocol "TLS 1.1" -Type "Server"
    $tls11Client = Get-ProtocolStatus -Protocol "TLS 1.1" -Type "Client"
    $status = if ($tls11Server -match "Disabled" -and $tls11Client -match "Disabled") { "PASS" } else { "WARN" }
    Add-ComplianceCheck -Standard "CIS" -CheckId "18.4.4" -CheckName "TLS 1.1 devre dışı (önerilen)" `
        -Status $status -Current "Server: $tls11Server, Client: $tls11Client" -Expected "Disabled"
    
    # TLS 1.2 aktif
    $tls12Server = Get-ProtocolStatus -Protocol "TLS 1.2" -Type "Server"
    $tls12Client = Get-ProtocolStatus -Protocol "TLS 1.2" -Type "Client"
    $status = if ($tls12Server -match "Enabled" -and $tls12Client -match "Enabled") { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "CIS" -CheckId "18.4.5" -CheckName "TLS 1.2 aktif" `
        -Status $status -Current "Server: $tls12Server, Client: $tls12Client" -Expected "Enabled"
    
    # NULL cipher
    $cipherSuites = Get-CipherSuites
    $nullCiphers = $cipherSuites | Where-Object { $_ -match "NULL" }
    $status = if ($nullCiphers.Count -eq 0) { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "CIS" -CheckId "18.4.6" -CheckName "NULL cipher'lar devre dışı" `
        -Status $status -Current "$($nullCiphers.Count) NULL cipher" -Expected "0"
    
    # RC4 cipher
    $rc4Ciphers = $cipherSuites | Where-Object { $_ -match "RC4" }
    $status = if ($rc4Ciphers.Count -eq 0) { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "CIS" -CheckId "18.4.7" -CheckName "RC4 cipher'lar devre dışı" `
        -Status $status -Current "$($rc4Ciphers.Count) RC4 cipher" -Expected "0"
    
    # DES cipher
    $desCiphers = $cipherSuites | Where-Object { $_ -match "DES" -and $_ -notmatch "3DES" }
    $status = if ($desCiphers.Count -eq 0) { "PASS" } else { "FAIL" }
    Add-ComplianceCheck -Standard "CIS" -CheckId "18.4.8" -CheckName "DES cipher'lar devre dışı" `
        -Status $status -Current "$($desCiphers.Count) DES cipher" -Expected "0"
    
    Write-Host ""
}

# ============================================================================
# ÖZET RAPOR
# ============================================================================

function Write-ComplianceSummary {
    Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  📊 UYUMLULUK ÖZETİ" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $standards = @("PCI-DSS", "NIST", "HIPAA", "CIS")
    
    foreach ($std in $standards) {
        if ($script:ComplianceResults[$std].Checks.Count -gt 0) {
            $passed = $script:ComplianceResults[$std].Passed
            $failed = $script:ComplianceResults[$std].Failed
            $warnings = $script:ComplianceResults[$std].Warnings
            $total = $passed + $failed + $warnings
            $percentage = [math]::Round(($passed / $total) * 100, 1)
            
            $color = if ($failed -eq 0) { "Green" } elseif ($percentage -ge 70) { "Yellow" } else { "Red" }
            $icon = if ($failed -eq 0) { "✅" } elseif ($percentage -ge 70) { "⚠️" } else { "❌" }
            
            Write-Host "  $icon $std" -ForegroundColor $color -NoNewline
            Write-Host " - " -NoNewline
            Write-Host "$percentage%" -ForegroundColor $color -NoNewline
            Write-Host " uyumlu " -NoNewline
            Write-Host "($passed geçti, $failed başarısız, $warnings uyarı)" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────────────" -ForegroundColor Gray
    
    $totalChecks = $script:TotalPassed + $script:TotalFailed + $script:TotalWarnings
    $overallPercentage = if ($totalChecks -gt 0) { [math]::Round(($script:TotalPassed / $totalChecks) * 100, 1) } else { 0 }
    
    $overallColor = if ($script:TotalFailed -eq 0) { "Green" } elseif ($overallPercentage -ge 70) { "Yellow" } else { "Red" }
    
    Write-Host "  TOPLAM: " -NoNewline
    Write-Host "$overallPercentage%" -ForegroundColor $overallColor -NoNewline
    Write-Host " uyumlu " -NoNewline
    Write-Host "($script:TotalPassed geçti, $script:TotalFailed başarısız, $script:TotalWarnings uyarı)" -ForegroundColor Gray
    Write-Host ""
    
    if ($script:TotalFailed -gt 0) {
        Write-Host "  💡 Önerilen aksiyon: " -ForegroundColor Yellow -NoNewline
        Write-Host ".\TLSHardener.ps1 -Profile recommended" -ForegroundColor White
    } else {
        Write-Host "  🎉 Tebrikler! Tüm kritik kontroller geçildi." -ForegroundColor Green
    }
    
    Write-Host ""
}

# ============================================================================
# HTML RAPOR OLUŞTURMA
# ============================================================================

function Export-ComplianceReport {
    $reportFolder = ".\reports"
    if (-not (Test-Path $reportFolder)) {
        New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $reportFolder "TLSHardener-Compliance_$timestamp.html"
    
    $totalChecks = $script:TotalPassed + $script:TotalFailed + $script:TotalWarnings
    $overallPercentage = if ($totalChecks -gt 0) { [math]::Round(($script:TotalPassed / $totalChecks) * 100, 1) } else { 0 }
    $overallColor = if ($script:TotalFailed -eq 0) { '#00c853' } elseif ($overallPercentage -ge 70) { '#ffc107' } else { '#ff5252' }
    
    # Standart kartları için HTML oluştur
    $standardCardsHtml = ""
    $standardSectionsHtml = ""
    $standards = @("PCI-DSS", "NIST", "HIPAA", "CIS")
    $standardDescriptions = @{
        "PCI-DSS" = "Payment Card Industry Data Security Standard v4.0"
        "NIST" = "NIST SP 800-52 Rev.2 - TLS Implementation Guidelines"
        "HIPAA" = "Health Insurance Portability and Accountability Act"
        "CIS" = "Center for Internet Security - Windows Server Benchmark"
    }
    
    foreach ($std in $standards) {
        $result = $script:ComplianceResults[$std]
        if ($result.Checks.Count -eq 0) { continue }
        
        $total = $result.Passed + $result.Failed + $result.Warnings
        $percentage = [math]::Round(($result.Passed / $total) * 100, 1)
        $statusClass = if ($result.Failed -eq 0) { "pass" } elseif ($percentage -ge 70) { "warn" } else { "fail" }
        $statusIcon = if ($result.Failed -eq 0) { "✅" } elseif ($percentage -ge 70) { "⚠️" } else { "❌" }
        
        # Standart kartı
        $standardCardsHtml += @"

            <div class="standard-card $statusClass" onclick="toggleSection('$std')">
                <div class="card-icon">$statusIcon</div>
                <div class="card-content">
                    <h3>$std</h3>
                    <div class="card-stats">
                        <span class="stat pass">✓ $($result.Passed)</span>
                        <span class="stat warn">⚠ $($result.Warnings)</span>
                        <span class="stat fail">✗ $($result.Failed)</span>
                    </div>
                </div>
                <div class="card-percentage">%$percentage</div>
            </div>
"@
        
        # Kontrol satırları
        $checksHtml = ""
        foreach ($check in $result.Checks) {
            $checkStatusClass = $check.Status.ToLower()
            $checkIcon = switch ($check.Status) {
                "PASS" { "✅" }
                "WARN" { "⚠️" }
                "FAIL" { "❌" }
            }
            
            $checksHtml += @"

                    <div class="check-row $checkStatusClass">
                        <div class="check-icon">$checkIcon</div>
                        <div class="check-info">
                            <div class="check-header">
                                <span class="check-id">$($check.Id)</span>
                                <span class="check-name">$($check.Name)</span>
                            </div>
                            <div class="check-detail">
                                <span class="label">Mevcut:</span> $($check.Current)
                            </div>
                            <div class="check-detail">
                                <span class="label">Beklenen:</span> $($check.Expected)
                            </div>
"@
            if ($check.Status -eq "FAIL" -and $check.Remediation) {
                $checksHtml += @"
                            <div class="check-remediation">
                                <span class="label">💡 Çözüm:</span> $($check.Remediation)
                            </div>
"@
            }
            $checksHtml += @"
                        </div>
                    </div>
"@
        }
        
        # Standart bölümü
        $standardSectionsHtml += @"

        <div id="$std" class="standard-section collapsed">
            <div class="section-header" onclick="toggleSection('$std')">
                <div class="section-title">
                    <span class="section-icon">📋</span>
                    <div>
                        <h2>$std</h2>
                        <p class="section-desc">$($standardDescriptions[$std])</p>
                    </div>
                </div>
                <div class="section-right">
                    <span class="section-badge $statusClass">%$percentage Uyumlu</span>
                    <span class="toggle-icon">▼</span>
                </div>
            </div>
            <div class="section-content">
                <div class="checks-container">$checksHtml
                </div>
            </div>
        </div>
"@
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLSHardener Compliance Raporu - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --status-pass: #3fb950;
            --status-warn: #d29922;
            --status-fail: #f85149;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            font-size: 15px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 1rem 1.5rem;
        }
        
        /* Header */
        .header {
            background: var(--bg-secondary);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.75rem;
        }
        
        .header h1 {
            font-size: 1.4rem;
            color: var(--accent-blue);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .header-meta {
            color: var(--text-secondary);
            font-size: 0.85rem;
            display: flex;
            gap: 1.25rem;
        }
        
        .header-meta span {
            display: flex;
            align-items: center;
            gap: 0.35rem;
        }
        
        /* Summary Row - All in one line */
        .summary-row {
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }
        
        .overall-score {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.75rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            flex: 0 0 auto;
        }
        
        .score-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: $overallColor;
            line-height: 1;
        }
        
        .score-label {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        
        /* Summary Cards */
        .summary-grid {
            display: flex;
            gap: 0.5rem;
            flex: 1;
        }
        
        .summary-card {
            background: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: 8px;
            padding: 0.5rem 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex: 1;
        }
        
        .summary-card.pass { border-color: var(--status-pass); }
        .summary-card.warn { border-color: var(--status-warn); }
        .summary-card.fail { border-color: var(--status-fail); }
        
        .summary-card h3 {
            font-size: 1.5rem;
            line-height: 1;
        }
        
        .summary-card.pass h3 { color: var(--status-pass); }
        .summary-card.warn h3 { color: var(--status-warn); }
        .summary-card.fail h3 { color: var(--status-fail); }
        
        .summary-card p {
            color: var(--text-secondary);
            font-size: 0.8rem;
            white-space: nowrap;
        }
        
        /* Standard Cards */
        .standards-overview {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 0.6rem;
            margin-bottom: 1rem;
        }
        
        .standard-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            cursor: pointer;
            transition: border-color 0.2s;
        }
        
        .standard-card:hover {
            border-color: var(--accent-blue);
        }
        
        .standard-card.pass { border-left: 3px solid var(--status-pass); }
        .standard-card.warn { border-left: 3px solid var(--status-warn); }
        .standard-card.fail { border-left: 3px solid var(--status-fail); }
        
        .card-icon { font-size: 1.4rem; }
        
        .card-content { flex: 1; }
        .card-content h3 { font-size: 1rem; margin-bottom: 0.2rem; }
        
        .card-stats {
            display: flex;
            gap: 0.75rem;
            font-size: 0.8rem;
        }
        
        .card-stats .stat.pass { color: var(--status-pass); }
        .card-stats .stat.warn { color: var(--status-warn); }
        .card-stats .stat.fail { color: var(--status-fail); }
        
        .card-percentage {
            font-size: 1.35rem;
            font-weight: 600;
        }
        
        .standard-card.pass .card-percentage { color: var(--status-pass); }
        .standard-card.warn .card-percentage { color: var(--status-warn); }
        .standard-card.fail .card-percentage { color: var(--status-fail); }
        
        /* Collapsible Sections */
        .standard-section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin-bottom: 0.5rem;
            overflow: hidden;
        }
        
        .section-header {
            padding: 0.75rem 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .section-header:hover {
            background: var(--bg-tertiary);
        }
        
        .section-title {
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }
        
        .section-icon { font-size: 1.1rem; }
        
        .section-title h2 {
            font-size: 1.1rem;
            color: var(--accent-blue);
        }
        
        .section-desc {
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-top: 0.1rem;
        }
        
        .section-right {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .section-badge {
            padding: 0.25rem 0.6rem;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85rem;
        }
        
        .section-badge.pass { background: rgba(63, 185, 80, 0.15); color: var(--status-pass); }
        .section-badge.warn { background: rgba(210, 153, 34, 0.15); color: var(--status-warn); }
        .section-badge.fail { background: rgba(248, 81, 73, 0.15); color: var(--status-fail); }
        
        .toggle-icon {
            font-size: 1rem;
            color: var(--text-secondary);
            transition: transform 0.3s;
        }
        
        .standard-section.collapsed .section-content {
            display: none;
        }
        
        .standard-section:not(.collapsed) .toggle-icon {
            transform: rotate(180deg);
        }
        
        .section-content {
            border-top: 1px solid var(--border-color);
        }
        
        .checks-container {
            padding: 0.5rem;
        }
        
        /* Check Rows */
        .check-row {
            display: flex;
            gap: 0.6rem;
            padding: 0.6rem 0.75rem;
            border-radius: 4px;
            margin-bottom: 0.35rem;
            background: var(--bg-tertiary);
            border-left: 3px solid transparent;
        }
        
        .check-row.pass { border-left-color: var(--status-pass); }
        .check-row.warn { border-left-color: var(--status-warn); }
        .check-row.fail { border-left-color: var(--status-fail); background: rgba(248, 81, 73, 0.05); }
        
        .check-icon { font-size: 1.1rem; }
        
        .check-info { flex: 1; }
        
        .check-header {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            margin-bottom: 0.35rem;
        }
        
        .check-id {
            font-family: 'Consolas', 'Monaco', monospace;
            background: var(--bg-primary);
            padding: 0.15rem 0.5rem;
            border-radius: 3px;
            font-size: 0.8rem;
            color: var(--accent-blue);
        }
        
        .check-name {
            font-size: 0.95rem;
            font-weight: 500;
        }
        
        .check-detail {
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 0.15rem;
        }
        
        .check-detail .label {
            color: var(--text-primary);
            font-weight: 500;
        }
        
        .check-remediation {
            margin-top: 0.4rem;
            padding: 0.4rem 0.6rem;
            background: rgba(210, 153, 34, 0.1);
            border-radius: 4px;
            font-size: 0.85rem;
            border-left: 2px solid var(--status-warn);
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 1rem;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            margin-top: 1rem;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .container { padding: 0.75rem; }
            .summary-row { flex-direction: column; }
            .summary-grid { flex-direction: column; }
            .standards-overview { grid-template-columns: 1fr; }
            .score-value { font-size: 2rem; }
            .header { flex-direction: column; align-items: flex-start; }
            .header h1 { font-size: 1.2rem; }
            .header-meta { flex-direction: column; gap: 0.35rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 TLSHardener Compliance Raporu</h1>
            <div class="header-meta">
                <span>📅 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
                <span>💻 $env:COMPUTERNAME</span>
                <span>🔍 $($script:TotalPassed + $script:TotalFailed + $script:TotalWarnings) kontrol yapıldı</span>
            </div>
        </div>
        
        <div class="summary-row">
            <div class="overall-score">
                <div class="score-value">%$overallPercentage</div>
                <div class="score-label">Genel Uyumluluk</div>
            </div>
            <div class="summary-grid">
                <div class="summary-card pass">
                    <h3>$script:TotalPassed</h3>
                    <p>Başarılı</p>
                </div>
                <div class="summary-card warn">
                    <h3>$script:TotalWarnings</h3>
                    <p>Uyarı</p>
                </div>
                <div class="summary-card fail">
                    <h3>$script:TotalFailed</h3>
                    <p>Başarısız</p>
                </div>
            </div>
        </div>
        
        <h2 style="color: var(--text-secondary); margin-bottom: 0.6rem; font-size: 0.95rem; font-weight: 500;">📊 Standart Özeti (Detay için tıklayın)</h2>
        
        <div class="standards-overview">$standardCardsHtml
        </div>
        
        <h2 style="color: var(--text-secondary); margin-bottom: 0.6rem; font-size: 0.95rem; font-weight: 500;">📋 Detaylı Kontroller</h2>
        $standardSectionsHtml
        
        <div class="footer">
            <p>TLSHardener Compliance Report v1.1 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p style="margin-top: 0.35rem;">Önerilen: <code style="background: var(--bg-tertiary); padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.8rem;">.\TLSHardener.ps1 -Profile recommended</code></p>
        </div>
    </div>
    
    <script>
        function toggleSection(id) {
            const section = document.getElementById(id);
            section.classList.toggle('collapsed');
        }
        
        // Başlangıçta tüm bölümleri kapalı tut
        document.addEventListener('DOMContentLoaded', function() {
            // İsterseniz başarısız olanları otomatik açabilirsiniz
            // document.querySelectorAll('.standard-section.fail').forEach(s => s.classList.remove('collapsed'));
        });
    </script>
</body>
</html>
"@

    $html | Out-File -FilePath $reportPath -Encoding UTF8
    
    Write-Host "  📄 HTML rapor oluşturuldu: " -NoNewline -ForegroundColor Cyan
    Write-Host $reportPath -ForegroundColor White
    
    return $reportPath
}

# ============================================================================
# ANA ÇALIŞTIRMA
# ============================================================================

Write-ComplianceHeader

switch ($Standard) {
    "All" {
        Test-PCIDSS
        Test-NIST
        Test-HIPAA
        Test-CIS
    }
    "PCI-DSS" { Test-PCIDSS }
    "NIST" { Test-NIST }
    "HIPAA" { Test-HIPAA }
    "CIS" { Test-CIS }
}

Write-ComplianceSummary

if ($ExportReport -or $OpenReport) {
    $reportPath = Export-ComplianceReport
    
    if ($OpenReport) {
        Write-Host "  🌐 Rapor tarayıcıda açılıyor..." -ForegroundColor Green
        Start-Process $reportPath
    }
}

Write-Host ""
