<#
.SYNOPSIS
    TLSHardener tarafından yapılan yapılandırmaları temizler ve Windows varsayılanlarına döndürür.

.DESCRIPTION
    Bu script, TLSHardener tarafından yapılan tüm TLS/SSL yapılandırmalarını kaldırır
    ve sistemi Windows varsayılan ayarlarına geri döndürür.
    
    Temizlenen ayarlar:
    - SCHANNEL Ciphers (AES, DES, RC4, NULL vb.)
    - SCHANNEL Hashes (MD5, SHA ailesi)
    - SCHANNEL KeyExchangeAlgorithms (DH, ECDH, PKCS)
    - SCHANNEL Protocols (SSL 2.0/3.0, TLS 1.0-1.3)
    - FIPS Algoritma Politikası
    - Cipher Suite sıralaması
    - Eliptik Eğri (ECC) yapılandırması
    - .NET Framework Strong Crypto ayarları

    ⚠️ UYARI: Bu işlem tüm TLS sıkılaştırma ayarlarını kaldırır!
    Sistem Windows varsayılanlarına dönecektir.

.PARAMETER BypassConfirmation
    Kullanıcı onayını atlar ve doğrudan temizleme işlemini başlatır.
    DİKKAT: Bu parametre ile script onay istemeden çalışır!

.EXAMPLE
    .\TLSHardener-Clean.ps1
    İnteraktif mod - kullanıcı onayı ister

.EXAMPLE
    .\TLSHardener-Clean.ps1 -BypassConfirmation
    Onay istemeden temizleme yapar (otomasyon için)

.INPUTS
    Yok

.OUTPUTS
    Log dosyası: logs/TLSHardener-Clean_YYYY_MM_DD_HHMM.log

.NOTES
    Proje      : TLSHardener
    Versiyon   : 3.5
    Yazar      : TLSHardener Contributors
    Lisans     : MIT
    Tarih      : 2025
    
    Gereksinimler:
    - Administrator yetkisi
    - Windows Server 2016+ veya Windows 10+

.LINK
    https://github.com/kullanici/TLSHardener

.LINK
    .\TLSHardener.ps1 -Rollback -ToDefaults
#>
param (
    [switch]$BypassConfirmation
)

# Konsol kodlamasını UTF-8 olarak ayarla
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Loglama için fonksiyon
$TimeStamp = Get-Date -Format "yyyy_MM_dd_HHmm"
[string]$LogFilePath = ".\logs\TLSHardener-Clean_$TimeStamp.log"
function Write-Log {
    [CmdletBinding()]
    param (
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error")]
        [string]$LogType = "Info",
        [switch]$VerboseOutput,
        [ValidateSet("Green", "Yellow", "Cyan")]
        [string]$InfoColor = "Green"
    )
    
    # Zaman damgası ve log girdisi formatı
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$TimeStamp $LogType $Message"
    
    # Log dosyasını oluştur (yoksa) ve UTF-8 ile yaz
    if (!(Test-Path -Path $LogFilePath)) {
        New-Item -Path $LogFilePath -ItemType File -Force | Out-Null
        Out-File -FilePath $LogFilePath -Encoding UTF8 -Append -InputObject ""
    }
    Out-File -FilePath $LogFilePath -Encoding UTF8 -Append -InputObject $LogEntry

    # Ekrana renkli çıktı
    if ($VerboseOutput) {
        switch ($LogType) {
            "Info" {
                Write-Host $LogEntry -ForegroundColor $InfoColor
            }
            "Warning" {
                Write-Host $LogEntry -ForegroundColor Yellow
            }
            "Error" {
                Write-Host $LogEntry -ForegroundColor Red
            }
        }
    }
}

# Registry anahtarını dışa aktarma fonksiyonu
function Export-RegistryKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$keyPath,
        
        [Parameter(Mandatory = $true)]
        [string]$exportPath
    )

    try {
        # Registry anahtarının varlığını kontrol et
        if (!(Test-Path -Path $keyPath)) {
            Write-Log "Registry key bulunamadı: $keyPath" -LogType Error -VerboseOutput
            return $false
        }

        # Registry anahtarını dışa aktar
        $traditionalPath = $keyPath -replace ':\\', '\'
        Write-Log "İşleniyor: $traditionalPath" -LogType Info -VerboseOutput -InfoColor Cyan
        
        $result = reg export $traditionalPath $exportPath /y
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Başarıyla dışa aktarıldı: $exportPath" -LogType Info -VerboseOutput -InfoColor Green
            return $true
        }
        else {
            Write-Log "Dışa aktarma başarısız: $result" -LogType Error -VerboseOutput
            return $false
        }
    }
    catch {
        Write-Log "Hata oluştu: $_" -LogType Error -VerboseOutput
        return $false
    }
}

# Ana yedekleme işlemi
function Backup-RegistryKeys {
    # Yedekleme klasörünü hazırla
    $backupFolder = ".\backups"
    if (-not (Test-Path $backupFolder)) {
        Write-Log "Yedekleme klasörü oluşturuluyor..." -LogType Info -VerboseOutput -InfoColor Yellow
        New-Item -Path $backupFolder -ItemType Directory | Out-Null
    }

    # Yedeklenecek anahtarlar
    $registryKeys = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy",
        "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002",
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    )

    Write-Log "Registry yedekleme işlemi başlatılıyor..." -LogType Info -VerboseOutput -InfoColor Cyan
    foreach ($key in $registryKeys) {
        $backupTime = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = if ($key -like "*Wow6432Node*") {
            Join-Path $backupFolder "Clean_Script_$backupTime`_$(($key -split '\\')[-1])_wow6432.reg"
        }
        else {
            Join-Path $backupFolder "Clean_Script_$backupTime`_$(($key -split '\\')[-1]).reg"
        }
        
        Write-Log "$key yedekleniyor..." -LogType Info -VerboseOutput -InfoColor Yellow
        Export-RegistryKey -keyPath $key -exportPath $backupFile
    }

    Write-Log "Yedekleme işlemi tamamlandı" -LogType Info -VerboseOutput -InfoColor Green
}

# SCHANNEL Ciphers temizleme fonksiyonu
function Clear-SCHANNELCiphers {
    Write-Log -Message "[1] SCHANNEL - Ciphers temizleniyor." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\*" -Force -ErrorAction Stop -Recurse
        Write-Log -Message "[1] SCHANNEL - Ciphers başarıyla temizlendi." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[1] SCHANNEL - Ciphers temizlenirken hata oluştu: $_" -LogType "Error" -VerboseOutput
    }
}

# SCHANNEL Hashes temizleme fonksiyonu
function Clear-SCHANNELHashes {
    Write-Log -Message "[2] SCHANNEL - Hashes algoritmaları temizleniyor." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\*" -Force -ErrorAction Stop -Recurse
        Write-Log -Message "[2] SCHANNEL - Hashes başarıyla temizlendi." -LogType "Info" -VerboseOutput  -InfoColor Green
    }
    catch {
        Write-Log -Message "[2] SCHANNEL - Hashes temizlenirken hata oluştu: $_" -LogType "Error" -VerboseOutput
    }
}

# SCHANNEL KeyExchangeAlgorithms temizleme fonksiyonu
function Clear-SCHANNELKeyExchangeAlgorithms {
    Write-Log -Message "[3] SCHANNEL - KeyExchangeAlgorithms temizleniyor." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\*" -Force -ErrorAction Stop -Recurse
        Write-Log -Message "[3] SCHANNEL - KeyExchangeAlgorithms başarıyla temizlendi." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[3] SCHANNEL - KeyExchangeAlgorithms temizlenirken hata oluştu: $_" -LogType "Error" -VerboseOutput
    }
}

# SCHANNEL Protocols temizleme fonksiyonu
function Clear-SCHANNELProtocols {
    Write-Log -Message "[4] SCHANNEL - Protocols temizleniyor." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*" -Force -ErrorAction Stop -Recurse
        Write-Log -Message "[4] SCHANNEL - Protocols temizlendi." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[4] SCHANNEL - Protocols temizlenirken hata oluştu: $_" -LogType "Error" -VerboseOutput
    }
}

# FIPS algoritma politikası devre dışı bırakma fonksiyonu
function Disable-FIPSAlgorithmPolicy {
    Write-Log -Message "[5] FIPS - FipsAlgorithmPolicy politikası devre dışı bırakılıyor." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name Enabled -Force -ErrorAction Stop
        Write-Log -Message "[5] FIPS - FipsAlgorithmPolicy politikası başarıyla devre dışı bırakıldı." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[5] FIPS - FipsAlgorithmPolicy politikası devre dışı bırakılırken hata oluştu: $_" -LogType "Error" -VerboseOutput
    }
}

# Cipher Suites sıralaması temizleme fonksiyonu
function Clear-CipherSuites {
    Write-Log -Message "[6] Cipher Suite sıralaması temizleniyor." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name Functions -Force -ErrorAction Stop
        Write-Log -Message "[6] Cipher Suite başarıyla temizlendi." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[6] Cipher Suite temizlenirken hata oluştu: $_" -LogType "Error" -VerboseOutput
    }
}

# Elliptic Curve yapılandırması temizleme fonksiyonu
function Clear-EllipticCurveConfig {
    Write-Log -Message "[7] Elliptic Curve yapılandırması temizleniyor." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name EccCurves -Force -ErrorAction Stop
        Write-Log -Message "[7] Elliptic Curve yapılandırması başarıyla temizlendi." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[7] Elliptic Curve yapılandırması temizlenirken hata oluştu: $_" -LogType "Error" -VerboseOutput
    }
}

# Script'i çalıştırmadan önce kullanıcıya uyarı ver ve onay al. Tam olarak anlaşılmadan devam edilmesi engellenir. Scripte bu adımı baypas edecek parametre verebilirsiniz.
function Confirm-Execution {
    if ($BypassConfirmation) {
        Write-Log "Kullanıcı onayı script çalıştırılırken verilen parametre ile baypas edildi." -LogType Info -VerboseOutput -InfoColor Yellow
        return
    }

    $confirmation = Read-Host "Bu script ile güvenlik ayarları temizlenecek. Devam etmek istediğinize emin misiniz? (Evet/evet)"
    if ($confirmation -notmatch "Evet|evet") {
        Write-Log "Kullanıcı onayı alınamadı. Script iptal edildi." -LogType Error -VerboseOutput
        exit
    }
}

#.net framework 4.6 ve üzeri için strong crypto ayarlarını geri alma fonksiyonu
function Clear-StrongCrypto {
    Write-Log "Strong Crypto ayarlarını geri alma işlemi başlatıldı." -LogType Info -VerboseOutput -InfoColor Cyan

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    )

    foreach ($regPath in $regPaths) {
        try {
            if (Test-Path -Path $regPath) {
                Remove-ItemProperty -Path $regPath -Name "SchUseStrongCrypto" -ErrorAction Stop
                Remove-ItemProperty -Path $regPath -Name "SystemDefaultTlsVersions" -ErrorAction Stop
                Write-Log "Strong Crypto ayarları başarıyla geri alındı: $regPath" -LogType Info -VerboseOutput -InfoColor Green
            }
            else {
                Write-Log "Registry path bulunamadı: $regPath" -LogType Warning -VerboseOutput
            }
        }
        catch {
            Write-Log "Strong Crypto ayarları geri alınırken hata oluştu: $_" -LogType Error -VerboseOutput
        }
    }
}

# Ana script fonksiyonu
function Invoke-SecurityCleanup {
    Confirm-Execution
    Backup-RegistryKeys
    Clear-SCHANNELCiphers
    Clear-SCHANNELHashes
    Clear-SCHANNELKeyExchangeAlgorithms
    Clear-SCHANNELProtocols
    Disable-FIPSAlgorithmPolicy
    Clear-CipherSuites
    Clear-EllipticCurveConfig
    Clear-StrongCrypto
    Write-Log -Message "Script tamamlandı." -LogType "Info" -VerboseOutput -InfoColor Green
}

# Script'i çalıştır
Invoke-SecurityCleanup