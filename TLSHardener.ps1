<#
.ScriptName: TLSHardener.ps1
.SYNOPSIS
Windows sunucularda TLS/SSL güvenlik yapılandırmasını sıkılaştıran PowerShell scripti.

.DESCRIPTION
Bu script aşağıdaki güvenlik ayarlarını yapılandırır:
- **Protokoller**: TLS 1.2/1.3 etkin, SSL 2.0/3.0 ve TLS 1.0/1.1 devre dışı
- **Şifreleme Algoritmaları**: AES etkin, RC4/DES/NULL devre dışı
- **Hash Algoritmaları**: SHA256/384/512 etkin, MD5 devre dışı
- **Anahtar Değişim**: ECDH/Diffie-Hellman yapılandırması
- **Cipher Suites**: Güvenli TLS 1.2/1.3 cipher suite sıralaması
- **FIPS Politikası**: Yapılandırılabilir

.PARAMETER BypassConfirmation
Kullanıcı onayını atlar

.PARAMETER EnableStrongCrypto
.NET Framework için Strong Crypto ayarlarını etkinleştirir

.PARAMETER WhatIf
Dry-Run modu - değişiklik yapmadan ne yapılacağını gösterir

.PARAMETER Profile
Güvenlik profili seçimi: strict, recommended, compatible
- strict: Sadece TLS 1.3, en güçlü cipher'lar
- recommended: TLS 1.2/1.3, GCM cipher'lar (varsayılan)
- compatible: Eski sistemlerle uyumlu, CBC dahil

.PARAMETER Rollback
Önceki bir yedeğe geri döner veya Windows varsayılanlarına sıfırlar

.PARAMETER BackupFile
Rollback için kullanılacak belirli bir yedek dosyası

.PARAMETER ToDefaults
Rollback sırasında yedek yerine Windows varsayılanlarına döner

.EXAMPLE
.\TLSHardener.ps1
Standart çalıştırma - kullanıcı onayı ister

.EXAMPLE
.\TLSHardener.ps1 -BypassConfirmation -EnableStrongCrypto
Onay istemeden ve Strong Crypto ile çalıştırır

.EXAMPLE
.\TLSHardener.ps1 -WhatIf
Dry-Run modu - değişiklik yapmadan ne yapılacağını gösterir

.EXAMPLE
.\TLSHardener.ps1 -Profile strict
En katı güvenlik profili ile çalıştırır

.EXAMPLE
.\TLSHardener.ps1 -Profile compatible -BypassConfirmation
Uyumlu profil ile onay istemeden çalıştırır

.EXAMPLE
.\TLSHardener.ps1 -Rollback
En son yedeğe geri döner

.EXAMPLE
.\TLSHardener.ps1 -Rollback -BackupFile ".\backups\20251129_103045_SCHANNEL.reg"
Belirtilen yedek dosyasına geri döner

.EXAMPLE
.\TLSHardener.ps1 -Rollback -ToDefaults
Windows varsayılan ayarlarına döner (Clean)

.NOTES
Proje: TLSHardener
Versiyon: 3.3
Tarih: 2025
#>
#Confirmation gerektiren işlemleri atlamak için scripte parametre ekler
param (
    [switch]$BypassConfirmation,
    [switch]$EnableStrongCrypto,
    [switch]$WhatIf,
    [switch]$Rollback,
    [string]$BackupFile = "",
    [switch]$ToDefaults,
    [ValidateSet("strict", "recommended", "compatible", "custom")]
    [string]$Profile = "recommended"
)

# Global değişkenler
$script:DryRun = $WhatIf
$script:ActiveProfile = $null

# ============================================================================
# ROLLBACK FONKSİYONLARI
# ============================================================================

# Mevcut yedekleri listele
function Get-AvailableBackups {
    $backupFolder = ".\backups"
    
    if (-not (Test-Path $backupFolder)) {
        return @()
    }
    
    # SCHANNEL yedeklerini bul (ana yedek dosyası)
    $backups = Get-ChildItem -Path $backupFolder -Filter "*SCHANNEL.reg" | 
               Sort-Object LastWriteTime -Descending
    
    return $backups
}

# Yedek dosyalarını grupla (aynı zaman damgasına sahip olanlar)
function Get-BackupGroup {
    param (
        [string]$BackupTimestamp
    )
    
    $backupFolder = ".\backups"
    $pattern = "*$BackupTimestamp*"
    
    return Get-ChildItem -Path $backupFolder -Filter $pattern
}

# Registry dosyasını içe aktar
function Import-RegistryBackup {
    param (
        [string]$RegFile
    )
    
    if (-not (Test-Path $RegFile)) {
        Write-Log "Yedek dosyası bulunamadı: $RegFile" -LogType Error -VerboseOutput
        return $false
    }
    
    try {
        $result = reg import $RegFile 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Başarıyla içe aktarıldı: $RegFile" -LogType Info -VerboseOutput -InfoColor Green
            return $true
        } else {
            Write-Log "İçe aktarma başarısız: $result" -LogType Error -VerboseOutput
            return $false
        }
    }
    catch {
        Write-Log "Hata oluştu: $_" -LogType Error -VerboseOutput
        return $false
    }
}

# Windows varsayılanlarına dön (Clean işlemi)
function Invoke-CleanToDefaults {
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║              WINDOWS VARSAYILANLARINA DÖNÜLÜYOR                ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    
    # SCHANNEL Ciphers
    Write-Log "[1/7] SCHANNEL Ciphers temizleniyor..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers") {
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\*" -Force -Recurse -ErrorAction SilentlyContinue
        }
        Write-Log "[1/7] SCHANNEL Ciphers temizlendi." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[1/7] SCHANNEL Ciphers temizlenirken hata: $_" -LogType Warning -VerboseOutput
    }
    
    # SCHANNEL Hashes
    Write-Log "[2/7] SCHANNEL Hashes temizleniyor..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes") {
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\*" -Force -Recurse -ErrorAction SilentlyContinue
        }
        Write-Log "[2/7] SCHANNEL Hashes temizlendi." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[2/7] SCHANNEL Hashes temizlenirken hata: $_" -LogType Warning -VerboseOutput
    }
    
    # SCHANNEL KeyExchangeAlgorithms
    Write-Log "[3/7] SCHANNEL KeyExchangeAlgorithms temizleniyor..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms") {
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\*" -Force -Recurse -ErrorAction SilentlyContinue
        }
        Write-Log "[3/7] SCHANNEL KeyExchangeAlgorithms temizlendi." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[3/7] SCHANNEL KeyExchangeAlgorithms temizlenirken hata: $_" -LogType Warning -VerboseOutput
    }
    
    # SCHANNEL Protocols
    Write-Log "[4/7] SCHANNEL Protocols temizleniyor..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols") {
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*" -Force -Recurse -ErrorAction SilentlyContinue
        }
        Write-Log "[4/7] SCHANNEL Protocols temizlendi." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[4/7] SCHANNEL Protocols temizlenirken hata: $_" -LogType Warning -VerboseOutput
    }
    
    # FIPS Policy
    Write-Log "[5/7] FIPS Policy temizleniyor..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name Enabled -Force -ErrorAction SilentlyContinue
        Write-Log "[5/7] FIPS Policy temizlendi." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[5/7] FIPS Policy temizlenirken hata: $_" -LogType Warning -VerboseOutput
    }
    
    # Cipher Suites
    Write-Log "[6/7] Cipher Suites temizleniyor..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name Functions -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name EccCurves -Force -ErrorAction SilentlyContinue
        Write-Log "[6/7] Cipher Suites temizlendi." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[6/7] Cipher Suites temizlenirken hata: $_" -LogType Warning -VerboseOutput
    }
    
    # .NET Strong Crypto
    Write-Log "[7/7] .NET Strong Crypto ayarları temizleniyor..." -LogType Info -VerboseOutput -InfoColor Cyan
    $netPaths = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    )
    foreach ($path in $netPaths) {
        try {
            if (Test-Path $path) {
                Remove-ItemProperty -Path $path -Name "SchUseStrongCrypto" -Force -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $path -Name "SystemDefaultTlsVersions" -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }
    Write-Log "[7/7] .NET Strong Crypto ayarları temizlendi." -LogType Info -VerboseOutput -InfoColor Green
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║         WINDOWS VARSAYILANLARINA DÖNÜŞ TAMAMLANDI              ║" -ForegroundColor Green
    Write-Host "║         Değişikliklerin aktif olması için yeniden başlatın     ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
}

# Rollback ana fonksiyonu
function Invoke-Rollback {
    param (
        [string]$SpecificBackupFile = "",
        [switch]$UseDefaults
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    ROLLBACK MODU                               ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # ToDefaults seçilmişse
    if ($UseDefaults) {
        Write-Log "Windows varsayılanlarına dönülecek..." -LogType Info -VerboseOutput -InfoColor Yellow
        
        if (-not $BypassConfirmation) {
            $confirm = Read-Host "Tüm TLS/SSL ayarları Windows varsayılanlarına dönecek. Onaylıyor musunuz? (E/H)"
            if ($confirm -notmatch "^[Ee]") {
                Write-Log "Rollback iptal edildi." -LogType Warning -VerboseOutput
                return
            }
        }
        
        Invoke-CleanToDefaults
        return
    }
    
    # Belirli bir yedek dosyası verilmişse
    if (-not [string]::IsNullOrEmpty($SpecificBackupFile)) {
        if (-not (Test-Path $SpecificBackupFile)) {
            Write-Log "Belirtilen yedek dosyası bulunamadı: $SpecificBackupFile" -LogType Error -VerboseOutput
            return
        }
        
        Write-Log "Belirtilen yedek dosyası yükleniyor: $SpecificBackupFile" -LogType Info -VerboseOutput -InfoColor Cyan
        
        if (-not $BypassConfirmation) {
            $confirm = Read-Host "Bu yedek dosyası yüklenecek. Onaylıyor musunuz? (E/H)"
            if ($confirm -notmatch "^[Ee]") {
                Write-Log "Rollback iptal edildi." -LogType Warning -VerboseOutput
                return
            }
        }
        
        Import-RegistryBackup -RegFile $SpecificBackupFile
        return
    }
    
    # Mevcut yedekleri listele
    $backups = Get-AvailableBackups
    
    if ($backups.Count -eq 0) {
        Write-Host "  ⚠️  Hiç yedek bulunamadı!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Seçenekler:" -ForegroundColor Gray
        Write-Host "    1. Windows varsayılanlarına dön" -ForegroundColor White
        Write-Host "    2. İptal" -ForegroundColor White
        Write-Host ""
        
        $choice = Read-Host "  Seçiminiz (1/2)"
        
        if ($choice -eq "1") {
            Invoke-CleanToDefaults
        } else {
            Write-Log "Rollback iptal edildi." -LogType Warning -VerboseOutput
        }
        return
    }
    
    # Yedekleri göster
    Write-Host "  Mevcut Yedekler:" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor Gray
    
    $i = 1
    foreach ($backup in $backups) {
        $timestamp = $backup.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        $size = [math]::Round($backup.Length / 1KB, 1)
        Write-Host "    [$i] $timestamp - $($backup.Name) ($size KB)" -ForegroundColor White
        $i++
    }
    
    Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "    [D] Windows varsayılanlarına dön" -ForegroundColor Yellow
    Write-Host "    [İ] İptal" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "  Seçiminiz"
    
    if ($choice -match "^[Dd]$") {
        Invoke-CleanToDefaults
        return
    }
    
    if ($choice -match "^[İiIı]$" -or [string]::IsNullOrEmpty($choice)) {
        Write-Log "Rollback iptal edildi." -LogType Warning -VerboseOutput
        return
    }
    
    # Sayısal seçim
    $selectedIndex = 0
    if ([int]::TryParse($choice, [ref]$selectedIndex)) {
        if ($selectedIndex -ge 1 -and $selectedIndex -le $backups.Count) {
            $selectedBackup = $backups[$selectedIndex - 1]
            
            # Aynı zaman damgasına sahip tüm yedekleri bul
            $timestamp = $selectedBackup.Name -replace ".*?(\d{8}_\d{6}).*", '$1'
            $backupGroup = Get-BackupGroup -BackupTimestamp $timestamp
            
            Write-Host ""
            Write-Host "  Seçilen yedek grubu ($($backupGroup.Count) dosya):" -ForegroundColor Cyan
            foreach ($file in $backupGroup) {
                Write-Host "    - $($file.Name)" -ForegroundColor Gray
            }
            Write-Host ""
            
            if (-not $BypassConfirmation) {
                $confirm = Read-Host "  Bu yedekler yüklenecek. Onaylıyor musunuz? (E/H)"
                if ($confirm -notmatch "^[Ee]") {
                    Write-Log "Rollback iptal edildi." -LogType Warning -VerboseOutput
                    return
                }
            }
            
            Write-Host ""
            Write-Log "Yedekler yükleniyor..." -LogType Info -VerboseOutput -InfoColor Cyan
            
            foreach ($file in $backupGroup) {
                Import-RegistryBackup -RegFile $file.FullName
            }
            
            Write-Host ""
            Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
            Write-Host "║                    ROLLBACK TAMAMLANDI                         ║" -ForegroundColor Green
            Write-Host "║         Değişikliklerin aktif olması için yeniden başlatın     ║" -ForegroundColor Green
            Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        } else {
            Write-Log "Geçersiz seçim." -LogType Error -VerboseOutput
        }
    } else {
        Write-Log "Geçersiz seçim." -LogType Error -VerboseOutput
    }
}

# ============================================================================
# YARDIMCI FONKSİYONLAR
# ============================================================================

# Dry-Run modu için yardımcı fonksiyon
function Write-DryRunAction {
    param (
        [string]$Action,
        [string]$Target,
        [string]$Details = ""
    )
    
    $message = "[DRY-RUN] $Action : $Target"
    if ($Details) {
        $message += " -> $Details"
    }
    Write-Host $message -ForegroundColor Magenta
}

# Profil yükleme fonksiyonu
function Load-SecurityProfile {
    param (
        [string]$ProfileName
    )
    
    if ([string]::IsNullOrEmpty($ProfileName)) {
        return $null
    }
    
    $profilePath = ".\config\$ProfileName.json"
    
    if (-not (Test-Path $profilePath)) {
        Write-Host "  ❌ Profil bulunamadı: $profilePath" -ForegroundColor Red
        Write-Host "  Mevcut profiller: strict, recommended, compatible, custom" -ForegroundColor Yellow
        exit 1
    }
    
    try {
        $profileData = Get-Content -Path $profilePath -Raw | ConvertFrom-Json
        $script:ActiveProfile = $profileData
        
        Write-Host "`n" -NoNewline
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║                    PROFİL YÜKLENDI                              ║" -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host "  Profil: " -NoNewline -ForegroundColor Gray
        Write-Host "$($profileData.name)" -ForegroundColor Green
        Write-Host "  Açıklama: " -NoNewline -ForegroundColor Gray
        Write-Host "$($profileData.description)" -ForegroundColor White
        Write-Host ""
        
        return $profileData
    }
    catch {
        Write-Host "  ❌ Profil yüklenirken hata: $_" -ForegroundColor Red
        exit 1
    }
}

# Profil veya config'den değer alma
function Get-ConfigValue {
    param (
        [string]$ConfigType,
        [string]$JsonPath = $null
    )
    
    if ($null -ne $script:ActiveProfile) {
        # Profilden al
        switch ($ConfigType) {
            "protocols" { return $script:ActiveProfile.protocols }
            "ciphers" { return $script:ActiveProfile.ciphers }
            "hashes" { return $script:ActiveProfile.hashes }
            "keyExchange" { return $script:ActiveProfile.keyExchange }
            "cipherSuitesTls13" { return $script:ActiveProfile.cipherSuitesTls13 }
            "cipherSuitesTls12" { return $script:ActiveProfile.cipherSuitesTls12 }
            "eccCurves" { return $script:ActiveProfile.eccCurves }
            "fipsPolicy" { return $script:ActiveProfile.fipsPolicy }
            "strongCrypto" { return $script:ActiveProfile.strongCrypto }
        }
    }
    
    # JSON dosyasından al
    if ($JsonPath) {
        return Get-ConfigFromJson -jsonFilePath $JsonPath
    }
    
    return $null
}

# Konsol kodlamasını UTF-8 olarak ayarla
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$os = Get-WmiObject -Class Win32_OperatingSystem
# Loglama için fonksiyon
$TimeStamp = Get-Date -Format "yyyy_MM_dd_HHmm"
[string]$LogFilePath = ".\logs\TLSHardener_$TimeStamp.log"
function Write-Log {
    [CmdletBinding()]
    param (
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error")]
        [string]$LogType = "Info",
        [switch]$VerboseOutput, # Bu parametre ile log ekran çıktısı kontrol edilir
        [ValidateSet("Green", "Yellow", "Cyan")]
        [string]$InfoColor = "Green" # Info log türü için renk seçimi
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
    if ($script:DryRun) {
        Write-DryRunAction -Action "YEDEKLEME" -Target "Registry anahtarları" -Details "backups/ klasörüne yedeklenecek"
        $registryKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy",
            "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002",
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        )
        foreach ($key in $registryKeys) {
            Write-DryRunAction -Action "  YEDEK" -Target $key
        }
        return
    }
    
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
            Join-Path $backupFolder "Protocol_Script_$backupTime`_$(($key -split '\\')[-1])_wow6432.reg"
        }
        else {
            Join-Path $backupFolder "Protocol_Script_$backupTime`_$(($key -split '\\')[-1]).reg"
        }
        
        Write-Log "$key yedekleniyor..." -LogType Info -VerboseOutput -InfoColor Yellow
        Export-RegistryKey -keyPath $key -exportPath $backupFile
    }

    Write-Log "Yedekleme işlemi tamamlandı" -LogType Info -VerboseOutput -InfoColor Green
}


# Protokolleri yapılandırma fonksiyonu
function Set-ProtocolsClients {
    
    Write-Log "Protokol[Clients] yapılandırması başlatıldı." -LogType Info -VerboseOutput -InfoColor Cyan
    
    # Profilden protokol yapılandırmasını al
    $protocols = @{}
    $script:ActiveProfile.protocols.PSObject.Properties | ForEach-Object {
        $protocols[$_.Name] = $_.Value
    }

    foreach ($protocol in ($protocols.Keys | Sort-Object)) {
        $enabled = $protocols[$protocol]
        $regPathClient = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"

        if ($script:DryRun) {
            Write-DryRunAction -Action "PROTOKOL[Client]" -Target $protocol -Details $(if ($enabled) { "ENABLED" } else { "DISABLED" })
            continue
        }

        try {
            if ($enabled -eq $false) {
                # Devre dışı bırakma işlemleri
                New-Item $regPathClient -Force | Out-Null
                New-ItemProperty -path $regPathClient -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
                New-ItemProperty -path $regPathClient -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
            }
            else {
                # Etkinleştirme işlemleri
                New-Item $regPathClient -Force | Out-Null
                New-ItemProperty -path $regPathClient -name Enabled -value 1 -PropertyType 'DWord' -Force | Out-Null
                New-ItemProperty -path $regPathClient -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null

            }
            Write-Log "$protocol $(if ($enabled) { 'enabled' } else { 'disabled' }) edildi." -LogType Info -VerboseOutput
        }
        catch {
            Write-Log "$protocol [Clients] protokolü yapılandırılırken hata oluştu: $_" -LogType Error -VerboseOutput
        }
    }

    Write-Log "Protokol[Clients] yapılandırması tamamlandı.`n" -LogType Info -VerboseOutput -InfoColor Cyan
}


# Protokolleri yapılandırma fonksiyonu

function Set-ProtocolsServers {
    
    Write-Log "Protokol[Servers] yapılandırması başlatıldı." -LogType Info -VerboseOutput -InfoColor Cyan
    
    # Profilden protokol yapılandırmasını al
    $protocols = @{}
    $script:ActiveProfile.protocols.PSObject.Properties | ForEach-Object {
        $protocols[$_.Name] = $_.Value
    }
        
    foreach ($protocol in ($protocols.Keys | Sort-Object)) {
        $enabled = $protocols[$protocol]
        $regPathServer = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"

        if ($script:DryRun) {
            Write-DryRunAction -Action "PROTOKOL[Server]" -Target $protocol -Details $(if ($enabled) { "ENABLED" } else { "DISABLED" })
            continue
        }

        try {
            if ($enabled -eq $false) {
                # Devre dışı bırakma işlemleri
                New-Item $regPathServer -Force | Out-Null
                New-ItemProperty -path $regPathServer -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
                New-ItemProperty -path $regPathServer -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
            }
            else {
                # Etkinleştirme işlemleri
                New-Item $regPathServer -Force | Out-Null
                New-ItemProperty -path $regPathServer -name Enabled -value 1 -PropertyType 'DWord' -Force | Out-Null
                New-ItemProperty -path $regPathServer -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
            }
            Write-Log "$protocol $(if ($enabled) { 'enabled' } else { 'disabled' }) edildi." -LogType Info -VerboseOutput
        }
        catch {
            Write-Log "$protocol [Servers] protokolü yapılandırılırken hata oluştu: $_" -LogType Error -VerboseOutput
        }
    }

    Write-Log "Protokol[Servers] yapılandırması tamamlandı.`n" -LogType Info -VerboseOutput -InfoColor Cyan
}

# Şifreleme algoritmalarını yapılandırma fonksiyonu
function Set-EncryptionAlgorithms {
    Write-Log "Şifreleme Algoritmaları yapılandırması başladı." -LogType Info -VerboseOutput -InfoColor Cyan
    
    # Profilden şifreleme algoritması yapılandırmasını al
    $encryptionAlgorithms = @{}
    $script:ActiveProfile.ciphers.PSObject.Properties | ForEach-Object {
        $encryptionAlgorithms[$_.Name] = $_.Value
    }

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"

    foreach ($algorithm in $encryptionAlgorithms.Keys) {
        $enabled = $encryptionAlgorithms[$algorithm]
        $regPathAlgorithm = "$regPath\$algorithm"
        
        if ($script:DryRun) {
            Write-DryRunAction -Action "ŞİFRELEME" -Target $algorithm -Details $(if ($enabled) { "ENABLED" } else { "DISABLED" })
            continue
        }
        
        $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($algorithm)
        Write-Log "$regPathAlgorithm registry KEY oluşturuldu" -LogType Info -VerboseOutput

        if ($enabled) {
            $key.SetValue('Enabled', 0xffffffff, 'DWord')
        }
        else {
            $key.SetValue('Enabled', 0x0, 'DWord')
        }

        $key.Close()
        Write-Log "$algorithm $(if ($enabled) { 'enabled' } else { 'disabled' }) edildi." -LogType Info -VerboseOutput
    }

    Write-Log "Şifreleme algoritmaları yapılandırması tamamlandı.`n" -LogType Info -VerboseOutput -InfoColor Cyan
}

# Hash algoritmalarını yapılandırma fonksiyonu
function Set-HashAlgorithms {
    Write-Log "Hash algoritmaları yapılandırması başladı." -LogType Info -VerboseOutput -InfoColor Cyan
    
    # Profilden hash algoritması yapılandırmasını al
    $hashAlgorithms = @{}
    $script:ActiveProfile.hashes.PSObject.Properties | ForEach-Object {
        $hashAlgorithms[$_.Name] = $_.Value
    }

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"

    foreach ($algorithm in $hashAlgorithms.Keys) {
        $enabled = $hashAlgorithms[$algorithm]
        $regPathAlgorithm = "$regPath\$algorithm"
        
        if ($script:DryRun) {
            Write-DryRunAction -Action "HASH" -Target $algorithm -Details $(if ($enabled) { "ENABLED" } else { "DISABLED" })
            continue
        }
        
        $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($algorithm)
        Write-Log "$regPathAlgorithm registry KEY oluşturuldu" -LogType Info -VerboseOutput

        if ($enabled) {
            $key.SetValue('Enabled', 0xffffffff, 'DWord')
        }
        else {
            $key.SetValue('Enabled', 0x0, 'DWord')
        }

        $key.Close()
        Write-Log "$algorithm $(if ($enabled) { 'enabled' } else { 'disabled' }) edildi." -LogType Info -VerboseOutput
    }

    Write-Log "Hash algoritmaları yapılandırması tamamlandı.`n" -LogType Info -VerboseOutput -InfoColor Cyan
}

# Anahtar değişim algoritmalarını yapılandırma fonksiyonu
function Set-KeyExchangeAlgorithms {
    Write-Log "TLS Anahtar değişim algoritmaları yapılandırması başladı." -LogType Info -VerboseOutput -InfoColor Cyan
    
    # Profilden anahtar değişim yapılandırmasını al
    $keyExchangeAlgorithms = @{}
    $dhMinKeyBitLength = 3072
    $script:ActiveProfile.keyExchange.PSObject.Properties | ForEach-Object {
        if ($_.Name -eq 'DH-MinKeyBitLength') {
            $dhMinKeyBitLength = $_.Value
        } else {
            $keyExchangeAlgorithms[$_.Name] = $_.Value
        }
    }

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"

    foreach ($algorithm in $keyExchangeAlgorithms.Keys) {
        # DH-MinKeyBitLength gibi meta bilgileri atla
        if ($algorithm -eq 'DH-MinKeyBitLength') { continue }
        
        $enabled = $keyExchangeAlgorithms[$algorithm]
        $regPathAlgorithm = "$regPath\$algorithm"
        
        if ($script:DryRun) {
            $details = if ($enabled) { "ENABLED" } else { "DISABLED" }
            if ($algorithm -eq 'Diffie-Hellman' -and $enabled) {
                $details += " (MinKeyBitLength: $dhMinKeyBitLength bit)"
            }
            Write-DryRunAction -Action "KEY-EXCHANGE" -Target $algorithm -Details $details
            continue
        }
        
        $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($algorithm)
        Write-Log "$regPathAlgorithm registry KEY oluşturuldu" -LogType Info -VerboseOutput

        if ($enabled) {
            $key.SetValue('Enabled', 0xffffffff, 'DWord')
            if ($algorithm -eq 'Diffie-Hellman') {
                $dhKeyHex = [convert]::ToInt32($dhMinKeyBitLength)
                $key.SetValue('ServerMinKeyBitLength', $dhKeyHex, 'DWord')
                $key.SetValue('ClientMinKeyBitLength', $dhKeyHex, 'DWord')
                Write-Log "DH MinKeyBitLength: $dhMinKeyBitLength bit olarak ayarlandı" -LogType Info -VerboseOutput
            }
        }
        else {
            $key.SetValue('Enabled', 0x0, 'DWord')
        }

        $key.Close()
        Write-Log "$algorithm $(if ($enabled) { 'enabled' } else { 'disabled' }) edildi." -LogType Info -VerboseOutput
    }

    Write-Log "TLS Anahtar değişim algoritmaları yapılandırması tamamlandı.`n" -LogType Info -VerboseOutput -InfoColor Cyan
}

# FIPS algoritma politikasını devre dışı bırakma fonksiyonu
function Set-FIPSAlgorithmPolicy {
    param (
        [Parameter(Mandatory = $true)]
        [int]$EnabledValue
    )
    
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
    
    if ($script:DryRun) {
        Write-DryRunAction -Action "FIPS" -Target "FipsAlgorithmPolicy" -Details "Enabled = $EnabledValue"
        return
    }
    
    try {
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "Enabled" -Value $EnabledValue -Type DWord
        Write-Log -Message "FIPS Algorithm Policy 'Enabled' değeri başarıyla $EnabledValue olarak ayarlandı." -LogType "Info" -VerboseOutput -InfoColor Yellow
    }
    catch {
        Write-Log -Message "FIPS Algorithm Policy 'Enabled' değeri ayarlanırken hata oluştu: $_" -LogType "Error" -VerboseOutput
    }
}

# Cipher suites ayarlama fonksiyonu
function Set-CipherSuites {
    Write-Log "Cipher Suites yapılandırması başladı." -LogType Info -VerboseOutput -InfoColor Cyan
    
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    
    # Profilden cipher suite yapılandırmasını al
    $tls13Suites = @($script:ActiveProfile.cipherSuitesTls13)
    $tls12Suites = @($script:ActiveProfile.cipherSuitesTls12)
    
    $cipherSuitesUsed = ""
    $allCipherSuites = @()

    if ($os.Version -ge [System.Version]'10.0.20348') {
        $allCipherSuites = $tls13Suites + $tls12Suites
        $cipherSuitesUsed = "TLS 1.3 ve TLS 1.2"
    }
    elseif ($os.Version -ge [System.Version]'10.0.14393') {
        $allCipherSuites = $tls12Suites
        $cipherSuitesUsed = "TLS 1.2"
    }
    else {
        Write-Log -Message "Desteklenmeyen işletim sistemi sürümü." -LogType Error -VerboseOutput
        return
    }

    if ($script:DryRun) {
        Write-DryRunAction -Action "CIPHER SUITES" -Target $cipherSuitesUsed -Details "$($allCipherSuites.Count) cipher suite yapılandırılacak"
        foreach ($suite in $allCipherSuites) {
            Write-DryRunAction -Action "  CIPHER" -Target $suite
        }
        return
    }
    
    try {
        if (!(Test-Path -Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        $key = Get-Item -Path $regPath -ErrorAction Stop
    }
    catch {
        Write-Log -Message "Registry key bulunamadı veya oluşturulamadı: $regPath" -LogType Error -VerboseOutput
        return
    }

    try {
        Set-ItemProperty -Path $regPath -Name 'Functions' -Value ([String]::Join(',', $allCipherSuites)) -Type String
        Write-Log -Message "Cipher suites başarıyla yapılandırıldı. Kullanılan cipher suites: $cipherSuitesUsed" -LogType Info -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "Cipher suites yapılandırılırken hata oluştu: $_" -LogType Error -VerboseOutput
    }
    finally {
        $key.Close()
    }
}

function Set-EccCurves {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    
    # Profilden ECC curves yapılandırmasını al
    $curvesToUse = $script:ActiveProfile.eccCurves
    Write-Log -Message "Profil ECC Curves kullanılıyor: $($curvesToUse.Count) eğri" -LogType Info -VerboseOutput -InfoColor Cyan
    
    if ($script:DryRun) {
        Write-DryRunAction -Action "ECC CURVES" -Target "Eliptik Eğriler" -Details "$($curvesToUse.Count) eğri yapılandırılacak"
        foreach ($curve in $curvesToUse) {
            Write-DryRunAction -Action "  ECC" -Target $curve
        }
        return
    }
    
    try {
        if (!(Test-Path -Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        $key = Get-Item -Path $regPath -ErrorAction Stop
    }
    catch {
        Write-Log -Message "Registry key bulunamadı veya oluşturulamadı: $regPath" -LogType Error -VerboseOutput
        return
    }

    try {
        Set-ItemProperty -Path $regPath -Name 'EccCurves' -Value $curvesToUse -Type MultiString -Force
        Write-Log -Message "ECC Curves başarıyla yapılandırıldı." -LogType Info -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "ECC Curves yapılandırılırken hata oluştu: $_" -LogType Error -VerboseOutput
    }
    finally {
        $key.Close()
    }
}
# Script'i çalıştır madan önce kullanıcıya uyarı ver ve onay al. Tam olarak anlaşılmadan devam edilmesi engellenir. Örnek tam olarak EVET veya evet yazılmalıdır.
function Confirm-Execution {
    if ($BypassConfirmation) {
        Write-Log "Kullanıcı onayı script çalıştırılırken verilen parametre ile baypas edildi." -LogType Info -VerboseOutput -InfoColor Yellow
        return
    }

    $confirmation = Read-Host "TLSHardener ile güvenlik ayarları yapılandırılacak. Devam etmek istediğinize emin misiniz? (Evet/evet)`
Bu uyarıyı görmeden çalıştırmak için: .\TLSHardener.ps1 -BypassConfirmation"
    if ($confirmation -notmatch "Evet|evet") {
        Write-Log "Kullanıcı onayı alınamadı. Script iptal edildi." -LogType Error -VerboseOutput
        exit
    }
}

#.net framework 4.0 için strong crypto ayarları
function Set-StrongCrypto {
    if ($EnableStrongCrypto) {
    
        Write-Log "Strong Crypto ayarları yapılandırması başlatıldı." -LogType Info -VerboseOutput -InfoColor Cyan

        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        )

        if ($script:DryRun) {
            foreach ($regPath in $regPaths) {
                Write-DryRunAction -Action ".NET CRYPTO" -Target $regPath -Details "SchUseStrongCrypto=1, SystemDefaultTlsVersions=1"
            }
            return
        }

        foreach ($regPath in $regPaths) {
            try {
                if (!(Test-Path -Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "SchUseStrongCrypto" -Value 1 -Type DWord -Force
                Set-ItemProperty -Path $regPath -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord -Force
                Write-Log ".NET Strong Crypto ayarları başarıyla yapılandırıldı: $regPath" -LogType Info -VerboseOutput -InfoColor Green
            }
            catch {
                Write-Log ".NET Strong Crypto ayarları yapılandırılırken hata oluştu: $_" -LogType Error -VerboseOutput
            }
        }
    }
}


# Ana script fonksiyonu
function Invoke-SecurityConfiguration {
    # Clear-Host
    
    # Profil yükleme (varsayılan: recommended)
    Load-SecurityProfile -ProfileName $Profile
    
    # Dry-Run modu başlangıç mesajı
    if ($script:DryRun) {
        Write-Host "`n" -NoNewline
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
        Write-Host "║                    DRY-RUN MODU AKTİF                          ║" -ForegroundColor Magenta
        Write-Host "║  Hiçbir değişiklik yapılmayacak, sadece önizleme gösterilecek  ║" -ForegroundColor Magenta
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
        Write-Host "`n" -NoNewline
    }
    
    Confirm-Execution
    Backup-RegistryKeys
    Set-ProtocolsClients
    Set-ProtocolsServers
    Set-EncryptionAlgorithms
    Set-HashAlgorithms
    Set-KeyExchangeAlgorithms
    Set-FIPSAlgorithmPolicy -EnabledValue 0
    Set-CipherSuites -regPath $regPath -tls13CipherSuites $tls13CipherSuites -tls12CipherSuites $tls12CipherSuites
    Set-EccCurves -regPath $regPath -eccCurves $eccCurves
    Set-StrongCrypto
    
    if ($script:DryRun) {
        Write-Host "`n" -NoNewline
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
        Write-Host "║                    DRY-RUN TAMAMLANDI                          ║" -ForegroundColor Magenta
        Write-Host "║  Gerçek değişiklik için -WhatIf parametresini kaldırın         ║" -ForegroundColor Magenta
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    } else {
        Write-Log -Message "Script tamamlandı.`n" -LogType "Info" -VerboseOutput -InfoColor Green
    }
}

# ============================================================================
# SCRIPT BAŞLATMA
# ============================================================================

# Rollback modu mu kontrol et
if ($Rollback) {
    # Log dosyası
    $TimeStamp = Get-Date -Format "yyyy_MM_dd_HHmm"
    [string]$LogFilePath = ".\logs\TLSHardener-Rollback_$TimeStamp.log"
    
    Invoke-Rollback -SpecificBackupFile $BackupFile -UseDefaults:$ToDefaults
    
    Write-Log "Rollback işlemi tamamlandı." -LogType Info -VerboseOutput -InfoColor Green
    exit 0
}

# Normal mod - Script'i çalıştır
Invoke-SecurityConfiguration

# Script sonlandır
Write-Log "Script sonlandırıldı." -LogType Info -VerboseOutput -InfoColor Green

# Kullanılmış olan değişkenleri temizle
Write-Log "Değişkenler temizleniyor" -LogType Info -VerboseOutput -InfoColor Yellow
Remove-Variable -Name LogFilePath, backupFolder, backupTime, backupFile, os, protocols, `
    protocol, enabled, regPathClient, regPathServer, algorithm, regPathAlgorithm, `
    key, keyExchangeAlgorithms, allCipherSuites, cipherSuitesUsed, tls13CipherSuites, `
    tls12CipherSuites -ErrorAction SilentlyContinue
