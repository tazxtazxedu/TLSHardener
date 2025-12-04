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

.PARAMETER ComputerName
Uzak sunucu(lar) üzerinde çalıştırır. PowerShell Remoting gerektirir.

.PARAMETER Credential
Uzak sunuculara bağlanmak için kullanılacak kimlik bilgisi

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

.EXAMPLE
.\TLSHardener.ps1 -ComputerName "Server01","Server02" -Profile recommended
Birden fazla uzak sunucuda yapılandırma uygular

.EXAMPLE
.\TLSHardener.ps1 -ComputerName "Server01" -Credential (Get-Credential)
Belirtilen kimlik bilgileri ile uzak sunucuda çalıştırır

.NOTES
    Proje      : TLSHardener
    Versiyon   : 3.5
    Yazar      : TLSHardener Contributors
    Lisans     : MIT
    Tarih      : 2025
    
    Gereksinimler:
    - Windows Server 2016+ veya Windows 10+
    - PowerShell 5.1+
    - Administrator yetkisi
    - TLS 1.3 için: Windows Server 2022+ / Windows 11+

.LINK
    https://github.com/tazxtazxedu/TLSHardener
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
    [Alias("Profile")]
    [string]$SecurityProfile = "recommended",
    [string[]]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential
)

# Global değişkenler
$script:DryRun = $WhatIf
$script:ActiveProfile = $null
$script:IsRemoteSession = $false

# ============================================================================
# HATA KODLARI VE YÖNETİMİ
# ============================================================================

# Hata kodları enum benzeri yapı
$script:ErrorCodes = @{
    # Genel Hatalar (1000-1099)
    SUCCESS                    = @{ Code = 0;    Message = "İşlem başarılı" }
    UNKNOWN_ERROR              = @{ Code = 1000; Message = "Bilinmeyen hata" }
    PERMISSION_DENIED          = @{ Code = 1001; Message = "Yetki reddedildi - Yönetici olarak çalıştırın" }
    INVALID_PARAMETER          = @{ Code = 1002; Message = "Geçersiz parametre" }
    
    # Profil Hataları (1100-1199)
    PROFILE_NOT_FOUND          = @{ Code = 1100; Message = "Profil dosyası bulunamadı" }
    PROFILE_INVALID_JSON       = @{ Code = 1101; Message = "Profil JSON formatı geçersiz" }
    PROFILE_MISSING_PROPERTY   = @{ Code = 1102; Message = "Profil gerekli özellik eksik" }
    
    # Registry Hataları (1200-1299)
    REGISTRY_ACCESS_DENIED     = @{ Code = 1200; Message = "Registry erişim engellendi" }
    REGISTRY_KEY_NOT_FOUND     = @{ Code = 1201; Message = "Registry anahtarı bulunamadı" }
    REGISTRY_WRITE_FAILED      = @{ Code = 1202; Message = "Registry yazma başarısız" }
    REGISTRY_BACKUP_FAILED     = @{ Code = 1203; Message = "Registry yedekleme başarısız" }
    REGISTRY_RESTORE_FAILED    = @{ Code = 1204; Message = "Registry geri yükleme başarısız" }
    
    # Uzak Sunucu Hataları (1300-1399)
    REMOTE_CONNECTION_FAILED   = @{ Code = 1300; Message = "Uzak sunucu bağlantısı başarısız" }
    REMOTE_PING_FAILED         = @{ Code = 1301; Message = "Ping başarısız" }
    REMOTE_WINRM_FAILED        = @{ Code = 1302; Message = "WinRM bağlantısı başarısız" }
    REMOTE_SESSION_FAILED      = @{ Code = 1303; Message = "Uzak oturum oluşturulamadı" }
    REMOTE_EXECUTION_FAILED    = @{ Code = 1304; Message = "Uzak komut çalıştırma başarısız" }
    
    # Dosya Hataları (1400-1499)
    FILE_NOT_FOUND             = @{ Code = 1400; Message = "Dosya bulunamadı" }
    FILE_READ_FAILED           = @{ Code = 1401; Message = "Dosya okuma başarısız" }
    FILE_WRITE_FAILED          = @{ Code = 1402; Message = "Dosya yazma başarısız" }
    BACKUP_NOT_FOUND           = @{ Code = 1403; Message = "Yedek dosyası bulunamadı" }
    
    # Yapılandırma Hataları (1500-1599)
    PROTOCOL_CONFIG_FAILED     = @{ Code = 1500; Message = "Protokol yapılandırması başarısız" }
    CIPHER_CONFIG_FAILED       = @{ Code = 1501; Message = "Şifreleme yapılandırması başarısız" }
    HASH_CONFIG_FAILED         = @{ Code = 1502; Message = "Hash yapılandırması başarısız" }
    KEYEXCHANGE_CONFIG_FAILED  = @{ Code = 1503; Message = "Anahtar değişim yapılandırması başarısız" }
    CIPHERSUITE_CONFIG_FAILED  = @{ Code = 1504; Message = "Cipher suite yapılandırması başarısız" }
    ECC_CONFIG_FAILED          = @{ Code = 1505; Message = "ECC eğri yapılandırması başarısız" }
}

# Merkezi hata yönetim fonksiyonu
function Write-TLSError {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ErrorType,
        
        [string]$Details = "",
        
        [string]$Target = "",
        
        [switch]$Throw,
        
        [System.Management.Automation.ErrorRecord]$Exception
    )
    
    $errorInfo = $script:ErrorCodes[$ErrorType]
    if (-not $errorInfo) {
        $errorInfo = $script:ErrorCodes["UNKNOWN_ERROR"]
    }
    
    $errorCode = $errorInfo.Code
    $errorMessage = $errorInfo.Message
    
    # Hata mesajını oluştur
    $fullMessage = "[TLS-$errorCode] $errorMessage"
    if ($Target) { $fullMessage += " - Hedef: $Target" }
    if ($Details) { $fullMessage += " - $Details" }
    if ($Exception) { $fullMessage += " - Hata: $($Exception.Exception.Message)" }
    
    # Log'a yaz
    Write-Log $fullMessage -LogType Error -VerboseOutput
    
    # İstenirse exception fırlat
    if ($Throw) {
        throw $fullMessage
    }
    
    # Hata bilgisini döndür
    return @{
        Code = $errorCode
        Type = $ErrorType
        Message = $errorMessage
        Details = $Details
        Target = $Target
        FullMessage = $fullMessage
    }
}

# ============================================================================
# UZAK SUNUCU FONKSİYONLARI
# ============================================================================

function Test-RemoteConnection {
    param (
        [string]$Computer,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $params = @{
            ComputerName = $Computer
            Count = 1
            Quiet = $true
            ErrorAction = 'Stop'
        }
        
        if (-not (Test-Connection @params)) {
            $errorInfo = Write-TLSError -ErrorType "REMOTE_PING_FAILED" -Target $Computer
            return @{ Success = $false; Error = $errorInfo.Message; ErrorCode = $errorInfo.Code }
        }
        
        # WinRM bağlantısını test et
        $sessionParams = @{
            ComputerName = $Computer
            ErrorAction = 'Stop'
        }
        if ($Cred) { $sessionParams.Credential = $Cred }
        
        $session = New-PSSession @sessionParams
        Remove-PSSession $session
        
        return @{ Success = $true; Error = $null; ErrorCode = 0 }
    }
    catch {
        $errorInfo = Write-TLSError -ErrorType "REMOTE_WINRM_FAILED" -Target $Computer -Exception $_
        return @{ Success = $false; Error = $errorInfo.Message; ErrorCode = $errorInfo.Code }
    }
}

function Invoke-RemoteConfiguration {
    param (
        [string[]]$Computers,
        [System.Management.Automation.PSCredential]$Cred,
        [string]$SelectedProfile,
        [bool]$IsDryRun,
        [bool]$StrongCrypto
    )
    
    $scriptPath = $PSScriptRoot
    $results = @()
    
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    UZAK SUNUCU YAPILANDIRMASI                      ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Bağlantıları test et
    Write-Host "  🔍 Sunucu bağlantıları kontrol ediliyor..." -ForegroundColor Yellow
    Write-Host ""
    
    $validComputers = @()
    foreach ($computer in $Computers) {
        Write-Host "    [$computer] " -NoNewline
        $testResult = Test-RemoteConnection -Computer $computer -Cred $Cred
        
        if ($testResult.Success) {
            Write-Host "✅ Bağlantı başarılı" -ForegroundColor Green
            $validComputers += $computer
        } else {
            Write-Host "❌ Bağlantı başarısız: $($testResult.Error)" -ForegroundColor Red
            $results += [PSCustomObject]@{
                ComputerName = $computer
                Status = "Bağlantı Hatası"
                Message = $testResult.Error
                Success = $false
            }
        }
    }
    
    if ($validComputers.Count -eq 0) {
        Write-Host "`n  ❌ Bağlanılabilecek sunucu bulunamadı!" -ForegroundColor Red
        return $results
    }
    
    Write-Host "`n  📦 Profil dosyası hazırlanıyor..." -ForegroundColor Yellow
    
    # Profil dosyasını oku
    $profilePath = Join-Path $scriptPath "config\$SelectedProfile.json"
    if (-not (Test-Path $profilePath)) {
        $profilePath = Join-Path $scriptPath "config\recommended.json"
    }
    $profileContent = Get-Content $profilePath -Raw
    
    # Script bloğu oluştur
    $remoteScriptBlock = {
        param($ProfileJson, $DryRun, $EnableStrong, $ProfileName)
        
        $ErrorActionPreference = 'Stop'
        $results = @{
            Success = $true
            Messages = @()
            Errors = @()
        }
        
        try {
            # Profili parse et
            $profileData = $ProfileJson | ConvertFrom-Json
            
            $results.Messages += "Profil yüklendi: $ProfileName"
            
            if ($DryRun) {
                $results.Messages += "[DRY-RUN] Değişiklikler simüle edilecek"
            } else {
                # Registry yedekleme
                $backupFolder = "C:\TLSHardener-Backups"
                if (-not (Test-Path $backupFolder)) {
                    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
                }
                
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $backupFile = Join-Path $backupFolder "SCHANNEL_$timestamp.reg"
                
                $null = reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $backupFile /y 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $results.Messages += "Yedek alındı: $backupFile"
                } else {
                    $results.Messages += "Yedek alınamadı (devam ediliyor)"
                }
            }
            
            # SCHANNEL Protocols
            $protocols = @(
                @{ Name = "SSL 2.0"; Enabled = $false },
                @{ Name = "SSL 3.0"; Enabled = $false },
                @{ Name = "TLS 1.0"; Enabled = $profileData.protocols.tls10 },
                @{ Name = "TLS 1.1"; Enabled = $profileData.protocols.tls11 },
                @{ Name = "TLS 1.2"; Enabled = $profileData.protocols.tls12 },
                @{ Name = "TLS 1.3"; Enabled = $profileData.protocols.tls13 }
            )
            
            foreach ($proto in $protocols) {
                foreach ($type in @("Server", "Client")) {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$($proto.Name)\$type"
                    
                    if ($DryRun) {
                        $results.Messages += "[DRY-RUN] $($proto.Name) $type = $($proto.Enabled)"
                    } else {
                        if (-not (Test-Path $regPath)) {
                            New-Item -Path $regPath -Force | Out-Null
                        }
                        
                        $enabledValue = if ($proto.Enabled) { 1 } else { 0 }
                        $disabledDefault = if ($proto.Enabled) { 0 } else { 1 }
                        
                        Set-ItemProperty -Path $regPath -Name "Enabled" -Value $enabledValue -Type DWord -Force
                        Set-ItemProperty -Path $regPath -Name "DisabledByDefault" -Value $disabledDefault -Type DWord -Force
                        
                        $results.Messages += "$($proto.Name) $type = $($proto.Enabled)"
                    }
                }
            }
            
            # Hash Algorithms
            $hashes = @(
                @{ Name = "MD5"; Enabled = $false },
                @{ Name = "SHA"; Enabled = $false },
                @{ Name = "SHA256"; Enabled = $true },
                @{ Name = "SHA384"; Enabled = $true },
                @{ Name = "SHA512"; Enabled = $true }
            )
            
            foreach ($hash in $hashes) {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$($hash.Name)"
                
                if (-not $DryRun) {
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    $value = if ($hash.Enabled) { 0xFFFFFFFF } else { 0 }
                    Set-ItemProperty -Path $regPath -Name "Enabled" -Value $value -Type DWord -Force
                }
                $results.Messages += "Hash $($hash.Name) = $($hash.Enabled)"
            }
            
            # Cipher Algorithms
            $ciphers = @(
                @{ Name = "AES 128/128"; Enabled = $true },
                @{ Name = "AES 256/256"; Enabled = $true },
                @{ Name = "Triple DES 168"; Enabled = $false },
                @{ Name = "RC4 128/128"; Enabled = $false },
                @{ Name = "RC4 64/128"; Enabled = $false },
                @{ Name = "RC4 56/128"; Enabled = $false },
                @{ Name = "RC4 40/128"; Enabled = $false },
                @{ Name = "DES 56/56"; Enabled = $false },
                @{ Name = "NULL"; Enabled = $false }
            )
            
            foreach ($cipher in $ciphers) {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$($cipher.Name)"
                
                if (-not $DryRun) {
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    $value = if ($cipher.Enabled) { 0xFFFFFFFF } else { 0 }
                    Set-ItemProperty -Path $regPath -Name "Enabled" -Value $value -Type DWord -Force
                }
                $results.Messages += "Cipher $($cipher.Name) = $($cipher.Enabled)"
            }
            
            # Key Exchange - DH Key Size
            $dhKeySize = $profileData.keyExchange.dhMinKeySize
            $dhRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman"
            
            if (-not $DryRun) {
                if (-not (Test-Path $dhRegPath)) {
                    New-Item -Path $dhRegPath -Force | Out-Null
                }
                Set-ItemProperty -Path $dhRegPath -Name "ServerMinKeyBitLength" -Value $dhKeySize -Type DWord -Force
                Set-ItemProperty -Path $dhRegPath -Name "ClientMinKeyBitLength" -Value $dhKeySize -Type DWord -Force
            }
            $results.Messages += "DH Key Size = $dhKeySize bit"
            
            # Cipher Suites
            $cipherSuitesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
            $allCiphers = @()
            
            if ($profileData.cipherSuites.tls13 -and $profileData.cipherSuites.tls13.Count -gt 0) {
                $allCiphers += $profileData.cipherSuites.tls13
            }
            if ($profileData.cipherSuites.tls12 -and $profileData.cipherSuites.tls12.Count -gt 0) {
                $allCiphers += $profileData.cipherSuites.tls12
            }
            
            if ($allCiphers.Count -gt 0 -and -not $DryRun) {
                if (-not (Test-Path $cipherSuitesPath)) {
                    New-Item -Path $cipherSuitesPath -Force | Out-Null
                }
                $cipherString = $allCiphers -join ','
                Set-ItemProperty -Path $cipherSuitesPath -Name "Functions" -Value $cipherString -Type String -Force
            }
            $results.Messages += "Cipher Suites yapılandırıldı ($($allCiphers.Count) cipher)"
            
            # Key Exchange Algorithms
            $keyExchanges = @(
                @{ Name = "Diffie-Hellman"; Enabled = $true },
                @{ Name = "ECDH"; Enabled = $true },
                @{ Name = "PKCS"; Enabled = $true }
            )
            
            foreach ($ke in $keyExchanges) {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$($ke.Name)"
                
                if (-not $DryRun) {
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    $value = if ($ke.Enabled) { 0xFFFFFFFF } else { 0 }
                    Set-ItemProperty -Path $regPath -Name "Enabled" -Value $value -Type DWord -Force
                }
                $results.Messages += "KeyExchange $($ke.Name) = $($ke.Enabled)"
            }
            
            # ECC Curves
            $eccCurvesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
            $eccCurves = @("NistP384", "NistP256", "NistP521")
            
            if (-not $DryRun) {
                if (-not (Test-Path $eccCurvesPath)) {
                    New-Item -Path $eccCurvesPath -Force | Out-Null
                }
                $eccString = $eccCurves -join ','
                Set-ItemProperty -Path $eccCurvesPath -Name "EccCurves" -Value $eccString -Type MultiString -Force
            }
            $results.Messages += "ECC Curves yapılandırıldı ($($eccCurves.Count) curve)"
            
            # FIPS Policy (disabled by default)
            $fipsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
            if (-not $DryRun) {
                if (-not (Test-Path $fipsPath)) {
                    New-Item -Path $fipsPath -Force | Out-Null
                }
                Set-ItemProperty -Path $fipsPath -Name "Enabled" -Value 0 -Type DWord -Force
            }
            $results.Messages += "FIPS Policy = Disabled"
            
            # Strong Crypto
            if ($EnableStrong) {
                $netPaths = @(
                    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
                )
                
                foreach ($netPath in $netPaths) {
                    if (-not $DryRun) {
                        if (-not (Test-Path $netPath)) {
                            New-Item -Path $netPath -Force | Out-Null
                        }
                        Set-ItemProperty -Path $netPath -Name "SchUseStrongCrypto" -Value 1 -Type DWord -Force
                        Set-ItemProperty -Path $netPath -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord -Force
                    }
                }
                $results.Messages += ".NET Strong Crypto etkinleştirildi"
            }
            
            $results.Messages += "Yapılandırma tamamlandı"
            
        } catch {
            $results.Success = $false
            $results.Errors += $_.Exception.Message
        }
        
        return $results
    }
    
    # Her sunucuda çalıştır
    Write-Host ""
    $successCount = 0
    $failCount = 0
    
    foreach ($computer in $validComputers) {
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "  📡 [$computer] Yapılandırılıyor..." -ForegroundColor Cyan
        
        try {
            $sessionParams = @{
                ComputerName = $computer
                ErrorAction = 'Stop'
            }
            if ($Cred) { $sessionParams.Credential = $Cred }
            
            $session = New-PSSession @sessionParams
            
            $remoteResult = Invoke-Command -Session $session -ScriptBlock $remoteScriptBlock `
                -ArgumentList $profileContent, $IsDryRun, $StrongCrypto, $SelectedProfile
            
            Remove-PSSession $session
            
            if ($remoteResult.Success) {
                Write-Host "  ✅ [$computer] Başarılı" -ForegroundColor Green
                foreach ($msg in $remoteResult.Messages | Select-Object -Last 5) {
                    Write-Host "      $msg" -ForegroundColor Gray
                }
                $successCount++
                
                $results += [PSCustomObject]@{
                    ComputerName = $computer
                    Status = "Başarılı"
                    Message = "Yapılandırma tamamlandı"
                    Success = $true
                }
            } else {
                Write-Host "  ❌ [$computer] Hata oluştu" -ForegroundColor Red
                foreach ($err in $remoteResult.Errors) {
                    Write-Host "      $err" -ForegroundColor Red
                }
                $failCount++
                
                $results += [PSCustomObject]@{
                    ComputerName = $computer
                    Status = "Hata"
                    Message = ($remoteResult.Errors -join "; ")
                    Success = $false
                }
            }
        }
        catch {
            Write-Host "  ❌ [$computer] Bağlantı hatası: $_" -ForegroundColor Red
            $failCount++
            
            $results += [PSCustomObject]@{
                ComputerName = $computer
                Status = "Bağlantı Hatası"
                Message = $_.Exception.Message
                Success = $false
            }
        }
    }
    
    # Özet
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                           ÖZET                                     ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Toplam Sunucu  : $($Computers.Count)" -ForegroundColor White
    Write-Host "  Başarılı       : $successCount" -ForegroundColor Green
    Write-Host "  Başarısız      : $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Gray" })
    Write-Host ""
    
    if (-not $IsDryRun -and $successCount -gt 0) {
        Write-Host "  ⚠️  Değişikliklerin etkili olması için sunucuların yeniden başlatılması gerekebilir." -ForegroundColor Yellow
    }
    
    return $results
}

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
function Import-SecurityProfile {
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


# Protokolleri yapılandırma fonksiyonu (Client ve Server birleşik)
function Set-Protocols {
    param(
        [ValidateSet("Client", "Server", "Both")]
        [string]$Type = "Both"
    )
    
    # Hangi tipleri işleyeceğimizi belirle
    $types = if ($Type -eq "Both") { @("Client", "Server") } else { @($Type) }
    $hasError = $false
    
    foreach ($t in $types) {
        Write-Log "Protokol[$t] yapılandırması başlatıldı." -LogType Info -VerboseOutput -InfoColor Cyan
        
        # Profilden protokol yapılandırmasını al
        $protocols = @{}
        $script:ActiveProfile.protocols.PSObject.Properties | ForEach-Object {
            $protocols[$_.Name] = $_.Value
        }

        foreach ($protocol in ($protocols.Keys | Sort-Object)) {
            $enabled = $protocols[$protocol]
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\$t"

            if ($script:DryRun) {
                Write-DryRunAction -Action "PROTOKOL[$t]" -Target $protocol -Details $(if ($enabled) { "ENABLED" } else { "DISABLED" })
                continue
            }

            try {
                if ($enabled -eq $false) {
                    # Devre dışı bırakma işlemleri
                    New-Item $regPath -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -path $regPath -name Enabled -value 0 -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -path $regPath -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null
                }
                else {
                    # Etkinleştirme işlemleri
                    New-Item $regPath -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -path $regPath -name Enabled -value 1 -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -path $regPath -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null
                }
                Write-Log "$protocol [$t] $(if ($enabled) { 'enabled' } else { 'disabled' }) edildi." -LogType Info -VerboseOutput
            }
            catch {
                Write-TLSError -ErrorType "PROTOCOL_CONFIG_FAILED" -Target "$protocol [$t]" -Exception $_
                $hasError = $true
            }
        }

        Write-Log "Protokol[$t] yapılandırması tamamlandı.`n" -LogType Info -VerboseOutput -InfoColor Cyan
    }
    
    return (-not $hasError)
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
    $hasError = $false

    foreach ($algorithm in $encryptionAlgorithms.Keys) {
        $enabled = $encryptionAlgorithms[$algorithm]
        $regPathAlgorithm = "$regPath\$algorithm"
        
        if ($script:DryRun) {
            Write-DryRunAction -Action "ŞİFRELEME" -Target $algorithm -Details $(if ($enabled) { "ENABLED" } else { "DISABLED" })
            continue
        }
        
        try {
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
        catch {
            Write-TLSError -ErrorType "CIPHER_CONFIG_FAILED" -Target $algorithm -Exception $_
            $hasError = $true
        }
    }

    Write-Log "Şifreleme algoritmaları yapılandırması tamamlandı.`n" -LogType Info -VerboseOutput -InfoColor Cyan
    return (-not $hasError)
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
    $hasError = $false

    foreach ($algorithm in $hashAlgorithms.Keys) {
        $enabled = $hashAlgorithms[$algorithm]
        $regPathAlgorithm = "$regPath\$algorithm"
        
        if ($script:DryRun) {
            Write-DryRunAction -Action "HASH" -Target $algorithm -Details $(if ($enabled) { "ENABLED" } else { "DISABLED" })
            continue
        }
        
        try {
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
        catch {
            Write-TLSError -ErrorType "HASH_CONFIG_FAILED" -Target $algorithm -Exception $_
            $hasError = $true
        }
    }

    Write-Log "Hash algoritmaları yapılandırması tamamlandı.`n" -LogType Info -VerboseOutput -InfoColor Cyan
    return (-not $hasError)
}

# Anahtar değişim algoritmalarını yapılandırma fonksiyonu
function Set-KeyExchangeAlgorithms {
    Write-Log "TLS Anahtar değişim algoritmaları yapılandırması başladı." -LogType Info -VerboseOutput -InfoColor Cyan
    
    # Profilden anahtar değişim yapılandırmasını al
    $keyExchangeAlgorithms = @{}
    $script:dhMinKeyBitLength = 3072
    $script:ActiveProfile.keyExchange.PSObject.Properties | ForEach-Object {
        if ($_.Name -eq 'DH-MinKeyBitLength') {
            $script:dhMinKeyBitLength = $_.Value
        } else {
            $keyExchangeAlgorithms[$_.Name] = $_.Value
        }
    }
    $dhMinKeyBitLength = $script:dhMinKeyBitLength

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"
    $hasError = $false

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
        
        try {
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
        catch {
            Write-TLSError -ErrorType "KEYEXCHANGE_CONFIG_FAILED" -Target $algorithm -Exception $_
            $hasError = $true
        }
    }

    Write-Log "TLS Anahtar değişim algoritmaları yapılandırması tamamlandı.`n" -LogType Info -VerboseOutput -InfoColor Cyan
    return (-not $hasError)
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
        return $true
    }
    
    try {
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "Enabled" -Value $EnabledValue -Type DWord -ErrorAction Stop
        Write-Log -Message "FIPS Algorithm Policy 'Enabled' değeri başarıyla $EnabledValue olarak ayarlandı." -LogType "Info" -VerboseOutput -InfoColor Yellow
        return $true
    }
    catch {
        Write-TLSError -ErrorType "REGISTRY_WRITE_FAILED" -Target "FipsAlgorithmPolicy" -Exception $_
        return $false
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
    Import-SecurityProfile -ProfileName $SecurityProfile
    
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
    Set-Protocols -Type "Both" | Out-Null
    Set-EncryptionAlgorithms | Out-Null
    Set-HashAlgorithms | Out-Null
    Set-KeyExchangeAlgorithms | Out-Null
    Set-FIPSAlgorithmPolicy -EnabledValue 0 | Out-Null
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

# Uzak sunucu modu mu kontrol et
if ($ComputerName -and $ComputerName.Count -gt 0) {
    # Log dosyası
    $TimeStamp = Get-Date -Format "yyyy_MM_dd_HHmm"
    [string]$LogFilePath = ".\logs\TLSHardener-Remote_$TimeStamp.log"
    
    # Uzak sunucularda çalıştır
    $remoteResults = Invoke-RemoteConfiguration -Computers $ComputerName -Cred $Credential `
        -SelectedProfile $Profile -IsDryRun $script:DryRun -StrongCrypto $EnableStrongCrypto
    
    # Sonuç raporu oluştur
    $reportPath = ".\reports\TLSHardener-Remote_$TimeStamp.csv"
    if (-not (Test-Path ".\reports")) {
        New-Item -Path ".\reports" -ItemType Directory -Force | Out-Null
    }
    $remoteResults | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Sonuç raporu: $reportPath" -ForegroundColor Cyan
    
    exit 0
}

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
