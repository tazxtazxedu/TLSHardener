<#
.ScriptName: TLSHardener.ps1
.SYNOPSIS
PowerShell script to harden TLS/SSL security configuration on Windows servers.

.DESCRIPTION
This script configures the following security settings:
- **Protocols**: TLS 1.2/1.3 enabled, SSL 2.0/3.0 and TLS 1.0/1.1 disabled
- **Encryption Algorithms**: AES enabled, RC4/DES/NULL disabled
- **Hash Algorithms**: SHA256/384/512 enabled, MD5 disabled
- **Key Exchange**: ECDH/Diffie-Hellman configuration
- **Cipher Suites**: Secure TLS 1.2/1.3 cipher suite ordering
- **FIPS Policy**: Configurable

.PARAMETER BypassConfirmation
Skips user confirmation

.PARAMETER EnableStrongCrypto
Enables Strong Crypto settings for .NET Framework

.PARAMETER WhatIf
Dry-Run mode - shows what would be done without making changes

.PARAMETER Profile
Security profile selection: strict, recommended, compatible
- strict: TLS 1.3 only, strongest ciphers
- recommended: TLS 1.2/1.3, GCM ciphers (default)
- compatible: Legacy system compatible, includes CBC

.PARAMETER Rollback
Reverts to a previous backup or resets to Windows defaults

.PARAMETER BackupFile
Specific backup file to use for rollback

.PARAMETER ToDefaults
Resets to Windows defaults instead of backup during rollback

.PARAMETER ComputerName
Runs on remote server(s). Requires PowerShell Remoting.

.PARAMETER Credential
Credentials to use for connecting to remote servers

.EXAMPLE
.\TLSHardener.ps1
Standard execution - prompts for user confirmation

.EXAMPLE
.\TLSHardener.ps1 -BypassConfirmation -EnableStrongCrypto
Runs without confirmation and with Strong Crypto

.EXAMPLE
.\TLSHardener.ps1 -WhatIf
Dry-Run mode - shows what would be done without making changes

.EXAMPLE
.\TLSHardener.ps1 -Profile strict
Runs with the strictest security profile

.EXAMPLE
.\TLSHardener.ps1 -Profile compatible -BypassConfirmation
Runs with compatible profile without confirmation

.EXAMPLE
.\TLSHardener.ps1 -Rollback
Reverts to the most recent backup

.EXAMPLE
.\TLSHardener.ps1 -Rollback -BackupFile ".\backups\20251129_103045_SCHANNEL.reg"
Reverts to the specified backup file

.EXAMPLE
.\TLSHardener.ps1 -Rollback -ToDefaults
Resets to Windows default settings (Clean)

.EXAMPLE
.\TLSHardener.ps1 -ComputerName "Server01","Server02" -Profile recommended
Applies configuration to multiple remote servers

.EXAMPLE
.\TLSHardener.ps1 -ComputerName "Server01" -Credential (Get-Credential)
Runs on remote server with specified credentials

.NOTES
    Project    : TLSHardener
    Version    : 3.5
    Author     : TLSHardener Contributors
    License    : MIT
    Date       : 2025
    
    Requirements:
    - Windows Server 2016+ or Windows 10+
    - PowerShell 5.1+
    - Administrator privileges
    - For TLS 1.3: Windows Server 2022+ / Windows 11+

.LINK
    https://github.com/tazxtazxedu/TLSHardener
#>
# Adds parameter to script to skip confirmation-required operations
param (
    [switch]$BypassConfirmation,
    [switch]$EnableStrongCrypto,
    [switch]$WhatIf,
    [switch]$Rollback,
    [string]$BackupFile = "",
    [switch]$ToDefaults,
    [ValidateSet("strict", "recommended", "compatible", "custom")]
    [string]$Profile = "recommended",
    [string[]]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential
)

# Global variables
$script:DryRun = $WhatIf
$script:ActiveProfile = $null
$script:IsRemoteSession = $false

# ============================================================================
# ERROR CODES AND MANAGEMENT
# ============================================================================

# Error codes enum-like structure
$script:ErrorCodes = @{
    # General Errors (1000-1099)
    SUCCESS                    = @{ Code = 0;    Message = "Operation successful" }
    UNKNOWN_ERROR              = @{ Code = 1000; Message = "Unknown error" }
    PERMISSION_DENIED          = @{ Code = 1001; Message = "Permission denied - Run as Administrator" }
    INVALID_PARAMETER          = @{ Code = 1002; Message = "Invalid parameter" }
    
    # Profile Errors (1100-1199)
    PROFILE_NOT_FOUND          = @{ Code = 1100; Message = "Profile file not found" }
    PROFILE_INVALID_JSON       = @{ Code = 1101; Message = "Profile JSON format invalid" }
    PROFILE_MISSING_PROPERTY   = @{ Code = 1102; Message = "Profile missing required property" }
    
    # Registry Errors (1200-1299)
    REGISTRY_ACCESS_DENIED     = @{ Code = 1200; Message = "Registry access denied" }
    REGISTRY_KEY_NOT_FOUND     = @{ Code = 1201; Message = "Registry key not found" }
    REGISTRY_WRITE_FAILED      = @{ Code = 1202; Message = "Registry write failed" }
    REGISTRY_BACKUP_FAILED     = @{ Code = 1203; Message = "Registry backup failed" }
    REGISTRY_RESTORE_FAILED    = @{ Code = 1204; Message = "Registry restore failed" }
    
    # Remote Server Errors (1300-1399)
    REMOTE_CONNECTION_FAILED   = @{ Code = 1300; Message = "Remote server connection failed" }
    REMOTE_PING_FAILED         = @{ Code = 1301; Message = "Ping failed" }
    REMOTE_WINRM_FAILED        = @{ Code = 1302; Message = "WinRM connection failed" }
    REMOTE_SESSION_FAILED      = @{ Code = 1303; Message = "Remote session could not be created" }
    REMOTE_EXECUTION_FAILED    = @{ Code = 1304; Message = "Remote command execution failed" }
    
    # File Errors (1400-1499)
    FILE_NOT_FOUND             = @{ Code = 1400; Message = "File not found" }
    FILE_READ_FAILED           = @{ Code = 1401; Message = "File read failed" }
    FILE_WRITE_FAILED          = @{ Code = 1402; Message = "File write failed" }
    BACKUP_NOT_FOUND           = @{ Code = 1403; Message = "Backup file not found" }
    
    # Configuration Errors (1500-1599)
    PROTOCOL_CONFIG_FAILED     = @{ Code = 1500; Message = "Protocol configuration failed" }
    CIPHER_CONFIG_FAILED       = @{ Code = 1501; Message = "Cipher configuration failed" }
    HASH_CONFIG_FAILED         = @{ Code = 1502; Message = "Hash configuration failed" }
    KEYEXCHANGE_CONFIG_FAILED  = @{ Code = 1503; Message = "Key exchange configuration failed" }
    CIPHERSUITE_CONFIG_FAILED  = @{ Code = 1504; Message = "Cipher suite configuration failed" }
    ECC_CONFIG_FAILED          = @{ Code = 1505; Message = "ECC curve configuration failed" }
}

# Central error management function
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
    
    # Build error message
    $fullMessage = "[TLS-$errorCode] $errorMessage"
    if ($Target) { $fullMessage += " - Target: $Target" }
    if ($Details) { $fullMessage += " - $Details" }
    if ($Exception) { $fullMessage += " - Error: $($Exception.Exception.Message)" }
    
    # Write to log
    Write-Log $fullMessage -LogType Error -VerboseOutput
    
    # Throw exception if requested
    if ($Throw) {
        throw $fullMessage
    }
    
    # Return error info
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
# REMOTE SERVER FUNCTIONS
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
        
        # Test WinRM connection
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
    Write-Host "║                    REMOTE SERVER CONFIGURATION                     ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Test connections
    Write-Host "  🔍 Checking server connections..." -ForegroundColor Yellow
    Write-Host ""
    
    $validComputers = @()
    foreach ($computer in $Computers) {
        Write-Host "    [$computer] " -NoNewline
        $testResult = Test-RemoteConnection -Computer $computer -Cred $Cred
        
        if ($testResult.Success) {
            Write-Host "✅ Connection successful" -ForegroundColor Green
            $validComputers += $computer
        } else {
            Write-Host "❌ Connection failed: $($testResult.Error)" -ForegroundColor Red
            $results += [PSCustomObject]@{
                ComputerName = $computer
                Status = "Connection Error"
                Message = $testResult.Error
                Success = $false
            }
        }
    }
    
    if ($validComputers.Count -eq 0) {
        Write-Host "`n  ❌ No reachable servers found!" -ForegroundColor Red
        return $results
    }
    
    Write-Host "`n  📦 Preparing profile file..." -ForegroundColor Yellow
    
    # Read profile file
    $profilePath = Join-Path $scriptPath "config\$SelectedProfile.json"
    if (-not (Test-Path $profilePath)) {
        $profilePath = Join-Path $scriptPath "config\recommended.json"
    }
    $profileContent = Get-Content $profilePath -Raw
    
    # Create script block
    $remoteScriptBlock = {
        param($ProfileJson, $DryRun, $EnableStrong, $ProfileName)
        
        $ErrorActionPreference = 'Stop'
        $results = @{
            Success = $true
            Messages = @()
            Errors = @()
        }
        
        try {
            # Parse profile
            $profile = $ProfileJson | ConvertFrom-Json
            
            $results.Messages += "Profile loaded: $ProfileName"
            
            if ($DryRun) {
                $results.Messages += "[DRY-RUN] Changes will be simulated"
            } else {
                # Registry backup
                $backupFolder = "C:\TLSHardener-Backups"
                if (-not (Test-Path $backupFolder)) {
                    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
                }
                
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $backupFile = Join-Path $backupFolder "SCHANNEL_$timestamp.reg"
                
                $regExport = reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $backupFile /y 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $results.Messages += "Backup created: $backupFile"
                } else {
                    $results.Messages += "Backup failed (continuing)"
                }
            }
            
            # SCHANNEL Protocols
            $protocols = @(
                @{ Name = "SSL 2.0"; Enabled = $false },
                @{ Name = "SSL 3.0"; Enabled = $false },
                @{ Name = "TLS 1.0"; Enabled = $profile.protocols.tls10 },
                @{ Name = "TLS 1.1"; Enabled = $profile.protocols.tls11 },
                @{ Name = "TLS 1.2"; Enabled = $profile.protocols.tls12 },
                @{ Name = "TLS 1.3"; Enabled = $profile.protocols.tls13 }
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
            $dhKeySize = $profile.keyExchange.dhMinKeySize
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
            
            if ($profile.cipherSuites.tls13 -and $profile.cipherSuites.tls13.Count -gt 0) {
                $allCiphers += $profile.cipherSuites.tls13
            }
            if ($profile.cipherSuites.tls12 -and $profile.cipherSuites.tls12.Count -gt 0) {
                $allCiphers += $profile.cipherSuites.tls12
            }
            
            if ($allCiphers.Count -gt 0 -and -not $DryRun) {
                if (-not (Test-Path $cipherSuitesPath)) {
                    New-Item -Path $cipherSuitesPath -Force | Out-Null
                }
                $cipherString = $allCiphers -join ','
                Set-ItemProperty -Path $cipherSuitesPath -Name "Functions" -Value $cipherString -Type String -Force
            }
            $results.Messages += "Cipher Suites configured ($($allCiphers.Count) cipher)"
            
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
            $results.Messages += "ECC Curves configured ($($eccCurves.Count) curve)"
            
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
                $results.Messages += ".NET Strong Crypto enabled"
            }
            
            $results.Messages += "Configuration completed"
            
        } catch {
            $results.Success = $false
            $results.Errors += $_.Exception.Message
        }
        
        return $results
    }
    
    # Run on each server
    Write-Host ""
    $successCount = 0
    $failCount = 0
    
    foreach ($computer in $validComputers) {
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "  📡 [$computer] Configuring..." -ForegroundColor Cyan
        
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
                Write-Host "  ✅ [$computer] Successful" -ForegroundColor Green
                foreach ($msg in $remoteResult.Messages | Select-Object -Last 5) {
                    Write-Host "      $msg" -ForegroundColor Gray
                }
                $successCount++
                
                $results += [PSCustomObject]@{
                    ComputerName = $computer
                    Status = "Successful"
                    Message = "Configuration completed"
                    Success = $true
                }
            } else {
                Write-Host "  ❌ [$computer] Error occurred" -ForegroundColor Red
                foreach ($err in $remoteResult.Errors) {
                    Write-Host "      $err" -ForegroundColor Red
                }
                $failCount++
                
                $results += [PSCustomObject]@{
                    ComputerName = $computer
                    Status = "Error"
                    Message = ($remoteResult.Errors -join "; ")
                    Success = $false
                }
            }
        }
        catch {
            Write-Host "  ❌ [$computer] Connection error: $_" -ForegroundColor Red
            $failCount++
            
            $results += [PSCustomObject]@{
                ComputerName = $computer
                Status = "Connection Error"
                Message = $_.Exception.Message
                Success = $false
            }
        }
    }
    
    # Summary
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                           SUMMARY                                  ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Total Servers  : $($Computers.Count)" -ForegroundColor White
    Write-Host "  Successful     : $successCount" -ForegroundColor Green
    Write-Host "  Failed         : $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Gray" })
    Write-Host ""
    
    if (-not $IsDryRun -and $successCount -gt 0) {
        Write-Host "  ⚠️  Servers may need to be restarted for changes to take effect." -ForegroundColor Yellow
    }
    
    return $results
}

# ============================================================================
# ROLLBACK FUNCTIONS
# ============================================================================

# List available backups
function Get-AvailableBackups {
    $backupFolder = ".\backups"
    
    if (-not (Test-Path $backupFolder)) {
        return @()
    }
    
    # Find SCHANNEL backups (main backup file)
    $backups = Get-ChildItem -Path $backupFolder -Filter "*SCHANNEL.reg" | 
               Sort-Object LastWriteTime -Descending
    
    return $backups
}

# Group backup files (those with the same timestamp)
function Get-BackupGroup {
    param (
        [string]$BackupTimestamp
    )
    
    $backupFolder = ".\backups"
    $pattern = "*$BackupTimestamp*"
    
    return Get-ChildItem -Path $backupFolder -Filter $pattern
}

# Import registry file
function Import-RegistryBackup {
    param (
        [string]$RegFile
    )
    
    if (-not (Test-Path $RegFile)) {
        Write-Log "Backup file not found: $RegFile" -LogType Error -VerboseOutput
        return $false
    }
    
    try {
        $result = reg import $RegFile 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully imported: $RegFile" -LogType Info -VerboseOutput -InfoColor Green
            return $true
        } else {
            Write-Log "Import failed: $result" -LogType Error -VerboseOutput
            return $false
        }
    }
    catch {
        Write-Log "Error occurred: $_" -LogType Error -VerboseOutput
        return $false
    }
}

# Reset to Windows defaults (Clean operation)
function Invoke-CleanToDefaults {
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║              RESETTING TO WINDOWS DEFAULTS                     ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    
    # SCHANNEL Ciphers
    Write-Log "[1/7] Cleaning SCHANNEL Ciphers..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers") {
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\*" -Force -Recurse -ErrorAction SilentlyContinue
        }
        Write-Log "[1/7] SCHANNEL Ciphers cleaned." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[1/7] Error cleaning SCHANNEL Ciphers: $_" -LogType Warning -VerboseOutput
    }
    
    # SCHANNEL Hashes
    Write-Log "[2/7] Cleaning SCHANNEL Hashes..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes") {
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\*" -Force -Recurse -ErrorAction SilentlyContinue
        }
        Write-Log "[2/7] SCHANNEL Hashes cleaned." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[2/7] Error cleaning SCHANNEL Hashes: $_" -LogType Warning -VerboseOutput
    }
    
    # SCHANNEL KeyExchangeAlgorithms
    Write-Log "[3/7] Cleaning SCHANNEL KeyExchangeAlgorithms..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms") {
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\*" -Force -Recurse -ErrorAction SilentlyContinue
        }
        Write-Log "[3/7] SCHANNEL KeyExchangeAlgorithms cleaned." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[3/7] Error cleaning SCHANNEL KeyExchangeAlgorithms: $_" -LogType Warning -VerboseOutput
    }
    
    # SCHANNEL Protocols
    Write-Log "[4/7] Cleaning SCHANNEL Protocols..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols") {
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*" -Force -Recurse -ErrorAction SilentlyContinue
        }
        Write-Log "[4/7] SCHANNEL Protocols cleaned." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[4/7] Error cleaning SCHANNEL Protocols: $_" -LogType Warning -VerboseOutput
    }
    
    # FIPS Policy
    Write-Log "[5/7] Cleaning FIPS Policy..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name Enabled -Force -ErrorAction SilentlyContinue
        Write-Log "[5/7] FIPS Policy cleaned." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[5/7] Error cleaning FIPS Policy: $_" -LogType Warning -VerboseOutput
    }
    
    # Cipher Suites
    Write-Log "[6/7] Cleaning Cipher Suites..." -LogType Info -VerboseOutput -InfoColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name Functions -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name EccCurves -Force -ErrorAction SilentlyContinue
        Write-Log "[6/7] Cipher Suites cleaned." -LogType Info -VerboseOutput -InfoColor Green
    } catch {
        Write-Log "[6/7] Error cleaning Cipher Suites: $_" -LogType Warning -VerboseOutput
    }
    
    # .NET Strong Crypto
    Write-Log "[7/7] Cleaning .NET Strong Crypto settings..." -LogType Info -VerboseOutput -InfoColor Cyan
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
    Write-Log "[7/7] .NET Strong Crypto settings cleaned." -LogType Info -VerboseOutput -InfoColor Green
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║           RESET TO WINDOWS DEFAULTS COMPLETED                  ║" -ForegroundColor Green
    Write-Host "║           Restart required for changes to take effect          ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
}

# Main rollback function
function Invoke-Rollback {
    param (
        [string]$SpecificBackupFile = "",
        [switch]$UseDefaults
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    ROLLBACK MODE                               ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # If ToDefaults is selected
    if ($UseDefaults) {
        Write-Log "Resetting to Windows defaults..." -LogType Info -VerboseOutput -InfoColor Yellow
        
        if (-not $BypassConfirmation) {
            $confirm = Read-Host "All TLS/SSL settings will be reset to Windows defaults. Confirm? (Y/N)"
            if ($confirm -notmatch "^[Yy]") {
                Write-Log "Rollback cancelled." -LogType Warning -VerboseOutput
                return
            }
        }
        
        Invoke-CleanToDefaults
        return
    }
    
    # If a specific backup file is provided
    if (-not [string]::IsNullOrEmpty($SpecificBackupFile)) {
        if (-not (Test-Path $SpecificBackupFile)) {
            Write-Log "Specified backup file not found: $SpecificBackupFile" -LogType Error -VerboseOutput
            return
        }
        
        Write-Log "Loading specified backup file: $SpecificBackupFile" -LogType Info -VerboseOutput -InfoColor Cyan
        
        if (-not $BypassConfirmation) {
            $confirm = Read-Host "This backup file will be loaded. Confirm? (Y/N)"
            if ($confirm -notmatch "^[Yy]") {
                Write-Log "Rollback cancelled." -LogType Warning -VerboseOutput
                return
            }
        }
        
        Import-RegistryBackup -RegFile $SpecificBackupFile
        return
    }
    
    # List available backups
    $backups = Get-AvailableBackups
    
    if ($backups.Count -eq 0) {
        Write-Host "  ⚠️  No backups found!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Options:" -ForegroundColor Gray
        Write-Host "    1. Reset to Windows defaults" -ForegroundColor White
        Write-Host "    2. Cancel" -ForegroundColor White
        Write-Host ""
        
        $choice = Read-Host "  Your choice (1/2)"
        
        if ($choice -eq "1") {
            Invoke-CleanToDefaults
        } else {
            Write-Log "Rollback cancelled." -LogType Warning -VerboseOutput
        }
        return
    }
    
    # Show backups
    Write-Host "  Available Backups:" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor Gray
    
    $i = 1
    foreach ($backup in $backups) {
        $timestamp = $backup.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        $size = [math]::Round($backup.Length / 1KB, 1)
        Write-Host "    [$i] $timestamp - $($backup.Name) ($size KB)" -ForegroundColor White
        $i++
    }
    
    Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "    [D] Reset to Windows defaults" -ForegroundColor Yellow
    Write-Host "    [C] Cancel" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "  Your choice"
    
    if ($choice -match "^[Dd]$") {
        Invoke-CleanToDefaults
        return
    }
    
    if ($choice -match "^[Cc]$" -or [string]::IsNullOrEmpty($choice)) {
        Write-Log "Rollback cancelled." -LogType Warning -VerboseOutput
        return
    }
    
    # Numeric selection
    $selectedIndex = 0
    if ([int]::TryParse($choice, [ref]$selectedIndex)) {
        if ($selectedIndex -ge 1 -and $selectedIndex -le $backups.Count) {
            $selectedBackup = $backups[$selectedIndex - 1]
            
            # Find all backups with the same timestamp
            $timestamp = $selectedBackup.Name -replace ".*?(\d{8}_\d{6}).*", '$1'
            $backupGroup = Get-BackupGroup -BackupTimestamp $timestamp
            
            Write-Host ""
            Write-Host "  Selected backup group ($($backupGroup.Count) files):" -ForegroundColor Cyan
            foreach ($file in $backupGroup) {
                Write-Host "    - $($file.Name)" -ForegroundColor Gray
            }
            Write-Host ""
            
            if (-not $BypassConfirmation) {
                $confirm = Read-Host "  These backups will be loaded. Confirm? (Y/N)"
                if ($confirm -notmatch "^[Yy]") {
                    Write-Log "Rollback cancelled." -LogType Warning -VerboseOutput
                    return
                }
            }
            
            Write-Host ""
            Write-Log "Loading backups..." -LogType Info -VerboseOutput -InfoColor Cyan
            
            foreach ($file in $backupGroup) {
                Import-RegistryBackup -RegFile $file.FullName
            }
            
            Write-Host ""
            Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
            Write-Host "║                    ROLLBACK COMPLETED                          ║" -ForegroundColor Green
            Write-Host "║           Restart required for changes to take effect          ║" -ForegroundColor Green
            Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        } else {
            Write-Log "Invalid selection." -LogType Error -VerboseOutput
        }
    } else {
        Write-Log "Invalid selection." -LogType Error -VerboseOutput
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Helper function for Dry-Run mode
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

# Profile loading function
function Load-SecurityProfile {
    param (
        [string]$ProfileName
    )
    
    if ([string]::IsNullOrEmpty($ProfileName)) {
        return $null
    }
    
    $profilePath = ".\config\$ProfileName.json"
    
    if (-not (Test-Path $profilePath)) {
        Write-Host "  ❌ Profile not found: $profilePath" -ForegroundColor Red
        Write-Host "  Available profiles: strict, recommended, compatible, custom" -ForegroundColor Yellow
        exit 1
    }
    
    try {
        $profileData = Get-Content -Path $profilePath -Raw | ConvertFrom-Json
        $script:ActiveProfile = $profileData
        
        Write-Host "`n" -NoNewline
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║                    PROFILE LOADED                              ║" -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host "  Profile: " -NoNewline -ForegroundColor Gray
        Write-Host "$($profileData.name)" -ForegroundColor Green
        Write-Host "  Description: " -NoNewline -ForegroundColor Gray
        Write-Host "$($profileData.description)" -ForegroundColor White
        Write-Host ""
        
        return $profileData
    }
    catch {
        Write-Host "  ❌ Error loading profile: $_" -ForegroundColor Red
        exit 1
    }
}

# Get value from profile or config
function Get-ConfigValue {
    param (
        [string]$ConfigType,
        [string]$JsonPath = $null
    )
    
    if ($null -ne $script:ActiveProfile) {
        # Get from profile
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
    
    # Get from JSON file
    if ($JsonPath) {
        return Get-ConfigFromJson -jsonFilePath $JsonPath
    }
    
    return $null
}

# Set console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$os = Get-WmiObject -Class Win32_OperatingSystem
# Logging function
$TimeStamp = Get-Date -Format "yyyy_MM_dd_HHmm"
[string]$LogFilePath = ".\logs\TLSHardener_$TimeStamp.log"
function Write-Log {
    [CmdletBinding()]
    param (
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error")]
        [string]$LogType = "Info",
        [switch]$VerboseOutput, # This parameter controls log screen output
        [ValidateSet("Green", "Yellow", "Cyan")]
        [string]$InfoColor = "Green" # Color selection for Info log type
    )
    
    # Timestamp and log entry format
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$TimeStamp $LogType $Message"
    
    # Create log file (if not exists) and write with UTF-8
    if (!(Test-Path -Path $LogFilePath)) {
        New-Item -Path $LogFilePath -ItemType File -Force | Out-Null
        Out-File -FilePath $LogFilePath -Encoding UTF8 -Append -InputObject ""
    }
    Out-File -FilePath $LogFilePath -Encoding UTF8 -Append -InputObject $LogEntry

    # Colored output to screen
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

# Registry key export function
function Export-RegistryKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$keyPath,
        
        [Parameter(Mandatory = $true)]
        [string]$exportPath
    )

    try {
        # Check if registry key exists
        if (!(Test-Path -Path $keyPath)) {
            Write-Log "Registry key not found: $keyPath" -LogType Error -VerboseOutput
            return $false
        }

        # Export registry key
        $traditionalPath = $keyPath -replace ':\\', '\'
        Write-Log "Processing: $traditionalPath" -LogType Info -VerboseOutput -InfoColor Cyan
        
        $result = reg export $traditionalPath $exportPath /y
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully exported: $exportPath" -LogType Info -VerboseOutput -InfoColor Green
            return $true
        }
        else {
            Write-Log "Export failed: $result" -LogType Error -VerboseOutput
            return $false
        }
    }
    catch {
        Write-Log "Error occurred: $_" -LogType Error -VerboseOutput
        return $false
    }
}

# Main backup operation
function Backup-RegistryKeys {
    if ($script:DryRun) {
        Write-DryRunAction -Action "BACKUP" -Target "Registry keys" -Details "Will be backed up to backups/ folder"
        $registryKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy",
            "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002",
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        )
        foreach ($key in $registryKeys) {
            Write-DryRunAction -Action "  BACKUP" -Target $key
        }
        return
    }
    
    # Prepare backup folder
    $backupFolder = ".\backups"
    if (-not (Test-Path $backupFolder)) {
        Write-Log "Creating backup folder..." -LogType Info -VerboseOutput -InfoColor Yellow
        New-Item -Path $backupFolder -ItemType Directory | Out-Null
    }

    # Keys to backup
    $registryKeys = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy",
        "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002",
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    )

    Write-Log "Starting registry backup operation..." -LogType Info -VerboseOutput -InfoColor Cyan
    foreach ($key in $registryKeys) {
        $backupTime = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = if ($key -like "*Wow6432Node*") {
            Join-Path $backupFolder "Protocol_Script_$backupTime`_$(($key -split '\\')[-1])_wow6432.reg"
        }
        else {
            Join-Path $backupFolder "Protocol_Script_$backupTime`_$(($key -split '\\')[-1]).reg"
        }
        
        Write-Log "Backing up $key..." -LogType Info -VerboseOutput -InfoColor Yellow
        Export-RegistryKey -keyPath $key -exportPath $backupFile
    }

    Write-Log "Backup operation completed" -LogType Info -VerboseOutput -InfoColor Green
}


# Protocol configuration function (Client and Server combined)
function Set-Protocols {
    param(
        [ValidateSet("Client", "Server", "Both")]
        [string]$Type = "Both"
    )
    
    # Determine which types to process
    $types = if ($Type -eq "Both") { @("Client", "Server") } else { @($Type) }
    $hasError = $false
    
    foreach ($t in $types) {
        Write-Log "Protocol[$t] configuration started." -LogType Info -VerboseOutput -InfoColor Cyan
        
        # Get protocol configuration from profile
        $protocols = @{}
        $script:ActiveProfile.protocols.PSObject.Properties | ForEach-Object {
            $protocols[$_.Name] = $_.Value
        }

        foreach ($protocol in ($protocols.Keys | Sort-Object)) {
            $enabled = $protocols[$protocol]
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\$t"

            if ($script:DryRun) {
                Write-DryRunAction -Action "PROTOCOL[$t]" -Target $protocol -Details $(if ($enabled) { "ENABLED" } else { "DISABLED" })
                continue
            }

            try {
                if ($enabled -eq $false) {
                    # Disable operations
                    New-Item $regPath -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -path $regPath -name Enabled -value 0 -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -path $regPath -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null
                }
                else {
                    # Enable operations
                    New-Item $regPath -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -path $regPath -name Enabled -value 1 -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -path $regPath -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null
                }
                Write-Log "$protocol [$t] $(if ($enabled) { 'enabled' } else { 'disabled' })." -LogType Info -VerboseOutput
            }
            catch {
                Write-TLSError -ErrorType "PROTOCOL_CONFIG_FAILED" -Target "$protocol [$t]" -Exception $_
                $hasError = $true
            }
        }

        Write-Log "Protocol[$t] configuration completed.`n" -LogType Info -VerboseOutput -InfoColor Cyan
    }
    
    return (-not $hasError)
}

# Encryption algorithms configuration function
function Set-EncryptionAlgorithms {
    Write-Log "Encryption Algorithms configuration started." -LogType Info -VerboseOutput -InfoColor Cyan
    
    # Get encryption algorithm configuration from profile
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
            Write-DryRunAction -Action "ENCRYPTION" -Target $algorithm -Details $(if ($enabled) { "ENABLED" } else { "DISABLED" })
            continue
        }
        
        try {
            $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($algorithm)
            Write-Log "$regPathAlgorithm registry KEY created" -LogType Info -VerboseOutput

            if ($enabled) {
                $key.SetValue('Enabled', 0xffffffff, 'DWord')
            }
            else {
                $key.SetValue('Enabled', 0x0, 'DWord')
            }

            $key.Close()
            Write-Log "$algorithm $(if ($enabled) { 'enabled' } else { 'disabled' })." -LogType Info -VerboseOutput
        }
        catch {
            Write-TLSError -ErrorType "CIPHER_CONFIG_FAILED" -Target $algorithm -Exception $_
            $hasError = $true
        }
    }

    Write-Log "Encryption algorithms configuration completed.`n" -LogType Info -VerboseOutput -InfoColor Cyan
    return (-not $hasError)
}

# Hash algorithms configuration function
function Set-HashAlgorithms {
    Write-Log "Hash algorithms configuration started." -LogType Info -VerboseOutput -InfoColor Cyan
    
    # Get hash algorithm configuration from profile
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
            Write-Log "$regPathAlgorithm registry KEY created" -LogType Info -VerboseOutput

            if ($enabled) {
                $key.SetValue('Enabled', 0xffffffff, 'DWord')
            }
            else {
                $key.SetValue('Enabled', 0x0, 'DWord')
            }

            $key.Close()
            Write-Log "$algorithm $(if ($enabled) { 'enabled' } else { 'disabled' })." -LogType Info -VerboseOutput
        }
        catch {
            Write-TLSError -ErrorType "HASH_CONFIG_FAILED" -Target $algorithm -Exception $_
            $hasError = $true
        }
    }

    Write-Log "Hash algorithms configuration completed.`n" -LogType Info -VerboseOutput -InfoColor Cyan
    return (-not $hasError)
}

# Key exchange algorithms configuration function
function Set-KeyExchangeAlgorithms {
    Write-Log "TLS Key exchange algorithms configuration started." -LogType Info -VerboseOutput -InfoColor Cyan
    
    # Get key exchange configuration from profile
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
    $hasError = $false

    foreach ($algorithm in $keyExchangeAlgorithms.Keys) {
        # Skip meta information like DH-MinKeyBitLength
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
            Write-Log "$regPathAlgorithm registry KEY created" -LogType Info -VerboseOutput

            if ($enabled) {
                $key.SetValue('Enabled', 0xffffffff, 'DWord')
                if ($algorithm -eq 'Diffie-Hellman') {
                    $dhKeyHex = [convert]::ToInt32($dhMinKeyBitLength)
                    $key.SetValue('ServerMinKeyBitLength', $dhKeyHex, 'DWord')
                    $key.SetValue('ClientMinKeyBitLength', $dhKeyHex, 'DWord')
                    Write-Log "DH MinKeyBitLength: Set to $dhMinKeyBitLength bit" -LogType Info -VerboseOutput
                }
            }
            else {
                $key.SetValue('Enabled', 0x0, 'DWord')
            }

            $key.Close()
            Write-Log "$algorithm $(if ($enabled) { 'enabled' } else { 'disabled' })." -LogType Info -VerboseOutput
        }
        catch {
            Write-TLSError -ErrorType "KEYEXCHANGE_CONFIG_FAILED" -Target $algorithm -Exception $_
            $hasError = $true
        }
    }

    Write-Log "TLS Key exchange algorithms configuration completed.`n" -LogType Info -VerboseOutput -InfoColor Cyan
    return (-not $hasError)
}

# FIPS algorithm policy configuration function
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
        Write-Log -Message "FIPS Algorithm Policy 'Enabled' value successfully set to $EnabledValue." -LogType "Info" -VerboseOutput -InfoColor Yellow
        return $true
    }
    catch {
        Write-TLSError -ErrorType "REGISTRY_WRITE_FAILED" -Target "FipsAlgorithmPolicy" -Exception $_
        return $false
    }
}

# Cipher suites configuration function
function Set-CipherSuites {
    Write-Log "Cipher Suites configuration started." -LogType Info -VerboseOutput -InfoColor Cyan
    
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    
    # Get cipher suite configuration from profile
    $tls13Suites = @($script:ActiveProfile.cipherSuitesTls13)
    $tls12Suites = @($script:ActiveProfile.cipherSuitesTls12)
    
    $cipherSuitesUsed = ""
    $allCipherSuites = @()

    if ($os.Version -ge [System.Version]'10.0.20348') {
        $allCipherSuites = $tls13Suites + $tls12Suites
        $cipherSuitesUsed = "TLS 1.3 and TLS 1.2"
    }
    elseif ($os.Version -ge [System.Version]'10.0.14393') {
        $allCipherSuites = $tls12Suites
        $cipherSuitesUsed = "TLS 1.2"
    }
    else {
        Write-Log -Message "Unsupported operating system version." -LogType Error -VerboseOutput
        return
    }

    if ($script:DryRun) {
        Write-DryRunAction -Action "CIPHER SUITES" -Target $cipherSuitesUsed -Details "$($allCipherSuites.Count) cipher suites will be configured"
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
        Write-Log -Message "Registry key not found or cannot be created: $regPath" -LogType Error -VerboseOutput
        return
    }

    try {
        Set-ItemProperty -Path $regPath -Name 'Functions' -Value ([String]::Join(',', $allCipherSuites)) -Type String
        Write-Log -Message "Cipher suites configured successfully. Cipher suites used: $cipherSuitesUsed" -LogType Info -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "Error occurred while configuring cipher suites: $_" -LogType Error -VerboseOutput
    }
    finally {
        $key.Close()
    }
}

function Set-EccCurves {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    
    # Get ECC curves configuration from profile
    $curvesToUse = $script:ActiveProfile.eccCurves
    Write-Log -Message "Using profile ECC Curves: $($curvesToUse.Count) curves" -LogType Info -VerboseOutput -InfoColor Cyan
    
    if ($script:DryRun) {
        Write-DryRunAction -Action "ECC CURVES" -Target "Elliptic Curves" -Details "$($curvesToUse.Count) curves will be configured"
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
        Write-Log -Message "Registry key not found or cannot be created: $regPath" -LogType Error -VerboseOutput
        return
    }

    try {
        Set-ItemProperty -Path $regPath -Name 'EccCurves' -Value $curvesToUse -Type MultiString -Force
        Write-Log -Message "ECC Curves configured successfully." -LogType Info -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "Error occurred while configuring ECC Curves: $_" -LogType Error -VerboseOutput
    }
    finally {
        $key.Close()
    }
}
# Warn user and get confirmation before running the script. Prevents proceeding without full understanding. Example: Must type YES or yes exactly.
function Confirm-Execution {
    if ($BypassConfirmation) {
        Write-Log "User confirmation bypassed with parameter provided when running script." -LogType Info -VerboseOutput -InfoColor Yellow
        return
    }

    $confirmation = Read-Host "Security settings will be configured with TLSHardener. Are you sure you want to continue? (Yes/yes)`
To run without seeing this warning: .\TLSHardener.ps1 -BypassConfirmation"
    if ($confirmation -notmatch "Yes|yes") {
        Write-Log "User confirmation not received. Script cancelled." -LogType Error -VerboseOutput
        exit
    }
}

# .NET Framework 4.0 strong crypto settings
function Set-StrongCrypto {
    if ($EnableStrongCrypto) {
    
        Write-Log "Strong Crypto settings configuration started." -LogType Info -VerboseOutput -InfoColor Cyan

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
                Write-Log ".NET Strong Crypto settings configured successfully: $regPath" -LogType Info -VerboseOutput -InfoColor Green
            }
            catch {
                Write-Log "Error occurred while configuring .NET Strong Crypto settings: $_" -LogType Error -VerboseOutput
            }
        }
    }
}


# Main script function
function Invoke-SecurityConfiguration {
    # Clear-Host
    
    # Load profile (default: recommended)
    Load-SecurityProfile -ProfileName $Profile
    
    # Dry-Run mode start message
    if ($script:DryRun) {
        Write-Host "`n" -NoNewline
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
        Write-Host "║                     DRY-RUN MODE ACTIVE                        ║" -ForegroundColor Magenta
        Write-Host "║  No changes will be made, only preview will be displayed       ║" -ForegroundColor Magenta
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
        Write-Host "║                    DRY-RUN COMPLETED                           ║" -ForegroundColor Magenta
        Write-Host "║  Remove -WhatIf parameter to make actual changes               ║" -ForegroundColor Magenta
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    } else {
        Write-Log -Message "Script completed.`n" -LogType "Info" -VerboseOutput -InfoColor Green
    }
}

# ============================================================================
# SCRIPT STARTUP
# ============================================================================

# Check if remote server mode
if ($ComputerName -and $ComputerName.Count -gt 0) {
    # Log file
    $TimeStamp = Get-Date -Format "yyyy_MM_dd_HHmm"
    [string]$LogFilePath = ".\logs\TLSHardener-Remote_$TimeStamp.log"
    
    # Run on remote servers
    $remoteResults = Invoke-RemoteConfiguration -Computers $ComputerName -Cred $Credential `
        -SelectedProfile $Profile -IsDryRun $script:DryRun -StrongCrypto $EnableStrongCrypto
    
    # Create result report
    $reportPath = ".\reports\TLSHardener-Remote_$TimeStamp.csv"
    if (-not (Test-Path ".\reports")) {
        New-Item -Path ".\reports" -ItemType Directory -Force | Out-Null
    }
    $remoteResults | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Result report: $reportPath" -ForegroundColor Cyan
    
    exit 0
}

# Check if rollback mode
if ($Rollback) {
    # Log file
    $TimeStamp = Get-Date -Format "yyyy_MM_dd_HHmm"
    [string]$LogFilePath = ".\logs\TLSHardener-Rollback_$TimeStamp.log"
    
    Invoke-Rollback -SpecificBackupFile $BackupFile -UseDefaults:$ToDefaults
    
    Write-Log "Rollback operation completed." -LogType Info -VerboseOutput -InfoColor Green
    exit 0
}

# Normal mode - Run the script
Invoke-SecurityConfiguration

# Terminate script
Write-Log "Script terminated." -LogType Info -VerboseOutput -InfoColor Green

# Clean up used variables
Write-Log "Cleaning up variables" -LogType Info -VerboseOutput -InfoColor Yellow
Remove-Variable -Name LogFilePath, backupFolder, backupTime, backupFile, os, protocols, `
    protocol, enabled, regPathClient, regPathServer, algorithm, regPathAlgorithm, `
    key, keyExchangeAlgorithms, allCipherSuites, cipherSuitesUsed, tls13CipherSuites, `
    tls12CipherSuites -ErrorAction SilentlyContinue
