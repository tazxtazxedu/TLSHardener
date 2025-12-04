<#
.SYNOPSIS
    Cleans configurations made by TLSHardener and restores Windows defaults.

.DESCRIPTION
    This script removes all TLS/SSL configurations made by TLSHardener
    and restores the system to Windows default settings.
    
    Cleaned settings:
    - SCHANNEL Ciphers (AES, DES, RC4, NULL, etc.)
    - SCHANNEL Hashes (MD5, SHA family)
    - SCHANNEL KeyExchangeAlgorithms (DH, ECDH, PKCS)
    - SCHANNEL Protocols (SSL 2.0/3.0, TLS 1.0-1.3)
    - FIPS Algorithm Policy
    - Cipher Suite ordering
    - Elliptic Curve (ECC) configuration
    - .NET Framework Strong Crypto settings

    ⚠️ WARNING: This operation removes all TLS hardening settings!
    The system will revert to Windows defaults.

.PARAMETER BypassConfirmation
    Skips user confirmation and starts cleanup directly.
    CAUTION: With this parameter, the script runs without asking for confirmation!

.EXAMPLE
    .\TLSHardener-Clean.ps1
    Interactive mode - asks for user confirmation

.EXAMPLE
    .\TLSHardener-Clean.ps1 -BypassConfirmation
    Performs cleanup without confirmation (for automation)

.INPUTS
    None

.OUTPUTS
    Log file: logs/TLSHardener-Clean_YYYY_MM_DD_HHMM.log

.NOTES
    Project    : TLSHardener
    Version    : 3.5
    Author     : TLSHardener Contributors
    License    : MIT
    Date       : 2025
    
    Requirements:
    - Administrator privileges
    - Windows Server 2016+ or Windows 10+

.LINK
    https://github.com/username/TLSHardener

.LINK
    .\TLSHardener.ps1 -Rollback -ToDefaults
#>
param (
    [switch]$BypassConfirmation
)

# Set console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Function for logging
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
            Join-Path $backupFolder "Clean_Script_$backupTime`_$(($key -split '\\')[-1])_wow6432.reg"
        }
        else {
            Join-Path $backupFolder "Clean_Script_$backupTime`_$(($key -split '\\')[-1]).reg"
        }
        
        Write-Log "Backing up $key..." -LogType Info -VerboseOutput -InfoColor Yellow
        Export-RegistryKey -keyPath $key -exportPath $backupFile
    }

    Write-Log "Backup operation completed" -LogType Info -VerboseOutput -InfoColor Green
}

# SCHANNEL Ciphers cleanup function
function Clear-SCHANNELCiphers {
    Write-Log -Message "[1] SCHANNEL - Cleaning Ciphers." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\*" -Force -ErrorAction Stop -Recurse
        Write-Log -Message "[1] SCHANNEL - Ciphers cleaned successfully." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[1] SCHANNEL - Error while cleaning Ciphers: $_" -LogType "Error" -VerboseOutput
    }
}

# SCHANNEL Hashes cleanup function
function Clear-SCHANNELHashes {
    Write-Log -Message "[2] SCHANNEL - Cleaning Hash algorithms." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\*" -Force -ErrorAction Stop -Recurse
        Write-Log -Message "[2] SCHANNEL - Hashes cleaned successfully." -LogType "Info" -VerboseOutput  -InfoColor Green
    }
    catch {
        Write-Log -Message "[2] SCHANNEL - Error while cleaning Hashes: $_" -LogType "Error" -VerboseOutput
    }
}

# SCHANNEL KeyExchangeAlgorithms cleanup function
function Clear-SCHANNELKeyExchangeAlgorithms {
    Write-Log -Message "[3] SCHANNEL - Cleaning KeyExchangeAlgorithms." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\*" -Force -ErrorAction Stop -Recurse
        Write-Log -Message "[3] SCHANNEL - KeyExchangeAlgorithms cleaned successfully." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[3] SCHANNEL - Error while cleaning KeyExchangeAlgorithms: $_" -LogType "Error" -VerboseOutput
    }
}

# SCHANNEL Protocols cleanup function
function Clear-SCHANNELProtocols {
    Write-Log -Message "[4] SCHANNEL - Cleaning Protocols." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*" -Force -ErrorAction Stop -Recurse
        Write-Log -Message "[4] SCHANNEL - Protocols cleaned." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[4] SCHANNEL - Error while cleaning Protocols: $_" -LogType "Error" -VerboseOutput
    }
}

# FIPS algorithm policy disable function
function Disable-FIPSAlgorithmPolicy {
    Write-Log -Message "[5] FIPS - Disabling FipsAlgorithmPolicy." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name Enabled -Force -ErrorAction Stop
        Write-Log -Message "[5] FIPS - FipsAlgorithmPolicy disabled successfully." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[5] FIPS - Error while disabling FipsAlgorithmPolicy: $_" -LogType "Error" -VerboseOutput
    }
}

# Cipher Suites ordering cleanup function
function Clear-CipherSuites {
    Write-Log -Message "[6] Cleaning Cipher Suite ordering." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name Functions -Force -ErrorAction Stop
        Write-Log -Message "[6] Cipher Suite cleaned successfully." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[6] Error while cleaning Cipher Suite: $_" -LogType "Error" -VerboseOutput
    }
}

# Elliptic Curve configuration cleanup function
function Clear-EllipticCurveConfig {
    Write-Log -Message "[7] Cleaning Elliptic Curve configuration." -LogType "Info" -VerboseOutput -InfoColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name EccCurves -Force -ErrorAction Stop
        Write-Log -Message "[7] Elliptic Curve configuration cleaned successfully." -LogType "Info" -VerboseOutput -InfoColor Green
    }
    catch {
        Write-Log -Message "[7] Error while cleaning Elliptic Curve configuration: $_" -LogType "Error" -VerboseOutput
    }
}

# Warn user and get confirmation before running the script. Prevents proceeding without full understanding. You can provide a parameter to bypass this step.
function Confirm-Execution {
    if ($BypassConfirmation) {
        Write-Log "User confirmation bypassed with parameter provided when running script." -LogType Info -VerboseOutput -InfoColor Yellow
        return
    }

    $confirmation = Read-Host "Security settings will be cleaned with this script. Are you sure you want to continue? (Yes/yes)"
    if ($confirmation -notmatch "Yes|yes") {
        Write-Log "User confirmation not received. Script cancelled." -LogType Error -VerboseOutput
        exit
    }
}

# .NET Framework 4.6+ strong crypto settings rollback function
function Clear-StrongCrypto {
    Write-Log "Strong Crypto settings rollback started." -LogType Info -VerboseOutput -InfoColor Cyan

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    )

    foreach ($regPath in $regPaths) {
        try {
            if (Test-Path -Path $regPath) {
                Remove-ItemProperty -Path $regPath -Name "SchUseStrongCrypto" -ErrorAction Stop
                Remove-ItemProperty -Path $regPath -Name "SystemDefaultTlsVersions" -ErrorAction Stop
                Write-Log "Strong Crypto settings rolled back successfully: $regPath" -LogType Info -VerboseOutput -InfoColor Green
            }
            else {
                Write-Log "Registry path not found: $regPath" -LogType Warning -VerboseOutput
            }
        }
        catch {
            Write-Log "Error while rolling back Strong Crypto settings: $_" -LogType Error -VerboseOutput
        }
    }
}

# Main script function
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
    Write-Log -Message "Script completed." -LogType "Info" -VerboseOutput -InfoColor Green
}

# Run the script
Invoke-SecurityCleanup