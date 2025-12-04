<#
.ScriptName: TLSHardener-Verify.ps1
.SYNOPSIS
Verification script that checks if TLSHardener configuration is applied correctly.

.DESCRIPTION
This script performs the following checks:
- Verifies protocol settings (TLS 1.0/1.1 disabled, TLS 1.2/1.3 enabled)
- Checks cipher suites
- Verifies hash algorithm settings
- Checks Key Exchange settings
- Verifies encryption algorithms
- Displays results as colored table
- Profile-based verification support

.PARAMETER ExportReport
Exports results as HTML report

.PARAMETER ReportPath
Path where the HTML report will be saved

.PARAMETER Profile
Profile to use for verification (strict, recommended, compatible)

.EXAMPLE
.\TLSHardener-Verify.ps1
Standard verification - prints results to screen

.EXAMPLE
.\TLSHardener-Verify.ps1 -ExportReport
Creates HTML report

.EXAMPLE
.\TLSHardener-Verify.ps1 -Profile strict
Verifies against strict profile settings

.EXAMPLE
.\TLSHardener-Verify.ps1 -Profile compatible -ExportReport
Verifies with compatible profile and creates HTML report

.EXAMPLE
.\TLSHardener-Verify.ps1 -Profile custom
Verifies against custom profile settings

.NOTES
    Project    : TLSHardener
    Version    : 3.5
    Author     : TLSHardener Contributors
    License    : MIT
    Date       : 2025
    
    Requirements:
    - Administrator privileges
    - Windows Server 2016+ or Windows 10+
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

# Set console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Active profile
$script:ActiveProfile = $null
$script:ProfileName = "Default"

# Profile loading function
function Load-VerifyProfile {
    param ([string]$ProfileName)
    
    $profilePath = ".\config\$ProfileName.json"
    
    if (-not (Test-Path $profilePath)) {
        Write-Host "  ⚠️ Profile not found: $profilePath" -ForegroundColor Yellow
        Write-Host "  Continuing with default settings..." -ForegroundColor Gray
        return $false
    }
    
    try {
        $script:ActiveProfile = Get-Content -Path $profilePath -Raw | ConvertFrom-Json
        $script:ProfileName = $script:ActiveProfile.name
        return $true
    }
    catch {
        Write-Host "  ❌ Error loading profile: $_" -ForegroundColor Red
        return $false
    }
}

# Get expected protocols from profile
function Get-ExpectedProtocols {
    if ($script:ActiveProfile -and $script:ActiveProfile.protocols) {
        $result = @{}
        foreach ($protocol in $script:ActiveProfile.protocols.PSObject.Properties) {
            $result[$protocol.Name] = $protocol.Value
        }
        return $result
    }
    
    # Default (recommended)
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

# Get expected ciphers from profile
function Get-ExpectedCiphers {
    if ($script:ActiveProfile -and $script:ActiveProfile.ciphers) {
        $result = @{}
        foreach ($cipher in $script:ActiveProfile.ciphers.PSObject.Properties) {
            $result[$cipher.Name] = $cipher.Value
        }
        return $result
    }
    
    # Default (recommended)
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

# Get expected hashes from profile
function Get-ExpectedHashes {
    if ($script:ActiveProfile -and $script:ActiveProfile.hashes) {
        $result = @{}
        foreach ($hash in $script:ActiveProfile.hashes.PSObject.Properties) {
            $result[$hash.Name] = $hash.Value
        }
        return $result
    }
    
    # Default (recommended)
    return @{
        "MD5"    = $false
        "SHA"    = $false
        "SHA256" = $true
        "SHA384" = $true
        "SHA512" = $true
    }
}

# Get expected key exchange from profile
function Get-ExpectedKeyExchange {
    if ($script:ActiveProfile -and $script:ActiveProfile.keyExchange) {
        $result = @{}
        foreach ($ke in $script:ActiveProfile.keyExchange.PSObject.Properties) {
            $result[$ke.Name] = $ke.Value
        }
        return $result
    }
    
    # Default (recommended)
    return @{
        "Diffie-Hellman" = $true
        "ECDH"           = $true
        "PKCS"           = $true
    }
}

# Get expected DH Key Size from profile
function Get-ExpectedDHKeySize {
    if ($script:ActiveProfile -and $script:ActiveProfile.dhMinKeySize) {
        return $script:ActiveProfile.dhMinKeySize
    }
    return 3072  # Default
}

# Get expected cipher suites from profile
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
        # Default recommended ciphers
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

# Get CBC permission status from profile
function Get-AllowCBC {
    if ($script:ActiveProfile -and $null -ne $script:ActiveProfile.allowCBC) {
        return $script:ActiveProfile.allowCBC
    }
    return $false  # Default: CBC not allowed
}

# Color definitions
$script:Colors = @{
    Pass    = "Green"
    Fail    = "Red"
    Warning = "Yellow"
    Info    = "Cyan"
    Header  = "Magenta"
}

# Result counters
$script:Results = @{
    Passed  = 0
    Failed  = 0
    Warning = 0
    Total   = 0
}

# Result list (for report)
$script:ResultList = @()

# Header printing function
function Write-Header {
    param ([string]$Title)
    
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor $script:Colors.Header
    Write-Host "  $Title" -ForegroundColor $script:Colors.Header
    Write-Host ("=" * 70) -ForegroundColor $script:Colors.Header
}

# Result printing function
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
    
    # Formatted output
    $itemPadded = $Item.PadRight(35)
    $expectedPadded = $Expected.PadRight(15)
    $actualPadded = $Actual.PadRight(15)
    
    Write-Host "  $icon " -NoNewline -ForegroundColor $color
    Write-Host "$itemPadded " -NoNewline
    Write-Host "Expected: " -NoNewline -ForegroundColor Gray
    Write-Host "$expectedPadded " -NoNewline -ForegroundColor White
    Write-Host "Current: " -NoNewline -ForegroundColor Gray
    Write-Host "$actualPadded" -ForegroundColor $color
    
    # Save for report
    $script:ResultList += [PSCustomObject]@{
        Category = $Category
        Item     = $Item
        Expected = $Expected
        Actual   = $Actual
        Status   = $Status
    }
}

# Safe registry value reading
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

# Check Enabled value (0xFFFFFFFF can be read as -1)
function Test-IsEnabled {
    param ($value)
    
    if ($null -eq $value) { return $null }
    
    # 0xFFFFFFFF as signed is -1, as unsigned is 4294967295
    # 1 also means enabled
    return ($value -eq -1 -or $value -eq 0xFFFFFFFF -or $value -eq 4294967295 -or $value -eq 1)
}

# Protocol verification
function Test-Protocols {
    Write-Header "PROTOCOL SETTINGS"
    
    # Get expectations from profile or defaults
    $protocols = Get-ExpectedProtocols
    
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    
    foreach ($protocol in $protocols.Keys) {
        $expected = $protocols[$protocol]
        
        # Check server setting
        $serverPath = "$basePath\$protocol\Server"
        $serverEnabled = Get-RegistryValue -Path $serverPath -Name "Enabled" -Default $null
        $serverDisabledByDefault = Get-RegistryValue -Path $serverPath -Name "DisabledByDefault" -Default $null
        
        # Special check for TLS 1.3 (requires Windows Server 2022+)
        if ($protocol -eq "TLS 1.3") {
            $os = Get-WmiObject -Class Win32_OperatingSystem
            if ([System.Version]$os.Version -lt [System.Version]'10.0.20348') {
                Write-Result -Category "Protocol" -Item "$protocol [Server]" -Expected "N/A" -Actual "OS Not Supported" -Status "Warning"
                continue
            }
        }
        
        # Determine status
        if ($null -eq $serverEnabled) {
            $actualStatus = "Undefined"
            $status = "Warning"
        }
        elseif ($expected -eq $true) {
            # Expected to be enabled
            if ($serverEnabled -eq 1 -and $serverDisabledByDefault -eq 0) {
                $actualStatus = "Enabled"
                $status = "Pass"
            }
            else {
                $actualStatus = "Disabled"
                $status = "Fail"
            }
        }
        else {
            # Expected to be disabled
            if ($serverEnabled -eq 0 -or $serverDisabledByDefault -eq 1) {
                $actualStatus = "Disabled"
                $status = "Pass"
            }
            else {
                $actualStatus = "Enabled"
                $status = "Fail"
            }
        }
        
        $expectedStr = if ($expected) { "Enabled" } else { "Disabled" }
        Write-Result -Category "Protocol" -Item "$protocol [Server]" -Expected $expectedStr -Actual $actualStatus -Status $status
    }
}

# Cipher algorithms verification
function Test-Ciphers {
    Write-Header "ENCRYPTION ALGORITHMS"
    
    # Get expectations from profile or defaults
    $ciphers = Get-ExpectedCiphers
    
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
    
    foreach ($cipher in $ciphers.Keys) {
        $expected = $ciphers[$cipher]
        $cipherPath = "$basePath\$cipher"
        
        $enabled = Get-RegistryValue -Path $cipherPath -Name "Enabled" -Default $null
        $isEnabled = Test-IsEnabled -value $enabled
        
        if ($null -eq $enabled) {
            $actualStatus = "Undefined"
            $status = "Warning"
        }
        elseif ($expected -eq $true) {
            if ($isEnabled) {
                $actualStatus = "Enabled"
                $status = "Pass"
            }
            else {
                $actualStatus = "Disabled"
                $status = "Fail"
            }
        }
        else {
            if ($enabled -eq 0) {
                $actualStatus = "Disabled"
                $status = "Pass"
            }
            else {
                $actualStatus = "Enabled"
                $status = "Fail"
            }
        }
        
        $expectedStr = if ($expected) { "Enabled" } else { "Disabled" }
        Write-Result -Category "Cipher" -Item $cipher -Expected $expectedStr -Actual $actualStatus -Status $status
    }
}

# Hash algorithms verification
function Test-Hashes {
    Write-Header "HASH ALGORITHMS"
    
    # Get expectations from profile or defaults
    $hashes = Get-ExpectedHashes
    
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"
    
    foreach ($hash in $hashes.Keys) {
        $expected = $hashes[$hash]
        $hashPath = "$basePath\$hash"
        
        $enabled = Get-RegistryValue -Path $hashPath -Name "Enabled" -Default $null
        $isEnabled = Test-IsEnabled -value $enabled
        
        if ($null -eq $enabled) {
            $actualStatus = "Undefined"
            $status = "Warning"
        }
        elseif ($expected -eq $true) {
            if ($isEnabled) {
                $actualStatus = "Enabled"
                $status = "Pass"
            }
            else {
                $actualStatus = "Disabled"
                $status = "Fail"
            }
        }
        else {
            if ($enabled -eq 0) {
                $actualStatus = "Disabled"
                $status = "Pass"
            }
            else {
                $actualStatus = "Enabled"
                $status = "Fail"
            }
        }
        
        $expectedStr = if ($expected) { "Enabled" } else { "Disabled" }
        Write-Result -Category "Hash" -Item $hash -Expected $expectedStr -Actual $actualStatus -Status $status
    }
}

# Key Exchange verification
function Test-KeyExchange {
    Write-Header "KEY EXCHANGE ALGORITHMS"
    
    # Get expectations from profile or defaults
    $keyExchanges = Get-ExpectedKeyExchange
    $expectedDHKeySize = Get-ExpectedDHKeySize
    
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"
    
    foreach ($ke in $keyExchanges.Keys) {
        $expected = $keyExchanges[$ke]
        $kePath = "$basePath\$ke"
        
        $enabled = Get-RegistryValue -Path $kePath -Name "Enabled" -Default $null
        $isEnabled = Test-IsEnabled -value $enabled
        
        if ($null -eq $enabled) {
            $actualStatus = "Undefined"
            $status = "Warning"
        }
        elseif ($expected -eq $true) {
            if ($isEnabled) {
                $actualStatus = "Enabled"
                $status = "Pass"
            }
            else {
                $actualStatus = "Disabled"
                $status = "Fail"
            }
        }
        else {
            if ($enabled -eq 0) {
                $actualStatus = "Disabled"
                $status = "Pass"
            }
            else {
                $actualStatus = "Enabled"
                $status = "Fail"
            }
        }
        
        $expectedStr = if ($expected) { "Enabled" } else { "Disabled" }
        Write-Result -Category "KeyExchange" -Item $ke -Expected $expectedStr -Actual $actualStatus -Status $status
    }
    
    # DH Key Size check - only check if DH is enabled
    $dhExpected = $keyExchanges['Diffie-Hellman']
    $dhPath = "$basePath\Diffie-Hellman"
    $serverMinKey = Get-RegistryValue -Path $dhPath -Name "ServerMinKeyBitLength" -Default $null
    $clientMinKey = Get-RegistryValue -Path $dhPath -Name "ClientMinKeyBitLength" -Default $null
    
    # Don't check MinKeyBitLength if DH is disabled
    if ($dhExpected -eq $false) {
        Write-Result -Category "KeyExchange" -Item "DH ServerMinKeyBitLength" -Expected "N/A" -Actual "DH Disabled" -Status "Pass"
        Write-Result -Category "KeyExchange" -Item "DH ClientMinKeyBitLength" -Expected "N/A" -Actual "DH Disabled" -Status "Pass"
    }
    else {
        # Server Min Key
        if ($null -eq $serverMinKey) {
            Write-Result -Category "KeyExchange" -Item "DH ServerMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "Undefined" -Status "Warning"
        }
        elseif ($serverMinKey -ge $expectedDHKeySize) {
            Write-Result -Category "KeyExchange" -Item "DH ServerMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "$serverMinKey" -Status "Pass"
        }
        else {
            Write-Result -Category "KeyExchange" -Item "DH ServerMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "$serverMinKey" -Status "Fail"
        }
        
        # Client Min Key
        if ($null -eq $clientMinKey) {
            Write-Result -Category "KeyExchange" -Item "DH ClientMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "Undefined" -Status "Warning"
        }
        elseif ($clientMinKey -ge $expectedDHKeySize) {
            Write-Result -Category "KeyExchange" -Item "DH ClientMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "$clientMinKey" -Status "Pass"
        }
        else {
            Write-Result -Category "KeyExchange" -Item "DH ClientMinKeyBitLength" -Expected "$expectedDHKeySize" -Actual "$clientMinKey" -Status "Fail"
        }
    }
}

# Cipher Suites verification
function Test-CipherSuites {
    Write-Header "CIPHER SUITES"
    
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    $currentSuites = Get-RegistryValue -Path $regPath -Name "Functions" -Default ""
    
    if ([string]::IsNullOrEmpty($currentSuites)) {
        Write-Result -Category "CipherSuites" -Item "Cipher Suite Configuration" -Expected "Configured" -Actual "Undefined" -Status "Warning"
        return
    }
    
    $suiteArray = $currentSuites -split ','
    
    # Get expected ciphers from profile
    $expectedSuites = Get-ExpectedCipherSuites
    $allowCBC = Get-AllowCBC
    
    # Unsafe ciphers (should not exist) - CBC check varies by profile
    $unsafeSuites = @(
        "_RC4_",
        "_DES_",
        "_NULL_",
        "_EXPORT_",
        "_MD5"
    )
    
    # CBC check (if profile doesn't allow)
    if (-not $allowCBC) {
        $unsafeSuites += "_CBC_"
    }
    
    Write-Host "`n  Total Cipher Suites: $($suiteArray.Count)" -ForegroundColor $script:Colors.Info
    if ($allowCBC) {
        Write-Host "  ⚠️ CBC Ciphers: ALLOWED (Profile: $script:ProfileName)" -ForegroundColor $script:Colors.Warning
    } else {
        Write-Host "  🔒 CBC Ciphers: PROHIBITED" -ForegroundColor $script:Colors.Info
    }
    
    # Unsafe cipher check
    $hasUnsafe = $false
    foreach ($suite in $suiteArray) {
        foreach ($unsafe in $unsafeSuites) {
            if ($suite -like "*$unsafe*") {
                Write-Result -Category "CipherSuites" -Item $suite -Expected "Should Not Exist" -Actual "Present" -Status "Fail"
                $hasUnsafe = $true
            }
        }
    }
    
    if (-not $hasUnsafe) {
        Write-Result -Category "CipherSuites" -Item "Unsafe Cipher Check" -Expected "None" -Actual "None" -Status "Pass"
    }
    
    # GCM cipher check
    $gcmCount = ($suiteArray | Where-Object { $_ -like "*_GCM_*" }).Count
    if ($gcmCount -gt 0) {
        Write-Result -Category "CipherSuites" -Item "GCM Cipher Count" -Expected ">0" -Actual "$gcmCount" -Status "Pass"
    }
    else {
        Write-Result -Category "CipherSuites" -Item "GCM Cipher Count" -Expected ">0" -Actual "0" -Status "Fail"
    }
}

# FIPS Policy verification
function Test-FIPSPolicy {
    Write-Header "FIPS POLICY"
    
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
    $enabled = Get-RegistryValue -Path $regPath -Name "Enabled" -Default $null
    
    if ($null -eq $enabled) {
        Write-Result -Category "FIPS" -Item "FIPS Algorithm Policy" -Expected "0 (Disabled)" -Actual "Undefined" -Status "Warning"
    }
    elseif ($enabled -eq 0) {
        Write-Result -Category "FIPS" -Item "FIPS Algorithm Policy" -Expected "0 (Disabled)" -Actual "0 (Disabled)" -Status "Pass"
    }
    else {
        Write-Result -Category "FIPS" -Item "FIPS Algorithm Policy" -Expected "0 (Disabled)" -Actual "$enabled (Enabled)" -Status "Warning"
    }
}

# .NET Strong Crypto verification
function Test-DotNetCrypto {
    Write-Header ".NET FRAMEWORK SETTINGS"
    
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
            Write-Result -Category ".NET" -Item "$pathName - StrongCrypto" -Expected "1" -Actual "Undefined" -Status "Warning"
        }
        elseif ($strongCrypto -eq 1) {
            Write-Result -Category ".NET" -Item "$pathName - StrongCrypto" -Expected "1" -Actual "1" -Status "Pass"
        }
        else {
            Write-Result -Category ".NET" -Item "$pathName - StrongCrypto" -Expected "1" -Actual "$strongCrypto" -Status "Fail"
        }
        
        # SystemDefaultTlsVersions
        if ($null -eq $systemTls) {
            Write-Result -Category ".NET" -Item "$pathName - SystemDefaultTls" -Expected "1" -Actual "Undefined" -Status "Warning"
        }
        elseif ($systemTls -eq 1) {
            Write-Result -Category ".NET" -Item "$pathName - SystemDefaultTls" -Expected "1" -Actual "1" -Status "Pass"
        }
        else {
            Write-Result -Category ".NET" -Item "$pathName - SystemDefaultTls" -Expected "1" -Actual "$systemTls" -Status "Fail"
        }
    }
}

# Summary printing
function Write-Summary {
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor $script:Colors.Header
    Write-Host "  VERIFICATION SUMMARY" -ForegroundColor $script:Colors.Header
    Write-Host ("=" * 70) -ForegroundColor $script:Colors.Header
    
    $total = $script:Results.Total
    $passed = $script:Results.Passed
    $failed = $script:Results.Failed
    $warning = $script:Results.Warning
    
    $passRate = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }
    
    Write-Host "`n  Total Checks    : " -NoNewline
    Write-Host "$total" -ForegroundColor White
    
    Write-Host "  ✅ Passed        : " -NoNewline
    Write-Host "$passed" -ForegroundColor $script:Colors.Pass
    
    Write-Host "  ❌ Failed        : " -NoNewline
    Write-Host "$failed" -ForegroundColor $script:Colors.Fail
    
    Write-Host "  ⚠️ Warning       : " -NoNewline
    Write-Host "$warning" -ForegroundColor $script:Colors.Warning
    
    Write-Host "`n  Pass Rate       : " -NoNewline
    
    if ($passRate -ge 90) {
        Write-Host "$passRate%" -ForegroundColor $script:Colors.Pass
    }
    elseif ($passRate -ge 70) {
        Write-Host "$passRate%" -ForegroundColor $script:Colors.Warning
    }
    else {
        Write-Host "$passRate%" -ForegroundColor $script:Colors.Fail
    }
    
    # Overall status
    Write-Host "`n" -NoNewline
    if ($failed -eq 0 -and $warning -eq 0) {
        Write-Host "  🎉 ALL CHECKS PASSED!" -ForegroundColor $script:Colors.Pass
    }
    elseif ($failed -eq 0) {
        Write-Host "  ✅ No critical issues, some warnings exist." -ForegroundColor $script:Colors.Warning
    }
    else {
        Write-Host "  ⚠️ WARNING: $failed failed check(s) found!" -ForegroundColor $script:Colors.Fail
        Write-Host "  Please run the TLSHardener.ps1 script." -ForegroundColor $script:Colors.Info
    }
    
    Write-Host "`n" -NoNewline
}

# HTML Report generation
function Export-HtmlReport {
    if (-not $ExportReport) { return }
    
    # Create folder
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLSHardener Verification Report</title>
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
        <h1>🔐 TLSHardener Verification Report</h1>
        
        <div class="summary">
            <div class="summary-card">
                <h2>$($script:Results.Total)</h2>
                <p>Total Checks</p>
            </div>
            <div class="summary-card">
                <h2 class="pass">$($script:Results.Passed)</h2>
                <p>Passed</p>
            </div>
            <div class="summary-card">
                <h2 class="fail">$($script:Results.Failed)</h2>
                <p>Failed</p>
            </div>
            <div class="summary-card">
                <h2 class="warning">$($script:Results.Warning)</h2>
                <p>Warning</p>
            </div>
            <div class="summary-card">
                <h2 class="rate">%$passRate</h2>
                <p>Pass Rate</p>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Item</th>
                    <th>Expected</th>
                    <th>Current</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
"@

    $currentCategory = ""
    foreach ($result in $script:ResultList) {
        $statusClass = "status-$($result.Status.ToLower())"
        $statusText = switch ($result.Status) {
            "Pass" { "✅ Passed" }
            "Fail" { "❌ Failed" }
            "Warning" { "⚠️ Warning" }
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
            <p>Report Date: $(Get-Date -Format "dd.MM.yyyy HH:mm:ss")</p>
            <p>Profile: $script:ProfileName</p>
            <p>TLSHardener v3.2 | Verification Script v1.1</p>
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
    
    Write-Host "`n  📄 HTML Report generated: " -NoNewline -ForegroundColor $script:Colors.Info
    Write-Host $ReportPath -ForegroundColor White
}

# Main function
function Invoke-Verification {
    Clear-Host
    
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor $script:Colors.Header
    Write-Host "║              🔐 TLSHardener VERIFICATION SCRIPT v1.1               ║" -ForegroundColor $script:Colors.Header
    Write-Host "║                    Configuration Check Tool                         ║" -ForegroundColor $script:Colors.Header
    Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor $script:Colors.Header
    
    Write-Host "`n  Date: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" -ForegroundColor Gray
    Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Gray
    
    # Load profile (default: recommended)
    if (Load-VerifyProfile -ProfileName $Profile) {
        Write-Host "`n" -NoNewline
        Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║                        PROFILE INFORMATION                          ║" -ForegroundColor Cyan
        Write-Host "╠════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host ("║  Profile: {0,-58}║" -f $script:ActiveProfile.name) -ForegroundColor Cyan
        $descShort = if ($script:ActiveProfile.description.Length -gt 56) { 
            $script:ActiveProfile.description.Substring(0, 53) + "..." 
        } else { 
            $script:ActiveProfile.description 
        }
        Write-Host ("║  Description: {0,-52}║" -f $descShort) -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    }
    
    # Run all tests
    Test-Protocols
    Test-Ciphers
    Test-Hashes
    Test-KeyExchange
    Test-CipherSuites
    Test-FIPSPolicy
    Test-DotNetCrypto
    
    # Summary and report
    Write-Summary
    Export-HtmlReport
}

# Run script
Invoke-Verification
