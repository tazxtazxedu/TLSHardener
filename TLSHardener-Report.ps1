<#
.SYNOPSIS
    TLSHardener - Security Configuration Report Generator
    Sistem güvenlik yapılandırmasının görsel HTML raporu.

.DESCRIPTION
    Bu script, TLS/SSL güvenlik yapılandırmasının detaylı ve görsel bir raporunu oluşturur.
    
    Rapor içeriği:
    - Protokol ayarları (TLS 1.0-1.3, SSL 2.0/3.0)
    - Şifreleme algoritmaları (Ciphers)
    - Hash algoritmaları (MD5, SHA ailesi)
    - Anahtar değişim algoritmaları (DH, ECDH, PKCS)
    - Cipher Suite sıralaması
    - ECC Curves yapılandırması
    - FIPS politikası
    - .NET Strong Crypto ayarları
    
    HTML rapor özellikleri:
    - Modern ve responsive tasarım
    - Renkli durum badge'leri (Etkin/Devre Dışı/Varsayılan)
    - İstatistik kartları
    - Arama ve filtreleme
    - Tıklanabilir genişleyebilir bölümler

.PARAMETER OpenReport
    Rapor oluşturduktan sonra otomatik olarak varsayılan tarayıcıda açar

.EXAMPLE
    .\TLSHardener-Report.ps1
    Rapor oluşturur ve reports/ klasörüne kaydeder

.EXAMPLE
    .\TLSHardener-Report.ps1 -OpenReport
    Rapor oluşturur ve tarayıcıda açar

.INPUTS
    Yok. Bu script parametre olarak girdi almaz.

.OUTPUTS
    HTML dosyası: reports/TLSHardener_Report_YYYY_MM_DD_HHMM.html

.NOTES
    Proje      : TLSHardener
    Versiyon   : 3.5
    Yazar      : TLSHardener Contributors
    Lisans     : MIT
    Tarih      : 2025
    
    Gereksinimler:
    - Windows Server 2016+ veya Windows 10+
    - PowerShell 5.1+
    - Administrator yetkisi (registry okuma için)

.LINK
    https://github.com/kullanici/TLSHardener

.LINK
    .\TLSHardener.ps1

.LINK
    .\TLSHardener-Verify.ps1
#>
param (
    [switch]$OpenReport
)
# Oluşturulacak Raporun Yolu
$TimeStamp = Get-Date -Format "yyyy_MM_dd_HHmm"
$outputPath = ".\reports\TLSHardener_Report_$TimeStamp.html"
#reports klasörü kontrol
if (-not (Test-Path -Path ".\reports")) {
    New-Item -Path ".\reports" -ItemType Directory
}
# Registry Path Listesi
$registryPaths = @{
    "Ciphers"               = @(
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"
    );
    "Hashes"                = @(
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512"
    );
    "KeyExchangeAlgorithms" = @(
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS"
    );
    "Protocols"             = @(
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client",
        "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
    );
    "FipsAlgorithmPolicy"   = @(
        "SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
    );
    "StrongCrypto"          = @(
        "SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    )
}

$registryPaths2 = @{
    "Functions" = @(
        "SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    );
    "EccCurves" = @(
        "SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    );
}

# Registry'den veri çekme ve rapor oluşturma
# Fonksiyon: Functions ve EccCurves Değerlerini Getir
function Get-FunctionsAndEccCurves {
    param (
        [string]$Path
    )
    try {
        $key = Get-Item -Path "HKLM:\$Path" -ErrorAction Stop
        $functions = $key.GetValue("Functions", "NotConfigured")
        $eccCurves = $key.GetValue("EccCurves", "NotConfigured")
        return @{ Functions = $functions; EccCurves = $eccCurves }
    }
    catch {
        return @{ Functions = "NotFound"; EccCurves = "NotFound" }
    }
}

# Veri Toplama
$reportData2 = @{}
foreach ($category in $registryPaths2.Keys) {
    $reportData2[$category] = @()
    foreach ($path in $registryPaths2[$category]) {
        
        $functionsAndCurves = Get-FunctionsAndEccCurves -Path $path
        $reportData2[$category] += [PSCustomObject]@{
            Path      = $path
            Functions = $functionsAndCurves.Functions
            EccCurves = $functionsAndCurves.EccCurves
        }
    }
}

$reportData = @{}
foreach ($category in $registryPaths.Keys) {
    $reportData[$category] = @()
    foreach ($path in $registryPaths[$category]) {
        $enabled = Get-ItemProperty -Path "HKLM:\$path" -Name "Enabled" -ErrorAction SilentlyContinue
        $disabledByDefault = Get-ItemProperty -Path "HKLM:\$path" -Name "DisabledByDefault" -ErrorAction SilentlyContinue
        $schUseStrongCrypto = Get-ItemProperty -Path "HKLM:\$path" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
        $systemDefaultTlsVersions = Get-ItemProperty -Path "HKLM:\$path" -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue

        if ($category -eq "Protocols" -and ($enabled -or $disabledByDefault)) {
            $status = "DisabledByDefault: $($disabledByDefault.DisabledByDefault), Enabled: $($enabled.Enabled)"
        }
        elseif ($category -eq "StrongCrypto" -and ($schUseStrongCrypto -or $systemDefaultTlsVersions)) {
            $status = "SchUseStrongCrypto: $($schUseStrongCrypto.SchUseStrongCrypto), SystemDefaultTlsVersions: $($systemDefaultTlsVersions.SystemDefaultTlsVersions)"
        }
        elseif ($enabled -ne $null) {
            $status = "Enabled: $($enabled.Enabled)"
        }
        else {
            $status = "NotFound"
        }

        $reportData[$category] += [PSCustomObject]@{
            Path   = $path
            Status = $status
        }
    }
}

# HTML Rapor Üretimi
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$iconsDir = Join-Path $scriptDir "assets"

# İstatistik hesaplama
$stats = @{
    TotalProtocols = 0
    EnabledProtocols = 0
    DisabledProtocols = 0
    TotalCiphers = 0
    EnabledCiphers = 0
    DisabledCiphers = 0
    TotalHashes = 0
    EnabledHashes = 0
    DisabledHashes = 0
}

# Protokol istatistikleri (Sadece ana protokolleri say - Client/Server ayrımı olmadan)
$protocolNames = @{}
foreach ($entry in $reportData["Protocols"]) {
    # Protokol adını çıkar (TLS 1.2, SSL 3.0 vb.)
    if ($entry.Path -match "Protocols\\([^\\]+)\\") {
        $protocolName = $Matches[1]
        if (-not $protocolNames.ContainsKey($protocolName)) {
            $protocolNames[$protocolName] = @{ Enabled = $false; Disabled = $false; NotFound = $true }
        }
        
        # Enabled: 1 veya 4294967295 = Etkin
        if ($entry.Status -match "Enabled:\s*(1|4294967295)") {
            $protocolNames[$protocolName].Enabled = $true
            $protocolNames[$protocolName].NotFound = $false
        }
        # Enabled: 0 veya DisabledByDefault: 1 = Devre dışı
        elseif ($entry.Status -match "Enabled:\s*0" -or $entry.Status -match "DisabledByDefault:\s*1") {
            $protocolNames[$protocolName].Disabled = $true
            $protocolNames[$protocolName].NotFound = $false
        }
    }
}

foreach ($proto in $protocolNames.Keys) {
    $stats.TotalProtocols++
    if ($protocolNames[$proto].Enabled) {
        $stats.EnabledProtocols++
    } elseif ($protocolNames[$proto].Disabled) {
        $stats.DisabledProtocols++
    }
}

# Cipher istatistikleri
foreach ($entry in $reportData["Ciphers"]) {
    $stats.TotalCiphers++
    # Enabled: 4294967295 (0xFFFFFFFF) veya 1 = Etkin
    if ($entry.Status -match "Enabled:\s*(4294967295|1)") {
        $stats.EnabledCiphers++
    }
    # Enabled: 0 = Devre dışı
    elseif ($entry.Status -match "Enabled:\s*0") {
        $stats.DisabledCiphers++
    }
}

# Hash istatistikleri
foreach ($entry in $reportData["Hashes"]) {
    $stats.TotalHashes++
    if ($entry.Status -match "Enabled:\s*(4294967295|1)") {
        $stats.EnabledHashes++
    }
    elseif ($entry.Status -match "Enabled:\s*0") {
        $stats.DisabledHashes++
    }
}

$reportHtml = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLSHardener - Güvenlik Yapılandırma Raporu - $env:COMPUTERNAME</title>
    <style>
        :root {
            --primary: #667eea;
            --primary-dark: #5a67d8;
            --secondary: #764ba2;
            --success: #10b981;
            --success-light: #d1fae5;
            --danger: #ef4444;
            --danger-light: #fee2e2;
            --warning: #f59e0b;
            --warning-light: #fef3c7;
            --info: #3b82f6;
            --info-light: #dbeafe;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-300: #d1d5db;
            --gray-600: #4b5563;
            --gray-700: #374151;
            --gray-800: #1f2937;
            --gray-900: #111827;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%);
            min-height: 100vh;
            color: var(--gray-800);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 2.5rem;
            border-radius: 20px;
            margin-bottom: 2rem;
            box-shadow: 0 20px 40px rgba(102, 126, 234, 0.3);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 100%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            pointer-events: none;
        }
        
        .header h1 {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .header-subtitle {
            opacity: 0.9;
            font-size: 1.1rem;
        }
        
        .server-info {
            display: flex;
            gap: 2rem;
            margin-top: 1.5rem;
            flex-wrap: wrap;
        }
        
        .server-info-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(255,255,255,0.15);
            padding: 0.75rem 1.25rem;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        
        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: white;
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            border-left: 4px solid;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }
        
        .stat-card.success { border-left-color: var(--success); }
        .stat-card.danger { border-left-color: var(--danger); }
        .stat-card.warning { border-left-color: var(--warning); }
        .stat-card.info { border-left-color: var(--info); }
        
        .stat-card .stat-icon {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .stat-card .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--gray-800);
        }
        
        .stat-card .stat-label {
            color: var(--gray-600);
            font-size: 0.9rem;
            margin-top: 0.25rem;
        }
        
        /* Search */
        .search-container {
            position: relative;
            margin-bottom: 2rem;
        }
        
        .search-icon {
            position: absolute;
            left: 1.25rem;
            top: 50%;
            transform: translateY(-50%);
            width: 20px;
            height: 20px;
            opacity: 0.5;
        }
        
        #searchBox {
            width: 100%;
            padding: 1rem 1rem 1rem 3.5rem;
            border: 2px solid var(--gray-200);
            border-radius: 12px;
            font-size: 1rem;
            background: white;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        
        #searchBox:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
        }
        
        /* Category Sections */
        .category-section {
            background: white;
            border-radius: 16px;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            overflow: hidden;
        }
        
        .category-header {
            padding: 1.25rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            cursor: pointer;
            transition: background 0.2s;
            user-select: none;
        }
        
        .category-header:hover {
            background: var(--gray-50);
        }
        
        .category-header.ciphers { border-left: 4px solid #8b5cf6; }
        .category-header.hashes { border-left: 4px solid #06b6d4; }
        .category-header.keyexchange { border-left: 4px solid #f59e0b; }
        .category-header.protocols { border-left: 4px solid #10b981; }
        .category-header.fips { border-left: 4px solid #ef4444; }
        .category-header.strongcrypto { border-left: 4px solid #3b82f6; }
        .category-header.ciphersuites { border-left: 4px solid #ec4899; }
        
        .category-icon {
            width: 28px;
            height: 28px;
            padding: 5px;
            border-radius: 8px;
        }
        
        .category-header.ciphers .category-icon { background: #ede9fe; }
        .category-header.hashes .category-icon { background: #cffafe; }
        .category-header.keyexchange .category-icon { background: #fef3c7; }
        .category-header.protocols .category-icon { background: #d1fae5; }
        .category-header.fips .category-icon { background: #fee2e2; }
        .category-header.strongcrypto .category-icon { background: #dbeafe; }
        .category-header.ciphersuites .category-icon { background: #fce7f3; }
        
        .category-title {
            flex: 1;
            font-weight: 600;
            font-size: 1.1rem;
        }
        
        .category-badge {
            background: var(--gray-100);
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.85rem;
            color: var(--gray-600);
        }
        
        .category-chevron {
            transition: transform 0.3s;
            color: var(--gray-400);
        }
        
        .category-section.collapsed .category-chevron {
            transform: rotate(-90deg);
        }
        
        .category-section.collapsed .category-content {
            display: none;
        }
        
        /* Tables */
        .category-content {
            border-top: 1px solid var(--gray-100);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: var(--gray-50);
            padding: 0.875rem 1.5rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--gray-600);
        }
        
        td {
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--gray-100);
            font-size: 0.95rem;
        }
        
        tr:hover td {
            background: var(--gray-50);
        }
        
        .path-cell {
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
            color: var(--gray-700);
            word-break: break-all;
        }
        
        /* Status Badges */
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            padding: 0.375rem 0.875rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        
        .status-enabled {
            background: var(--success-light);
            color: #065f46;
        }
        
        .status-disabled {
            background: var(--danger-light);
            color: #991b1b;
        }
        
        .status-notfound {
            background: var(--gray-100);
            color: var(--gray-600);
        }
        
        .status-warning {
            background: var(--warning-light);
            color: #92400e;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        
        .status-enabled .status-dot { background: var(--success); }
        .status-disabled .status-dot { background: var(--danger); }
        .status-notfound .status-dot { background: var(--gray-400); }
        .status-warning .status-dot { background: var(--warning); }
        
        /* Cipher Suites */
        .cipher-list {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            padding: 1rem 1.5rem;
        }
        
        .cipher-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.625rem 1rem;
            background: var(--gray-50);
            border-radius: 8px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
        }
        
        .cipher-item.secure {
            background: var(--success-light);
            border-left: 3px solid var(--success);
        }
        
        .cipher-item.weak {
            background: var(--warning-light);
            border-left: 3px solid var(--warning);
        }
        
        .cipher-number {
            background: var(--gray-200);
            color: var(--gray-600);
            padding: 0.125rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            min-width: 24px;
            text-align: center;
        }
        
        .cipher-item.secure .cipher-number {
            background: #86efac;
            color: #065f46;
        }
        
        /* ECC Curves */
        .ecc-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            padding: 1rem 1.5rem;
        }
        
        .ecc-item {
            background: linear-gradient(135deg, #fce7f3, #fbcfe8);
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 500;
            color: #9d174d;
        }
        
        /* Info Box */
        .info-box {
            background: linear-gradient(135deg, var(--info-light), #bfdbfe);
            border-left: 4px solid var(--info);
            padding: 1rem 1.5rem;
            border-radius: 0 12px 12px 0;
            margin: 2rem 0;
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
        }
        
        .info-box-icon {
            font-size: 1.25rem;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--gray-500);
            font-size: 0.9rem;
        }
        
        .footer a {
            color: var(--primary);
            text-decoration: none;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header {
                padding: 1.5rem;
            }
            
            .header h1 {
                font-size: 1.5rem;
            }
            
            .server-info {
                flex-direction: column;
                gap: 0.75rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            th, td {
                padding: 0.75rem 1rem;
            }
        }
    </style>
    <script>
        function searchTable() {
            var input = document.getElementById('searchBox');
            var filter = input.value.toUpperCase();
            var sections = document.querySelectorAll('.category-section');
            
            sections.forEach(function(section) {
                var rows = section.querySelectorAll('tbody tr');
                var hasVisible = false;
                
                rows.forEach(function(row) {
                    var text = row.textContent.toUpperCase();
                    if (text.indexOf(filter) > -1) {
                        row.style.display = '';
                        hasVisible = true;
                    } else {
                        row.style.display = 'none';
                    }
                });
                
                // Show/hide section based on results
                if (filter && !hasVisible) {
                    section.style.display = 'none';
                } else {
                    section.style.display = '';
                }
            });
        }
        
        function toggleSection(header) {
            var section = header.parentElement;
            section.classList.toggle('collapsed');
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('searchBox').addEventListener('input', searchTable);
        });
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                TLSHardener Güvenlik Raporu
            </h1>
            <p class="header-subtitle">SChannel Güvenlik Yapılandırması ve Protokol Analizi</p>
            <div class="server-info">
                <div class="server-info-item">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                        <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                        <line x1="6" y1="6" x2="6.01" y2="6"/>
                        <line x1="6" y1="18" x2="6.01" y2="18"/>
                    </svg>
                    <span><strong>Sunucu:</strong> $env:COMPUTERNAME</span>
                </div>
                <div class="server-info-item">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
                        <line x1="16" y1="2" x2="16" y2="6"/>
                        <line x1="8" y1="2" x2="8" y2="6"/>
                        <line x1="3" y1="10" x2="21" y2="10"/>
                    </svg>
                    <span><strong>Rapor Tarihi:</strong> $(Get-Date -Format "dd MMMM yyyy HH:mm")</span>
                </div>
                <div class="server-info-item">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <path d="M12 6v6l4 2"/>
                    </svg>
                    <span><strong>OS:</strong> $([System.Environment]::OSVersion.VersionString)</span>
                </div>
            </div>
        </div>
        
        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card success">
                <div class="stat-icon">🔓</div>
                <div class="stat-value">$($stats.EnabledProtocols)</div>
                <div class="stat-label">Etkin Protokol (/$($stats.TotalProtocols))</div>
            </div>
            <div class="stat-card danger">
                <div class="stat-icon">🚫</div>
                <div class="stat-value">$($stats.DisabledProtocols)</div>
                <div class="stat-label">Devre Dışı Protokol</div>
            </div>
            <div class="stat-card info">
                <div class="stat-icon">🔐</div>
                <div class="stat-value">$($stats.EnabledCiphers)</div>
                <div class="stat-label">Etkin Cipher (/$($stats.TotalCiphers))</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-icon">🛡️</div>
                <div class="stat-value">$($stats.EnabledHashes)</div>
                <div class="stat-label">Etkin Hash (/$($stats.TotalHashes))</div>
            </div>
        </div>
        
        <!-- Search -->
        <div class="search-container">
            <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="8"/>
                <path d="M21 21l-4.35-4.35"/>
            </svg>
            <input type="text" id="searchBox" placeholder="Registry path veya değer ara...">
        </div>
"@

# Kategori yapılandırması
$categoryConfig = @{
    "Protocols" = @{
        Title = "TLS/SSL Protokolleri"
        Subtitle = "Protocol Settings"
        Class = "protocols"
        Icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
    }
    "Ciphers" = @{
        Title = "Şifreleme Algoritmaları"
        Subtitle = "Cipher Algorithms"
        Class = "ciphers"
        Icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
    }
    "Hashes" = @{
        Title = "Hash Algoritmaları"
        Subtitle = "Hash Algorithms"
        Class = "hashes"
        Icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>'
    }
    "KeyExchangeAlgorithms" = @{
        Title = "Anahtar Değişim Algoritmaları"
        Subtitle = "Key Exchange"
        Class = "keyexchange"
        Icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>'
    }
    "FipsAlgorithmPolicy" = @{
        Title = "FIPS Politikası"
        Subtitle = "FIPS Compliance"
        Class = "fips"
        Icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>'
    }
    "StrongCrypto" = @{
        Title = ".NET Framework Şifreleme"
        Subtitle = "Strong Crypto Settings"
        Class = "strongcrypto"
        Icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>'
    }
}

# Status badge fonksiyonu
function Get-StatusBadge {
    param([string]$Status)
    
    if ($Status -match "Enabled: (4294967295|1)" -or $Status -match "SchUseStrongCrypto: 1") {
        return '<span class="status-badge status-enabled"><span class="status-dot"></span>Etkin</span>'
    }
    elseif ($Status -match "Enabled: 0" -or $Status -match "DisabledByDefault: 1") {
        return '<span class="status-badge status-disabled"><span class="status-dot"></span>Devre Dışı</span>'
    }
    elseif ($Status -eq "NotFound") {
        return '<span class="status-badge status-notfound"><span class="status-dot"></span>Varsayılan</span>'
    }
    else {
        return '<span class="status-badge status-warning"><span class="status-dot"></span>' + $Status + '</span>'
    }
}

# Kategorileri oluştur
foreach ($category in @("Protocols", "Ciphers", "Hashes", "KeyExchangeAlgorithms", "FipsAlgorithmPolicy", "StrongCrypto")) {
    if (-not $reportData.ContainsKey($category)) { continue }
    
    $config = $categoryConfig[$category]
    $itemCount = $reportData[$category].Count
    
    $reportHtml += @"
        <div class="category-section">
            <div class="category-header $($config.Class)" onclick="toggleSection(this)">
                <div class="category-icon">$($config.Icon)</div>
                <span class="category-title">$($config.Title) <small style="color: var(--gray-500);">($($config.Subtitle))</small></span>
                <span class="category-badge">$itemCount öğe</span>
                <svg class="category-chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"/>
                </svg>
            </div>
            <div class="category-content">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 70%">Registry Path</th>
                            <th style="width: 30%">Durum</th>
                        </tr>
                    </thead>
                    <tbody>
"@
    
    foreach ($entry in $reportData[$category]) {
        $pathDisplay = $entry.Path -replace "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\", ""
        $statusBadge = Get-StatusBadge -Status $entry.Status
        
        $reportHtml += @"
                        <tr>
                            <td class="path-cell">$pathDisplay</td>
                            <td>$statusBadge</td>
                        </tr>
"@
    }
    
    $reportHtml += @"
                    </tbody>
                </table>
            </div>
        </div>
"@
}

# Cipher Suites ve ECC Curves bölümü
$reportHtml += @"
        <div class="category-section">
            <div class="category-header ciphersuites" onclick="toggleSection(this)">
                <div class="category-icon">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <ellipse cx="12" cy="5" rx="9" ry="3"/>
                        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                    </svg>
                </div>
                <span class="category-title">Cipher Suites & ECC Curves <small style="color: var(--gray-500);">(Şifreleme Paketleri)</small></span>
                <svg class="category-chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"/>
                </svg>
            </div>
            <div class="category-content" style="display: flex; flex-wrap: wrap;">
"@

foreach ($entry in $reportData2["Functions"]) {
    $functionsList = @($entry.Functions -split ",")
    $eccCurvesList = @($entry.EccCurves -split ",")
    
    # Cipher Suites
    $reportHtml += '<div style="flex: 2; min-width: 300px; padding: 1rem;"><h4 style="margin-bottom: 1rem; color: var(--gray-700);">🔐 Cipher Suites</h4><div class="cipher-list">'
    
    $index = 1
    foreach ($cipher in $functionsList) {
        $cipher = $cipher.Trim()
        if ($cipher -and $cipher -ne "NotConfigured" -and $cipher -ne "NotFound") {
            $cipherClass = if ($cipher -match "AES.*GCM|CHACHA20") { "secure" } elseif ($cipher -match "CBC|3DES|RC4") { "weak" } else { "" }
            $reportHtml += "<div class='cipher-item $cipherClass'><span class='cipher-number'>$index</span>$cipher</div>"
            $index++
        }
    }
    
    if ($index -eq 1) {
        $reportHtml += '<div class="cipher-item">Yapılandırılmamış (Sistem Varsayılanları)</div>'
    }
    
    $reportHtml += '</div></div>'
    
    # ECC Curves
    $reportHtml += '<div style="flex: 1; min-width: 200px; padding: 1rem; border-left: 1px solid var(--gray-100);"><h4 style="margin-bottom: 1rem; color: var(--gray-700);">📈 ECC Curves</h4><div class="ecc-grid">'
    
    foreach ($curve in $eccCurvesList) {
        $curve = $curve.Trim()
        if ($curve -and $curve -ne "NotConfigured" -and $curve -ne "NotFound") {
            $reportHtml += "<div class='ecc-item'>$curve</div>"
        }
    }
    
    if (-not ($eccCurvesList | Where-Object { $_ -and $_ -ne "NotConfigured" -and $_ -ne "NotFound" })) {
        $reportHtml += '<div class="ecc-item" style="background: var(--gray-100); color: var(--gray-600);">Varsayılan</div>'
    }
    
    $reportHtml += '</div></div>'
}

$reportHtml += @"
            </div>
        </div>
        
        <!-- Info Box -->
        <div class="info-box">
            <span class="info-box-icon">ℹ️</span>
            <div>
                <strong>Not:</strong> "Varsayılan" olarak işaretlenen ayarlar, registry'de tanımlanmamış ve işletim sistemi varsayılanları kullanılmaktadır.
                Güvenlik için tüm protokol ve algoritmaların açıkça yapılandırılması önerilir.
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>🛡️ <strong>TLSHardener</strong> v3.5 ile oluşturuldu</p>
            <p style="margin-top: 0.5rem;">Rapor Tarihi: $(Get-Date -Format "dd MMMM yyyy HH:mm:ss")</p>
        </div>
    </div>
</body>
</html>
"@

# HTML Dosyasına Kaydet
$reportHtml | Out-File -FilePath $outputPath -Encoding UTF8

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    RAPOR OLUŞTURULDU                           ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  📄 Dosya: " -NoNewline -ForegroundColor White
Write-Host $outputPath -ForegroundColor Green
Write-Host ""

if ($OpenReport) {
    Write-Host "  🌐 Tarayıcıda açılıyor..." -ForegroundColor Yellow
    Start-Process $outputPath
}