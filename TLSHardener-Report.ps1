<#
.SYNOPSIS
    TLSHardener - Security Configuration Report Generator
    Sistem güvenlik yapılandırmasının HTML raporu.

.DESCRIPTION
    Bu script, TLS/SSL güvenlik yapılandırmasının detaylı bir raporunu oluşturur.
    Protokoller, cipher'lar, hash'ler ve diğer güvenlik ayarlarını analiz eder.

.PARAMETER OpenReport
    Rapor oluşturduktan sonra otomatik olarak tarayıcıda açar

.EXAMPLE
    .\TLSHardener-Report.ps1
    .\TLSHardener-Report.ps1 -OpenReport

.NOTES
    Proje: TLSHardener
    Versiyon: 3.0
    Tarih: 2025
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

$reportHtml = @"
<html>
<head>
    <meta charset="UTF-8">
    <title>TLSHardener - Güvenlik Yapılandırma Raporu - $env:COMPUTERNAME</title>
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #3498db;
            --success: #27ae60;
            --danger: #e74c3c;
        }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 2rem;
            background: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            text-align: center;
        }
        .server-info {
            background: rgba(255,255,255,0.1);
            padding: 1rem;
            border-radius: 5px;
            margin-top: 1rem;
            text-align: left;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 2rem 0;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: var(--primary);
            color: white;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        .status-enabled { color: var(--success); font-weight: bold; }
        .status-disabled { color: var(--danger); font-weight: bold; }
        .search-container {
            position: relative;
            width: 100%;
            margin: 1rem 0;
        }

        .search-icon {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            width: 16px;
            height: 16px;
            z-index: 2;
            pointer-events: none; /* İmleç etkileşimini engeller */
        }

        #searchBox {
            width: 100%;
            padding: 1rem 1rem 1rem 40px; /* Sol padding'i artır */
            border: 2px solid var(--secondary);
            border-radius: 5px;
            font-size: 1rem;
            position: relative;
            background-color: #fff;
        }
        .icon {
            margin-right: 0.5rem;
            vertical-align: middle;
        }
        .config-table {
            margin-top: 2rem;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
        }
        .config-column {
            background: white;
            padding: 1rem;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .title {
            display: flex;
            align-items: center;
        }
    </style>
    <script>
        function searchTable() {
            var input, filter, tables, rows, cell, i, j, txtValue;
            input = document.getElementById('searchBox');
            filter = input.value.toUpperCase();
            tables = document.querySelectorAll("table");

            tables.forEach(function(table) {
                rows = table.getElementsByTagName("tr");
                for (i = 1; i < rows.length; i++) {
                    var rowVisible = false;
                    for (j = 0; j < rows[i].cells.length; j++) {
                        cell = rows[i].cells[j];
                        if (cell) {
                            txtValue = cell.textContent || cell.innerText;
                            if (txtValue.toUpperCase().indexOf(filter) > -1) {
                                rowVisible = true;
                                break;
                            }
                        }
                    }
                    if (rowVisible) {
                        rows[i].style.display = "";
                    } else {
                        rows[i].style.display = "none";
                    }
                }
            });
        }

        document.addEventListener("DOMContentLoaded", function() {
            document.getElementById('searchBox').addEventListener('input', searchTable);
        });
    </script>
</head>
<body>
    <div class="header">
        <h1 class="title"><img src="$iconsDir/shield.svg" class="icon" style="filter: invert(1);" alt="Shield Icon"/>SChannel Güvenlik Yapılandırma ve Protokol Analizi Raporu</h1>
        <div class="server-info">
            <img src="$iconsDir/server.svg" class="icon" style="filter: invert(1);" alt="Server Icon"/> Sunucu: $env:COMPUTERNAME<br>
            <img src="$iconsDir/calendar.svg" class="icon" style="filter: invert(1);" alt="Calendar Icon"/> Rapor Tarihi: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        </div>
    </div>
    <div class="search-container">
        <img src="$iconsDir\search.svg" class="search-icon" alt="Search Icon"/>
        <input type="text" id="searchBox" onkeyup="searchTable()" placeholder="Path içerisinde arama yapın...">
    </div>
"@

$categoryTitles = @{
    "Ciphers"               = "<div class='title'><img src='$iconsDir/encryption.svg' class='icon' alt='Cipher Icon'/><span>Şifreleme Algoritmaları (<strong>Ciphers</strong>)</span></div>"
    "Hashes"                = "<div class='title'><img src='$iconsDir/hash.svg' class='icon' alt='Hash Icon'/><span>Hash Algoritmaları (<strong>Hash Algorithms</strong>)</span></div>"
    "KeyExchangeAlgorithms" = "<div class='title'><img src='$iconsDir/key_exchange.svg' class='icon' alt='Key Exchange Icon'/><span>Anahtar Değişim Algoritmaları (<strong>Key Exchange Algorithms</strong>)</span></div>"
    "Protocols"             = "<div class='title'><img src='$iconsDir/protocol.svg' class='icon' alt='Protocol Icon'/><span>TLS ve SSL Protokol Ayarları (<strong>TLS/SSL Protocol Settings</strong>)</span></div>"
    "FipsAlgorithmPolicy"   = "<div class='title'><img src='$iconsDir/fips.svg' class='icon' alt='FIPS Icon'/><span>FIPS Uyumluluk Politikası (<strong>FIPS Compliance Policy</strong>)</span></div>"
    "StrongCrypto"          = "<div class='title'><img src='$iconsDir/encryption.svg' class='icon' alt='Crypto Icon'/><span>NET Framework Şifreleme Ayarları (<strong>.NET Framework Crypto Settings</strong>)</span></div>"
}

foreach ($category in $reportData.Keys) {
    $title = $categoryTitles[$category]
    $reportHtml += "<h2>$title</h2><table><tr><th>Path</th><th>Status</th></tr>"
    foreach ($entry in $reportData[$category]) {
        $reportHtml += "<tr><td>$($entry.Path)</td><td>$($entry.Status)</td></tr>"
    }
    $reportHtml += "</table>"
}
# Functions ve EccCurves için ayrı tablo ekleme
$reportHtml += "<h2 class='title'><img src='$iconsDir/encryption.svg' class='icon' alt='Cipher ECC Icon'/><span>Şifreleme Paketleri ve Eliptik Eğri Ayarları (<strong>Cipher Suites & ECC Curves</strong>)</span></h2>"
$reportHtml += "<table>
    <tr><th>Functions</th><th>EccCurves</th></tr>"

foreach ($entry in $reportData2["Functions"]) {
    $functionsList = $entry.Functions -split ","
    $eccCurvesList = $entry.EccCurves -split ","
    
    # Functions ve EccCurves'i aynı satıra yaz
    $functionsColumn = $functionsList -join "<br>"
    $eccCurvesColumn = $eccCurvesList -join "<br>"

    $reportHtml += "<tr><td>$functionsColumn</td><td>$eccCurvesColumn</td></tr>"
}

$reportHtml += "</table>"
$reportHtml += "<div class='info-box'>
<strong>Not:</strong> Status kısmında <strong>NotFound</strong> yazıyor ise, işletim sistemi varsayılan değerleri geçerlidir.
</div>"
$reportHtml += "</body></html>"

# HTML Dosyasına Kaydet
$reportHtml | Out-File -FilePath $outputPath -Encoding UTF8
Write-Host "Rapor oluşturuldu: $outputPath"

if ($OpenReport) {
    Start-Process $outputPath
}