# 🔐 TLSHardener

**Automated TLS/SSL Security Hardening for Windows Server**

A comprehensive PowerShell script to harden TLS/SSL security configuration on Windows servers. Disable weak protocols (SSL 2.0/3.0, TLS 1.0/1.1), enable secure ciphers (AES-GCM), and ensure compliance with PCI-DSS, NIST, HIPAA, and CIS benchmarks.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2016%20|%202019%20|%202022%20|%202025-0078D6.svg)](https://www.microsoft.com/en-us/windows-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.6-orange.svg)](CHANGELOG.md)

### 🏷️ Keywords
`TLS` `SSL` `Security` `Hardening` `Windows Server` `PowerShell` `SCHANNEL` `Cipher Suites` `PCI-DSS` `NIST` `HIPAA` `CIS` `TLS 1.3` `TLS 1.2` `Registry` `Compliance`

---

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Remote Server Support](#-remote-server-support)
- [Compliance Report](#-compliance-report)
- [Configuration Files](#-configuration-files)
- [Security Settings](#-security-settings)
- [Compatibility](#-compatibility)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔒 **Protocol Management** | Disable SSL 2.0/3.0, TLS 1.0/1.1, Enable TLS 1.2/1.3 |
| 🛡️ **Cipher Suite Optimization** | Only GCM mode secure ciphers |
| 🔑 **DH Key Size** | Minimum 3072-bit Diffie-Hellman key |
| #️⃣ **Hash Algorithms** | Disable MD5/SHA1, Enable SHA256/384/512 |
| 📦 **Automatic Backup** | Creates backup before registry changes |
| 👁️ **Dry-Run Mode** | Preview changes without applying (-WhatIf) |
| 🎯 **Profile Support** | strict/recommended/compatible profiles |
| 🔄 **Rollback** | Restore previous configuration or defaults |
| 🌐 **Remote Server** | Configure multiple servers with single command |
| 📊 **Compliance Report** | PCI-DSS, NIST, HIPAA, CIS compliance check |
| ✅ **Verification Script** | Post-configuration check |
| 📝 **Detailed Logging** | All operations are logged |

---

## 📦 Requirements

### System Requirements

| Requirement | Minimum |
|-------------|---------|
| Operating System | Windows Server 2016+ or Windows 10+ |
| PowerShell | 5.1 or later |
| Privileges | Administrator |
| TLS 1.3 Support | Windows Server 2022+ / Windows 11+ |

### Prerequisites

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Verify running as Administrator
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
```

---

## ⚠️ IMPORTANT WARNING

> **WARNING:** Always create a system backup before running this script! Registry changes can cause irreversible issues. Test with `-WhatIf` parameter first.

---

## 📥 Installation

### Method 1: Git Clone

```powershell
git clone https://github.com/tazxtazxedu/TLSHardener.git
cd TLSHardener
```

### Method 2: Manual Download

1. Download the repository as ZIP
2. Extract to your desired folder
3. Open PowerShell as Administrator

---

## 🚀 Usage

### Basic Usage

```powershell
# Standard execution (prompts for confirmation)
.\TLSHardener.ps1

# Run without confirmation prompts
.\TLSHardener.ps1 -BypassConfirmation

# Run with .NET Strong Crypto
.\TLSHardener.ps1 -EnableStrongCrypto

# With all parameters
.\TLSHardener.ps1 -BypassConfirmation -EnableStrongCrypto
```

### 🎯 Profile Usage

Ready-made profiles for different security levels:

```powershell
# Strict profile - Maximum security, TLS 1.3 only
.\TLSHardener.ps1 -Profile strict

# Recommended profile - Balanced security (default settings)
.\TLSHardener.ps1 -Profile recommended

# Compatible profile - Compatible with legacy systems
.\TLSHardener.ps1 -Profile compatible

# Profile with Dry-Run
.\TLSHardener.ps1 -Profile strict -WhatIf
```

#### Profile Comparison

| Feature | Strict | Recommended | Compatible |
|---------|--------|-------------|------------|
| **TLS 1.2** | ❌ Disabled | ✅ Enabled | ✅ Enabled |
| **TLS 1.3** | ✅ Enabled | ✅ Enabled | ✅ Enabled |
| **CBC Cipher** | ❌ Prohibited | ❌ Prohibited | ✅ Allowed |
| **DH Key Size** | 4096 bit | 3072 bit | 2048 bit |
| **AES-128** | ❌ Disabled | ✅ Enabled | ✅ Enabled |
| **Cipher Count** | 2 | 9 | 15 |
| **Compatibility** | Low | Medium | High |
| **Security** | Maximum | High | Medium |

### Dry-Run Mode (Preview)

To see what would happen without making any changes:

```powershell
.\TLSHardener.ps1 -WhatIf
```

Example output:
```
╔════════════════════════════════════════════════════════════════╗
║                    DRY-RUN MODE ACTIVE                         ║
║  No changes will be made, only preview will be shown           ║
╚════════════════════════════════════════════════════════════════╝

[DRY-RUN] PROTOCOL[Client] : TLS 1.0 -> DISABLED
[DRY-RUN] PROTOCOL[Client] : TLS 1.2 -> ENABLED
[DRY-RUN] CIPHER SUITES : TLS 1.3 and TLS 1.2 -> 9 cipher suites will be configured
...
```

### Other Scripts

```powershell
# Report current TLS configuration
.\TLSHardener-Report.ps1

# Clean/reset configuration
.\TLSHardener-Clean.ps1

# Verify configuration
.\TLSHardener-Verify.ps1

# Profile-based verification
.\TLSHardener-Verify.ps1 -Profile recommended

# Verification with HTML report
.\TLSHardener-Verify.ps1 -Profile strict -ExportReport
```

### 🔄 Rollback

Flexible options for reverting configuration:

```powershell
# Interactive mode - lists available backups and lets you choose
.\TLSHardener.ps1 -Rollback

# Load a specific backup file
.\TLSHardener.ps1 -Rollback -BackupFile ".\backups\20251129_103045_SCHANNEL.reg"

# Restore to Windows defaults (clear all TLS settings)
.\TLSHardener.ps1 -Rollback -ToDefaults

# Rollback without confirmation
.\TLSHardener.ps1 -Rollback -ToDefaults -BypassConfirmation
```

During rollback:
- All backup files with the same timestamp are grouped together
- All files in the selected backup group are loaded together
- If no backup exists, option to restore Windows defaults is offered

### 🌐 Remote Server Support

#### Prerequisites

PowerShell Remoting (WinRM) is required for remote server support. First configure the following on target servers:

```powershell
# Enable WinRM on target servers
Enable-PSRemoting -Force

# Check firewall rule
Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP" | Enable-NetFirewallRule

# Add to Trusted Hosts (if needed)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "Server01,Server02"
```

#### Usage

Configure multiple servers with a single command:

```powershell
# Single server
.\TLSHardener.ps1 -ComputerName "Server01" -Profile recommended

# Multiple servers
.\TLSHardener.ps1 -ComputerName "Server01","Server02","Server03" -Profile strict

# With credentials
.\TLSHardener.ps1 -ComputerName "Server01" -Credential (Get-Credential)

# Preview with Dry-Run
.\TLSHardener.ps1 -ComputerName "Server01","Server02" -WhatIf

# With Strong Crypto
.\TLSHardener.ps1 -ComputerName "Server01" -EnableStrongCrypto -BypassConfirmation
```

#### Output

- Connection test and status report
- Detailed progress for each server
- CSV format result report (`.\reports\TLSHardener-Remote_*.csv`)

### 📋 Compliance Report

Check compliance with security standards:

```powershell
# Check all standards
.\TLSHardener-Compliance.ps1

# Only a specific standard
.\TLSHardener-Compliance.ps1 -Standard PCI-DSS
.\TLSHardener-Compliance.ps1 -Standard NIST
.\TLSHardener-Compliance.ps1 -Standard HIPAA
.\TLSHardener-Compliance.ps1 -Standard CIS

# Generate HTML report
.\TLSHardener-Compliance.ps1 -ExportReport

# Generate HTML report and open in browser
.\TLSHardener-Compliance.ps1 -OpenReport

# Detailed explanations
.\TLSHardener-Compliance.ps1 -Detailed
```

Supported standards:
| Standard | Description |
|----------|-------------|
| **PCI-DSS v4.0** | Payment Card Industry Data Security Standard |
| **NIST SP 800-52** | Guidelines for TLS Implementations |
| **HIPAA** | Health Insurance Portability and Accountability Act |
| **CIS Benchmark** | Center for Internet Security Windows Hardening |

HTML Report Features:
- 📊 Large and readable font sizes
- 🎨 Modern dark theme design
- 📋 Clickable expandable sections (Accordion)
- ✅❌⚠️ Colored status icons
- 💡 Solution suggestions for failed checks

Example output:
```
╔════════════════════════════════════════════════════════════════════╗
║          🔐 TLSHardener COMPLIANCE REPORT v1.0                     ║
╚════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════
  📋 PCI-DSS v4.0
═══════════════════════════════════════════════════════════════════════

  ✅ [4.2.1.a] SSL 2.0 disabled
  ✅ [4.2.1.b] SSL 3.0 disabled
  ✅ [4.2.1.c] TLS 1.0 disabled
  ❌ [4.2.1.f] Weak cipher suites disabled

═══════════════════════════════════════════════════════════════════════
  📊 COMPLIANCE SUMMARY
═══════════════════════════════════════════════════════════════════════

  ✅ PCI-DSS - 85.7% compliant (6 passed, 1 failed, 0 warnings)
  ✅ NIST - 100% compliant (6 passed, 0 failed, 0 warnings)
  
  TOTAL: 92.3% compliant
```

### ✅ Verification Script

Check that settings are correctly applied after configuration:

```powershell
# Basic verification
.\TLSHardener-Verify.ps1

# Profile-based verification (according to which profile you applied)
.\TLSHardener-Verify.ps1 -Profile recommended

# Generate HTML report
.\TLSHardener-Verify.ps1 -Profile strict -ExportReport
```

Example output:
```
╔════════════════════════════════════════════════════════════════════╗
║              🔐 TLSHardener VERIFICATION SCRIPT v1.1               ║
╚════════════════════════════════════════════════════════════════════╝

======================================================================
  PROTOCOL SETTINGS
======================================================================
  ✅ TLS 1.0 [Server]              Expected: Disabled  Current: Disabled
  ✅ TLS 1.2 [Server]              Expected: Enabled   Current: Enabled
  ✅ TLS 1.3 [Server]              Expected: Enabled   Current: Enabled

======================================================================
  VERIFICATION SUMMARY
======================================================================
  Total Checks    : 35
  ✅ Passed        : 32
  ❌ Failed        : 0
  ⚠️ Warning       : 3
  Pass Rate       : 91.4%
```

---

## 📁 Configuration Files

All profile settings are stored in JSON files in the `config/` folder:

```
config/
├── strict.json          # Maximum security (TLS 1.3 only)
├── recommended.json     # Recommended settings (default)
├── compatible.json      # Legacy compatibility
└── custom.json          # User customization
```

### Profile Files

Each profile defines all security settings in a single file:

#### strict.json
```json
{
    "name": "Strict",
    "description": "TLS 1.3 only and strongest ciphers",
    "protocols": {
        "TLS 1.2": false,
        "TLS 1.3": true
    },
    "cipherSuitesTls13": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
    ],
    "dhMinKeySize": 4096,
    "allowCBC": false
}
```

#### recommended.json (Default)
```json
{
    "name": "Recommended", 
    "description": "TLS 1.2/1.3 and GCM ciphers",
    "protocols": {
        "TLS 1.2": true,
        "TLS 1.3": true
    },
    "dhMinKeySize": 3072,
    "allowCBC": false
}
```

#### compatible.json
```json
{
    "name": "Compatible",
    "description": "Compatible with legacy systems, includes CBC",
    "protocols": {
        "TLS 1.2": true,
        "TLS 1.3": true
    },
    "dhMinKeySize": 2048,
    "allowCBC": true
}
```

#### custom.json
```json
{
    "name": "Custom",
    "description": "Customize according to your needs",
    // Copy of recommended.json - feel free to edit
}
```

### Example: protocols-server.json

```json
{
  "Multi-Protocol Unified Hello": false,
  "PCT 1.0": false,
  "SSL 2.0": false,
  "SSL 3.0": false,
  "TLS 1.0": false,
  "TLS 1.1": false,
  "TLS 1.2": true,
  "TLS 1.3": true
}
```

### Example: cipher-suites-tls12.json

```json
{
    "$12CipherSuites": [
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256"
    ]
}
```

---

## 🔒 Security Settings

### Protocols

| Protocol | Status | Description |
|----------|--------|-------------|
| SSL 2.0 | ❌ Disabled | Serious security vulnerabilities |
| SSL 3.0 | ❌ Disabled | Vulnerable to POODLE attack |
| TLS 1.0 | ❌ Disabled | Vulnerable to BEAST attack |
| TLS 1.1 | ❌ Disabled | Weak cipher support |
| TLS 1.2 | ✅ Enabled | Secure (with GCM) |
| TLS 1.3 | ✅ Enabled | Most secure |

### Cipher Suites

#### TLS 1.3 (3 ciphers - cannot be changed)
```
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
```

#### TLS 1.2 (6 ciphers - GCM only)
```
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  ← Most secure
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384          ← For compatibility
TLS_RSA_WITH_AES_128_GCM_SHA256
```

### Disabled Features

| Category | Disabled |
|----------|----------|
| Ciphers | RC4, DES, 3DES, NULL |
| Hash | MD5, SHA1 |
| Mode | CBC (all ciphers) |
| Key Exchange | RSA (only ECDHE/DHE recommended) |

### DH Key Size

| Setting | Value |
|---------|-------|
| ServerMinKeyBitLength | 3072 bit |
| ClientMinKeyBitLength | 3072 bit |

---

## ⚠️ Compatibility

### Supported Systems

| System | TLS 1.2 | TLS 1.3 |
|--------|---------|---------|
| Windows Server 2022+ | ✅ | ✅ |
| Windows Server 2019 | ✅ | ❌ |
| Windows Server 2016 | ✅ | ❌ |
| Windows 11 | ✅ | ✅ |
| Windows 10 (1903+) | ✅ | ✅ |

### ❌ Incompatible Clients

This configuration **will not work** with the following legacy systems:

| System/Application | Reason |
|--------------------|--------|
| Windows XP | No TLS 1.2 support |
| Windows Vista | TLS 1.2 not default |
| Internet Explorer 10 and below | Legacy cipher support |
| Android 4.3 and below | No GCM support |
| Java 7 and below | Limited TLS 1.2 support |
| OpenSSL 0.9.8 | Legacy version |

### 📌 Important Notes

1. **Restart Required**: You may need to restart the server for changes to fully apply.

2. **Test First**: Test in a test environment before applying to production.

3. **Backup**: Script creates automatic backup but manual backup is also recommended.

4. **Legacy Applications**: For legacy .NET applications, use the `-EnableStrongCrypto` parameter.

---

## 🔧 Troubleshooting

### Common Issues

#### 1. "Access denied" error
```powershell
# Run PowerShell as Administrator
Start-Process powershell -Verb runAs
```

#### 2. Cannot enable TLS 1.3
```powershell
# Check Windows version
[System.Environment]::OSVersion.Version
# For TLS 1.3: Windows Server 2022+ or Windows 11+ required
```

#### 3. Application connection error
```powershell
# Enable Strong Crypto for .NET applications
.\TLSHardener.ps1 -EnableStrongCrypto
```

#### 4. Restore from backup
```powershell
# Double-click the .reg file in the backups/ folder
# or
reg import .\backups\Protocol_Script_YYYYMMDD_HHMMSS_SCHANNEL.reg
```

### Log Files

Logs are stored in the `logs/` folder:
```
logs/TLSHardener_2025_11_29_1430.log
```

---

## 📊 Compliance (Standards)

This configuration is compliant with the following standards:

| Standard | Status | Notes |
|----------|--------|-------|
| PCI-DSS 4.0 | ✅ | TLS 1.2+ required |
| NIST SP 800-52 Rev. 2 | ✅ | GCM cipher recommended |
| HIPAA | ✅ | Strong encryption |
| GDPR | ✅ | Data encryption |
| CIS Benchmark | ✅ | Windows Server hardening |

---

## 📂 Project Structure

```
TLSHardener/
├── TLSHardener.ps1           # Main script
├── TLSHardener-Verify.ps1    # Verification script
├── TLSHardener-Compliance.ps1 # Compliance report script
├── TLSHardener-Report.ps1    # Reporting script
├── TLSHardener-Clean.ps1     # Cleanup script
├── README.md                 # This file
├── CHANGELOG.md              # Version history
├── TODO.md                   # To-do list
├── config/                   # Profile configuration files
│   ├── strict.json           # Maximum security (TLS 1.3 only)
│   ├── recommended.json      # Recommended (default)
│   ├── compatible.json       # Legacy compatibility
│   └── custom.json           # User customization
├── assets/                   # Images
├── backups/                  # Automatic backups
├── logs/                     # Log files
└── reports/                  # Verification and compliance reports
```

---

## 🤝 Contributing

1. Fork this repository
2. Create a feature branch (`git checkout -b feature/NewFeature`)
3. Commit your changes (`git commit -m 'Added new feature'`)
4. Push your branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📞 Contact

- **Project**: [GitHub Repository](https://github.com/user/TLSHardener)
- **Issues**: [Issues](https://github.com/user/TLSHardener/issues)

---

## 🙏 Acknowledgements

- Microsoft TLS/SSL security documentation
- NIST cryptographic standards
- Open source community

---

<div align="center">

**⭐ If this project helped you, don't forget to give it a star! ⭐**

</div>
