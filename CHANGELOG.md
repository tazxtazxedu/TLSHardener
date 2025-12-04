# 📋 Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Pester unit tests
- CI/CD integration

---

## [3.6.0] - 2025-12-04

### ✨ Added
- **Multilingual Support**: Turkish (TR/) and English (EN/) directories
  - All scripts translated to English in EN/ folder
  - Original Turkish scripts preserved in TR/ folder
  - Shared config/ folder for both languages
- **New Root README.md**: Bilingual landing page
  - English and Turkish keywords for SEO
  - Links to language-specific documentation
  - Quick start examples for both languages
- **Project Cleanup**: Reorganized file structure
  - Each language folder (EN/, TR/) now has its own config/ and assets/
  - Config descriptions translated to English for EN/config/
  - Updated CONTRIBUTING.md (English only)
  - Updated CHANGELOG.md (English only)

### 🔄 Changed
- Root README.md now serves as language selector
- All root documentation files converted to English

---

## [3.5.0] - 2025-11-29

### ✨ Added
- **TLSHardener-Report.ps1 Redesigned**
  - Modern and responsive HTML design
  - Statistics cards (Active protocols, ciphers, hash counts)
  - Colored status badges (Enabled/Disabled/Default)
  - Clickable accordion sections
  - Search and filter functionality
  - Cipher Suite and ECC Curves visualization
- **Centralized Error Management System**
  - `$script:ErrorCodes` hashtable (40+ error codes)
  - `Write-TLSError` function
  - Categorized error codes: General (1000), Profile (1100), Registry (1200), Remote Server (1300), File (1400), Configuration (1500)
- **Function Consolidation**
  - `Set-ProtocolsClients` + `Set-ProtocolsServers` → `Set-Protocols -Type "Both"`
  - ~40% code reduction
- **GitHub Preparation**
  - LICENSE (MIT)
  - .gitignore
  - CONTRIBUTING.md
  - SECURITY.md
  - Updated Synopsis in all scripts

### 🔄 Changed
- All script versions synchronized to 3.5
- Added try-catch to `Set-EncryptionAlgorithms`, `Set-HashAlgorithms`, `Set-KeyExchangeAlgorithms` functions
- README.md version badge updated to 3.5

---

## [3.4.0] - 2025-11-29

### ✨ Added
- **Remote Server Support**: Configure multiple servers with single command
  - `-ComputerName "Server01","Server02"` parameter
  - `-Credential` for credential support
  - Uses PowerShell Remoting (WinRM)
  - Connection test (Ping + WinRM)
  - Automatic Registry backup on each server (`C:\TLSHardener-Backups\`)
  - CSV result report (`.\reports\TLSHardener-Remote_*.csv`)
  - Dry-Run mode works on remote servers
  - Profile support works on remote servers
  - All configuration categories: Protocols, Hashes, Ciphers, Key Exchange, DH Size, Cipher Suites, ECC Curves, FIPS, Strong Crypto
- **Compliance Report**: Security standards compliance check
  - `TLSHardener-Compliance.ps1` script
  - PCI-DSS v4.0 controls (SSL/TLS, cipher suites, hash algorithms)
  - NIST SP 800-52 Rev.2 controls (TLS versions, AEAD ciphers, key exchange)
  - HIPAA Technical Safeguards controls (encryption, transmission security)
  - CIS Benchmark controls (protocols, NULL/RC4/DES ciphers)
  - `-Standard` parameter: All, PCI-DSS, NIST, HIPAA, CIS
  - `-ExportReport` for HTML report generation
  - `-OpenReport` for automatic browser opening
  - Modern HTML design with accordion/collapsible sections
  - Single line summary (Overall Compliance + Passed/Warning/Failed)

### 🔄 Changed
- Version 3.3 → 3.4
- README.md updated (Remote Server and Compliance sections)

---

## [3.3.0] - 2025-11-29

### ✨ Added
- **Rollback Feature**: Flexible restore options
  - `.\TLSHardener.ps1 -Rollback` → Interactive mode, lists backups
  - `.\TLSHardener.ps1 -Rollback -BackupFile "..."` → Loads specific backup
  - `.\TLSHardener.ps1 -Rollback -ToDefaults` → Restores to Windows defaults
  - Backup files with same timestamp are grouped
  - Option to restore to Windows defaults when no backup exists
- **custom.json** profile: Template for user customization

### 🔄 Changed
- Profile files moved `config/profiles/` → `config/` (simplification)
- Separate JSON configuration files removed (all settings in profiles)
- `Get-ConfigFromJson` function removed (dead code cleanup)
- `UseProfile` variable removed (profiles always used)
- All else blocks cleaned up (simplification)

---

## [3.2.0] - 2025-11-29

### ✨ Added
- **Profile Support**: Ready-made profiles for different security levels
  - `strict.json`: TLS 1.3 only, maximum security
  - `recommended.json`: TLS 1.2/1.3, balanced security (default)
  - `compatible.json`: Legacy system compatible, CBC support
  - `-Profile "strict|recommended|compatible"` parameter
  - Profile info shown in console output
- **TLSHardener-Verify.ps1**: Configuration verification script
  - Checks Registry values
  - Compares with expected values
  - HTML report support (`-ExportReport`)
  - Fixed 0xFFFFFFFF value reading error (signed/unsigned int)

### 🔄 Changed
- All Set-* functions updated for profile support
- When profile is active, profile settings are used

---

## [3.1.0] - 2025-11-29

### ✨ Added
- **Dry-Run (-WhatIf) Mode**: Preview without making changes
  - DryRun support added to all functions
  - Colored output for easy readability
  - Use with `.\TLSHardener.ps1 -WhatIf` command
- **README.md**: Comprehensive documentation
  - Installation and usage instructions
  - Security settings explanations
  - Compatibility tables
  - Troubleshooting guide
- **CHANGELOG.md**: Version history tracking

### 🔒 Security Improvements
- **DH Key Size increased**: 2048 bit → 3072 bit
  - Added `ServerMinKeyBitLength` and `ClientMinKeyBitLength`
  - Strengthened protection against Logjam attack
- **CBC Cipher Suites removed**: 10 insecure ciphers deleted
  - Protection against BEAST/POODLE/Lucky13 attacks
  - Only GCM mode ciphers active
  - TLS 1.2 cipher count: 18 → 6

### 🔄 Changed
- Cipher suite ordering optimized (ECDSA priority)
- TLS 1.3 cipher ordering updated (AES-256 first)
- Added `DH-MinKeyBitLength` to `key-exchange.json`

---

## [3.0.0] - 2025-11-28

### 🎉 Major Changes
- **Project renamed**: ProtocolConfig → **TLSHardener**
- **File structure renewed**:
  - `jsons/` → `config/`
  - `icons/` → `assets/`
  - `ProtocolConfigV2.8.ps1` → `TLSHardener.ps1`
  - `CleanProtocolConfigVersion2.3.ps1` → `TLSHardener-Clean.ps1`
  - `GenerateProtocolConfigReportv1.9.ps1` → `TLSHardener-Report.ps1`

### 🔄 Changed
- JSON files converted to kebab-case format:
  - `protocolsClient.json` → `protocols-client.json`
  - `protocolsServer.json` → `protocols-server.json`
  - `tls12CipherSuites.json` → `cipher-suites-tls12.json`
  - `tls13CipherSuites.json` → `cipher-suites-tls13.json`
  - `hashAlgorithms.json` → `hashes.json`
  - `keyExchange.json` → `key-exchange.json`
  - `eccCurves.json` → `ecc-curves.json`
  - `encryptionAlgorithms.json` → `ciphers.json`
- Script headers and version numbers updated

### 🐛 Fixed
- **TLS 1.1 Client inconsistency**: Corrected `true` → `false`
- **TLS 1.2 logic error**: Fixed to always be `true`

### 🗑️ Removed
- `deepseekexamplereport.ps1` (unnecessary file)

---

## [2.8.0] - 2025-11-15

### ✨ Added
- TLS 1.3 support (for Windows Server 2022+)
- ECC Curves configuration (NistP256, NistP384, NistP521)
- Dynamic OS version check
- `-EnableStrongCrypto` parameter (for .NET Framework)

### 🔄 Changed
- Cipher suites split into separate files for TLS 1.2 and TLS 1.3
- Log system improved (colored output support)

---

## [2.7.0] - 2025-10-01

### ✨ Added
- Automatic registry backup (`backups/` folder)
- `-BypassConfirmation` parameter
- Detailed logging system (`logs/` folder)

### 🔒 Security
- RC4, DES, 3DES, NULL ciphers disabled
- MD5 hash algorithm disabled

---

## [2.5.0] - 2025-08-15

### ✨ Added
- JSON-based configuration system
- FIPS Algorithm Policy settings
- Key Exchange algorithm configuration

### 🔄 Changed
- Hardcoded values moved to JSON files
- Functions made modular

---

## [2.0.0] - 2025-06-01

### 🎉 First Major Release
- Disable TLS 1.0 and TLS 1.1
- Enable TLS 1.2
- Disable SSL 2.0 and SSL 3.0
- Basic cipher suite configuration
- Registry-based configuration

---

## Versioning

- **MAJOR** (X.0.0): Breaking changes, not backward compatible
- **MINOR** (0.X.0): New features, backward compatible
- **PATCH** (0.0.X): Bug fixes

---

## Links

- [README](README.md)
- [TODO](TODO.md)
- [GitHub Repository](https://github.com/tazxtazxedu/TLSHardener)
