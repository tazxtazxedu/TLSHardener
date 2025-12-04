# 🤝 Contributing Guide

Thank you for your interest in contributing to TLSHardener! This guide explains how you can contribute to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Environment](#development-environment)
- [Code Standards](#code-standards)
- [Pull Request Process](#pull-request-process)

---

## 📜 Code of Conduct

This project aims to provide a respectful and inclusive environment. Please:

- Provide constructive criticism
- Respect different opinions
- Be kind to community members
- Use professional language

---

## 🚀 How Can I Contribute?

### 🐛 Bug Reports

1. Check the [Issues](https://github.com/tazxtazxedu/TLSHardener/issues) page
2. If the same bug hasn't been reported, open a new issue
3. Include the following information:
   - Windows and PowerShell version
   - Step-by-step reproduction method
   - Expected vs actual behavior
   - Error messages and log outputs

### 💡 Feature Requests

1. Open a "Feature Request" on the [Issues](https://github.com/tazxtazxedu/TLSHardener/issues) page
2. Explain the purpose and use case of the feature
3. If possible, add example code or design

### 🔧 Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/NewFeature`
3. Make your changes
4. Run your tests
5. Commit: `git commit -m 'New feature: Description'`
6. Push: `git push origin feature/NewFeature`
7. Open a Pull Request

---

## 🛠️ Development Environment

### Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or PowerShell 7+
- VS Code (recommended) + PowerShell extension
- Git

### Setup

```powershell
# Clone the repository
git clone https://github.com/tazxtazxedu/TLSHardener.git
cd TLSHardener

# Run in test mode (English version)
.\EN\TLSHardener.ps1 -WhatIf

# Run in test mode (Turkish version)
.\TR\TLSHardener.ps1 -WhatIf
```

---

## 📝 Code Standards

### PowerShell Rules

```powershell
# ✅ Correct: Descriptive function names
function Set-TlsProtocol {
    param(
        [Parameter(Mandatory)]
        [string]$Protocol,
        
        [bool]$Enabled = $true
    )
}

# ❌ Wrong: Short and ambiguous names
function SetTls { }
```

### Comment Standards

```powershell
# Use Synopsis for functions
<#
.SYNOPSIS
    Sets protocol configuration.

.DESCRIPTION
    Enables or disables TLS/SSL protocols.

.PARAMETER Protocol
    Name of the protocol to configure.

.EXAMPLE
    Set-TlsProtocol -Protocol "TLS 1.2" -Enabled $true
#>
```

### Logging

```powershell
# All important operations should be logged
Write-Log "Operation started" -LogType Info
Write-Log "Error occurred: $_" -LogType Error
```

---

## 🔄 Pull Request Process

### Before Opening a PR

- [ ] Does the code work?
- [ ] Is `.\EN\TLSHardener.ps1 -WhatIf` successful?
- [ ] Is documentation added for new features?
- [ ] Is CHANGELOG.md updated?

### PR Description Template

```markdown
## Description
This PR adds/fixes:
- ...

## Testing
- [ ] Tested on Windows Server 2019
- [ ] Tested on Windows Server 2022
- [ ] Dry-Run mode tested

## Related Issue
Fixes #123
```

### Review Process

1. At least 1 reviewer approval required
2. All CI tests must pass
3. No merge conflicts

---

## 📞 Questions?

- Ask on [Discussions](https://github.com/tazxtazxedu/TLSHardener/discussions)
- Check existing [Issues](https://github.com/tazxtazxedu/TLSHardener/issues)

---

Thank you for your contributions! 🙏
