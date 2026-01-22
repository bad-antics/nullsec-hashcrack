# 🔓 NullSec HashCrack

<div align="center">

![F#](https://img.shields.io/badge/F%23-.NET%208-378BBA?style=for-the-badge&logo=fsharp&logoColor=white)
![Security](https://img.shields.io/badge/Security-Analysis-red?style=for-the-badge&logo=shield)
![License](https://img.shields.io/badge/License-Proprietary-purple?style=for-the-badge)

**Hash Analysis and Identification Tool**

*ML-family functional programming with .NET power*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Hash Types](#hash-types)

</div>

---

## 🎯 Overview

NullSec HashCrack is a hash analysis and identification tool written in F#. It identifies hash types, assesses their security strength, and provides recommendations for remediation.

## ✨ Features

- **🔍 Hash Identification** - Detect MD5, SHA, NTLM, BCrypt, Argon2
- **📊 Security Assessment** - Rate hash strength by severity
- **📋 Bulk Analysis** - Process files with multiple hashes
- **🎯 Recommendations** - Actionable security guidance
- **⚡ Fast** - Native AOT compilation support

## 🛡️ Security Features

```
┌─────────────────────────────────────────────┐
│        NullSec HashCrack v2.0.0            │
├─────────────────────────────────────────────┤
│  ✓ Immutable by Default                    │
│  ✓ Strong Static Typing                    │
│  ✓ Pattern Matching                        │
│  ✓ Option Types (No Nulls)                 │
│  ✓ Result Types for Errors                 │
│  ✓ Pure Functions                          │
│  ✓ Discriminated Unions                    │
└─────────────────────────────────────────────┘
```

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/bad-antics/nullsec-hashcrack.git
cd nullsec-hashcrack

# Build with .NET
dotnet build -c Release

# Or publish as single file
dotnet publish -c Release -r linux-x64 --self-contained
```

### Requirements

- .NET 8.0 SDK or later

## 🚀 Usage

```bash
# Analyze a single hash
./nullsec-hashcrack 5f4dcc3b5aa765d61d8327deb882cf99

# Analyze a file of hashes
./nullsec-hashcrack hashes.txt

# Show help
./nullsec-hashcrack --help

# Show version
./nullsec-hashcrack --version
```

## 📊 Output Example

```
██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗
██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
███████║███████║███████╗███████║██║     ██████╔╝███████║██║     █████╔╝ 
██╔══██║██╔══██║╚════██║██╔══██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ 
██║  ██║██║  ██║███████║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                  bad-antics • Hash Analysis Tool

[*] Hash Analysis

  [CRITICAL] MD5
    Hash:   5f4dcc3b5aa765d61d8327deb882cf99
    Length: 32 characters
    Hex:    true
    CRITICAL: MD5 is cryptographically broken. Migrate to bcrypt/argon2 immediately.

[✗] This hash uses a critically weak algorithm!
```

## 🔍 Supported Hash Types

| Hash Type | Length | Severity | Status |
|-----------|--------|----------|--------|
| **MD5** | 32 hex | Critical | Broken |
| **SHA1** | 40 hex | Critical | Broken |
| **NTLM** | 32 | Critical | Weak |
| **MySQL** | 16/41 | Critical | Weak |
| **SHA256** | 64 hex | Medium | Fast |
| **SHA384** | 96 hex | Low | Fast |
| **SHA512** | 128 hex | Low | Fast |
| **BCrypt** | 60+ | Good | Recommended |
| **Argon2** | Varies | Excellent | Best |

## 📋 File Format

For bulk analysis, use one hash per line:

```
5f4dcc3b5aa765d61d8327deb882cf99
e99a18c428cb38d5f260853678922e03
$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
```

Or hash:password format:

```
5f4dcc3b5aa765d61d8327deb882cf99:password
e99a18c428cb38d5f260853678922e03:abc123
```

## 📜 License

NullSec Proprietary License

## 👤 Author

**bad-antics**
- GitHub: [@bad-antics](https://github.com/bad-antics)
- Website: [bad-antics.github.io](https://bad-antics.github.io)
- Discord: [discord.gg/killers](https://discord.gg/killers)

---

<div align="center">

**Part of the NullSec Security Framework**

</div>
