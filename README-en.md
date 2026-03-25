# 🛡️ Ubuntu VPS Hardening Script

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-E95420?style=flat-square&logo=ubuntu )
![Bash](https://img.shields.io/badge/Bash-4.0+-4EAA25?style=flat-square&logo=gnu-bash )
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square )

Modular automated hardening script for Ubuntu 24.04 LTS servers, designed to secure VPS and dedicated servers through user configurations, hardened SSH, and UFW firewall with intelligent service consistency validations.

---

## 📋 Table of Contents

- [Purpose](#purpose)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Available Options](#available-options)
- [Use Cases](#use-cases)
- [Security Validations](#security-validations)
- [Script Structure](#script-structure)
- [Warnings](#warnings)

---

## 🎯 Purpose

This script automates the **basic hardening** process for Ubuntu servers, implementing essential security best practices for newly provisioned VPS:

- **Access Management**: Creation of administrative users with sudo privileges
- **Secure Authentication**: SSH configuration with Ed25519 key authentication and root access disabled
- **Network Protection**: UFW firewall configuration with port validation
- **Active Defense**: Fail2ban implementation against brute force attacks
- **Maintenance**: Automatic security updates

The script is **fully modular**, allowing execution of only necessary configurations without affecting the rest of the system.

---

## ✨ Features

### 🔐 SSH Security
- SSH port change to dynamic range (49152-65335)
- Password authentication disabled (public keys only)
- Root access via SSH blocked
- Automatic Ed25519 key generation with passphrase
- Restrictive `AllowUsers` configuration
- Hardened connection parameters (MaxAuthTries, ClientAliveInterval, etc.)

### 🛡️ Network Protection
- UFW configuration with restrictive default policies
- Consistency validation between SSH port and firewall rules
- **Smart Detection**: If you change the SSH port without reconfiguring the firewall, the script detects the potential lockout and asks if you want to add the rule automatically

### 👥 User Management
- Creation of administrative users with sudo group
- Modification of existing users
- Automatic SSH key pair generation for the user
- Secure password validation (8+ characters, uppercase, lowercase, numbers, and symbols)

### 🔄 Automation
- Automatic security updates (unattended-upgrades)
- Fail2ban with preconfigured rules
- Root account lock
- Automatic backups of original configurations

---

## 📦 Requirements

- **System**: Ubuntu 24.04 LTS (focal recommended, may work on 22.04+)
- **Privileges**: Root access or user with sudo
- **Dependencies**: `bash` 4.0+, internet connection (for package installation)

### Automatically Installed Packages
- `ufw` (Firewall)
- `fail2ban` (Bruteforce protection)
- `unattended-upgrades` (Automatic updates)
- `openssh-server` (SSH)

---

## 🚀 Installation

```bash
# Download the script
wget https://your-repository/hardening.sh
# or
curl -O https://your-repository/hardening.sh

# Give execution permissions
chmod +x hardening.sh

# Run with root privileges
sudo ./hardening.sh [options]
