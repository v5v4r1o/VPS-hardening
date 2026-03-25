# 🛡️ Ubuntu VPS Hardening Script

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-E95420?style=flat-square&logo=ubuntu)
![Bash](https://img.shields.io/badge/Bash-4.0+-4EAA25?style=flat-square&logo=gnu-bash)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

Script modular de hardening automatizado para servidores Ubuntu 24.04 LTS, diseñado para securizar VPS y servidores dedicados mediante configuraciones de usuarios, SSH endurecido y firewall UFW con validaciones inteligentes de coherencia entre servicios.

---

## 📋 Tabla de Contenidos

- [Propósito](#propósito)
- [Características](#características)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Uso](#uso)
- [Opciones Disponibles](#opciones-disponibles)
- [Casos de Uso](#casos-de-uso)
- [Validaciones de Seguridad](#validaciones-de-seguridad)
- [Estructura del Script](#estructura-del-script)
- [Advertencias](#advertencias)

---

## 🎯 Propósito

Este script automatiza el proceso de **hardening básico** para servidores Ubuntu, implementando las mejores prácticas de seguridad esenciales para VPS recién provisionados:

- **Gestión de accesos**: Creación de usuarios administrativos con privilegios sudo
- **Autenticación segura**: Configuración SSH con autenticación por claves Ed25519 y deshabilitación de acceso root
- **Protección de red**: Configuración de firewall UFW con validación de puertos
- **Defensa activa**: Implementación de Fail2ban contra ataques de fuerza bruta
- **Mantenimiento**: Actualizaciones automáticas de seguridad

El script es **completamente modular**, permitiendo ejecutar solo las configuraciones necesarias sin afectar el resto del sistema.

---

## ✨ Características

### 🔐 Seguridad SSH
- Cambio de puerto SSH a rango dinámico (49152-65335)
- Deshabilitación de autenticación por contraseña (solo claves públicas)
- Bloqueo de acceso root vía SSH
- Generación automática de claves Ed25519 con passphrase
- Configuración de `AllowUsers` restrictiva
- Parámetros de conexión endurecidos (MaxAuthTries, ClientAliveInterval, etc.)

### 🛡️ Protección de Red
- Configuración UFW con políticas restrictivas por defecto
- Validación de coherencia entre puerto SSH y reglas de firewall
- **Detección inteligente**: Si cambias el puerto SSH sin reconfigurar el firewall, el script detecta el bloqueo potencial y pregunta si deseas añadir la regla automáticamente

### 👥 Gestión de Usuarios
- Creación de usuarios administrativos con grupo sudo
- Modificación de usuarios existentes
- Generación automática de par de claves SSH para el usuario
- Validación de contraseñas seguras (8+ caracteres, mayúsculas, minúsculas, números y símbolos)

### 🔄 Automatización
- Actualizaciones automáticas de seguridad (unattended-upgrades)
- Fail2ban con reglas preconfiguradas
- Bloqueo de cuenta root
- Backups automáticos de configuraciones originales

---

## 📦 Requisitos

- **Sistema**: Ubuntu 24.04 LTS (focal recomendado, puede funcionar en 22.04+)
- **Privilegios**: Acceso root o usuario con sudo
- **Dependencias**: `bash` 4.0+, conexión a internet (para instalación de paquetes)

### Paquetes Instalados Automáticamente
- `ufw` (Firewall)
- `fail2ban` (Protección contra bruteforce)
- `unattended-upgrades` (Actualizaciones automáticas)
- `openssh-server` (SSH)

---

## 🚀 Instalación

```bash
# Descargar el script
wget https://tu-repositorio/hardening.sh
# o
curl -O https://tu-repositorio/hardening.sh

# Dar permisos de ejecución
chmod +x hardening.sh

# Ejecutar con privilegios root
sudo ./hardening.sh [opciones]


