#!/bin/bash
# Script de hardening basico para servidores ubuntu 24.04
set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

# ==========================================
# NUEVAS FUNCIONES PARA VERIFICACION DE FIREWALL
# ==========================================

is_ufw_active() {
    if command -v ufw &> /dev/null; then
        if ufw status | grep -q "Status: active"; then
            return 0
        fi
    fi
    return 1
}

is_port_allowed_in_ufw() {
    local port="$1"
    if ufw status | grep -q "$port/tcp.*ALLOW"; then
        return 0
    fi
    return 1
}

# ==========================================
# FUNCION DE AYUDA / DOCUMENTACION
# ==========================================
show_help() {
    cat << 'EOF'
================================================================================
  SCRIPT DE HARDENING MODULAR PARA UBUNTU 24.04
================================================================================

DESCRIPCION:
  Script automatizado modular para securización de servidores Ubuntu 24.04.
  Permite ejecutar configuraciones independientes o combinadas con validación
  de coherencia entre puertos SSH y reglas de firewall.

SINTAXIS:
  sudo ./hardening.sh [opciones]

PARAMETROS:

  Gestión de Usuarios (Opcional):
    -u <usuario>       Crear nuevo usuario administrador
    -U <usuario>       Modificar usuario existente
    -s                 Saltar generación de claves SSH para el usuario
  
  Configuración SSH Global (Opcional):
    -P <puerto>        Puerto SSH (49152-65335) 
                       OBLIGATORIO si se configura SSH o Firewall
    -S                 Saltar configuración global de SSH
  
  Configuracion Firewall (Opcional):
    -f <puertos>       Puertos TCP adicionales (ej: 80,443)
    -F                 Saltar configuración del firewall

  General:
    -h                 Mostrar esta ayuda

REGLAS IMPORTANTES:

  1. CONSISTENCIA DE PUERTOS:
     - Si configura SSH global (-P sin -S): El puerto cambia y el firewall 
       se sincroniza automáticamente con ese puerto.
     - Si configura SOLO firewall (-P con -S): El puerto especificado DEBE 
       coincidir con el puerto actual de SSH, o se bloqueará el acceso.

  2. VALIDACIONES:
     - Debe especificarse al menos una acción: usuario, SSH global o Firewall
     - -P es obligatorio si se configura SSH global O Firewall (sin -S o -F)
     - No se puede usar -u y -U simultáneamente

CASOS DE USO:

  A. Hardening completo (Usuario + SSH + Firewall):
     sudo ./hardening.sh -u admin -P 52222 -f 80,443

  B. Solo configurar SSH global y Firewall (sin usuario):
     sudo ./hardening.sh -P 52222 -f 80,443
  
  C. Solo Firewall (SSH ya configurado manualmente en puerto 52222):
     sudo ./hardening.sh -P 52222 -S -f 80,443
     NOTA: El puerto 52222 debe ser el puerto REAL donde escucha SSH actualmente

  D. Cambiar puerto SSH global (sin Firewall):
     sudo ./hardening.sh -P 60000 -F

  E. Solo crear usuario (sin tocar red):
     sudo ./hardening.sh -u admin -s -S -F

ADVERTENCIA DE SEGURIDAD:
  Si configura el firewall (-F no usado) sin configurar SSH global (-S usado),
  el script verificará que el puerto especificado en -P coincida con el puerto
  real de SSH. Si no coinciden, el script fallará para evitar bloquear el acceso.
  
  Ejemplo de error:
    SSH actual está en puerto 22
    Ejecuta: sudo ./hardening.sh -P 52222 -S
    Resultado: ERROR porque firewall abriría 52222 pero SSH está en 22

AUTOR: v5v4r1o
VERSION: 2.2 (Validación de Firewall al cambiar SSH)
================================================================================
EOF
    exit 0
}

# ==========================================
# FUNCIONES DE VALIDACION
# ==========================================

validate_username() {
    local username="$1"
    
    if [[ -z "$username" ]]; then
        error "El nombre de usuario no puede estar vacío"
        return 1
    fi
    
    if [[ ${#username} -gt 32 ]]; then
        error "El nombre de usuario no puede tener más de 32 caracteres"
        return 1
    fi
    
    if [[ "$username" =~ ^[0-9] ]]; then
        error "El nombre de usuario no puede empezar con un número"
        return 1
    fi
    
    if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        error "El nombre de usuario solo puede contener letras minúsculas, números, guiones y guiones bajos"
        return 1
    fi
    
    if [[ "$username" == "root" ]]; then
        error "No se puede usar 'root' como nombre de usuario"
        return 1
    fi
    
    return 0
}

validate_password() {
    local password="$1"
    local name="$2"
    
    if [[ ${#password} -lt 8 ]]; then
        error "La $name debe tener al menos 8 caracteres"
        return 1
    fi
    
    if ! [[ "$password" =~ [A-Z] ]]; then
        error "La $name debe contener al menos una mayúscula"
        return 1
    fi
    
    if ! [[ "$password" =~ [a-z] ]]; then
        error "La $name debe contener al menos una minúscula"
        return 1
    fi
    
    if ! [[ "$password" =~ [0-9] ]]; then
        error "La $name debe contener al menos un número"
        return 1
    fi
    
    local special_chars="${password//[A-Za-z0-9[:space:]]/}"
    
    if [[ -z "$special_chars" ]]; then
        error "La $name debe contener al menos un símbolo especial"
        return 1
    fi
      
    return 0
}

validate_ssh_port() {
    local port="$1"
    
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        error "El puerto SSH debe ser un número"
        return 1
    fi
    
    if [[ "$port" -lt 49152 || "$port" -gt 65335 ]]; then
        error "El puerto SSH debe estar entre 49152 y 65335"
        return 1
    fi
    
    return 0
}

# ==========================================
# NUEVA FUNCION: Detectar puerto SSH actual
# ==========================================
get_current_ssh_port() {
    local current_port=""
    
    # Intentar leer del archivo de configuración actual
    if [[ -f /etc/ssh/sshd_config ]]; then
        current_port=$(grep -E "^\s*Port\s+[0-9]+" /etc/ssh/sshd_config | tail -1 | awk '{print $2}' || true)
    fi
    
    # Si no se encuentra, usar 22 (default)
    if [[ -z "$current_port" ]]; then
        current_port="22"
    fi
    
    echo "$current_port"
}

read_password() {
    local prompt_text="$1"
    local var_name="$2"
    local name="$3"
    local password=""
    local password_confirm=""

    echo ""
    info "CONFIGURACIÓN DE $name SEGURA"
    info "============================================="
    echo ""

    while true; do
        echo -n "$prompt_text: " >&2
        read -rs password
        echo "" >&2
        
        if [[ -z "$password" ]]; then
            error "La contraseña no puede estar vacía" >&2
            continue
        fi
        
        validate_password "$password" "$name" || continue
        
        echo -n "Confirma la contraseña: " >&2
        read -rs password_confirm
        echo "" >&2
        
        if [[ "$password" != "$password_confirm" ]]; then
            error "Las contraseñas no coinciden. Inténtalo de nuevo." >&2
            echo "" >&2
            continue
        fi
        
        printf -v "$var_name" '%s' "$password"
        break
    done
}

create_user_ssh_conf() {
    local USERNAME="$1"
    local SSH_KEY_PASSPHRASE="$2"
    local SSH_DIR="/home/$USERNAME/.ssh"
    
    mkdir -p "$SSH_DIR"

    log "Generando clave SSH Ed25519 para $USERNAME..."
    ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519" -N "$SSH_KEY_PASSPHRASE" -C "$USERNAME@$(hostname)"

    cp "$SSH_DIR/id_ed25519.pub" "$SSH_DIR/authorized_keys"

    chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chmod 600 "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/id_ed25519"
    chmod 644 "$SSH_DIR/id_ed25519.pub"

    log "Clave SSH generada correctamente en $SSH_DIR"
}

# ==========================================
# PARSEO DE ARGUMENTOS 
# ==========================================

ADMIN_USER=""
USER_PASS=""
SSH_KEY_PASS=""
SSH_PORT=""
EXTRA_PORTS=""
EXISTING_ADMIN_USER=""
SKIP_USER_SSH=0
SKIP_SSH_CONF=0
SKIP_FIREWALL_CONF=0

while getopts ":u:U:P:f:sSFh" opt; do
    case $opt in
        u) ADMIN_USER="$OPTARG" ;;
        U) EXISTING_ADMIN_USER="$OPTARG" ;;
        P) SSH_PORT="$OPTARG" ;;
        f) EXTRA_PORTS="$OPTARG" ;;
        s) SKIP_USER_SSH=1 ;;
        S) SKIP_SSH_CONF=1 ;;
        F) SKIP_FIREWALL_CONF=1 ;;
        h) show_help ;;
        \?) error "Opción inválida: -$OPTARG" >&2; show_help ;;
        :) error "La opción -$OPTARG requiere un argumento." >&2; show_help ;;
    esac
done

# ==========================================
# VALIDACIONES MODULARES CORREGIDAS
# ==========================================

# Verificar que haya al menos una acción a realizar
if [[ -z "$ADMIN_USER" && -z "$EXISTING_ADMIN_USER" && "$SKIP_SSH_CONF" -eq 1 && "$SKIP_FIREWALL_CONF" -eq 1 ]]; then
    error "Debe especificar al menos una acción: usuario, SSH global o Firewall"
    show_help
    exit 1
fi

# Validar usuarios solo si se proporcionaron
if [[ -n "$ADMIN_USER" && -n "$EXISTING_ADMIN_USER" ]]; then
    error "No puede usar -u y -U simultáneamente. Elija solo una opción."
    exit 1
fi

if [[ -n "$ADMIN_USER" ]]; then
    validate_username "$ADMIN_USER" || exit 1
fi

if [[ -n "$EXISTING_ADMIN_USER" ]]; then
    validate_username "$EXISTING_ADMIN_USER" || exit 1
    if ! id "$EXISTING_ADMIN_USER" &>/dev/null; then
        error "El usuario existente '$EXISTING_ADMIN_USER' no existe en el sistema"
        exit 1
    fi
fi

# Si se va a configurar SSH global O Firewall, se necesita el puerto SSH
if [[ "$SKIP_SSH_CONF" -eq 0 || "$SKIP_FIREWALL_CONF" -eq 0 ]]; then
    if [[ -z "$SSH_PORT" ]]; then
        error "El puerto SSH (-P) es obligatorio cuando se configura SSH global o Firewall"
        show_help
        exit 1
    fi
    validate_ssh_port "$SSH_PORT" || exit 1
fi

# ==========================================
# VALIDACION CRITICA: Coherencia de puertos
# ==========================================
# Si se configura Firewall pero NO se configura SSH global,
# el puerto especificado debe coincidir con el puerto SSH actual
if [[ "$SKIP_FIREWALL_CONF" -eq 0 && "$SKIP_SSH_CONF" -eq 1 ]]; then
    CURRENT_SSH_PORT=$(get_current_ssh_port)
    
    if [[ "$SSH_PORT" != "$CURRENT_SSH_PORT" ]]; then
        error "INCONSISTENCIA DE PUERTOS DETECTADA"
        error "Puerto especificado para firewall: $SSH_PORT"
        error "Puerto actual de SSH: $CURRENT_SSH_PORT"
        error ""
        error "Si configura el firewall sin reconfigurar SSH global,"
        error "el puerto especificado (-P) debe coincidir con el puerto"
        error "donde actualmente escucha el servicio SSH."
        error ""
        error "Opciones:"
        error "  1. Use el puerto actual de SSH: -P $CURRENT_SSH_PORT"
        error "  2. Elimine -S para reconfigurar SSH global también: -P $SSH_PORT"
        exit 1
    else
        log "Validación de puertos: Puerto $SSH_PORT coincide con configuración SSH actual"
    fi
fi

log "Iniciando hardening del servidor..."
[[ -n "$ADMIN_USER" ]] && log "Modo: Crear usuario: $ADMIN_USER"
[[ -n "$EXISTING_ADMIN_USER" ]] && log "Modo: Modificar usuario: $EXISTING_ADMIN_USER"
[[ "$SKIP_SSH_CONF" -eq 0 ]] && log "Configuración SSH global: Puerto $SSH_PORT"
[[ "$SKIP_FIREWALL_CONF" -eq 0 ]] && log "Configuración Firewall: Puerto SSH $SSH_PORT"

# ==========================================
# INSTALACION DE DEPENDENCIAS (Siempre)
# ==========================================

log "Actualizando sistema e instalando dependencias..."
apt-get update > /dev/null 2>&1 && apt-get upgrade -y > /dev/null 2>&1
apt-get install -y curl wget git ufw fail2ban unattended-upgrades apt-listchanges > /dev/null 2>&1

# ==========================================
# GESTION DE USUARIOS (Condicional)
# ==========================================

TARGET_USER=""
TARGET_SSH_DIR=""
USER_CREATED_OR_MODIFIED=0

if [[ -n "$ADMIN_USER" ]]; then
    TARGET_USER="$ADMIN_USER"
    USER_CREATED_OR_MODIFIED=1
    
    read_password "Introduce la contraseña para el nuevo usuario $ADMIN_USER (sudo)" "USER_PASS" "CONTRASEÑA DE USUARIO"

    if id "$ADMIN_USER" &>/dev/null; then
        warn "El usuario $ADMIN_USER ya existe. Actualizando contraseña y permisos..."
    else
        log "Creando usuario administrador: $ADMIN_USER"
        adduser --gecos "" --disabled-password "$ADMIN_USER"
    fi
    
    echo "$ADMIN_USER:$USER_PASS" | chpasswd
    usermod -aG sudo "$ADMIN_USER"
    TARGET_SSH_DIR="/home/$ADMIN_USER/.ssh"
    
    if [[ "$SKIP_USER_SSH" -eq 0 ]]; then
        log "Generando claves SSH para el usuario $ADMIN_USER..."
        read_password "Introduce la passphrase para la clave SSH privada" "SSH_KEY_PASS" "PASSPHRASE DE LA CLAVE SSH"
        create_user_ssh_conf "$ADMIN_USER" "$SSH_KEY_PASS"
    else
        log "Opción -s seleccionada. No se generarán claves SSH para el usuario"
    fi
fi

if [[ -n "$EXISTING_ADMIN_USER" ]]; then
    TARGET_USER="$EXISTING_ADMIN_USER"
    USER_CREATED_OR_MODIFIED=1
    
    log "Configurando usuario existente: $EXISTING_ADMIN_USER"
    
    read_password "Introduce la nueva contraseña para $EXISTING_ADMIN_USER (sudo)" "USER_PASS" "CONTRASEÑA DE USUARIO"
    echo "$EXISTING_ADMIN_USER:$USER_PASS" | chpasswd
    usermod -aG sudo "$EXISTING_ADMIN_USER"
    TARGET_SSH_DIR="/home/$EXISTING_ADMIN_USER/.ssh"
    
    if [[ "$SKIP_USER_SSH" -eq 0 ]]; then
        log "Generando nuevas claves SSH para el usuario $EXISTING_ADMIN_USER..."
        if [[ -f "$TARGET_SSH_DIR/id_ed25519" ]]; then
            backup_date=$(date +%F_%H%M%S)
            mv "$TARGET_SSH_DIR/id_ed25519" "$TARGET_SSH_DIR/id_ed25519.backup.$backup_date"
            mv "$TARGET_SSH_DIR/id_ed25519.pub" "$TARGET_SSH_DIR/id_ed25519.pub.backup.$backup_date"
            warn "Claves SSH anteriores respaldadas con extensión .backup.$backup_date"
        fi
        
        read_password "Introduce la passphrase para la nueva clave SSH" "SSH_KEY_PASS" "PASSPHRASE DE LA CLAVE SSH"
        create_user_ssh_conf "$EXISTING_ADMIN_USER" "$SSH_KEY_PASS"
    else
        log "Opción -s seleccionada. No se generarán nuevas claves SSH"
    fi
fi

# ==========================================
# CONFIGURACION SSH GLOBAL (Condicional)
# ==========================================

SSH_GLOBAL_CONFIGURED=0

if [[ "$SKIP_SSH_CONF" -eq 1 ]]; then
    log "Opción -S seleccionada. No se modificará la configuración global de SSH"
else
    log "Configurando SSH global seguro en puerto $SSH_PORT..."
    SSH_GLOBAL_CONFIGURED=1
    
    # ==========================================
    # NUEVA SECCION: Leer usuarios existentes ANTES del backup
    # ==========================================
    EXISTING_USERS=""
    if [[ -f /etc/ssh/sshd_config ]]; then
        EXISTING_USERS=$(grep -E "^\s*AllowUsers\s+" /etc/ssh/sshd_config | tail -1 | sed 's/AllowUsers//' | xargs 2>/dev/null || true)
        if [[ -n "$EXISTING_USERS" ]]; then
            info "Usuarios existentes detectados en AllowUsers: $EXISTING_USERS"
        fi
    fi
    
    # Hacer backup DESPUES de leer los usuarios existentes
    [[ -f /etc/ssh/sshd_config ]] && cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F)

    # ==========================================
    # MERGE DE USUARIOS: Nuevos + Existentes
    # ==========================================
    NEW_USERS=""
    
    # Recopilar usuarios nuevos especificados por parámetro
    if [[ -n "$ADMIN_USER" ]]; then
        NEW_USERS="$ADMIN_USER"
    fi
    if [[ -n "$EXISTING_ADMIN_USER" ]]; then
        NEW_USERS="$NEW_USERS $EXISTING_ADMIN_USER"
    fi
    NEW_USERS=$(echo "$NEW_USERS" | xargs)
    
    # Combinar con usuarios existentes y eliminar duplicados
    if [[ -n "$NEW_USERS" && -n "$EXISTING_USERS" ]]; then
        # Hay usuarios nuevos y existentes - hacer merge
        ALLOWED_USERS=$(echo "$NEW_USERS $EXISTING_USERS" | tr ' ' '\n' | sort -u | tr '\n' ' ' | xargs)
        log "Merge de usuarios completado. Usuarios permitidos: $ALLOWED_USERS"
    elif [[ -n "$NEW_USERS" ]]; then
        # Solo hay usuarios nuevos
        ALLOWED_USERS="$NEW_USERS"
        log "Configurando acceso SSH para usuarios: $ALLOWED_USERS"
    elif [[ -n "$EXISTING_USERS" ]]; then
        # Solo hay usuarios existentes (no se especificaron nuevos)
        ALLOWED_USERS="$EXISTING_USERS"
        log "Preservando usuarios SSH existentes: $ALLOWED_USERS"
    else
        # No hay ningún usuario
        ALLOWED_USERS=""
        warn "No se especificaron usuarios ni se encontraron AllowUsers existentes"
    fi

    # ==========================================
    # ESCRIBIR CONFIGURACION SSH
    # ==========================================
    cat > /etc/ssh/sshd_config <<EOF
# Configuración SSH Hardened
Port $SSH_PORT
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30

X11Forwarding no
PrintMotd no
PrintLastLog yes
AllowTcpForwarding yes
AllowAgentForwarding no
PermitTunnel no

Subsystem sftp /usr/lib/openssh/sftp-server

AllowUsers $ALLOWED_USERS
DenyUsers root
EOF

    SSH_SOCKET_FILE="/lib/systemd/system/ssh.socket"
    if [[ -f "$SSH_SOCKET_FILE" ]]; then
        cp "$SSH_SOCKET_FILE" "$SSH_SOCKET_FILE.backup.$(date +%F)"
        sed -Ei "s/^ListenStream=0\.0\.0\.0:[0-9]+$/ListenStream=0.0.0.0:$SSH_PORT/" "$SSH_SOCKET_FILE"
        sed -Ei "s/^ListenStream=\[::\]:[0-9]+$/ListenStream=\[::\]:$SSH_PORT/" "$SSH_SOCKET_FILE"
        systemctl daemon-reload
    fi

    log "Configurando Fail2ban..."
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

    systemctl restart fail2ban
    systemctl enable fail2ban

    log "Reiniciando servicio SSH..."
    systemctl restart ssh
    log "Servicio SSH reiniciado en puerto $SSH_PORT"
    
    # ==========================================
    # NUEVA SECCION: Verificacion de Firewall al cambiar SSH
    # ==========================================
    
    # Si solo configuramos SSH (no el firewall global), verificar si UFW está bloqueando el nuevo puerto
    if [[ "$SKIP_FIREWALL_CONF" -eq 1 ]]; then
        if is_ufw_active; then
            log "Detectado firewall UFW activo"
            
            if ! is_port_allowed_in_ufw "$SSH_PORT"; then
                echo ""
                warn "¡ATENCIÓN! El puerto SSH $SSH_PORT NO está permitido en el firewall UFW actual"
                warn "Esto puede bloquear su acceso al servidor inmediatamente"
                echo ""
                info "Puertos actualmente permitidos en UFW:"
                ufw status | grep "ALLOW" || true
                echo ""
                
                response=""
                while true; do
                    echo -n "¿Desea añadir automáticamente el puerto $SSH_PORT/tcp al firewall UFW? [S/n]: "
                    read -r response
                    
                    case "$response" in
                        [Ss]*|"")
                            log "Añadiendo regla UFW para puerto SSH $SSH_PORT..."
                            ufw allow "$SSH_PORT/tcp" comment 'SSH Access (auto-added)'
                            log "Regla añadida correctamente"
                            break
                            ;;
                        [Nn]*)
                            warn "No se añadirá la regla al firewall"
                            warn "ADVERTENCIA: Puede perder acceso SSH si el puerto $SSH_PORT está bloqueado"
                            echo ""
                            info "Estado actual del firewall:"
                            ufw status verbose
                            echo ""
                            info "Si necesita añadirlo manualmente más tarde, ejecute:"
                            info "  sudo ufw allow $SSH_PORT/tcp"
                            break
                            ;;
                        *)
                            error "Por favor responda 's' para sí o 'n' para no"
                            ;;
                    esac
                done
            else
                log "Puerto $SSH_PORT ya está permitido en el firewall UFW"
            fi
        else
            info "Firewall UFW no está activo, omitiendo verificación de puertos"
        fi
    fi
fi

# ==========================================
# CONFIGURACION FIREWALL (Condicional)
# ==========================================

FIREWALL_CONFIGURED=0

if [[ "$SKIP_FIREWALL_CONF" -eq 1 ]]; then
    log "Opción -F seleccionada. No se configurará el firewall"
else
    log "Configurando UFW..."
    FIREWALL_CONFIGURED=1
    
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming
    ufw default allow outgoing

    ufw allow "$SSH_PORT/tcp" comment 'SSH Access'
    log "Puerto SSH $SSH_PORT/tcp permitido en firewall"

    ALLOWED_PORTS=()
    if [[ -n "$EXTRA_PORTS" ]]; then
        IFS=',' read -ra PORTS <<< "$EXTRA_PORTS"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | xargs)
            if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
                if [[ "$port" -ne "$SSH_PORT" ]]; then
                    ufw allow "$port/tcp" comment "Custom port $port"
                    ALLOWED_PORTS+=("$port")
                    log "Puerto $port/tcp habilitado en firewall"
                else
                    warn "Puerto $port ignorado (ya está configurado como puerto SSH)"
                fi
            else
                error "Puerto inválido ignorado: $port"
            fi
        done
    fi

    ufw --force enable
    log "Firewall UFW habilitado"
fi

# ==========================================
# CONFIGURACIONES FINALES
# ==========================================

if [[ "$USER_CREATED_OR_MODIFIED" -eq 1 || "$SSH_GLOBAL_CONFIGURED" -eq 1 ]]; then
    log "Asegurando cuenta root..."
    passwd -l root
fi

log "Configurando actualizaciones automáticas de seguridad..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

systemctl restart unattended-upgrades
systemctl enable unattended-upgrades

# ==========================================
# RESUMEN FINAL
# ==========================================

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   HARDENING COMPLETADO               ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if [[ "$USER_CREATED_OR_MODIFIED" -eq 1 ]]; then
    info "CONFIGURACIÓN DE USUARIO:"
    echo -e "  ${YELLOW}Usuario:${NC} $TARGET_USER"
    echo -e "  ${YELLOW}Contraseña sudo:${NC} ${GREEN}$USER_PASS${NC}"
    
    if [[ "$SKIP_USER_SSH" -eq 0 && -f "$TARGET_SSH_DIR/id_ed25519" ]]; then
        echo -e "  ${YELLOW}Passphrase SSH:${NC} ${GREEN}$SSH_KEY_PASS${NC}"
        echo ""
        echo -e "${YELLOW}CLAVE PRIVADA SSH:${NC}"
        echo -e "${GREEN}-----BEGIN OPENSSH PRIVATE KEY-----${NC}"
        cat "$TARGET_SSH_DIR/id_ed25519"
        echo -e "${GREEN}------END OPENSSH PRIVATE KEY------${NC}"
        echo ""
        warn "INSTRUCCIONES:"
        echo "  1. Guarde la clave privada en su máquina local: ~/.ssh/id_ed25519"
        echo "  2. Permisos: chmod 600 ~/.ssh/id_ed25519"
        if [[ "$SSH_GLOBAL_CONFIGURED" -eq 1 ]]; then
            echo "  3. Conéctese: ssh -p $SSH_PORT -i ~/.ssh/id_ed25519 $TARGET_USER@<IP>"
        elif [[ "$FIREWALL_CONFIGURED" -eq 1 ]]; then
            echo "  3. Conéctese: ssh -p $SSH_PORT -i ~/.ssh/id_ed25519 $TARGET_USER@<IP>"
        fi
    fi
    echo ""
fi

if [[ "$SSH_GLOBAL_CONFIGURED" -eq 1 ]]; then
    info "CONFIGURACIÓN SSH GLOBAL:"
    echo -e "  ${YELLOW}Puerto SSH:${NC} $SSH_PORT"
    echo -e "  ${YELLOW}Autenticación:${NC} Solo claves públicas"
    echo -e "  ${YELLOW}Root login:${NC} Prohibido"
    
    if [[ -z "$ADMIN_USER" && -z "$EXISTING_ADMIN_USER" ]]; then
        echo ""
        warn "ADVERTENCIA: No se configuró AllowUsers porque no especificó usuario"
        warn "Edite /etc/ssh/sshd_config y agregue: AllowUsers su_usuario"
    fi
    echo ""
fi

if [[ "$FIREWALL_CONFIGURED" -eq 1 ]]; then
    info "CONFIGURACIÓN FIREWALL (UFW):"
    echo -e "  ${YELLOW}Puerto SSH permitido:${NC} $SSH_PORT/tcp"
    [[ ${#ALLOWED_PORTS[@]} -gt 0 ]] && echo -e "  ${YELLOW}Puertos adicionales:${NC} ${ALLOWED_PORTS[*]}"
    echo ""
    ufw status verbose
    echo ""
fi

info "CONFIGURACIÓN DEL SISTEMA:"
echo "  - Actualizaciones automáticas: Activadas (03:00 AM)"
echo "  - Cuenta root: Bloqueada"
echo ""

log "Hardening completado exitosamente."
