#!/bin/bash
# Basic hardening script for Ubuntu 24.04 servers
set -euo pipefail

# Colors
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
# NEW FUNCTIONS FOR FIREWALL VERIFICATION
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
# HELP / DOCUMENTATION FUNCTION
# ==========================================
show_help() {
    cat << 'EOF'
================================================================================
  MODULAR HARDENING SCRIPT FOR UBUNTU 24.04
================================================================================

DESCRIPTION:
  Automated modular script for securing Ubuntu 24.04 servers.
  Allows execution of independent or combined configurations with validation
  of consistency between SSH ports and firewall rules.

SYNTAX:
  sudo ./hardening.sh [options]

PARAMETERS:

  User Management (Optional):
    -u <user>          Create new administrator user
    -U <user>          Modify existing user
    -s                 Skip SSH key generation for the user
  
  Global SSH Configuration (Optional):
    -P <port>          SSH port (49152-65335) 
                       REQUIRED if configuring SSH or Firewall
    -S                 Skip global SSH configuration
  
  Firewall Configuration (Optional):
    -f <ports>         Additional TCP ports (e.g.: 80,443)
    -F                 Skip firewall configuration

  General:
    -h                 Show this help

IMPORTANT RULES:

  1. PORT CONSISTENCY:
     - If configuring global SSH (-P without -S): Port changes and firewall 
       automatically syncs with that port.
     - If configuring ONLY firewall (-P with -S): Specified port MUST 
       match the current SSH port, or access will be blocked.

  2. VALIDATIONS:
     - At least one action must be specified: user, global SSH, or Firewall
     - -P is required if configuring global SSH OR Firewall (without -S or -F)
     - Cannot use -u and -U simultaneously

USE CASES:

  A. Complete hardening (User + SSH + Firewall):
     sudo ./hardening.sh -u admin -P 52222 -f 80,443

  B. Only configure global SSH and Firewall (no user):
     sudo ./hardening.sh -P 52222 -f 80,443
  
  C. Only Firewall (SSH already manually configured on port 52222):
     sudo ./hardening.sh -P 52222 -S -f 80,443
     NOTE: Port 52222 must be the REAL port where SSH currently listens

  D. Change global SSH port (no Firewall):
     sudo ./hardening.sh -P 60000 -F

  E. Only create user (no network changes):
     sudo ./hardening.sh -u admin -s -S -F

SECURITY WARNING:
  If configuring firewall (-F not used) without configuring global SSH (-S used),
  the script will verify that the port specified in -P matches the real SSH port.
  If they don't match, the script will fail to prevent blocking access.
  
  Error example:
    Current SSH is on port 22
    Run: sudo ./hardening.sh -P 52222 -S
    Result: ERROR because firewall would open 52222 but SSH is on 22

AUTHOR: v5v4r1o
VERSION: 2.2 (Firewall Validation when changing SSH)
================================================================================
EOF
    exit 0
}

# ==========================================
# VALIDATION FUNCTIONS
# ==========================================

validate_username() {
    local username="$1"
    
    if [[ -z "$username" ]]; then
        error "Username cannot be empty"
        return 1
    fi
    
    if [[ ${#username} -gt 32 ]]; then
        error "Username cannot exceed 32 characters"
        return 1
    fi
    
    if [[ "$username" =~ ^[0-9] ]]; then
        error "Username cannot start with a number"
        return 1
    fi
    
    if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        error "Username can only contain lowercase letters, numbers, hyphens and underscores"
        return 1
    fi
    
    if [[ "$username" == "root" ]]; then
        error "Cannot use 'root' as username"
        return 1
    fi
    
    return 0
}

validate_password() {
    local password="$1"
    local name="$2"
    
    if [[ ${#password} -lt 8 ]]; then
        error "$name must be at least 8 characters"
        return 1
    fi
    
    if ! [[ "$password" =~ [A-Z] ]]; then
        error "$name must contain at least one uppercase letter"
        return 1
    fi
    
    if ! [[ "$password" =~ [a-z] ]]; then
        error "$name must contain at least one lowercase letter"
        return 1
    fi
    
    if ! [[ "$password" =~ [0-9] ]]; then
        error "$name must contain at least one number"
        return 1
    fi
    
    local special_chars="${password//[A-Za-z0-9[:space:]]/}"
    
    if [[ -z "$special_chars" ]]; then
        error "$name must contain at least one special character"
        return 1
    fi
      
    return 0
}

validate_ssh_port() {
    local port="$1"
    
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        error "SSH port must be a number"
        return 1
    fi
    
    if [[ "$port" -lt 49152 || "$port" -gt 65335 ]]; then
        error "SSH port must be between 49152 and 65335"
        return 1
    fi
    
    return 0
}

# ==========================================
# NEW FUNCTION: Detect current SSH port
# ==========================================
get_current_ssh_port() {
    local current_port=""
    
    # Try to read from current configuration file
    if [[ -f /etc/ssh/sshd_config ]]; then
        current_port=$(grep -E "^\s*Port\s+[0-9]+" /etc/ssh/sshd_config | tail -1 | awk '{print $2}' || true)
    fi
    
    # If not found, use 22 (default)
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
    info "SECURE $name CONFIGURATION"
    info "============================================="
    echo ""

    while true; do
        echo -n "$prompt_text: " >&2
        read -rs password
        echo "" >&2
        
        if [[ -z "$password" ]]; then
            error "Password cannot be empty" >&2
            continue
        fi
        
        validate_password "$password" "$name" || continue
        
        echo -n "Confirm password: " >&2
        read -rs password_confirm
        echo "" >&2
        
        if [[ "$password" != "$password_confirm" ]]; then
            error "Passwords do not match. Try again." >&2
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

    log "Generating Ed25519 SSH key for $USERNAME..."
    ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519" -N "$SSH_KEY_PASSPHRASE" -C "$USERNAME@$(hostname)"

    cp "$SSH_DIR/id_ed25519.pub" "$SSH_DIR/authorized_keys"

    chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chmod 600 "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/id_ed25519"
    chmod 644 "$SSH_DIR/id_ed25519.pub"

    log "SSH key generated successfully in $SSH_DIR"
}

# ==========================================
# ARGUMENT PARSING 
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
        \?) error "Invalid option: -$OPTARG" >&2; show_help ;;
        :) error "Option -$OPTARG requires an argument." >&2; show_help ;;
    esac
done

# ==========================================
# MODULAR VALIDATIONS
# ==========================================

# Verify at least one action is specified
if [[ -z "$ADMIN_USER" && -z "$EXISTING_ADMIN_USER" && "$SKIP_SSH_CONF" -eq 1 && "$SKIP_FIREWALL_CONF" -eq 1 ]]; then
    error "At least one action must be specified: user, global SSH, or Firewall"
    show_help
    exit 1
fi

# Validate users only if provided
if [[ -n "$ADMIN_USER" && -n "$EXISTING_ADMIN_USER" ]]; then
    error "Cannot use -u and -U simultaneously. Choose only one option."
    exit 1
fi

if [[ -n "$ADMIN_USER" ]]; then
    validate_username "$ADMIN_USER" || exit 1
fi

if [[ -n "$EXISTING_ADMIN_USER" ]]; then
    validate_username "$EXISTING_ADMIN_USER" || exit 1
    if ! id "$EXISTING_ADMIN_USER" &>/dev/null; then
        error "Existing user '$EXISTING_ADMIN_USER' does not exist in the system"
        exit 1
    fi
fi

# If global SSH OR Firewall will be configured, SSH port is needed
if [[ "$SKIP_SSH_CONF" -eq 0 || "$SKIP_FIREWALL_CONF" -eq 0 ]]; then
    if [[ -z "$SSH_PORT" ]]; then
        error "SSH port (-P) is required when configuring global SSH or Firewall"
        show_help
        exit 1
    fi
    validate_ssh_port "$SSH_PORT" || exit 1
fi

# ==========================================
# CRITICAL VALIDATION: Port Consistency
# ==========================================
# If configuring Firewall but NOT global SSH,
# specified port must match current SSH port
if [[ "$SKIP_FIREWALL_CONF" -eq 0 && "$SKIP_SSH_CONF" -eq 1 ]]; then
    CURRENT_SSH_PORT=$(get_current_ssh_port)
    
    if [[ "$SSH_PORT" != "$CURRENT_SSH_PORT" ]]; then
        error "PORT INCONSISTENCY DETECTED"
        error "Port specified for firewall: $SSH_PORT"
        error "Current SSH port: $CURRENT_SSH_PORT"
        error ""
        error "If configuring firewall without reconfiguring global SSH,"
        error "the specified port (-P) must match the port where SSH service"
        error "currently listens."
        error ""
        error "Options:"
        error "  1. Use current SSH port: -P $CURRENT_SSH_PORT"
        error "  2. Remove -S to also reconfigure global SSH: -P $SSH_PORT"
        exit 1
    else
        log "Port validation: Port $SSH_PORT matches current SSH configuration"
    fi
fi

log "Starting server hardening..."
[[ -n "$ADMIN_USER" ]] && log "Mode: Create user: $ADMIN_USER"
[[ -n "$EXISTING_ADMIN_USER" ]] && log "Mode: Modify user: $EXISTING_ADMIN_USER"
[[ "$SKIP_SSH_CONF" -eq 0 ]] && log "Global SSH configuration: Port $SSH_PORT"
[[ "$SKIP_FIREWALL_CONF" -eq 0 ]] && log "Firewall configuration: SSH Port $SSH_PORT"

# ==========================================
# DEPENDENCY INSTALLATION (Always)
# ==========================================

log "Updating system and installing dependencies..."
apt-get update > /dev/null 2>&1 && apt-get upgrade -y > /dev/null 2>&1
apt-get install -y curl wget git ufw fail2ban unattended-upgrades apt-listchanges > /dev/null 2>&1

# ==========================================
# USER MANAGEMENT (Conditional)
# ==========================================

TARGET_USER=""
TARGET_SSH_DIR=""
USER_CREATED_OR_MODIFIED=0

if [[ -n "$ADMIN_USER" ]]; then
    TARGET_USER="$ADMIN_USER"
    USER_CREATED_OR_MODIFIED=1
    
    read_password "Enter password for new user $ADMIN_USER (sudo)" "USER_PASS" "USER PASSWORD"

    if id "$ADMIN_USER" &>/dev/null; then
        warn "User $ADMIN_USER already exists. Updating password and permissions..."
    else
        log "Creating administrator user: $ADMIN_USER"
        adduser --gecos "" --disabled-password "$ADMIN_USER"
    fi
    
    echo "$ADMIN_USER:$USER_PASS" | chpasswd
    usermod -aG sudo "$ADMIN_USER"
    TARGET_SSH_DIR="/home/$ADMIN_USER/.ssh"
    
    if [[ "$SKIP_USER_SSH" -eq 0 ]]; then
        log "Generating SSH keys for user $ADMIN_USER..."
        read_password "Enter passphrase for private SSH key" "SSH_KEY_PASS" "SSH KEY PASSPHRASE"
        create_user_ssh_conf "$ADMIN_USER" "$SSH_KEY_PASS"
    else
        log "Option -s selected. SSH keys will not be generated for user"
    fi
fi

if [[ -n "$EXISTING_ADMIN_USER" ]]; then
    TARGET_USER="$EXISTING_ADMIN_USER"
    USER_CREATED_OR_MODIFIED=1
    
    log "Configuring existing user: $EXISTING_ADMIN_USER"
    
    read_password "Enter new password for $EXISTING_ADMIN_USER (sudo)" "USER_PASS" "USER PASSWORD"
    echo "$EXISTING_ADMIN_USER:$USER_PASS" | chpasswd
    usermod -aG sudo "$EXISTING_ADMIN_USER"
    TARGET_SSH_DIR="/home/$EXISTING_ADMIN_USER/.ssh"
    
    if [[ "$SKIP_USER_SSH" -eq 0 ]]; then
        log "Generating new SSH keys for user $EXISTING_ADMIN_USER..."
        if [[ -f "$TARGET_SSH_DIR/id_ed25519" ]]; then
            backup_date=$(date +%F_%H%M%S)
            mv "$TARGET_SSH_DIR/id_ed25519" "$TARGET_SSH_DIR/id_ed25519.backup.$backup_date"
            mv "$TARGET_SSH_DIR/id_ed25519.pub" "$TARGET_SSH_DIR/id_ed25519.pub.backup.$backup_date"
            warn "Previous SSH keys backed up with extension .backup.$backup_date"
        fi
        
        read_password "Enter passphrase for new SSH key" "SSH_KEY_PASS" "SSH KEY PASSPHRASE"
        create_user_ssh_conf "$EXISTING_ADMIN_USER" "$SSH_KEY_PASS"
    else
        log "Option -s selected. No new SSH keys will be generated"
    fi
fi

# ==========================================
# GLOBAL SSH CONFIGURATION (Conditional)
# ==========================================

SSH_GLOBAL_CONFIGURED=0

if [[ "$SKIP_SSH_CONF" -eq 1 ]]; then
    log "Option -S selected. Global SSH configuration will not be modified"
else
    log "Configuring secure global SSH on port $SSH_PORT..."
    SSH_GLOBAL_CONFIGURED=1
    
    [[ -f /etc/ssh/sshd_config ]] && cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F)

    ALLOW_USERS_LINE=""
    if [[ -n "$ADMIN_USER" || -n "$EXISTING_ADMIN_USER" ]]; then
        ALLOWED_USERS="$ADMIN_USER $EXISTING_ADMIN_USER"
        ALLOWED_USERS=$(echo "$ALLOWED_USERS" | xargs)
        ALLOW_USERS_LINE="AllowUsers $ALLOWED_USERS"
        log "Restricting SSH access to users: $ALLOWED_USERS"
    else
        warn "No users specified. AllowUsers will not be configured"
    fi

    cat > /etc/ssh/sshd_config <<EOF
# Hardened SSH Configuration
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

    log "Configuring Fail2ban..."
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

    log "Restarting SSH service..."
    systemctl restart ssh
    log "SSH service restarted on port $SSH_PORT"
    
    # ==========================================
    # NEW SECTION: Firewall Verification when changing SSH
    # ==========================================
    
    # If we only configured SSH (not global firewall), check if UFW is blocking the new port
    if [[ "$SKIP_FIREWALL_CONF" -eq 1 ]]; then
        if is_ufw_active; then
            log "Active UFW firewall detected"
            
            if ! is_port_allowed_in_ufw "$SSH_PORT"; then
                echo ""
                warn "WARNING! SSH port $SSH_PORT is NOT allowed in current UFW firewall"
                warn "This may immediately block your access to the server"
                echo ""
                info "Currently allowed ports in UFW:"
                ufw status | grep "ALLOW" || true
                echo ""
                
                response=""
                while true; do
                    echo -n "Do you want to automatically add port $SSH_PORT/tcp to UFW firewall? [Y/n]: "
                    read -r response
                    
                    case "$response" in
                        [Yy]*|"")
                            log "Adding UFW rule for SSH port $SSH_PORT..."
                            ufw allow "$SSH_PORT/tcp" comment 'SSH Access (auto-added)'
                            log "Rule added successfully"
                            break
                            ;;
                        [Nn]*)
                            warn "Rule will not be added to firewall"
                            warn "WARNING: You may lose SSH access if port $SSH_PORT is blocked"
                            echo ""
                            info "Current firewall status:"
                            ufw status verbose
                            echo ""
                            info "If you need to add it manually later, run:"
                            info "  sudo ufw allow $SSH_PORT/tcp"
                            break
                            ;;
                        *)
                            error "Please answer 'y' for yes or 'n' for no"
                            ;;
                    esac
                done
            else
                log "Port $SSH_PORT is already allowed in UFW firewall"
            fi
        else
            info "UFW firewall is not active, skipping port verification"
        fi
    fi
fi

# ==========================================
# FIREWALL CONFIGURATION (Conditional)
# ==========================================

FIREWALL_CONFIGURED=0

if [[ "$SKIP_FIREWALL_CONF" -eq 1 ]]; then
    log "Option -F selected. Firewall will not be configured"
else
    log "Configuring UFW..."
    FIREWALL_CONFIGURED=1
    
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming
    ufw default allow outgoing

    ufw allow "$SSH_PORT/tcp" comment 'SSH Access'
    log "SSH port $SSH_PORT/tcp allowed in firewall"

    ALLOWED_PORTS=()
    if [[ -n "$EXTRA_PORTS" ]]; then
        IFS=',' read -ra PORTS <<< "$EXTRA_PORTS"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | xargs)
            if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
                if [[ "$port" -ne "$SSH_PORT" ]]; then
                    ufw allow "$port/tcp" comment "Custom port $port"
                    ALLOWED_PORTS+=("$port")
                    log "Port $port/tcp enabled in firewall"
                else
                    warn "Port $port ignored (already configured as SSH port)"
                fi
            else
                error "Invalid port ignored: $port"
            fi
        done
    fi

    ufw --force enable
    log "UFW firewall enabled"
fi

# ==========================================
# FINAL CONFIGURATIONS
# ==========================================

if [[ "$USER_CREATED_OR_MODIFIED" -eq 1 || "$SSH_GLOBAL_CONFIGURED" -eq 1 ]]; then
    log "Securing root account..."
    passwd -l root
fi

log "Configuring automatic security updates..."
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
# FINAL SUMMARY
# ==========================================

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   HARDENING COMPLETED                ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if [[ "$USER_CREATED_OR_MODIFIED" -eq 1 ]]; then
    info "USER CONFIGURATION:"
    echo -e "  ${YELLOW}User:${NC} $TARGET_USER"
    echo -e "  ${YELLOW}Sudo password:${NC} ${GREEN}$USER_PASS${NC}"
    
    if [[ "$SKIP_USER_SSH" -eq 0 && -f "$TARGET_SSH_DIR/id_ed25519" ]]; then
        echo -e "  ${YELLOW}SSH Passphrase:${NC} ${GREEN}$SSH_KEY_PASS${NC}"
        echo ""
        echo -e "${YELLOW}SSH PRIVATE KEY:${NC}"
        echo -e "${GREEN}-----BEGIN OPENSSH PRIVATE KEY-----${NC}"
        cat "$TARGET_SSH_DIR/id_ed25519"
        echo -e "${GREEN}------END OPENSSH PRIVATE KEY------${NC}"
        echo ""
        warn "INSTRUCTIONS:"
        echo "  1. Save the private key on your local machine: ~/.ssh/id_ed25519"
        echo "  2. Set permissions: chmod 600 ~/.ssh/id_ed25519"
        if [[ "$SSH_GLOBAL_CONFIGURED" -eq 1 ]]; then
            echo "  3. Connect: ssh -p $SSH_PORT -i ~/.ssh/id_ed25519 $TARGET_USER@<IP>"
        elif [[ "$FIREWALL_CONFIGURED" -eq 1 ]]; then
            echo "  3. Connect: ssh -p $SSH_PORT -i ~/.ssh/id_ed25519 $TARGET_USER@<IP>"
        fi
    fi
    echo ""
fi

if [[ "$SSH_GLOBAL_CONFIGURED" -eq 1 ]]; then
    info "GLOBAL SSH CONFIGURATION:"
    echo -e "  ${YELLOW}SSH Port:${NC} $SSH_PORT"
    echo -e "  ${YELLOW}Authentication:${NC} Public keys only"
    echo -e "  ${YELLOW}Root login:${NC} Prohibited"
    
    if [[ -z "$ADMIN_USER" && -z "$EXISTING_ADMIN_USER" ]]; then
        echo ""
        warn "WARNING: AllowUsers was not configured because no user was specified"
        warn "Edit /etc/ssh/sshd_config and add: AllowUsers your_user"
    fi
    echo ""
fi

if [[ "$FIREWALL_CONFIGURED" -eq 1 ]]; then
    info "FIREWALL CONFIGURATION (UFW):"
    echo -e "  ${YELLOW}Allowed SSH port:${NC} $SSH_PORT/tcp"
    [[ ${#ALLOWED_PORTS[@]} -gt 0 ]] && echo -e "  ${YELLOW}Additional ports:${NC} ${ALLOWED_PORTS[*]}"
    echo ""
    ufw status verbose
    echo ""
fi

info "SYSTEM CONFIGURATION:"
echo "  - Automatic updates: Enabled (03:00 AM)"
echo "  - Root account: Locked"
echo ""

log "Hardening completed successfully."
