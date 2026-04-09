#!/usr/bin/env bash
# =============================================================================
#  linux-hardening.sh — Audit & Hardening Interactif Linux (FR)
#  Version : 3.0.0
#
#  Sources agrégées :
#    · CIS Benchmarks (Level 1 & 2)
#    · ANSSI R41+ (Configuration d'un système GNU/Linux)
#    · dev-sec/linux-baseline (os-hardening)
#    · Wazuh hardening script
#    · captainzero93/security_harden_linux
#    · trimstray/the-practical-linux-hardening-guide
#    · DISA STIG Ubuntu/RHEL
#
#  Compatibilité : Debian · Ubuntu · RHEL/CentOS/AlmaLinux/Rocky
#                  Fedora · openSUSE/SLES · Arch/Manjaro
#
#  Usage :
#    sudo bash linux-hardening.sh            # Mode interactif (défaut)
#    sudo bash linux-hardening.sh --audit    # Audit seul, aucune modification
#    sudo bash linux-hardening.sh --dry-run  # Simule les actions sans les appliquer
# =============================================================================

set -uo pipefail

# ─── Arguments ────────────────────────────────────────────────────────────────
AUDIT_ONLY=false
DRY_RUN=false
for arg in "$@"; do
    case "$arg" in
        --audit)   AUDIT_ONLY=true ;;
        --dry-run) DRY_RUN=true ;;
    esac
done

# ─── Couleurs ─────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
    BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
    RED=''; ORANGE=''; GREEN=''; CYAN=''; BLUE=''; MAGENTA=''
    BOLD=''; DIM=''; RESET=''
fi

# ─── Log ──────────────────────────────────────────────────────────────────────
LOG_FILE="/var/log/linux-hardening-$(date +%Y%m%d_%H%M%S).log"
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/linux-hardening-$(date +%Y%m%d_%H%M%S).log"

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }
_exec() {
    log "EXEC: $*"
    if [ "$DRY_RUN" = true ]; then
        echo -e "  ${DIM}[DRY-RUN] $*${RESET}"
    else
        eval "$@" >> "$LOG_FILE" 2>&1 || true
    fi
}

# ─── Compteurs ────────────────────────────────────────────────────────────────
APPLIED=0; SKIPPED=0; ERRORS=0
AUDIT_PASS=0; AUDIT_FAIL=0; AUDIT_WARN=0

# ─── UI helpers ───────────────────────────────────────────────────────────────
banner() {
    clear
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║       🛡️   Linux Hardening — Audit & Configuration Interactif        ║"
    echo "║      CIS · ANSSI R41+ · dev-sec · Wazuh · DISA STIG · trimstray     ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    [ "$DRY_RUN" = true ]    && echo -e "  ${ORANGE}[MODE DRY-RUN] Aucune modification ne sera effectuée.${RESET}\n"
    [ "$AUDIT_ONLY" = true ] && echo -e "  ${CYAN}[MODE AUDIT] Lecture seule.${RESET}\n"
}

section() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━  $1  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    log "=== SECTION: $1 ==="
}

info()    { echo -e "  ${CYAN}ℹ${RESET}  $*";            log "INFO: $*"; }
ok()      { echo -e "  ${GREEN}✔${RESET}  $*";            log "OK: $*"; }
warn()    { echo -e "  ${ORANGE}⚠${RESET}  $*";           log "WARN: $*"; }
applied() { echo -e "  ${GREEN}✔ Appliqué :${RESET} $*";  log "APPLIED: $*"; APPLIED=$((APPLIED+1)); }
skipped() { echo -e "  ${DIM}↷ Ignoré   : $*${RESET}";   log "SKIPPED: $*"; SKIPPED=$((SKIPPED+1)); }
dim()     { echo -e "  ${DIM}$*${RESET}"; }

audit_ok()   { echo -e "  ${GREEN}[AUDIT ✔]${RESET}  $*"; AUDIT_PASS=$((AUDIT_PASS+1));  log "AUDIT_PASS: $*"; }
audit_fail() { echo -e "  ${RED}[AUDIT ✖]${RESET}  $*";   AUDIT_FAIL=$((AUDIT_FAIL+1));  log "AUDIT_FAIL: $*"; }
audit_warn() { echo -e "  ${ORANGE}[AUDIT ⚠]${RESET}  $*"; AUDIT_WARN=$((AUDIT_WARN+1)); log "AUDIT_WARN: $*"; }

risk() {
    local level="$1"; shift
    case "$level" in
        low)    echo -e "  ${GREEN}  ╰─ Risque FAIBLE${RESET}  — $*" ;;
        medium) echo -e "  ${ORANGE}  ╰─ Risque MOYEN${RESET}  — $*" ;;
        high)   echo -e "  ${RED}  ╰─ Risque ÉLEVÉ${RESET}  — $*" ;;
    esac
}

ask() {
    local prompt="$1" default="${2:-n}"
    if [ "$AUDIT_ONLY" = true ]; then return 1; fi
    local hint
    [ "$default" = "y" ] && hint="${GREEN}[O${RESET}/n]" || hint="[o/${GREEN}N${RESET}]"
    echo ""
    printf "  ${BOLD}%s %b ${RESET}" "$prompt" "$hint"
    read -r answer </dev/tty
    answer="${answer:-$default}"
    case "$answer" in [oOyY]*) return 0 ;; *) return 1 ;; esac
}

# ─── Détection distrib ────────────────────────────────────────────────────────
detect_distro() {
    DISTRO="unknown"; PKG_MANAGER="unknown"; PKG_INSTALL="echo SKIP_INSTALL"
    DISTRO_NAME="Unknown"; DISTRO_VERSION="?"
    IS_DEBIAN=false; IS_RHEL=false; IS_SUSE=false; IS_ARCH=false

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="${ID:-unknown}"; DISTRO_LIKE="${ID_LIKE:-}"
        DISTRO_NAME="${NAME:-$DISTRO}"; DISTRO_VERSION="${VERSION_ID:-?}"
    fi

    _set_pkg() {
        case "$1" in
            apt)    PKG_MANAGER="apt";    PKG_INSTALL="apt-get install -y -qq"; IS_DEBIAN=true ;;
            dnf)    PKG_MANAGER="dnf";    PKG_INSTALL="dnf install -y -q";     IS_RHEL=true ;;
            yum)    PKG_MANAGER="yum";    PKG_INSTALL="yum install -y -q";     IS_RHEL=true ;;
            zypper) PKG_MANAGER="zypper"; PKG_INSTALL="zypper install -y -q";  IS_SUSE=true ;;
            pacman) PKG_MANAGER="pacman"; PKG_INSTALL="pacman -S --noconfirm"; IS_ARCH=true ;;
        esac
    }

    case "$DISTRO" in
        debian|ubuntu|linuxmint|kali|pop|raspbian) _set_pkg apt ;;
        rhel|centos|almalinux|rocky|ol|scientific)
            command -v dnf &>/dev/null && _set_pkg dnf || _set_pkg yum ;;
        fedora) _set_pkg dnf ;;
        opensuse*|sles) _set_pkg zypper ;;
        arch|manjaro|endeavouros|garuda) _set_pkg pacman ;;
        *)
            case "$DISTRO_LIKE" in
                *debian*|*ubuntu*) _set_pkg apt ;;
                *rhel*|*fedora*)
                    command -v dnf &>/dev/null && _set_pkg dnf || _set_pkg yum ;;
                *suse*) _set_pkg zypper ;;
                *arch*)  _set_pkg pacman ;;
                *) warn "Distribution non reconnue ($DISTRO). Certaines actions ignorées." ;;
            esac ;;
    esac
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "\n${RED}${BOLD}ERREUR : Ce script doit être exécuté en root (sudo).${RESET}\n"
        exit 1
    fi
}

backup_file() {
    local file="$1"
    if [ -f "$file" ] && [ ! -f "${file}.harden.bak" ]; then
        cp "$file" "${file}.harden.bak"
        log "BACKUP: $file"
    fi
}

set_config() {
    local key="$1" value="$2" file="$3"
    backup_file "$file"
    if grep -Eq "^\s*#?\s*${key}\s*[= ]" "$file" 2>/dev/null; then
        _exec "sed -i 's|^\s*#\?.*${key}\s*[= ].*|${key} = ${value}|' \"$file\""
    else
        _exec "echo '${key} = ${value}' >> \"$file\""
    fi
}

set_login_def() {
    local key="$1" value="$2" file="/etc/login.defs"
    backup_file "$file"
    if grep -Eq "^\s*#?\s*${key}\b" "$file" 2>/dev/null; then
        _exec "sed -i 's|^\s*#\?.*${key}.*|${key} ${value}|' \"$file\""
    else
        _exec "echo '${key} ${value}' >> \"$file\""
    fi
}

set_sshd() {
    local key="$1" value="$2" file="/etc/ssh/sshd_config"
    backup_file "$file"
    if grep -Eq "^\s*#?\s*${key}\b" "$file" 2>/dev/null; then
        _exec "sed -i 's|^\s*#\?\s*${key}.*|${key} ${value}|' \"$file\""
    else
        _exec "echo '${key} ${value}' >> \"$file\""
    fi
}

sshd_restart() {
    _exec "systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true"
}

sysctl_set() {
    # Écrit un paramètre sysctl dans le fichier de config et l'applique live
    local setting="$1" cfg="$2"
    local key="${setting%%=*}"
    if [ "$DRY_RUN" = false ]; then
        grep -q "^${key}" "$cfg" 2>/dev/null \
            && sed -i "s|^${key}.*|$setting|" "$cfg" \
            || echo "$setting" >> "$cfg"
    else
        echo -e "  ${DIM}[DRY-RUN] $setting >> $cfg${RESET}"
    fi
}

# =============================================================================
#  PHASE 1 : AUDIT
# =============================================================================
run_audit() {
    section "AUDIT — État de sécurité actuel"
    echo ""
    info "Système   : $DISTRO_NAME $DISTRO_VERSION ($(uname -m))"
    info "Kernel    : $(uname -r)"
    info "Hostname  : $(hostname -f 2>/dev/null || hostname)"
    info "Uptime    : $(uptime -p 2>/dev/null || uptime)"
    info "Log       : $LOG_FILE"
    echo ""

    # ── SSH ──────────────────────────────────────────────────────────────────
    echo -e "  ${BOLD}── SSH ────────────────────────────────────────────────────${RESET}"
    local sshd_cfg="/etc/ssh/sshd_config"
    if [ -f "$sshd_cfg" ]; then
        _chk_sshd() {
            local key="$1" good="$2" label="$3" fallback="$4"
            local val
            val=$(grep -Ei "^\s*${key}\b" "$sshd_cfg" | awk '{print $2}' | tail -1)
            val="${val:-$fallback}"
            [ "${val,,}" = "${good,,}" ] \
                && audit_ok   "$label : $val" \
                || audit_fail "$label : $val (recommandé: $good)"
        }
        _chk_sshd "PermitRootLogin"    "no"  "PermitRootLogin"    "yes (défaut)"
        _chk_sshd "X11Forwarding"      "no"  "X11Forwarding"      "yes (défaut)"
        _chk_sshd "AllowTcpForwarding" "no"  "AllowTcpForwarding" "yes (défaut)"

        local pass_auth
        pass_auth=$(grep -Ei '^\s*PasswordAuthentication' "$sshd_cfg" | awk '{print $2}' | tail -1)
        pass_auth="${pass_auth:-yes (défaut)}"
        [ "${pass_auth,,}" = "no" ] \
            && audit_ok  "PasswordAuthentication : no (clé uniquement)" \
            || audit_warn "PasswordAuthentication : $pass_auth (acceptable avec mdp+2FA)"

        local maxtries
        maxtries=$(grep -Ei '^\s*MaxAuthTries' "$sshd_cfg" | awk '{print $2}' | tail -1)
        maxtries="${maxtries:-6}"
        [ "${maxtries}" -le 4 ] 2>/dev/null \
            && audit_ok   "MaxAuthTries : $maxtries" \
            || audit_warn "MaxAuthTries : $maxtries (recommandé ≤ 4)"

        [ -s /etc/issue.net ] \
            && audit_ok  "Bannière SSH : présente" \
            || audit_warn "Bannière SSH : absente"
    else
        audit_warn "sshd_config introuvable"
    fi

    # ── Mots de passe ────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Mots de passe ─────────────────────────────────────────${RESET}"
    if [ -f /etc/login.defs ]; then
        local maxdays mindays warnage
        maxdays=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')
        mindays=$(grep -E '^\s*PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}')
        warnage=$(grep -E '^\s*PASS_WARN_AGE' /etc/login.defs | awk '{print $2}')
        maxdays="${maxdays:-99999}"; mindays="${mindays:-0}"; warnage="${warnage:-7}"
        [ "${maxdays}" -le 90 ] 2>/dev/null \
            && audit_ok   "PASS_MAX_DAYS : $maxdays j" \
            || audit_fail "PASS_MAX_DAYS : $maxdays (recommandé ≤ 90)"
        [ "${mindays}" -ge 1 ] 2>/dev/null \
            && audit_ok   "PASS_MIN_DAYS : $mindays j" \
            || audit_warn "PASS_MIN_DAYS : $mindays (recommandé ≥ 1)"
    fi
    if [ -f /etc/security/pwquality.conf ]; then
        local minlen minclass
        minlen=$(grep -E '^\s*minlen' /etc/security/pwquality.conf | awk -F'=' '{print $2}' | tr -d ' ')
        minclass=$(grep -E '^\s*minclass' /etc/security/pwquality.conf | awk -F'=' '{print $2}' | tr -d ' ')
        minlen="${minlen:-8}"; minclass="${minclass:-0}"
        [ "${minlen}" -ge 14 ] 2>/dev/null \
            && audit_ok   "pwquality minlen : $minlen" \
            || audit_fail "pwquality minlen : $minlen (CIS recommande ≥ 14)"
        [ "${minclass}" -ge 3 ] 2>/dev/null \
            && audit_ok   "pwquality minclass : $minclass" \
            || audit_warn "pwquality minclass : $minclass (recommandé ≥ 3)"
    else
        audit_warn "pwquality.conf absent"
    fi

    # Algorithme de hashage
    local hash_algo
    hash_algo=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}')
    hash_algo="${hash_algo:-DES/MD5 (défaut)}"
    case "${hash_algo^^}" in
        SHA512|YESCRYPT) audit_ok  "Hashage mots de passe : $hash_algo" ;;
        *)               audit_fail "Hashage mots de passe : $hash_algo (recommandé: SHA512 ou YESCRYPT)" ;;
    esac

    # ── Kernel / sysctl ──────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Kernel (sysctl) ───────────────────────────────────────${RESET}"
    _sc() {
        local key="$1" expected="$2" label="$3"
        local val; val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        [ "$val" = "$expected" ] \
            && audit_ok   "$label ($key=$val)" \
            || audit_fail "$label ($key=$val, attendu: $expected)"
    }
    _sc "kernel.randomize_va_space"              "2" "ASLR"
    _sc "net.ipv4.conf.all.accept_redirects"     "0" "ICMP redirects désactivés"
    _sc "net.ipv4.conf.all.send_redirects"       "0" "Envoi redirects désactivé"
    _sc "net.ipv4.conf.all.rp_filter"            "1" "Reverse path filtering"
    _sc "net.ipv4.conf.all.log_martians"         "1" "Log paquets Martians"
    _sc "net.ipv4.tcp_syncookies"                "1" "TCP SYN cookies"
    _sc "kernel.dmesg_restrict"                  "1" "dmesg restreint"
    _sc "kernel.kptr_restrict"                   "2" "Pointeurs kernel masqués"
    _sc "kernel.yama.ptrace_scope"               "1" "ptrace limité"
    _sc "fs.protected_hardlinks"                 "1" "Hardlinks protégés"
    _sc "fs.protected_symlinks"                  "1" "Symlinks protégés"
    _sc "fs.suid_dumpable"                       "0" "SUID core dumps désactivés"
    _sc "kernel.sysrq"                           "0" "Magic SysRq désactivé"
    _sc "kernel.unprivileged_bpf_disabled"       "1" "BPF non-privilégié désactivé"

    # ── Services dangereux ───────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Services ──────────────────────────────────────────────${RESET}"
    local had_dangerous=false
    for svc in avahi-daemon cups telnet rsh rlogin rexec tftp vsftpd; do
        if systemctl is-active "$svc" &>/dev/null 2>&1; then
            audit_fail "Service actif dangereux : $svc"; had_dangerous=true
        fi
    done
    $had_dangerous || audit_ok "Aucun service dangereux actif"
    systemctl is-active auditd &>/dev/null \
        && audit_ok  "auditd : actif" \
        || audit_fail "auditd : inactif"
    { command -v fail2ban-client &>/dev/null && systemctl is-active fail2ban &>/dev/null; } \
        && audit_ok  "fail2ban : actif" \
        || audit_warn "fail2ban : absent ou inactif"

    # ── Pare-feu ─────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Pare-feu ──────────────────────────────────────────────${RESET}"
    local fw_found=false
    { command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; } \
        && { audit_ok "UFW actif"; fw_found=true; }
    systemctl is-active firewalld &>/dev/null \
        && { audit_ok "firewalld actif"; fw_found=true; }
    $fw_found || audit_fail "Aucun pare-feu actif"

    # ── Montages ─────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Montages · Cron · Sudo · Session ─────────────────────${RESET}"
    mount | grep '/dev/shm' | grep -q 'noexec' \
        && audit_ok   "/dev/shm : noexec" \
        || audit_fail "/dev/shm : noexec manquant"
    mount | grep '[[:space:]]/tmp[[:space:]]' | grep -q 'noexec' \
        && audit_ok   "/tmp : noexec" \
        || audit_warn "/tmp : noexec absent"

    # /proc hidepid
    mount | grep '[[:space:]]/proc[[:space:]]' | grep -qE 'hidepid=[12]' \
        && audit_ok   "/proc : hidepid activé" \
        || audit_warn "/proc : hidepid absent (utilisateurs voient les process des autres)"

    # Cron
    for f in /etc/crontab /etc/cron.d; do
        if [ -e "$f" ]; then
            local perms; perms=$(stat -c '%a' "$f" 2>/dev/null)
            case "$perms" in
                600|700) audit_ok "$f : permissions $perms" ;;
                *)       audit_warn "$f : permissions $perms (recommandé 600/700)" ;;
            esac
        fi
    done

    # Sudo
    grep -Eq '^\s*Defaults.*logfile=' /etc/sudoers 2>/dev/null \
        && audit_ok  "sudo : log file configuré" \
        || audit_warn "sudo : log file absent"

    # TMOUT
    grep -rq 'TMOUT' /etc/profile /etc/profile.d/ 2>/dev/null \
        && audit_ok  "TMOUT : configuré" \
        || audit_warn "TMOUT : absent"

    # Umask
    local umask_val
    umask_val=$(grep -E '^\s*UMASK' /etc/login.defs 2>/dev/null | awk '{print $2}')
    umask_val="${umask_val:-022 (défaut)}"
    case "$umask_val" in
        027|077) audit_ok  "Umask login.defs : $umask_val" ;;
        *)       audit_warn "Umask login.defs : $umask_val (recommandé: 027)" ;;
    esac

    # Core dumps
    echo ""
    echo -e "  ${BOLD}── Core dumps ────────────────────────────────────────────${RESET}"
    grep -rEq '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null \
        && audit_ok  "Core dumps désactivés (limits.conf)" \
        || audit_warn "Core dumps non restreints"

    # ── Comptes sans mot de passe ─────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Comptes ───────────────────────────────────────────────${RESET}"
    local empty_pass
    empty_pass=$(awk -F: '($2 == "" || $2 == "!!" ) && $3 >= 1000 {print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
    [ -z "$empty_pass" ] \
        && audit_ok  "Aucun compte utilisateur sans mot de passe" \
        || audit_fail "Comptes sans mot de passe : $empty_pass"

    # ── Résumé ───────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}━━━  Résumé de l'audit  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${GREEN}✔ Conformes      : $AUDIT_PASS${RESET}"
    echo -e "  ${RED}✖ Non conformes  : $AUDIT_FAIL${RESET}"
    echo -e "  ${ORANGE}⚠ Avertissements : $AUDIT_WARN${RESET}"
    echo ""
    log "AUDIT SUMMARY: PASS=$AUDIT_PASS FAIL=$AUDIT_FAIL WARN=$AUDIT_WARN"
}

# =============================================================================
#  PHASE 2 : HARDENING — 22 SECTIONS
# =============================================================================

# ─── 1. SSH ───────────────────────────────────────────────────────────────────
harden_ssh() {
    section "1/22 · SSH"
    [ ! -f /etc/ssh/sshd_config ] && info "SSH non installé — section ignorée." && return

    info "Connexion root directe via SSH."
    risk high "Un attaquant n'aurait besoin que du mot de passe root, sans compte intermédiaire."
    if ask "Désactiver PermitRootLogin ?" n; then
        set_sshd "PermitRootLogin" "no"; applied "PermitRootLogin no"
    else skipped "PermitRootLogin"; fi

    info "Nombre maximum de tentatives d'auth SSH par session."
    risk medium "3 tentatives réduisent l'efficacité du brute-force même sans fail2ban."
    if ask "Fixer MaxAuthTries à 3 ?" y; then
        set_sshd "MaxAuthTries" "3"; applied "MaxAuthTries 3"
    else skipped "MaxAuthTries"; fi

    info "Délai pour s'authentifier après connexion TCP."
    risk low "30s est largement suffisant — une valeur haute laisse des connexions pendantes."
    if ask "Fixer LoginGraceTime à 30s ?" y; then
        set_sshd "LoginGraceTime" "30"; applied "LoginGraceTime 30"
    else skipped "LoginGraceTime"; fi

    info "Transfert de session graphique X11 via SSH."
    risk medium "Peut permettre à un serveur compromis d'injecter des frappes dans votre session locale."
    if ask "Désactiver X11Forwarding ?" y; then
        set_sshd "X11Forwarding" "no"; applied "X11Forwarding no"
    else skipped "X11Forwarding"; fi

    info "Tunneling TCP arbitraire via SSH."
    risk medium "Permet de contourner des règles pare-feu en encapsulant du trafic dans SSH."
    if ask "Désactiver AllowTcpForwarding ?" y; then
        set_sshd "AllowTcpForwarding" "no"; applied "AllowTcpForwarding no"
    else skipped "AllowTcpForwarding"; fi

    info "Déconnexion des sessions SSH inactives."
    risk low "Les sessions abandonnées sont une surface d'attaque en cas d'accès physique ou de pivoting."
    if ask "Déconnecter après 15 min d'inactivité SSH ?" y; then
        set_sshd "ClientAliveInterval" "300"
        set_sshd "ClientAliveCountMax" "3"
        applied "ClientAliveInterval=300 / ClientAliveCountMax=3 (15 min)"
    else skipped "ClientAliveInterval"; fi

    info "Suites cryptographiques SSH — éliminer les algorithmes obsolètes."
    risk medium "3DES, arcfour, blowfish sont vulnérables. On impose AES-GCM, ChaCha20, curve25519."
    if ask "Forcer Ciphers/MACs/KexAlgorithms modernes ?" y; then
        set_sshd "Ciphers"       "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
        set_sshd "MACs"          "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
        set_sshd "KexAlgorithms" "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
        applied "Ciphers/MACs/KexAlgorithms modernes"
    else skipped "Ciphers SSH"; fi

    info "Bannière légale à chaque connexion SSH."
    risk low "Valeur juridique lors d'audits ou d'incidents. Requis par CIS et ANSSI."
    if ask "Configurer une bannière légale (/etc/issue.net) ?" y; then
        _exec "printf 'Authorized users only. All activity is monitored and logged.\n' > /etc/issue.net"
        set_sshd "Banner" "/etc/issue.net"
        applied "Bannière SSH configurée"
    else skipped "Bannière SSH"; fi

    echo ""
    warn "PasswordAuthentication NON modifié — à ajuster manuellement selon votre setup (clé / mdp+2FA)."
    sshd_restart && info "sshd rechargé."
}

# ─── 2. Mots de passe ────────────────────────────────────────────────────────
harden_passwords() {
    section "2/22 · Politique de mots de passe"

    info "Complexité des mots de passe (libpam-pwquality)."
    risk high "Sans contrainte, les utilisateurs peuvent définir 'password1'. CIS impose minlen=14, 4 classes de caractères."
    if ask "Configurer pwquality (minlen=14, 4 classes, maxrepeat=3) ?" y; then
        $IS_DEBIAN && _exec "apt-get install -y -qq libpam-pwquality"
        $IS_RHEL   && _exec "$PKG_INSTALL libpwquality"
        $IS_SUSE   && _exec "$PKG_INSTALL pam_pwquality"
        local pwq="/etc/security/pwquality.conf"
        set_config "minlen"      "14" "$pwq"
        set_config "minclass"    "4"  "$pwq"
        set_config "maxrepeat"   "3"  "$pwq"
        set_config "maxsequence" "3"  "$pwq"
        set_config "difok"       "2"  "$pwq"
        applied "pwquality : minlen=14 minclass=4 maxrepeat=3 maxsequence=3 difok=2"
    else skipped "pwquality"; fi

    info "Verrouillage de compte après échecs (faillock)."
    risk high "Sans faillock, un attaquant peut tenter des milliers de mots de passe localement sans blocage."
    if ask "Configurer faillock (5 tentatives, 15 min de blocage) ?" y; then
        local flk="/etc/security/faillock.conf"
        [ ! -f "$flk" ] && _exec "touch $flk"
        set_config "deny"             "5"   "$flk"
        set_config "unlock_time"      "900" "$flk"
        set_config "root_unlock_time" "60"  "$flk"
        applied "faillock : deny=5 unlock=900s root_unlock=60s"
    else skipped "faillock"; fi

    info "Expiration des mots de passe (login.defs + chage sur l'existant)."
    risk medium "Un mot de passe compromis sans expiration reste valide indéfiniment."
    if ask "Expiration : max 90j, min 1j, alerte 7j, inactif 45j ?" y; then
        set_login_def "PASS_MAX_DAYS" "90"
        set_login_def "PASS_MIN_DAYS" "1"
        set_login_def "PASS_WARN_AGE" "7"
        while IFS=: read -r user _ uid _; do
            if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$user" != "nobody" ]; then
                _exec "chage --mindays 1 --maxdays 90 --warndays 7 --inactive 45 \"$user\""
            fi
        done < /etc/passwd
        _exec "chage --mindays 1 --maxdays 90 --warndays 7 --inactive 45 root"
        applied "Expiration : max=90j min=1j warn=7j inactif=45j"
    else skipped "Expiration mots de passe"; fi
}

# ─── 3. Algorithme de hashage ────────────────────────────────────────────────
harden_password_hash() {
    section "3/22 · Algorithme de hashage des mots de passe"

    info "Vérification de l'algorithme de hashage utilisé pour /etc/shadow."
    risk high "MD5 est cassable en quelques minutes sur GPU. DES en secondes. SHA-512 ou yescrypt sont les standards actuels — résistants aux attaques par dictionnaire."
    local current_algo
    current_algo=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}')
    current_algo="${current_algo:-non défini}"
    info "Algorithme actuel : $current_algo"

    case "${current_algo^^}" in
        SHA512|YESCRYPT)
            ok "Algorithme déjà sécurisé ($current_algo)"
            skipped "Hashage (déjà bon)"
            ;;
        *)
            if ask "Passer le hashage à SHA512 ?" y; then
                set_login_def "ENCRYPT_METHOD" "SHA512"
                # Sur Debian/Ubuntu, aussi dans PAM
                if $IS_DEBIAN && [ -f /etc/pam.d/common-password ]; then
                    backup_file /etc/pam.d/common-password
                    _exec "sed -i 's/pam_unix.so.*/pam_unix.so obscure sha512/' /etc/pam.d/common-password"
                fi
                applied "ENCRYPT_METHOD=SHA512 (nouveaux mots de passe uniquement)"
                dim "Les mots de passe existants ne changent pas — ils seront rehashés à la prochaine modification."
            else skipped "Hashage"; fi
            ;;
    esac
}

# ─── 4. Kernel / sysctl réseau ───────────────────────────────────────────────
harden_sysctl_network() {
    section "4/22 · Kernel sysctl — réseau"
    local cfg="/etc/sysctl.d/99-hardening.conf"
    info "Paramètres réseau IPv4/IPv6 (fichier : $cfg)"
    risk high "Redirects ICMP, source routing et absence de SYN cookies exposent à MITM, SYN flood, IP spoofing."
    if ask "Appliquer le durcissement réseau IPv4/IPv6 ?" y; then
        backup_file "$cfg"
        local settings=(
            "net.ipv4.conf.all.send_redirects=0"
            "net.ipv4.conf.default.send_redirects=0"
            "net.ipv4.conf.all.accept_redirects=0"
            "net.ipv4.conf.default.accept_redirects=0"
            "net.ipv4.conf.all.secure_redirects=0"
            "net.ipv4.conf.default.secure_redirects=0"
            "net.ipv4.conf.all.accept_source_route=0"
            "net.ipv4.conf.default.accept_source_route=0"
            "net.ipv4.conf.all.rp_filter=1"
            "net.ipv4.conf.default.rp_filter=1"
            "net.ipv4.conf.all.log_martians=1"
            "net.ipv4.conf.default.log_martians=1"
            "net.ipv4.tcp_syncookies=1"
            "net.ipv4.tcp_timestamps=0"
            "net.ipv4.icmp_echo_ignore_broadcasts=1"
            "net.ipv4.icmp_ignore_bogus_error_responses=1"
            "net.ipv6.conf.all.accept_redirects=0"
            "net.ipv6.conf.default.accept_redirects=0"
            "net.ipv6.conf.all.accept_source_route=0"
        )
        for s in "${settings[@]}"; do sysctl_set "$s" "$cfg"; done
        applied "Paramètres réseau écrits dans $cfg"
    else skipped "sysctl réseau"; fi
}

# ─── 5. Kernel / sysctl système ──────────────────────────────────────────────
harden_sysctl_kernel() {
    section "5/22 · Kernel sysctl — système"
    local cfg="/etc/sysctl.d/99-hardening.conf"
    info "ASLR, ptrace, kptr_restrict, dmesg, hardlinks, core dumps."
    risk high "Ces paramètres réduisent drastiquement la surface d'exploitation locale (LPE)."
    if ask "Appliquer le durcissement kernel (ASLR, ptrace, kptr, dmesg) ?" y; then
        local settings=(
            "kernel.randomize_va_space=2"
            "kernel.dmesg_restrict=1"
            "kernel.kptr_restrict=2"
            "kernel.yama.ptrace_scope=1"
            "kernel.core_uses_pid=1"
            "fs.protected_hardlinks=1"
            "fs.protected_symlinks=1"
            "fs.suid_dumpable=0"
        )
        for s in "${settings[@]}"; do sysctl_set "$s" "$cfg"; done
        applied "Paramètres kernel écrits dans $cfg"
    else skipped "sysctl kernel"; fi

    info "BPF non-privilégié — empêche les utilisateurs normaux de charger des programmes eBPF."
    risk high "eBPF non restreint a été exploité dans plusieurs LPE récentes (CVE-2021-3490, CVE-2022-23222...). Inutile pour les utilisateurs standards."
    if ask "Désactiver BPF non-privilégié (bpf + bpf_jit_harden) ?" y; then
        sysctl_set "kernel.unprivileged_bpf_disabled=1"      "$cfg"
        sysctl_set "net.core.bpf_jit_harden=2"               "$cfg"
        applied "BPF non-privilégié désactivé"
    else skipped "BPF hardening"; fi

    info "Forwarding IP — à désactiver si le système n'est pas un routeur."
    risk medium "Activer ip_forward transforme le système en routeur potentiel, permettant d'acheminer du trafic entre interfaces."
    if ask "Désactiver le forwarding IPv4/IPv6 (si pas un routeur) ?" y; then
        sysctl_set "net.ipv4.ip_forward=0"        "$cfg"
        sysctl_set "net.ipv6.conf.all.forwarding=0" "$cfg"
        applied "Forwarding IP désactivé"
    else skipped "Forwarding IP"; fi

    if ask "Appliquer maintenant (sysctl --system) ?" y; then
        _exec "sysctl --system"; applied "sysctl --system exécuté"
    fi
}

# ─── 6. Magic SysRq + Ctrl+Alt+Del ──────────────────────────────────────────
harden_sysrq_ctrlaltdel() {
    section "6/22 · Magic SysRq & Ctrl+Alt+Del"

    info "Magic SysRq — séquence de touches pour envoyer des commandes bas niveau au kernel."
    risk medium "Sur un serveur, SysRq permet à quiconque ayant accès au clavier (ou à un terminal série) de forcer un reboot, killer des processus ou monter le filesystem en RW."
    if ask "Désactiver le Magic SysRq (kernel.sysrq=0) ?" y; then
        local cfg="/etc/sysctl.d/99-hardening.conf"
        sysctl_set "kernel.sysrq=0" "$cfg"
        _exec "sysctl -w kernel.sysrq=0"
        applied "Magic SysRq désactivé"
    else skipped "Magic SysRq"; fi

    info "Ctrl+Alt+Del — redémarre le système immédiatement sur la plupart des distros."
    risk medium "En accès physique ou console série, Ctrl+Alt+Del peut redémarrer un serveur en production. systemd peut masquer ce comportement."
    if ask "Désactiver Ctrl+Alt+Del (systemd) ?" y; then
        _exec "systemctl mask ctrl-alt-del.target"
        _exec "systemctl daemon-reload"
        applied "Ctrl+Alt+Del masqué"
    else skipped "Ctrl+Alt+Del"; fi
}

# ─── 7. Montages sécurisés ───────────────────────────────────────────────────
harden_mounts() {
    section "7/22 · Montages sécurisés"

    info "/dev/shm — mémoire partagée entre processus."
    risk high "/dev/shm exécutable est utilisé dans des exploits pour déposer et exécuter des payloads en mémoire, contournant les protections du filesystem principal."
    if ask "Sécuriser /dev/shm (nodev,nosuid,noexec) ?" y; then
        backup_file /etc/fstab
        local shm_entry="tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"
        if grep -q "^tmpfs /dev/shm" /etc/fstab; then
            _exec "sed -i 's|^tmpfs /dev/shm.*|$shm_entry|' /etc/fstab"
        else
            _exec "echo '$shm_entry' >> /etc/fstab"
        fi
        _exec "mount -o remount,noexec /dev/shm 2>/dev/null || true"
        applied "/dev/shm : nodev,nosuid,noexec"
    else skipped "/dev/shm"; fi

    info "/tmp — répertoire temporaire world-writable."
    risk medium "Les malwares déposent classiquement leurs binaires dans /tmp avant exécution. noexec bloque cette technique."
    dim "Certains installers scriptent dans /tmp et exécutent. Testez sur une machine non critique d'abord."
    if ask "Sécuriser /tmp (nodev,nosuid,noexec) ?" n; then
        if ask "Confirmer /tmp noexec ?" n; then
            backup_file /etc/fstab
            if grep -qE '[[:space:]]/tmp[[:space:]]' /etc/fstab; then
                _exec "sed -i '/[[:space:]]\/tmp[[:space:]]/s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab"
            else
                _exec "echo 'tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab"
            fi
            applied "/tmp : nodev,nosuid,noexec (redémarrage requis)"
        else skipped "/tmp"; fi
    else skipped "/tmp"; fi
}

# ─── 8. /proc hidepid ────────────────────────────────────────────────────────
harden_proc_hidepid() {
    section "8/22 · /proc hidepid — isolation des processus"

    info "Par défaut, tout utilisateur peut lister les processus de tous les autres via /proc."
    risk medium "Un attaquant ou utilisateur compromis peut voir les arguments en ligne de commande (parfois des mots de passe), les variables d'environnement et les descripteurs de fichiers de tous les processus du système."

    if ask "Monter /proc avec hidepid=2 (chaque utilisateur ne voit que ses propres processus) ?" y; then
        backup_file /etc/fstab
        if grep -qE '[[:space:]]/proc[[:space:]]' /etc/fstab; then
            _exec "sed -i '/[[:space:]]\/proc[[:space:]]/s/defaults/defaults,hidepid=2/' /etc/fstab"
        else
            _exec "echo 'proc /proc proc defaults,hidepid=2 0 0' >> /etc/fstab"
        fi
        _exec "mount -o remount,hidepid=2 /proc 2>/dev/null || true"
        warn "Certains outils de monitoring (ps, top, htop en root) fonctionnent quand même — hidepid=2 n'affecte que les non-root."
        applied "/proc : hidepid=2 (redémarrage pour fstab)"
    else skipped "/proc hidepid"; fi
}

# ─── 9. Core dumps ───────────────────────────────────────────────────────────
harden_coredumps() {
    section "9/22 · Core dumps"

    info "Les core dumps peuvent contenir des clés privées, tokens, hashs de mots de passe présents en mémoire."
    risk high "Un core dump d'un processus SUID peut révéler des secrets critiques si capturé par un utilisateur local."
    if ask "Désactiver les core dumps (limits.conf + sysctl + systemd) ?" y; then
        local lim="/etc/security/limits.d/99-coredump.conf"
        _exec "echo '* hard core 0' > \"$lim\""
        _exec "echo '* soft core 0' >> \"$lim\""
        local cfg="/etc/sysctl.d/99-hardening.conf"
        sysctl_set "fs.suid_dumpable=0" "$cfg"
        _exec "sysctl -w fs.suid_dumpable=0"
        if [ -f /etc/systemd/coredump.conf ]; then
            backup_file /etc/systemd/coredump.conf
            _exec "sed -i 's|^#*Storage.*|Storage=none|' /etc/systemd/coredump.conf"
            _exec "sed -i 's|^#*ProcessSizeMax.*|ProcessSizeMax=0|' /etc/systemd/coredump.conf"
        fi
        applied "Core dumps désactivés"
    else skipped "Core dumps"; fi
}

# ─── 10. Umask ───────────────────────────────────────────────────────────────
harden_umask() {
    section "10/22 · Umask par défaut"

    info "L'umask détermine les permissions des fichiers et répertoires créés par défaut."
    risk medium "Umask 022 crée des fichiers lisibles par tous (644). Umask 027 restreint aux membres du groupe — meilleure pratique pour les serveurs multi-utilisateurs."
    local current_umask
    current_umask=$(grep -E '^\s*UMASK' /etc/login.defs 2>/dev/null | awk '{print $2}')
    current_umask="${current_umask:-022}"
    info "Umask actuel (login.defs) : $current_umask"

    if ask "Passer l'umask à 027 (login.defs + /etc/profile.d) ?" y; then
        set_login_def "UMASK" "027"
        local f="/etc/profile.d/99-umask.sh"
        if [ "$DRY_RUN" = false ]; then
            echo "umask 027" > "$f"
            chmod +x "$f"
        else
            echo -e "  ${DIM}[DRY-RUN] echo 'umask 027' > $f${RESET}"
        fi
        applied "Umask=027 (login.defs + profile.d)"
        dim "Effet sur les nouvelles sessions uniquement — pas sur les sessions en cours."
    else skipped "Umask"; fi
}

# ─── 11. Services inutiles ───────────────────────────────────────────────────
harden_services() {
    section "11/22 · Services inutiles / dangereux"

    if systemctl list-units --all 2>/dev/null | grep -q avahi; then
        info "Avahi-daemon — résolution mDNS/DNS-SD (Bonjour)."
        risk medium "Diffuse hostname et services sur le réseau local. Facilite la reconnaissance et des attaques MITM."
        if ask "Désactiver et masquer avahi-daemon ?" y; then
            for svc in avahi-daemon.socket avahi-daemon.service; do
                _exec "systemctl stop $svc 2>/dev/null || true"
                _exec "systemctl disable $svc 2>/dev/null || true"
                _exec "systemctl mask $svc 2>/dev/null || true"
            done
            applied "avahi-daemon masqué"
        else skipped "avahi-daemon"; fi
    else ok "avahi-daemon absent"; fi

    if systemctl list-units --all 2>/dev/null | grep -q cups; then
        info "CUPS — service d'impression réseau."
        risk medium "Historique de CVE critiques dont des RCE. Inutile sur un serveur sans imprimante."
        if ask "Désactiver CUPS ?" y; then
            for svc in cups.socket cups.service cups-browsed.service; do
                _exec "systemctl stop $svc 2>/dev/null || true"
                _exec "systemctl mask $svc 2>/dev/null || true"
            done
            applied "CUPS masqué"
        else skipped "CUPS"; fi
    else ok "CUPS absent"; fi

    info "Synchronisation NTP — essentiel pour la cohérence des logs."
    risk medium "Timestamps erronés brisent les investigations forensics et peuvent rompre l'auth Kerberos (drift > 5 min)."
    if ask "Configurer NTP : pool.ntp.org ?" y; then
        backup_file /etc/systemd/timesyncd.conf
        if grep -q "^#NTP=" /etc/systemd/timesyncd.conf 2>/dev/null; then
            _exec "sed -i 's|^#NTP=.*|NTP=pool.ntp.org|' /etc/systemd/timesyncd.conf"
        elif ! grep -q "^NTP=" /etc/systemd/timesyncd.conf 2>/dev/null; then
            _exec "echo 'NTP=pool.ntp.org' >> /etc/systemd/timesyncd.conf"
        fi
        _exec "systemctl enable systemd-timesyncd --now && systemctl restart systemd-timesyncd"
        applied "NTP : pool.ntp.org"
    else skipped "NTP"; fi

    if systemctl list-units --all 2>/dev/null | grep -q apport; then
        info "Apport — rapport d'erreurs automatique (Ubuntu)."
        risk low "Peut envoyer des informations système (crashs, traces) vers Canonical."
        if ask "Désactiver apport ?" y; then
            _exec "systemctl disable apport.service --now 2>/dev/null || true"
            _exec "sed -i 's/enabled=1/enabled=0/' /etc/default/apport 2>/dev/null || true"
            applied "apport désactivé"
        else skipped "apport"; fi
    fi
}

# ─── 12. Auditd ──────────────────────────────────────────────────────────────
harden_auditd() {
    section "12/22 · Auditd — journalisation système"

    info "auditd trace les appels système, accès fichiers sensibles, escalades de privilèges."
    risk high "Sans auditd, vous ne pouvez pas détecter ni investiguer une intrusion. Recommandé par CIS, ANSSI et toutes les bonnes pratiques opérationnelles."

    if ask "Installer/activer auditd + règles CIS/ANSSI ?" y; then
        $IS_DEBIAN && _exec "apt-get install -y -qq auditd audispd-plugins"
        $IS_RHEL   && _exec "$PKG_INSTALL audit audit-libs"
        $IS_SUSE   && _exec "$PKG_INSTALL audit"
        $IS_ARCH   && _exec "pacman -S --noconfirm audit"
        _exec "systemctl enable auditd --now"

        local rules_file="/etc/audit/rules.d/99-hardening.rules"
        if [ "$DRY_RUN" = false ]; then
            cat > "$rules_file" <<'AUDRULES'
## Règles auditd — linux-hardening.sh (CIS + ANSSI R41+)
-D
-b 8192
-f 1

## Fichiers d'authentification
-w /etc/shadow    -p wa -k auth_files
-w /etc/passwd    -p wa -k auth_files
-w /etc/group     -p wa -k auth_files
-w /etc/gshadow   -p wa -k auth_files
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

## SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/            -p wa -k ssh_config

## Config auditd elle-même
-w /etc/audit/   -p wa -k audit_config
-w /sbin/auditctl -p x -k auditctl

## Escalade de privilèges
-w /bin/su           -p x -k priv_esc
-w /usr/bin/sudo     -p x -k priv_esc
-a always,exit -F arch=b64 -S setuid -S setgid -k setuid

## Cron
-w /etc/cron.d       -p wa -k cron
-w /etc/cron.daily   -p wa -k cron
-w /etc/cron.hourly  -p wa -k cron
-w /etc/crontab      -p wa -k cron
-w /var/spool/cron   -p wa -k cron

## Modules kernel
-w /sbin/insmod   -p x -k kernel_modules
-w /sbin/rmmod    -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules

## Accès refusés
-a always,exit -F arch=b64 -S open -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open -F exit=-EPERM  -k access_denied

## ptrace (injection mémoire)
-a always,exit -F arch=b64 -S ptrace -k ptrace

## Figer les règles en production (reboot requis pour modifier)
## -e 2
AUDRULES
        else
            echo -e "  ${DIM}[DRY-RUN] Écriture de $rules_file${RESET}"
        fi
        _exec "augenrules --load 2>/dev/null || auditctl -R \"$rules_file\" 2>/dev/null || true"
        applied "auditd activé + règles dans $rules_file"
    else skipped "auditd"; fi
}

# ─── 13. Fail2ban ────────────────────────────────────────────────────────────
harden_fail2ban() {
    section "13/22 · Fail2ban"

    info "Bannit automatiquement les IPs après N échecs d'authentification."
    risk high "Sans fail2ban, un attaquant peut lancer du brute-force sans être bloqué au niveau réseau."

    if ! command -v fail2ban-client &>/dev/null; then
        if ask "Installer fail2ban ?" y; then
            $IS_DEBIAN && _exec "apt-get install -y -qq fail2ban"
            $IS_RHEL   && _exec "$PKG_INSTALL epel-release; $PKG_INSTALL fail2ban"
            $IS_SUSE   && _exec "$PKG_INSTALL fail2ban"
            $IS_ARCH   && _exec "pacman -S --noconfirm fail2ban"
        else skipped "fail2ban"; return; fi
    fi

    if ask "Configurer le jail SSH (3 tentatives, ban 2h) ?" y; then
        backup_file /etc/fail2ban/jail.local
        if [ "$DRY_RUN" = false ]; then
            cat > /etc/fail2ban/jail.local <<'F2B'
[DEFAULT]
bantime  = 7200
findtime = 600
maxretry = 5
backend  = auto
banaction = iptables-multiport
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 7200
F2B
        else
            echo -e "  ${DIM}[DRY-RUN] Écriture de /etc/fail2ban/jail.local${RESET}"
        fi
        _exec "systemctl enable fail2ban --now"
        applied "fail2ban : SSH — 3 tentatives, ban 2h"
    else skipped "fail2ban jail"; fi
}

# ─── 14. Sudo ────────────────────────────────────────────────────────────────
harden_sudo() {
    section "14/22 · Sécurisation sudo"

    if ! grep -Eq '^\s*Defaults.*logfile=' /etc/sudoers 2>/dev/null; then
        info "sudo ne logue pas dans un fichier dédié par défaut."
        risk medium "Un fichier de log dédié est requis par CIS pour tracer 'qui a fait quoi en root'."
        if ask "Log sudo dans /var/log/sudo.log ?" y; then
            _exec "echo 'Defaults logfile=\"/var/log/sudo.log\"' | EDITOR='tee -a' visudo"
            applied "sudo logfile : /var/log/sudo.log"
        else skipped "sudo logfile"; fi
    else ok "sudo logfile déjà configuré"; fi

    if ! grep -Eq '^\s*auth\s+required\s+pam_wheel' /etc/pam.d/su 2>/dev/null; then
        info "Restriction de 'su' aux membres du groupe sudo/wheel."
        risk medium "Sans restriction, tout utilisateur peut tenter 'su root' de manière illimitée."
        if ask "Restreindre 'su' au groupe sudo/wheel (pam_wheel) ?" y; then
            backup_file /etc/pam.d/su
            local wgrp
            getent group wheel &>/dev/null && wgrp="wheel" || wgrp="sudo"
            _exec "sed -i '/^auth/a auth required pam_wheel.so use_uid group=$wgrp' /etc/pam.d/su"
            applied "pam_wheel pour 'su' — groupe: $wgrp"
        else skipped "pam_wheel"; fi
    else ok "pam_wheel déjà configuré"; fi

    info "Timeout du token sudo (défaut: 15 min)."
    risk low "Réduire à 5 min limite la fenêtre d'exploitation si une session est laissée ouverte."
    if ask "Timeout sudo à 5 min ?" n; then
        _exec "echo 'Defaults timestamp_timeout=5' | EDITOR='tee -a' visudo"
        applied "sudo timestamp_timeout=5"
    else skipped "sudo timeout"; fi
}

# ─── 15. Cron ────────────────────────────────────────────────────────────────
harden_cron() {
    section "15/22 · Permissions cron"

    info "Les fichiers cron doivent appartenir à root:root avec des permissions restrictives."
    risk medium "Permissions trop larges → lecture des tâches planifiées (fuite d'info) ou modification (persistence)."
    if ask "Corriger les permissions cron (og-rwx, root:root) ?" y; then
        for f in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
            [ -e "$f" ] && _exec "chown root:root \"$f\" && chmod og-rwx \"$f\""
        done
        [ -f /etc/cron.deny ] || _exec "touch /etc/cron.deny"
        applied "Permissions cron corrigées"
    else skipped "Cron"; fi
}

# ─── 16. TMOUT ───────────────────────────────────────────────────────────────
harden_tmout() {
    section "16/22 · Déconnexion automatique des sessions inactives"

    info "TMOUT ferme automatiquement les sessions bash inactives."
    risk medium "Session inactive laissée ouverte = porte si accès physique console ou terminal."
    if ask "TMOUT=900 (15 min) pour toutes les sessions ?" y; then
        local f="/etc/profile.d/99-tmout.sh"
        if [ "$DRY_RUN" = false ]; then
            cat > "$f" <<'EOF'
# Déconnexion automatique après 15 min — linux-hardening.sh
readonly TMOUT=900
readonly HISTFILE
export TMOUT
EOF
            chmod +x "$f"
        else
            echo -e "  ${DIM}[DRY-RUN] Écriture de $f${RESET}"
        fi
        applied "TMOUT=900"
    else skipped "TMOUT"; fi
}

# ─── 17. Bannières légales ───────────────────────────────────────────────────
harden_banners() {
    section "17/22 · Bannières légales"

    info "Bannière affichée aux connexions locales (/etc/issue) et SSH (/etc/issue.net)."
    risk low "Valeur juridique lors d'incidents. Requis par CIS et ANSSI. Dissuasif."
    if ask "Écrire une bannière légale ?" y; then
        printf "  Texte (Entrée pour défaut) : "
        read -r msg </dev/tty
        [ -z "$msg" ] && msg="Authorized users only. All activity is monitored and logged."
        _exec "echo '$msg' > /etc/issue"
        _exec "echo '$msg' > /etc/issue.net"
        applied "Bannières écrites dans /etc/issue et /etc/issue.net"
    else skipped "Bannières"; fi
}

# ─── 18. AppArmor / SELinux ──────────────────────────────────────────────────
harden_mac() {
    section "18/22 · Contrôle d'accès obligatoire (AppArmor / SELinux)"

    if $IS_DEBIAN; then
        info "AppArmor confine les processus dans des profils d'accès stricts."
        risk high "Limite l'impact d'une vulnérabilité applicative (nginx, samba, etc.) en empêchant le processus de sortir de son profil."
        if ! systemctl is-active apparmor &>/dev/null; then
            if ask "Installer et activer AppArmor ?" y; then
                _exec "apt-get install -y -qq apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra"
                _exec "systemctl enable apparmor --now"
                applied "AppArmor installé et activé"
            else skipped "AppArmor"; fi
        else
            ok "AppArmor déjà actif"
            if ask "Passer tous les profils en mode 'enforce' ?" n; then
                warn "Enforce peut bloquer des applications légitimes. Surveillez /var/log/kern.log."
                if ask "Confirmer enforce ?" n; then
                    _exec "aa-enforce /etc/apparmor.d/* 2>/dev/null || true"
                    applied "AppArmor : enforce"
                else skipped "AppArmor enforce"; fi
            else skipped "AppArmor enforce"; fi
        fi
    elif $IS_RHEL; then
        info "SELinux — MAC intégré RHEL/CentOS/Alma/Rocky."
        risk high "SELinux Enforcing est la protection la plus robuste du monde Linux contre les exploits kernel et applicatifs."
        local selinux_status; selinux_status=$(getenforce 2>/dev/null || echo "Désactivé")
        info "État SELinux : $selinux_status"
        if [ "$selinux_status" != "Enforcing" ]; then
            if ask "Activer SELinux Enforcing ?" n; then
                warn "Tester en Permissive d'abord (audit2allow pour capturer les refus)."
                if ask "Confirmer Enforcing ?" n; then
                    _exec "setenforce 1 2>/dev/null || true"
                    backup_file /etc/selinux/config
                    _exec "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
                    applied "SELinux Enforcing (reboot pour effet complet)"
                else skipped "SELinux enforcing"; fi
            else skipped "SELinux"; fi
        else ok "SELinux déjà en mode Enforcing"; fi
    fi
}

# ─── 19. Mises à jour ────────────────────────────────────────────────────────
harden_updates() {
    section "19/22 · Mises à jour de sécurité automatiques"

    info "Mises à jour security-only automatiques."
    risk high "La majorité des compromissions exploitent des CVEs patchés. La gestion des vulnérabilités est une bonne pratique universelle."
    dim "Sur des serveurs de production critiques, préférez des MAJ manuelles testées avant déploiement."

    if $IS_DEBIAN; then
        if ask "Installer unattended-upgrades (security-only) ?" n; then
            _exec "apt-get install -y -qq unattended-upgrades apt-listchanges"
            _exec "dpkg-reconfigure --frontend=noninteractive unattended-upgrades"
            applied "unattended-upgrades installé"
        else skipped "unattended-upgrades"; fi
    elif $IS_RHEL; then
        if ask "Installer dnf-automatic (security-only) ?" n; then
            _exec "$PKG_INSTALL dnf-automatic"
            backup_file /etc/dnf/automatic.conf
            _exec "sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf"
            _exec "sed -i 's/^upgrade_type = default/upgrade_type = security/' /etc/dnf/automatic.conf"
            _exec "systemctl enable dnf-automatic.timer --now"
            applied "dnf-automatic (security-only)"
        else skipped "dnf-automatic"; fi
    fi
}

# ─── 20. Permissions fichiers critiques ──────────────────────────────────────
harden_file_perms() {
    section "20/22 · Permissions fichiers système"

    info "Permissions sur /etc/shadow, passwd, sudoers, grub."
    risk high "/etc/shadow lisible par tous = hashs exposés. /etc/passwd modifiable = comptes fantômes possibles."
    if ask "Corriger les permissions des fichiers critiques ?" y; then
        _exec "chown root:root /etc/passwd  && chmod 644 /etc/passwd"
        _exec "chown root:root /etc/group   && chmod 644 /etc/group"
        _exec "chown root:shadow /etc/shadow  2>/dev/null || chown root:root /etc/shadow"
        _exec "chmod 640 /etc/shadow 2>/dev/null || chmod 000 /etc/shadow"
        _exec "chown root:shadow /etc/gshadow 2>/dev/null || chown root:root /etc/gshadow"
        _exec "chmod 640 /etc/gshadow 2>/dev/null || chmod 000 /etc/gshadow"
        [ -f /etc/sudoers ] && _exec "chown root:root /etc/sudoers && chmod 440 /etc/sudoers"
        for grubcfg in /boot/grub/grub.cfg /boot/grub2/grub.cfg /etc/grub.conf; do
            [ -f "$grubcfg" ] && _exec "chown root:root \"$grubcfg\" && chmod og-rwx \"$grubcfg\""
        done
        applied "Permissions fichiers critiques corrigées"
    else skipped "Permissions fichiers"; fi
}

# ─── 21. Modules kernel ──────────────────────────────────────────────────────
harden_kernel_modules() {
    section "21/22 · Modules kernel inutiles"

    info "Désactivation de protocoles réseau rares et systèmes de fichiers non utilisés."
    risk medium "DCCP, SCTP, RDS, TIPC ont tous eu des CVE critiques (RCE/LPE). Les blacklister supprime la surface sans impact opérationnel si non utilisés."
    if ask "Blacklister les modules inutiles (dccp, sctp, rds, tipc, cramfs, hfs...) ?" y; then
        local f="/etc/modprobe.d/99-hardening-blacklist.conf"
        if [ "$DRY_RUN" = false ]; then
            cat > "$f" <<'MODULES'
# Modules blacklistés — linux-hardening.sh (CIS + ANSSI)

# Protocoles réseau rarement utilisés (historique CVE)
install dccp    /bin/true
install sctp    /bin/true
install rds     /bin/true
install tipc    /bin/true
install n-hdlc  /bin/true

# Systèmes de fichiers rares/obsolètes
install cramfs   /bin/true
install freevxfs /bin/true
install jffs2    /bin/true
install hfs      /bin/true
install hfsplus  /bin/true
install udf      /bin/true

# USB storage — décommenter pour bloquer les clés USB
# install usb-storage /bin/true
MODULES
        else
            echo -e "  ${DIM}[DRY-RUN] Écriture de /etc/modprobe.d/99-hardening-blacklist.conf${RESET}"
        fi
        applied "Modules blacklistés (effet au prochain boot)"
    else skipped "Modules kernel"; fi

    info "Désactivation du stockage USB (usb-storage)."
    risk high "Les clés USB sont un vecteur classique d'introduction de malwares et d'exfiltration. Utile sur les serveurs sans besoin de stockage USB."
    dim "Souris, claviers, audio USB et chargeurs USB ne sont PAS affectés."
    if ask "Désactiver usb-storage ?" n; then
        if ask "Confirmer — plus de clés USB sur ce système ?" n; then
            _exec "echo 'install usb-storage /bin/true' >> /etc/modprobe.d/99-hardening-blacklist.conf"
            _exec "modprobe -r usb-storage 2>/dev/null || true"
            applied "usb-storage désactivé"
        else skipped "USB storage"; fi
    else skipped "USB storage"; fi
}

# ─── 22. Scan de sécurité post-hardening ─────────────────────────────────────
harden_scan() {
    section "22/22 · Scan post-hardening — fichiers sensibles"

    info "Recherche de fichiers world-writable et de binaires SUID non standards."
    risk medium "Un fichier world-writable dans /etc ou /usr peut être modifié par n'importe qui. Un SUID non-standard peut être une backdoor ou un vecteur LPE."

    if ask "Lancer un scan des fichiers world-writable (hors /tmp, /dev, /proc) ?" y; then
        echo ""
        info "Fichiers world-writable trouvés :"
        if [ "$DRY_RUN" = false ]; then
            local ww_files
            ww_files=$(find / -xdev -type f -perm -0002 \
                -not -path '/tmp/*' -not -path '/var/tmp/*' \
                -not -path '/proc/*' -not -path '/dev/*' \
                -not -path '/sys/*' 2>/dev/null)
            if [ -z "$ww_files" ]; then
                ok "Aucun fichier world-writable trouvé hors /tmp et /dev."
            else
                echo "$ww_files" | while read -r f; do
                    warn "$f"
                done
                echo "$ww_files" >> "$LOG_FILE"
            fi
        else
            echo -e "  ${DIM}[DRY-RUN] find / -xdev -perm -0002 ...${RESET}"
        fi
        applied "Scan world-writable effectué (voir log $LOG_FILE)"
    else skipped "Scan world-writable"; fi

    if ask "Lancer un scan des binaires SUID/SGID non standards ?" y; then
        echo ""
        info "Binaires SUID/SGID trouvés (hors /proc, /sys, /dev) :"
        if [ "$DRY_RUN" = false ]; then
            find / -xdev -type f \( -perm -4000 -o -perm -2000 \) \
                -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' \
                2>/dev/null | sort | while read -r f; do
                    warn "$f  ($(stat -c '%U:%G %a' "$f" 2>/dev/null))"
            done
        else
            echo -e "  ${DIM}[DRY-RUN] find / -xdev -perm -4000 -o -perm -2000 ...${RESET}"
        fi
        dim "Vérifiez cette liste manuellement — tout binaire SUID inconnu est suspect."
        applied "Scan SUID/SGID effectué (voir log $LOG_FILE)"
    else skipped "Scan SUID"; fi
}

# =============================================================================
#  RAPPORT FINAL
# =============================================================================
final_report() {
    echo ""
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║                        RAPPORT FINAL                                ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  ${GREEN}✔ Actions appliquées  : $APPLIED${RESET}"
    echo -e "  ${DIM}↷ Actions ignorées   : $SKIPPED${RESET}"
    echo -e "  ${RED}✖ Erreurs            : $ERRORS${RESET}"
    echo ""
    echo -e "  📋 Log complet : ${BOLD}$LOG_FILE${RESET}"
    echo ""
    echo -e "  ${BOLD}Sauvegardes (.harden.bak) :${RESET}"
    find / -maxdepth 6 -name "*.harden.bak" 2>/dev/null | head -15 | \
        while read -r f; do echo -e "  ${DIM}$f${RESET}"; done
    echo ""
    echo -e "  ${ORANGE}${BOLD}Étapes manuelles recommandées :${RESET}"
    echo -e "  ${DIM}1. Ouvrir une NOUVELLE session SSH pour tester avant de fermer l'actuelle${RESET}"
    echo -e "  ${DIM}2. Redémarrer pour appliquer sysctl, modules kernel, fstab${RESET}"
    echo -e "  ${DIM}3. Tester les applications critiques après reboot${RESET}"
    echo -e "  ${DIM}4. Lynis audit complet : sudo lynis audit system${RESET}"
    echo -e "  ${DIM}5. Vérifier auditd : ausearch -k auth_files | aureport -f${RESET}"
    echo ""
    log "FINAL: APPLIED=$APPLIED SKIPPED=$SKIPPED ERRORS=$ERRORS"
}

# =============================================================================
#  MAIN
# =============================================================================
main() {
    check_root
    banner
    detect_distro
    echo -e "  Système  : ${BOLD}$DISTRO_NAME $DISTRO_VERSION${RESET} ($(uname -m))"
    echo -e "  Packages : ${BOLD}$PKG_MANAGER${RESET}"
    echo -e "  Log      : $LOG_FILE"
    echo ""
    log "START: distro=$DISTRO pkg=$PKG_MANAGER kernel=$(uname -r)"

    run_audit

    if [ "$AUDIT_ONLY" = true ]; then
        echo -e "\n  ${CYAN}Mode --audit : aucun changement.${RESET}\n"
        exit 0
    fi

    echo ""
    echo -e "${BOLD}  L'audit est terminé. Le script va parcourir ${GREEN}22 sections de hardening${RESET}${BOLD}."
    echo -e "  Une question est posée avant chaque action.${RESET}"
    echo ""
    if ! ask "Démarrer le hardening interactif ?" y; then
        echo -e "\n  Sortie propre. Aucune modification.\n"; exit 0
    fi

    harden_ssh
    harden_passwords
    harden_password_hash
    harden_sysctl_network
    harden_sysctl_kernel
    harden_sysrq_ctrlaltdel
    harden_mounts
    harden_proc_hidepid
    harden_coredumps
    harden_umask
    harden_services
    harden_auditd
    harden_fail2ban
    harden_sudo
    harden_cron
    harden_tmout
    harden_banners
    harden_mac
    harden_updates
    harden_file_perms
    harden_kernel_modules
    harden_scan

    final_report
}

main "$@"
