#!/usr/bin/env bash
# =============================================================================
#  linux-hardening.sh — Interactive Linux Audit & Hardening (EN)
#  Version : 3.0.0
#
#  Aggregated sources:
#    · CIS Benchmarks (Level 1 & 2)
#    · ANSSI R41+ (GNU/Linux system configuration guide)
#    · dev-sec/linux-baseline (os-hardening)
#    · Wazuh hardening script
#    · captainzero93/security_harden_linux
#    · trimstray/the-practical-linux-hardening-guide
#    · DISA STIG Ubuntu/RHEL
#
#  Compatibility: Debian · Ubuntu · RHEL/CentOS/AlmaLinux/Rocky
#                 Fedora · openSUSE/SLES · Arch/Manjaro
#
#  Usage:
#    sudo bash linux-hardening.sh            # Interactive mode (default)
#    sudo bash linux-hardening.sh --audit    # Audit only, no changes
#    sudo bash linux-hardening.sh --dry-run  # Simulate actions without applying
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

# ─── Colors ───────────────────────────────────────────────────────────────────
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

# ─── Counters ─────────────────────────────────────────────────────────────────
APPLIED=0; SKIPPED=0; ERRORS=0
AUDIT_PASS=0; AUDIT_FAIL=0; AUDIT_WARN=0

# ─── UI helpers ───────────────────────────────────────────────────────────────
banner() {
    clear
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║          🛡️  Linux Hardening — Interactive Audit & Setup             ║"
    echo "║      CIS · ANSSI R41+ · dev-sec · Wazuh · DISA STIG · trimstray     ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    [ "$DRY_RUN" = true ]    && echo -e "  ${ORANGE}[DRY-RUN MODE] No changes will be made.${RESET}\n"
    [ "$AUDIT_ONLY" = true ] && echo -e "  ${CYAN}[AUDIT MODE] Read-only scan.${RESET}\n"
}

section() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━  $1  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    log "=== SECTION: $1 ==="
}

info()    { echo -e "  ${CYAN}ℹ${RESET}  $*";           log "INFO: $*"; }
ok()      { echo -e "  ${GREEN}✔${RESET}  $*";           log "OK: $*"; }
warn()    { echo -e "  ${ORANGE}⚠${RESET}  $*";          log "WARN: $*"; }
applied() { echo -e "  ${GREEN}✔ Applied:${RESET} $*";   log "APPLIED: $*"; APPLIED=$((APPLIED+1)); }
skipped() { echo -e "  ${DIM}↷ Skipped: $*${RESET}";    log "SKIPPED: $*"; SKIPPED=$((SKIPPED+1)); }
dim()     { echo -e "  ${DIM}$*${RESET}"; }

audit_ok()   { echo -e "  ${GREEN}[AUDIT ✔]${RESET}  $*"; AUDIT_PASS=$((AUDIT_PASS+1));  log "AUDIT_PASS: $*"; }
audit_fail() { echo -e "  ${RED}[AUDIT ✖]${RESET}  $*";   AUDIT_FAIL=$((AUDIT_FAIL+1));  log "AUDIT_FAIL: $*"; }
audit_warn() { echo -e "  ${ORANGE}[AUDIT ⚠]${RESET}  $*"; AUDIT_WARN=$((AUDIT_WARN+1)); log "AUDIT_WARN: $*"; }

risk() {
    local level="$1"; shift
    case "$level" in
        low)    echo -e "  ${GREEN}  ╰─ LOW RISK${RESET}    — $*" ;;
        medium) echo -e "  ${ORANGE}  ╰─ MEDIUM RISK${RESET} — $*" ;;
        high)   echo -e "  ${RED}  ╰─ HIGH RISK${RESET}   — $*" ;;
    esac
}

ask() {
    local prompt="$1" default="${2:-n}"
    if [ "$AUDIT_ONLY" = true ]; then return 1; fi
    local hint
    [ "$default" = "y" ] && hint="${GREEN}[Y${RESET}/n]" || hint="[y/${GREEN}N${RESET}]"
    echo ""
    printf "  ${BOLD}%s %b ${RESET}" "$prompt" "$hint"
    read -r answer </dev/tty
    answer="${answer:-$default}"
    case "$answer" in [yY]*) return 0 ;; *) return 1 ;; esac
}

# ─── Distro detection ─────────────────────────────────────────────────────────
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
                *) warn "Unrecognized distribution ($DISTRO). Some actions may be skipped." ;;
            esac ;;
    esac
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "\n${RED}${BOLD}ERROR: This script must be run as root (sudo).${RESET}\n"
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
#  PHASE 1: AUDIT
# =============================================================================
run_audit() {
    section "AUDIT — Current Security State"
    echo ""
    info "System   : $DISTRO_NAME $DISTRO_VERSION ($(uname -m))"
    info "Kernel   : $(uname -r)"
    info "Hostname : $(hostname -f 2>/dev/null || hostname)"
    info "Uptime   : $(uptime -p 2>/dev/null || uptime)"
    info "Log      : $LOG_FILE"
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
                && audit_ok   "$label: $val" \
                || audit_fail "$label: $val (recommended: $good)"
        }
        _chk_sshd "PermitRootLogin"    "no"  "PermitRootLogin"    "yes (default)"
        _chk_sshd "X11Forwarding"      "no"  "X11Forwarding"      "yes (default)"
        _chk_sshd "AllowTcpForwarding" "no"  "AllowTcpForwarding" "yes (default)"

        local pass_auth
        pass_auth=$(grep -Ei '^\s*PasswordAuthentication' "$sshd_cfg" | awk '{print $2}' | tail -1)
        pass_auth="${pass_auth:-yes (default)}"
        [ "${pass_auth,,}" = "no" ] \
            && audit_ok  "PasswordAuthentication: no (key-only)" \
            || audit_warn "PasswordAuthentication: $pass_auth (acceptable with password+2FA)"

        local maxtries
        maxtries=$(grep -Ei '^\s*MaxAuthTries' "$sshd_cfg" | awk '{print $2}' | tail -1)
        maxtries="${maxtries:-6}"
        [ "${maxtries}" -le 4 ] 2>/dev/null \
            && audit_ok   "MaxAuthTries: $maxtries" \
            || audit_warn "MaxAuthTries: $maxtries (recommended: ≤ 4)"

        [ -s /etc/issue.net ] \
            && audit_ok  "SSH banner: present" \
            || audit_warn "SSH banner: missing"
    else
        audit_warn "sshd_config not found"
    fi

    # ── Passwords ────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Password Policy ───────────────────────────────────────${RESET}"
    if [ -f /etc/login.defs ]; then
        local maxdays mindays warnage
        maxdays=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')
        mindays=$(grep -E '^\s*PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}')
        warnage=$(grep -E '^\s*PASS_WARN_AGE' /etc/login.defs | awk '{print $2}')
        maxdays="${maxdays:-99999}"; mindays="${mindays:-0}"; warnage="${warnage:-7}"
        [ "${maxdays}" -le 90 ] 2>/dev/null \
            && audit_ok   "PASS_MAX_DAYS: $maxdays days" \
            || audit_fail "PASS_MAX_DAYS: $maxdays (recommended: ≤ 90)"
        [ "${mindays}" -ge 1 ] 2>/dev/null \
            && audit_ok   "PASS_MIN_DAYS: $mindays day(s)" \
            || audit_warn "PASS_MIN_DAYS: $mindays (recommended: ≥ 1)"
    fi
    if [ -f /etc/security/pwquality.conf ]; then
        local minlen minclass
        minlen=$(grep -E '^\s*minlen' /etc/security/pwquality.conf | awk -F'=' '{print $2}' | tr -d ' ')
        minclass=$(grep -E '^\s*minclass' /etc/security/pwquality.conf | awk -F'=' '{print $2}' | tr -d ' ')
        minlen="${minlen:-8}"; minclass="${minclass:-0}"
        [ "${minlen}" -ge 14 ] 2>/dev/null \
            && audit_ok   "pwquality minlen: $minlen" \
            || audit_fail "pwquality minlen: $minlen (CIS recommends ≥ 14)"
        [ "${minclass}" -ge 3 ] 2>/dev/null \
            && audit_ok   "pwquality minclass: $minclass" \
            || audit_warn "pwquality minclass: $minclass (recommended: ≥ 3)"
    else
        audit_warn "pwquality.conf not found"
    fi

    local hash_algo
    hash_algo=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}')
    hash_algo="${hash_algo:-not set}"
    case "${hash_algo^^}" in
        SHA512|YESCRYPT) audit_ok  "Password hashing: $hash_algo" ;;
        *)               audit_fail "Password hashing: $hash_algo (recommended: SHA512 or YESCRYPT)" ;;
    esac

    # ── Kernel / sysctl ──────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Kernel (sysctl) ───────────────────────────────────────${RESET}"
    _sc() {
        local key="$1" expected="$2" label="$3"
        local val; val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        [ "$val" = "$expected" ] \
            && audit_ok   "$label ($key=$val)" \
            || audit_fail "$label ($key=$val, expected: $expected)"
    }
    _sc "kernel.randomize_va_space"              "2" "ASLR enabled"
    _sc "net.ipv4.conf.all.accept_redirects"     "0" "ICMP redirects disabled"
    _sc "net.ipv4.conf.all.send_redirects"       "0" "Send redirects disabled"
    _sc "net.ipv4.conf.all.rp_filter"            "1" "Reverse path filtering"
    _sc "net.ipv4.conf.all.log_martians"         "1" "Martian packet logging"
    _sc "net.ipv4.tcp_syncookies"                "1" "TCP SYN cookies"
    _sc "kernel.dmesg_restrict"                  "1" "dmesg restricted"
    _sc "kernel.kptr_restrict"                   "2" "Kernel pointers hidden"
    _sc "kernel.yama.ptrace_scope"               "1" "ptrace restricted"
    _sc "fs.protected_hardlinks"                 "1" "Hardlinks protected"
    _sc "fs.protected_symlinks"                  "1" "Symlinks protected"
    _sc "fs.suid_dumpable"                       "0" "SUID core dumps disabled"
    _sc "kernel.sysrq"                           "0" "Magic SysRq disabled"
    _sc "kernel.unprivileged_bpf_disabled"       "1" "Unprivileged BPF disabled"

    # ── Services ─────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Services ──────────────────────────────────────────────${RESET}"
    local had_dangerous=false
    for svc in avahi-daemon cups telnet rsh rlogin rexec tftp vsftpd; do
        if systemctl is-active "$svc" &>/dev/null 2>&1; then
            audit_fail "Dangerous service active: $svc"; had_dangerous=true
        fi
    done
    $had_dangerous || audit_ok "No dangerous services active"
    systemctl is-active auditd &>/dev/null \
        && audit_ok  "auditd: active" \
        || audit_fail "auditd: inactive"
    { command -v fail2ban-client &>/dev/null && systemctl is-active fail2ban &>/dev/null; } \
        && audit_ok  "fail2ban: active" \
        || audit_warn "fail2ban: absent or inactive"

    # ── Firewall ─────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Firewall ──────────────────────────────────────────────${RESET}"
    local fw_found=false
    { command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; } \
        && { audit_ok "UFW active"; fw_found=true; }
    systemctl is-active firewalld &>/dev/null \
        && { audit_ok "firewalld active"; fw_found=true; }
    $fw_found || audit_fail "No active firewall detected"

    # ── Mounts / Misc ────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Mounts · Cron · Sudo · Session ───────────────────────${RESET}"
    mount | grep '/dev/shm' | grep -q 'noexec' \
        && audit_ok   "/dev/shm: noexec" \
        || audit_fail "/dev/shm: noexec missing"
    mount | grep '[[:space:]]/tmp[[:space:]]' | grep -q 'noexec' \
        && audit_ok   "/tmp: noexec" \
        || audit_warn "/tmp: noexec not set"
    mount | grep '[[:space:]]/proc[[:space:]]' | grep -qE 'hidepid=[12]' \
        && audit_ok   "/proc: hidepid active" \
        || audit_warn "/proc: hidepid not set (users can see other users' processes)"

    for f in /etc/crontab /etc/cron.d; do
        if [ -e "$f" ]; then
            local perms; perms=$(stat -c '%a' "$f" 2>/dev/null)
            case "$perms" in
                600|700) audit_ok "$f: permissions $perms" ;;
                *)       audit_warn "$f: permissions $perms (recommended: 600/700)" ;;
            esac
        fi
    done

    grep -Eq '^\s*Defaults.*logfile=' /etc/sudoers 2>/dev/null \
        && audit_ok  "sudo: log file configured" \
        || audit_warn "sudo: log file not configured"

    grep -rq 'TMOUT' /etc/profile /etc/profile.d/ 2>/dev/null \
        && audit_ok  "TMOUT: configured" \
        || audit_warn "TMOUT: not set (idle sessions unlimited)"

    local umask_val
    umask_val=$(grep -E '^\s*UMASK' /etc/login.defs 2>/dev/null | awk '{print $2}')
    umask_val="${umask_val:-022 (default)}"
    case "$umask_val" in
        027|077) audit_ok  "Umask: $umask_val" ;;
        *)       audit_warn "Umask: $umask_val (recommended: 027)" ;;
    esac

    echo ""
    echo -e "  ${BOLD}── Core Dumps · Accounts ─────────────────────────────────${RESET}"
    grep -rEq '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null \
        && audit_ok  "Core dumps disabled (limits.conf)" \
        || audit_warn "Core dumps not restricted"

    local empty_pass
    empty_pass=$(awk -F: '($2 == "" || $2 == "!!") && $3 >= 1000 {print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
    [ -z "$empty_pass" ] \
        && audit_ok  "No user accounts without password" \
        || audit_fail "Accounts without password: $empty_pass"

    # ── Summary ──────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}━━━  Audit Summary  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${GREEN}✔ Compliant     : $AUDIT_PASS${RESET}"
    echo -e "  ${RED}✖ Non-compliant : $AUDIT_FAIL${RESET}"
    echo -e "  ${ORANGE}⚠ Warnings      : $AUDIT_WARN${RESET}"
    echo ""
    log "AUDIT SUMMARY: PASS=$AUDIT_PASS FAIL=$AUDIT_FAIL WARN=$AUDIT_WARN"
}

# =============================================================================
#  PHASE 2: HARDENING — 22 SECTIONS
# =============================================================================

# ─── 1. SSH ───────────────────────────────────────────────────────────────────
harden_ssh() {
    section "1/22 · SSH"
    [ ! -f /etc/ssh/sshd_config ] && info "SSH not installed — section skipped." && return

    info "Direct root login via SSH."
    risk high "An attacker would only need the root password — no intermediate account required."
    if ask "Disable PermitRootLogin?" n; then
        set_sshd "PermitRootLogin" "no"; applied "PermitRootLogin no"
    else skipped "PermitRootLogin"; fi

    info "Maximum SSH authentication attempts per session."
    risk medium "Limiting to 3 drastically reduces brute-force effectiveness even without fail2ban."
    if ask "Set MaxAuthTries to 3?" y; then
        set_sshd "MaxAuthTries" "3"; applied "MaxAuthTries 3"
    else skipped "MaxAuthTries"; fi

    info "Grace time to authenticate after TCP connection."
    risk low "30s is plenty — a higher value leaves pending connections open."
    if ask "Set LoginGraceTime to 30s?" y; then
        set_sshd "LoginGraceTime" "30"; applied "LoginGraceTime 30"
    else skipped "LoginGraceTime"; fi

    info "X11 graphical session forwarding over SSH."
    risk medium "Can allow a compromised server to inject keystrokes into your local graphical session."
    if ask "Disable X11Forwarding?" y; then
        set_sshd "X11Forwarding" "no"; applied "X11Forwarding no"
    else skipped "X11Forwarding"; fi

    info "Arbitrary TCP tunneling over SSH."
    risk medium "Allows bypassing firewall rules by encapsulating traffic inside SSH."
    if ask "Disable AllowTcpForwarding?" y; then
        set_sshd "AllowTcpForwarding" "no"; applied "AllowTcpForwarding no"
    else skipped "AllowTcpForwarding"; fi

    info "Auto-disconnect idle SSH sessions."
    risk low "Idle sessions left open are an attack surface for physical or pivot access."
    if ask "Disconnect after 15 min of SSH inactivity?" y; then
        set_sshd "ClientAliveInterval" "300"
        set_sshd "ClientAliveCountMax" "3"
        applied "ClientAliveInterval=300 / ClientAliveCountMax=3 (15 min)"
    else skipped "ClientAliveInterval"; fi

    info "SSH cryptographic suites — remove legacy algorithms."
    risk medium "3DES, arcfour, blowfish are vulnerable. Enforce AES-GCM, ChaCha20, curve25519."
    if ask "Enforce modern Ciphers/MACs/KexAlgorithms?" y; then
        set_sshd "Ciphers"       "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
        set_sshd "MACs"          "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
        set_sshd "KexAlgorithms" "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
        applied "Modern Ciphers/MACs/KexAlgorithms"
    else skipped "SSH Ciphers"; fi

    info "Legal warning banner displayed at each SSH login."
    risk low "Legal/audit value. Required by CIS and ANSSI. Deterrent for attackers."
    if ask "Set a legal banner (/etc/issue.net)?" y; then
        _exec "printf 'Authorized users only. All activity is monitored and logged.\n' > /etc/issue.net"
        set_sshd "Banner" "/etc/issue.net"
        applied "SSH banner configured"
    else skipped "SSH banner"; fi

    echo ""
    warn "PasswordAuthentication NOT modified — adjust manually based on your setup (key / password+2FA)."
    sshd_restart && info "sshd reloaded."
}

# ─── 2. Passwords ────────────────────────────────────────────────────────────
harden_passwords() {
    section "2/22 · Password Policy"

    info "Password complexity (libpam-pwquality)."
    risk high "Without constraints, users can set 'password1'. CIS requires minlen=14, 4 character classes."
    if ask "Configure pwquality (minlen=14, 4 classes, maxrepeat=3)?" y; then
        $IS_DEBIAN && _exec "apt-get install -y -qq libpam-pwquality"
        $IS_RHEL   && _exec "$PKG_INSTALL libpwquality"
        $IS_SUSE   && _exec "$PKG_INSTALL pam_pwquality"
        local pwq="/etc/security/pwquality.conf"
        set_config "minlen"      "14" "$pwq"
        set_config "minclass"    "4"  "$pwq"
        set_config "maxrepeat"   "3"  "$pwq"
        set_config "maxsequence" "3"  "$pwq"
        set_config "difok"       "2"  "$pwq"
        applied "pwquality: minlen=14 minclass=4 maxrepeat=3 maxsequence=3 difok=2"
    else skipped "pwquality"; fi

    info "Account lockout after failed attempts (faillock)."
    risk high "Without faillock, an attacker can try thousands of passwords locally without any lockout."
    if ask "Configure faillock (5 attempts, 15 min lockout)?" y; then
        local flk="/etc/security/faillock.conf"
        [ ! -f "$flk" ] && _exec "touch $flk"
        set_config "deny"             "5"   "$flk"
        set_config "unlock_time"      "900" "$flk"
        set_config "root_unlock_time" "60"  "$flk"
        applied "faillock: deny=5 unlock=900s root_unlock=60s"
    else skipped "faillock"; fi

    info "Password expiration (login.defs + chage on existing accounts)."
    risk medium "A compromised password with no expiration remains valid indefinitely."
    if ask "Set expiration: max 90d, min 1d, warn 7d, inactive 45d?" y; then
        set_login_def "PASS_MAX_DAYS" "90"
        set_login_def "PASS_MIN_DAYS" "1"
        set_login_def "PASS_WARN_AGE" "7"
        while IFS=: read -r user _ uid _; do
            if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$user" != "nobody" ]; then
                _exec "chage --mindays 1 --maxdays 90 --warndays 7 --inactive 45 \"$user\""
            fi
        done < /etc/passwd
        _exec "chage --mindays 1 --maxdays 90 --warndays 7 --inactive 45 root"
        applied "Expiration: max=90d min=1d warn=7d inactive=45d"
    else skipped "Password expiration"; fi
}

# ─── 3. Password hashing ─────────────────────────────────────────────────────
harden_password_hash() {
    section "3/22 · Password Hashing Algorithm"

    info "Checking the hashing algorithm used for /etc/shadow."
    risk high "MD5 is crackable in minutes on a GPU. DES in seconds. SHA-512 or yescrypt are current standards — resistant to dictionary attacks."
    local current_algo
    current_algo=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}')
    current_algo="${current_algo:-not set}"
    info "Current algorithm: $current_algo"

    case "${current_algo^^}" in
        SHA512|YESCRYPT)
            ok "Algorithm already secure ($current_algo)"
            skipped "Hashing (already good)"
            ;;
        *)
            if ask "Switch password hashing to SHA512?" y; then
                set_login_def "ENCRYPT_METHOD" "SHA512"
                if $IS_DEBIAN && [ -f /etc/pam.d/common-password ]; then
                    backup_file /etc/pam.d/common-password
                    _exec "sed -i 's/pam_unix.so.*/pam_unix.so obscure sha512/' /etc/pam.d/common-password"
                fi
                applied "ENCRYPT_METHOD=SHA512 (new passwords only)"
                dim "Existing passwords are not changed — they will be re-hashed on next update."
            else skipped "Hashing"; fi
            ;;
    esac
}

# ─── 4. Kernel sysctl — network ──────────────────────────────────────────────
harden_sysctl_network() {
    section "4/22 · Kernel sysctl — Network"
    local cfg="/etc/sysctl.d/99-hardening.conf"
    info "IPv4/IPv6 network parameters (file: $cfg)"
    risk high "ICMP redirects, source routing and missing SYN cookies expose to MITM, SYN flood, IP spoofing."
    if ask "Apply IPv4/IPv6 network hardening?" y; then
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
        applied "Network sysctl parameters written to $cfg"
    else skipped "Network sysctl"; fi
}

# ─── 5. Kernel sysctl — system ───────────────────────────────────────────────
harden_sysctl_kernel() {
    section "5/22 · Kernel sysctl — System"
    local cfg="/etc/sysctl.d/99-hardening.conf"

    info "ASLR, ptrace, kptr_restrict, dmesg, hardlinks, core dumps."
    risk high "These parameters drastically reduce local privilege escalation (LPE) attack surface."
    if ask "Apply kernel hardening (ASLR, ptrace, kptr, dmesg)?" y; then
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
        applied "Kernel sysctl parameters written to $cfg"
    else skipped "Kernel sysctl"; fi

    info "Unprivileged eBPF — prevent regular users from loading BPF programs."
    risk high "Unrestricted eBPF has been exploited in several recent LPEs (CVE-2021-3490, CVE-2022-23222...). Unnecessary for standard users."
    if ask "Disable unprivileged BPF (bpf + bpf_jit_harden)?" y; then
        sysctl_set "kernel.unprivileged_bpf_disabled=1" "$cfg"
        sysctl_set "net.core.bpf_jit_harden=2"          "$cfg"
        applied "Unprivileged BPF disabled"
    else skipped "BPF hardening"; fi

    info "IP forwarding — disable if the system is not a router."
    risk medium "Enabling ip_forward turns the system into a potential router, allowing traffic to be forwarded between interfaces."
    if ask "Disable IPv4/IPv6 forwarding (if not a router)?" y; then
        sysctl_set "net.ipv4.ip_forward=0"          "$cfg"
        sysctl_set "net.ipv6.conf.all.forwarding=0" "$cfg"
        applied "IP forwarding disabled"
    else skipped "IP forwarding"; fi

    if ask "Apply now (sysctl --system)?" y; then
        _exec "sysctl --system"; applied "sysctl --system executed"
    fi
}

# ─── 6. Magic SysRq + Ctrl+Alt+Del ──────────────────────────────────────────
harden_sysrq_ctrlaltdel() {
    section "6/22 · Magic SysRq & Ctrl+Alt+Del"

    info "Magic SysRq — key sequence to send low-level commands directly to the kernel."
    risk medium "On a server, SysRq allows anyone with keyboard/serial access to force reboot, kill processes or remount filesystems read-write."
    if ask "Disable Magic SysRq (kernel.sysrq=0)?" y; then
        local cfg="/etc/sysctl.d/99-hardening.conf"
        sysctl_set "kernel.sysrq=0" "$cfg"
        _exec "sysctl -w kernel.sysrq=0"
        applied "Magic SysRq disabled"
    else skipped "Magic SysRq"; fi

    info "Ctrl+Alt+Del — immediately reboots the system on most distros."
    risk medium "Physical or serial console access could reboot a production server accidentally or maliciously."
    if ask "Disable Ctrl+Alt+Del (systemd)?" y; then
        _exec "systemctl mask ctrl-alt-del.target"
        _exec "systemctl daemon-reload"
        applied "Ctrl+Alt+Del masked"
    else skipped "Ctrl+Alt+Del"; fi
}

# ─── 7. Secure mounts ────────────────────────────────────────────────────────
harden_mounts() {
    section "7/22 · Secure Mount Options"

    info "/dev/shm — shared memory between processes."
    risk high "Executable /dev/shm is used in known exploits to drop and run payloads in memory, bypassing filesystem protections."
    if ask "Secure /dev/shm (nodev,nosuid,noexec)?" y; then
        backup_file /etc/fstab
        local shm_entry="tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"
        if grep -q "^tmpfs /dev/shm" /etc/fstab; then
            _exec "sed -i 's|^tmpfs /dev/shm.*|$shm_entry|' /etc/fstab"
        else
            _exec "echo '$shm_entry' >> /etc/fstab"
        fi
        _exec "mount -o remount,noexec /dev/shm 2>/dev/null || true"
        applied "/dev/shm: nodev,nosuid,noexec"
    else skipped "/dev/shm"; fi

    info "/tmp — world-writable temporary directory."
    risk medium "Malware classically drops binaries in /tmp before execution. noexec blocks this technique."
    dim "Warning: some installers write and execute scripts from /tmp. Test on a non-critical machine first."
    if ask "Secure /tmp (nodev,nosuid,noexec)?" n; then
        if ask "Confirm /tmp noexec?" n; then
            backup_file /etc/fstab
            if grep -qE '[[:space:]]/tmp[[:space:]]' /etc/fstab; then
                _exec "sed -i '/[[:space:]]\/tmp[[:space:]]/s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab"
            else
                _exec "echo 'tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab"
            fi
            applied "/tmp: nodev,nosuid,noexec (reboot required)"
        else skipped "/tmp"; fi
    else skipped "/tmp"; fi
}

# ─── 8. /proc hidepid ────────────────────────────────────────────────────────
harden_proc_hidepid() {
    section "8/22 · /proc hidepid — Process Isolation"

    info "By default, any user can list all other users' processes via /proc."
    risk medium "An attacker or compromised user can see command-line arguments (sometimes passwords), environment variables and file descriptors of all running processes."

    if ask "Mount /proc with hidepid=2 (users only see their own processes)?" y; then
        backup_file /etc/fstab
        if grep -qE '[[:space:]]/proc[[:space:]]' /etc/fstab; then
            _exec "sed -i '/[[:space:]]\/proc[[:space:]]/s/defaults/defaults,hidepid=2/' /etc/fstab"
        else
            _exec "echo 'proc /proc proc defaults,hidepid=2 0 0' >> /etc/fstab"
        fi
        _exec "mount -o remount,hidepid=2 /proc 2>/dev/null || true"
        warn "Some monitoring tools (ps, top, htop as root) still work — hidepid=2 only affects non-root users."
        applied "/proc: hidepid=2 (reboot to persist via fstab)"
    else skipped "/proc hidepid"; fi
}

# ─── 9. Core dumps ───────────────────────────────────────────────────────────
harden_coredumps() {
    section "9/22 · Core Dumps"

    info "Core dumps can contain private keys, tokens, password hashes present in memory."
    risk high "A core dump from a SUID process can reveal critical secrets if captured by a local unprivileged user."
    if ask "Disable core dumps (limits.conf + sysctl + systemd)?" y; then
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
        applied "Core dumps disabled"
    else skipped "Core dumps"; fi
}

# ─── 10. Umask ───────────────────────────────────────────────────────────────
harden_umask() {
    section "10/22 · Default Umask"

    info "Umask determines default permissions for newly created files and directories."
    risk medium "Umask 022 creates world-readable files (644). Umask 027 restricts to group members — better practice for multi-user servers."
    local current_umask
    current_umask=$(grep -E '^\s*UMASK' /etc/login.defs 2>/dev/null | awk '{print $2}')
    current_umask="${current_umask:-022}"
    info "Current umask (login.defs): $current_umask"

    if ask "Set umask to 027 (login.defs + /etc/profile.d)?" y; then
        set_login_def "UMASK" "027"
        local f="/etc/profile.d/99-umask.sh"
        if [ "$DRY_RUN" = false ]; then
            echo "umask 027" > "$f"
            chmod +x "$f"
        else
            echo -e "  ${DIM}[DRY-RUN] echo 'umask 027' > $f${RESET}"
        fi
        applied "Umask=027 (login.defs + profile.d)"
        dim "Takes effect on new sessions only."
    else skipped "Umask"; fi
}

# ─── 11. Unnecessary services ────────────────────────────────────────────────
harden_services() {
    section "11/22 · Unnecessary / Dangerous Services"

    if systemctl list-units --all 2>/dev/null | grep -q avahi; then
        info "Avahi-daemon — mDNS/DNS-SD resolution (Bonjour)."
        risk medium "Broadcasts hostname and services on the local network. Facilitates reconnaissance and MITM attacks."
        if ask "Disable and mask avahi-daemon?" y; then
            for svc in avahi-daemon.socket avahi-daemon.service; do
                _exec "systemctl stop $svc 2>/dev/null || true"
                _exec "systemctl disable $svc 2>/dev/null || true"
                _exec "systemctl mask $svc 2>/dev/null || true"
            done
            applied "avahi-daemon masked"
        else skipped "avahi-daemon"; fi
    else ok "avahi-daemon not present"; fi

    if systemctl list-units --all 2>/dev/null | grep -q cups; then
        info "CUPS — network printing service."
        risk medium "History of critical CVEs including RCEs. Unnecessary on servers without printers."
        if ask "Disable CUPS?" y; then
            for svc in cups.socket cups.service cups-browsed.service; do
                _exec "systemctl stop $svc 2>/dev/null || true"
                _exec "systemctl mask $svc 2>/dev/null || true"
            done
            applied "CUPS masked"
        else skipped "CUPS"; fi
    else ok "CUPS not present"; fi

    info "NTP synchronization — essential for log consistency."
    risk medium "Wrong timestamps break forensic investigations and can break Kerberos auth (drift > 5 min)."
    if ask "Configure NTP: pool.ntp.org?" y; then
        backup_file /etc/systemd/timesyncd.conf
        if grep -q "^#NTP=" /etc/systemd/timesyncd.conf 2>/dev/null; then
            _exec "sed -i 's|^#NTP=.*|NTP=pool.ntp.org|' /etc/systemd/timesyncd.conf"
        elif ! grep -q "^NTP=" /etc/systemd/timesyncd.conf 2>/dev/null; then
            _exec "echo 'NTP=pool.ntp.org' >> /etc/systemd/timesyncd.conf"
        fi
        _exec "systemctl enable systemd-timesyncd --now && systemctl restart systemd-timesyncd"
        applied "NTP: pool.ntp.org"
    else skipped "NTP"; fi

    if systemctl list-units --all 2>/dev/null | grep -q apport; then
        info "Apport — automatic error reporting (Ubuntu)."
        risk low "Can send system information (crashes, stack traces) to Canonical."
        if ask "Disable apport?" y; then
            _exec "systemctl disable apport.service --now 2>/dev/null || true"
            _exec "sed -i 's/enabled=1/enabled=0/' /etc/default/apport 2>/dev/null || true"
            applied "apport disabled"
        else skipped "apport"; fi
    fi
}

# ─── 12. Auditd ──────────────────────────────────────────────────────────────
harden_auditd() {
    section "12/22 · Auditd — System Logging"

    info "auditd traces syscalls, sensitive file access, privilege escalations."
    risk high "Without auditd, you cannot detect or investigate an intrusion. Recommended by CIS, ANSSI and all operational best practices."

    if ask "Install/activate auditd + CIS baseline rules?" y; then
        $IS_DEBIAN && _exec "apt-get install -y -qq auditd audispd-plugins"
        $IS_RHEL   && _exec "$PKG_INSTALL audit audit-libs"
        $IS_SUSE   && _exec "$PKG_INSTALL audit"
        $IS_ARCH   && _exec "pacman -S --noconfirm audit"
        _exec "systemctl enable auditd --now"

        local rules_file="/etc/audit/rules.d/99-hardening.rules"
        if [ "$DRY_RUN" = false ]; then
            cat > "$rules_file" <<'AUDRULES'
## auditd rules — linux-hardening.sh (CIS + ANSSI R41+)
-D
-b 8192
-f 1

## Authentication files
-w /etc/shadow    -p wa -k auth_files
-w /etc/passwd    -p wa -k auth_files
-w /etc/group     -p wa -k auth_files
-w /etc/gshadow   -p wa -k auth_files
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

## SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/            -p wa -k ssh_config

## auditd config itself
-w /etc/audit/   -p wa -k audit_config
-w /sbin/auditctl -p x -k auditctl

## Privilege escalation
-w /bin/su           -p x -k priv_esc
-w /usr/bin/sudo     -p x -k priv_esc
-a always,exit -F arch=b64 -S setuid -S setgid -k setuid

## Cron
-w /etc/cron.d       -p wa -k cron
-w /etc/cron.daily   -p wa -k cron
-w /etc/cron.hourly  -p wa -k cron
-w /etc/crontab      -p wa -k cron
-w /var/spool/cron   -p wa -k cron

## Kernel modules
-w /sbin/insmod   -p x -k kernel_modules
-w /sbin/rmmod    -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules

## Denied access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open -F exit=-EPERM  -k access_denied

## ptrace (memory injection)
-a always,exit -F arch=b64 -S ptrace -k ptrace

## Lock rules in production (requires reboot to change)
## -e 2
AUDRULES
        else
            echo -e "  ${DIM}[DRY-RUN] Writing $rules_file${RESET}"
        fi
        _exec "augenrules --load 2>/dev/null || auditctl -R \"$rules_file\" 2>/dev/null || true"
        applied "auditd active + rules in $rules_file"
    else skipped "auditd"; fi
}

# ─── 13. Fail2ban ────────────────────────────────────────────────────────────
harden_fail2ban() {
    section "13/22 · Fail2ban"

    info "Automatically bans IPs after N consecutive authentication failures."
    risk high "Without fail2ban, an attacker can run brute-force attacks without being network-blocked."

    if ! command -v fail2ban-client &>/dev/null; then
        if ask "Install fail2ban?" y; then
            $IS_DEBIAN && _exec "apt-get install -y -qq fail2ban"
            $IS_RHEL   && _exec "$PKG_INSTALL epel-release; $PKG_INSTALL fail2ban"
            $IS_SUSE   && _exec "$PKG_INSTALL fail2ban"
            $IS_ARCH   && _exec "pacman -S --noconfirm fail2ban"
        else skipped "fail2ban"; return; fi
    fi

    if ask "Configure SSH jail (3 attempts, 2h ban)?" y; then
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
            echo -e "  ${DIM}[DRY-RUN] Writing /etc/fail2ban/jail.local${RESET}"
        fi
        _exec "systemctl enable fail2ban --now"
        applied "fail2ban: SSH — 3 attempts, 2h ban"
    else skipped "fail2ban jail"; fi
}

# ─── 14. Sudo ────────────────────────────────────────────────────────────────
harden_sudo() {
    section "14/22 · Sudo Hardening"

    if ! grep -Eq '^\s*Defaults.*logfile=' /etc/sudoers 2>/dev/null; then
        info "sudo doesn't log to a dedicated file by default."
        risk medium "A dedicated log file is required by CIS to track 'who did what as root'."
        if ask "Log sudo to /var/log/sudo.log?" y; then
            _exec "echo 'Defaults logfile=\"/var/log/sudo.log\"' | EDITOR='tee -a' visudo"
            applied "sudo logfile: /var/log/sudo.log"
        else skipped "sudo logfile"; fi
    else ok "sudo logfile already configured"; fi

    if ! grep -Eq '^\s*auth\s+required\s+pam_wheel' /etc/pam.d/su 2>/dev/null; then
        info "Restrict 'su' to sudo/wheel group members."
        risk medium "Without restriction, any user can attempt 'su root' with no lockout."
        if ask "Restrict 'su' to sudo/wheel group (pam_wheel)?" y; then
            backup_file /etc/pam.d/su
            local wgrp
            getent group wheel &>/dev/null && wgrp="wheel" || wgrp="sudo"
            _exec "sed -i '/^auth/a auth required pam_wheel.so use_uid group=$wgrp' /etc/pam.d/su"
            applied "pam_wheel for 'su' — group: $wgrp"
        else skipped "pam_wheel"; fi
    else ok "pam_wheel already configured"; fi

    info "sudo token timeout (default: 15 min)."
    risk low "Reducing to 5 min limits the window if a session is left open."
    if ask "Set sudo timeout to 5 min?" n; then
        _exec "echo 'Defaults timestamp_timeout=5' | EDITOR='tee -a' visudo"
        applied "sudo timestamp_timeout=5"
    else skipped "sudo timeout"; fi
}

# ─── 15. Cron ────────────────────────────────────────────────────────────────
harden_cron() {
    section "15/22 · Cron Permissions"

    info "Cron files must be owned by root:root with restrictive permissions."
    risk medium "Too-open permissions allow reading scheduled tasks (info leak) or modifying them (persistence)."
    if ask "Fix cron file permissions (og-rwx, root:root)?" y; then
        for f in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
            [ -e "$f" ] && _exec "chown root:root \"$f\" && chmod og-rwx \"$f\""
        done
        [ -f /etc/cron.deny ] || _exec "touch /etc/cron.deny"
        applied "Cron permissions fixed"
    else skipped "Cron"; fi
}

# ─── 16. TMOUT ───────────────────────────────────────────────────────────────
harden_tmout() {
    section "16/22 · Automatic Session Timeout"

    info "TMOUT automatically closes idle bash sessions."
    risk medium "An idle open session is an attack vector if someone gains physical or console access."
    if ask "Set TMOUT=900 (15 min) for all sessions?" y; then
        local f="/etc/profile.d/99-tmout.sh"
        if [ "$DRY_RUN" = false ]; then
            cat > "$f" <<'EOF'
# Auto-disconnect after 15 min of inactivity — linux-hardening.sh
readonly TMOUT=900
readonly HISTFILE
export TMOUT
EOF
            chmod +x "$f"
        else
            echo -e "  ${DIM}[DRY-RUN] Writing $f${RESET}"
        fi
        applied "TMOUT=900"
    else skipped "TMOUT"; fi
}

# ─── 17. Legal banners ───────────────────────────────────────────────────────
harden_banners() {
    section "17/22 · Legal Banners"

    info "Banner displayed at local (/etc/issue) and SSH (/etc/issue.net) logins."
    risk low "Legal/audit value for incidents. Required by CIS and ANSSI. Acts as a deterrent."
    if ask "Write a legal banner?" y; then
        printf "  Banner text (Enter for default): "
        read -r msg </dev/tty
        [ -z "$msg" ] && msg="Authorized users only. All activity is monitored and logged."
        _exec "echo '$msg' > /etc/issue"
        _exec "echo '$msg' > /etc/issue.net"
        applied "Legal banners written to /etc/issue and /etc/issue.net"
    else skipped "Banners"; fi
}

# ─── 18. AppArmor / SELinux ──────────────────────────────────────────────────
harden_mac() {
    section "18/22 · Mandatory Access Control (AppArmor / SELinux)"

    if $IS_DEBIAN; then
        info "AppArmor confines processes within strict access profiles."
        risk high "Limits the blast radius of an application vulnerability (nginx, samba...) by preventing the process from accessing out-of-profile resources."
        if ! systemctl is-active apparmor &>/dev/null; then
            if ask "Install and activate AppArmor?" y; then
                _exec "apt-get install -y -qq apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra"
                _exec "systemctl enable apparmor --now"
                applied "AppArmor installed and active"
            else skipped "AppArmor"; fi
        else
            ok "AppArmor already active"
            if ask "Switch all AppArmor profiles to 'enforce' mode?" n; then
                warn "Enforce mode may block legitimate applications. Monitor /var/log/kern.log."
                if ask "Confirm enforce?" n; then
                    _exec "aa-enforce /etc/apparmor.d/* 2>/dev/null || true"
                    applied "AppArmor: enforce"
                else skipped "AppArmor enforce"; fi
            else skipped "AppArmor enforce"; fi
        fi
    elif $IS_RHEL; then
        info "SELinux — integrated MAC for RHEL/CentOS/Alma/Rocky."
        risk high "SELinux Enforcing is the most robust Linux protection against kernel and application exploits."
        local selinux_status; selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
        info "SELinux status: $selinux_status"
        if [ "$selinux_status" != "Enforcing" ]; then
            if ask "Enable SELinux Enforcing?" n; then
                warn "Test in Permissive mode first (use audit2allow to capture denials)."
                if ask "Confirm Enforcing?" n; then
                    _exec "setenforce 1 2>/dev/null || true"
                    backup_file /etc/selinux/config
                    _exec "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
                    applied "SELinux Enforcing (reboot for full effect)"
                else skipped "SELinux enforcing"; fi
            else skipped "SELinux"; fi
        else ok "SELinux already Enforcing"; fi
    fi
}

# ─── 19. Automatic updates ───────────────────────────────────────────────────
harden_updates() {
    section "19/22 · Automatic Security Updates"

    info "Security-only automatic updates."
    risk high "Most compromises exploit patched CVEs. Vulnerability management is a universal best practice."
    dim "On critical production servers, prefer manually tested updates before deployment."

    if $IS_DEBIAN; then
        if ask "Install unattended-upgrades (security-only)?" n; then
            _exec "apt-get install -y -qq unattended-upgrades apt-listchanges"
            _exec "dpkg-reconfigure --frontend=noninteractive unattended-upgrades"
            applied "unattended-upgrades installed"
        else skipped "unattended-upgrades"; fi
    elif $IS_RHEL; then
        if ask "Install dnf-automatic (security-only)?" n; then
            _exec "$PKG_INSTALL dnf-automatic"
            backup_file /etc/dnf/automatic.conf
            _exec "sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf"
            _exec "sed -i 's/^upgrade_type = default/upgrade_type = security/' /etc/dnf/automatic.conf"
            _exec "systemctl enable dnf-automatic.timer --now"
            applied "dnf-automatic (security-only)"
        else skipped "dnf-automatic"; fi
    fi
}

# ─── 20. Critical file permissions ───────────────────────────────────────────
harden_file_perms() {
    section "20/22 · Critical File Permissions"

    info "Permissions on /etc/shadow, passwd, sudoers, grub."
    risk high "/etc/shadow world-readable = exposed hashes. /etc/passwd writable = phantom accounts possible."
    if ask "Fix critical file permissions?" y; then
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
        applied "Critical file permissions fixed"
    else skipped "File permissions"; fi
}

# ─── 21. Kernel modules ──────────────────────────────────────────────────────
harden_kernel_modules() {
    section "21/22 · Unused Kernel Modules"

    info "Disable rarely-used network protocols and filesystems."
    risk medium "DCCP, SCTP, RDS, TIPC all had critical CVEs (RCE/LPE). Blacklisting removes attack surface without operational impact if unused."
    if ask "Blacklist unused modules (dccp, sctp, rds, tipc, cramfs, hfs...)?" y; then
        local f="/etc/modprobe.d/99-hardening-blacklist.conf"
        if [ "$DRY_RUN" = false ]; then
            cat > "$f" <<'MODULES'
# Blacklisted modules — linux-hardening.sh (CIS + ANSSI)

# Rarely-used network protocols (historical CVEs)
install dccp    /bin/true
install sctp    /bin/true
install rds     /bin/true
install tipc    /bin/true
install n-hdlc  /bin/true

# Rare/legacy filesystems
install cramfs   /bin/true
install freevxfs /bin/true
install jffs2    /bin/true
install hfs      /bin/true
install hfsplus  /bin/true
install udf      /bin/true

# USB storage — uncomment to block USB drives
# install usb-storage /bin/true
MODULES
        else
            echo -e "  ${DIM}[DRY-RUN] Writing /etc/modprobe.d/99-hardening-blacklist.conf${RESET}"
        fi
        applied "Modules blacklisted (takes effect on next boot)"
    else skipped "Kernel modules"; fi

    info "Disable USB storage (usb-storage)."
    risk high "USB drives are a classic vector for malware introduction and data exfiltration on servers."
    dim "Mice, keyboards, USB audio and chargers are NOT affected — only mass storage."
    if ask "Disable usb-storage?" n; then
        if ask "Confirm — no more USB drives on this system?" n; then
            _exec "echo 'install usb-storage /bin/true' >> /etc/modprobe.d/99-hardening-blacklist.conf"
            _exec "modprobe -r usb-storage 2>/dev/null || true"
            applied "usb-storage disabled"
        else skipped "USB storage"; fi
    else skipped "USB storage"; fi
}

# ─── 22. Post-hardening scan ─────────────────────────────────────────────────
harden_scan() {
    section "22/22 · Post-Hardening Security Scan"

    info "Scan for world-writable files and non-standard SUID binaries."
    risk medium "A world-writable file in /etc or /usr can be modified by anyone. An unknown SUID binary may be a backdoor or LPE vector."

    if ask "Scan for world-writable files (excluding /tmp, /dev, /proc)?" y; then
        echo ""
        info "World-writable files found:"
        if [ "$DRY_RUN" = false ]; then
            local ww_files
            ww_files=$(find / -xdev -type f -perm -0002 \
                -not -path '/tmp/*' -not -path '/var/tmp/*' \
                -not -path '/proc/*' -not -path '/dev/*' \
                -not -path '/sys/*' 2>/dev/null)
            if [ -z "$ww_files" ]; then
                ok "No world-writable files found outside /tmp and /dev."
            else
                echo "$ww_files" | while read -r f; do warn "$f"; done
                echo "$ww_files" >> "$LOG_FILE"
            fi
        else
            echo -e "  ${DIM}[DRY-RUN] find / -xdev -perm -0002 ...${RESET}"
        fi
        applied "World-writable scan done (see log $LOG_FILE)"
    else skipped "World-writable scan"; fi

    if ask "Scan for non-standard SUID/SGID binaries?" y; then
        echo ""
        info "SUID/SGID binaries found (excluding /proc, /sys, /dev):"
        if [ "$DRY_RUN" = false ]; then
            find / -xdev -type f \( -perm -4000 -o -perm -2000 \) \
                -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' \
                2>/dev/null | sort | while read -r f; do
                    warn "$f  ($(stat -c '%U:%G %a' "$f" 2>/dev/null))"
            done
        else
            echo -e "  ${DIM}[DRY-RUN] find / -xdev -perm -4000 -o -perm -2000 ...${RESET}"
        fi
        dim "Review this list manually — any unknown SUID binary is suspicious."
        applied "SUID/SGID scan done (see log $LOG_FILE)"
    else skipped "SUID scan"; fi
}

# =============================================================================
#  FINAL REPORT
# =============================================================================
final_report() {
    echo ""
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║                        FINAL REPORT                                 ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  ${GREEN}✔ Actions applied  : $APPLIED${RESET}"
    echo -e "  ${DIM}↷ Actions skipped  : $SKIPPED${RESET}"
    echo -e "  ${RED}✖ Errors           : $ERRORS${RESET}"
    echo ""
    echo -e "  📋 Full log: ${BOLD}$LOG_FILE${RESET}"
    echo ""
    echo -e "  ${BOLD}Backups created (.harden.bak):${RESET}"
    find / -maxdepth 6 -name "*.harden.bak" 2>/dev/null | head -15 | \
        while read -r f; do echo -e "  ${DIM}$f${RESET}"; done
    echo ""
    echo -e "  ${ORANGE}${BOLD}Recommended manual steps:${RESET}"
    echo -e "  ${DIM}1. Open a NEW SSH session to test before closing the current one${RESET}"
    echo -e "  ${DIM}2. Reboot to apply sysctl, kernel modules, fstab changes${RESET}"
    echo -e "  ${DIM}3. Test critical applications after reboot${RESET}"
    echo -e "  ${DIM}4. Run a full Lynis audit: sudo lynis audit system${RESET}"
    echo -e "  ${DIM}5. Check auditd: ausearch -k auth_files | aureport -f${RESET}"
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
    echo -e "  System   : ${BOLD}$DISTRO_NAME $DISTRO_VERSION${RESET} ($(uname -m))"
    echo -e "  Packages : ${BOLD}$PKG_MANAGER${RESET}"
    echo -e "  Log      : $LOG_FILE"
    echo ""
    log "START: distro=$DISTRO pkg=$PKG_MANAGER kernel=$(uname -r)"

    run_audit

    if [ "$AUDIT_ONLY" = true ]; then
        echo -e "\n  ${CYAN}Audit mode: no changes made.${RESET}\n"
        exit 0
    fi

    echo ""
    echo -e "${BOLD}  Audit complete. The script will now walk through ${GREEN}22 hardening sections${RESET}${BOLD}."
    echo -e "  A question is asked before each action.${RESET}"
    echo ""
    if ! ask "Start interactive hardening?" y; then
        echo -e "\n  Clean exit. No changes made.\n"; exit 0
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
