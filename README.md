<div align="center">

# 🛡️ HardenKit

[![Version](https://img.shields.io/badge/version-3.0.0-blue?style=flat-square)](https://github.com/Grujowmi/HardenKit/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash-89e051?style=flat-square&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![CIS](https://img.shields.io/badge/CIS-Benchmarks-orange?style=flat-square)](https://www.cisecurity.org/)
[![ANSSI](https://img.shields.io/badge/ANSSI-R41%2B-blue?style=flat-square)](https://www.ssi.gouv.fr/)
[![Distros](https://img.shields.io/badge/distros-Debian%20·%20Ubuntu%20·%20RHEL%20·%20Arch%20·%20openSUSE-lightgrey?style=flat-square)](#compatibilité--compatibility)

**🇫🇷 Script de durcissement Linux interactif — auditez votre système, puis corrigez-le étape par étape.**

**🇬🇧 Interactive Linux hardening script — audit your system, then fix it one step at a time.**

[🇫🇷 Français](#-français) · [🇬🇧 English](#-english)

</div>

---

## 🇫🇷 Français

### Présentation

HardenKit agrège les meilleures pratiques de **CIS Benchmarks**, **ANSSI R41+**, **dev-sec/linux-baseline**, **Wazuh**, **captainzero93/security_harden_linux**, **trimstray** et **DISA STIG** dans un seul script bash interactif.

Il se déroule en deux phases :

1. **Audit** — scan de l'état de sécurité actuel avec un rapport `✔ CONFORME / ✖ NON CONFORME / ⚠ AVERTISSEMENT`
2. **Hardening interactif** — 22 sections, une question par action, chaque action accompagnée d'une explication et d'un niveau de risque avant application

> Aucune action n'est appliquée sans confirmation explicite.

---

### Démarrage rapide

```bash
# Cloner le dépôt
git clone https://github.com/Grujowmi/HardenKit.git
cd HardenKit

# Audit seul — aucune modification
sudo bash linux-hardening-fr.sh --audit

# Simulation — montre ce qui serait fait sans rien appliquer
sudo bash linux-hardening-fr.sh --dry-run

# Mode interactif complet (recommandé)
sudo bash linux-hardening-fr.sh
```

> ⚠️ **Ouvrez toujours une nouvelle session SSH pour tester la connectivité avant de fermer la session en cours.**

---

### Modes d'exécution

| Flag | Description |
|------|-------------|
| *(aucun)* | Mode interactif complet — audit puis hardening |
| `--audit` | Audit seul, aucune modification |
| `--dry-run` | Simule les actions sans les appliquer |

---

### Sections de durcissement (22)

| # | Section | Actions principales |
|---|---------|---------------------|
| 1 | 🔐 SSH | PermitRootLogin, MaxAuthTries, LoginGraceTime, X11/TCP forwarding, ciphers modernes, bannière |
| 2 | 🔑 Politique mots de passe | pwquality (minlen=14, 4 classes), faillock (verrouillage), expiration |
| 3 | 🔒 Algorithme de hashage | Forcer SHA-512 / yescrypt (migration depuis MD5/DES) |
| 4 | 🌐 sysctl — réseau | Redirects ICMP, source routing, SYN cookies, log martians |
| 5 | ⚙️ sysctl — kernel | ASLR, ptrace, kptr_restrict, dmesg, BPF non-privilégié, forwarding IP |
| 6 | ⌨️ Magic SysRq & Ctrl+Alt+Del | Désactiver les vecteurs d'attaque bas niveau clavier |
| 7 | 💾 Montages sécurisés | /dev/shm et /tmp avec nodev, nosuid, noexec |
| 8 | 🔍 /proc hidepid | Isoler les processus entre utilisateurs |
| 9 | 💥 Core dumps | Désactiver via limits.conf + sysctl + systemd |
| 10 | 📁 Umask | Resserrer les permissions par défaut (022 → 027) |
| 11 | 🚫 Services inutiles | Désactiver avahi, CUPS, configurer NTP, désactiver apport |
| 12 | 📋 Auditd | Installer, activer, charger les règles CIS/ANSSI |
| 13 | 🚧 Fail2ban | Installer, configurer le jail SSH (3 tentatives, ban 2h) |
| 14 | 🔧 Sudo | Log dédié, pam_wheel pour su, timeout |
| 15 | 🕐 Cron | Corriger les permissions (og-rwx, root:root) |
| 16 | ⏱️ TMOUT | Déconnexion automatique des sessions inactives (15 min) |
| 17 | 📢 Bannières légales | /etc/issue et /etc/issue.net |
| 18 | 🛡️ AppArmor / SELinux | Activer et enforcer le MAC (selon distrib) |
| 19 | 🔄 Mises à jour auto | unattended-upgrades ou dnf-automatic (security-only) |
| 20 | 📄 Permissions fichiers | shadow, passwd, sudoers, grub — owner + mode corrects |
| 21 | 🧩 Modules kernel | Blacklist dccp, sctp, rds, tipc, cramfs, hfs, usb-storage |
| 22 | 🔎 Scan post-hardening | Fichiers world-writable + binaires SUID/SGID non standards |

---

### Ce que le script ne fait PAS

- **Forcer l'auth par clé SSH uniquement** — `PasswordAuthentication` n'est jamais modifié. Si vous utilisez mdp+2FA, c'est respecté. Ajustez manuellement si besoin.
- **Modifier votre pare-feu** — les règles UFW, firewalld et iptables existantes ne sont pas touchées.
- **Appliquer quoi que ce soit automatiquement** — chaque action requiert une confirmation explicite.

---

### Compatibilité

| Distribution | Statut |
|-------------|--------|
| Ubuntu 22.04 / 24.04 | ✅ |
| Debian 11 / 12 | ✅ |
| AlmaLinux / Rocky 8 / 9 | ✅ |
| Fedora 39+ | ✅ |
| openSUSE Leap / Tumbleweed | ✅ |
| Arch Linux / Manjaro | ✅ |

---

### Sources

| Source | Contribution |
|--------|-------------|
| [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | sysctl, PAM, permissions fichiers, cron, règles auditd |
| [ANSSI R41+](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-un-systeme-gnulinux/) | Complexité mdp, règles audit, bannière légale |
| [dev-sec/linux-baseline](https://github.com/dev-sec/linux-baseline) | sysctl hardening, blacklist modules |
| [captainzero93/security_harden_linux](https://github.com/captainzero93/security_harden_linux) | Désactivation services, approche dry-run |
| [trimstray/linux-hardening-guide](https://github.com/trimstray/the-practical-linux-hardening-guide) | hidepid, umask, SysRq, Ctrl+Alt+Del |
| [Wazuh hardening](https://github.com/wazuh) | /dev/shm, PAM faillock, auditd, permissions cron |
| [DISA STIG](https://public.cyber.mil/stigs/) | Hashage SHA-512, BPF hardening, TMOUT |

---

### Après exécution

```bash
# 1. Ouvrir une nouvelle session SSH pour tester avant de fermer l'actuelle

# 2. Redémarrer (sysctl, modules kernel, fstab)
sudo reboot

# 3. Audit complet avec Lynis
sudo apt install lynis   # ou dnf/pacman
sudo lynis audit system

# 4. Vérifier les logs auditd
ausearch -k auth_files | aureport -f
ausearch -k priv_esc
```

---

### Restaurer une sauvegarde

Chaque fichier modifié reçoit une copie `.harden.bak` avant toute modification.

```bash
# Lister toutes les sauvegardes
find / -maxdepth 6 -name "*.harden.bak" 2>/dev/null

# Restaurer un fichier
cp /etc/ssh/sshd_config.harden.bak /etc/ssh/sshd_config
systemctl restart sshd
```

---

<br>

---

## 🇬🇧 English

### Overview

HardenKit aggregates best practices from **CIS Benchmarks**, **ANSSI R41+**, **dev-sec/linux-baseline**, **Wazuh**, **captainzero93/security_harden_linux**, **trimstray** and **DISA STIG** into a single interactive bash script.

It runs in two phases:

1. **Audit** — scans your current security state and produces a `✔ PASS / ✖ FAIL / ⚠ WARN` report
2. **Interactive hardening** — 22 sections, one question per action, each with a risk level and explanation before applying

> No action is applied without explicit confirmation.

---

### Quick Start

```bash
# Clone the repo
git clone https://github.com/Grujowmi/HardenKit.git
cd HardenKit

# Audit only — no changes
sudo bash linux-hardening-en.sh --audit

# Dry run — shows what would be done without applying
sudo bash linux-hardening-en.sh --dry-run

# Full interactive mode (recommended)
sudo bash linux-hardening-en.sh
```

> ⚠️ **Always open a new SSH session to test connectivity before closing the current one.**

---

### Modes

| Flag | Description |
|------|-------------|
| *(none)* | Full interactive mode — audit then harden |
| `--audit` | Audit only, no changes made |
| `--dry-run` | Simulates actions without applying anything |

---

### Hardening Sections (22)

| # | Section | Key actions |
|---|---------|-------------|
| 1 | 🔐 SSH | PermitRootLogin, MaxAuthTries, LoginGraceTime, X11/TCP forwarding, modern ciphers, banner |
| 2 | 🔑 Password policy | pwquality (minlen=14, 4 classes), faillock (lockout), expiration |
| 3 | 🔒 Password hashing | Enforce SHA-512 / yescrypt (migrate from MD5/DES) |
| 4 | 🌐 sysctl — network | ICMP redirects, source routing, SYN cookies, martian logging |
| 5 | ⚙️ sysctl — kernel | ASLR, ptrace, kptr_restrict, dmesg, unprivileged BPF, IP forwarding |
| 6 | ⌨️ Magic SysRq & Ctrl+Alt+Del | Disable low-level keyboard attack vectors |
| 7 | 💾 Secure mounts | /dev/shm and /tmp with nodev, nosuid, noexec |
| 8 | 🔍 /proc hidepid | Isolate processes between users |
| 9 | 💥 Core dumps | Disable via limits.conf + sysctl + systemd |
| 10 | 📁 Umask | Tighten default file creation permissions (022 → 027) |
| 11 | 🚫 Unnecessary services | Disable avahi, CUPS, configure NTP, disable apport |
| 12 | 📋 Auditd | Install, enable, load CIS/ANSSI baseline rules |
| 13 | 🚧 Fail2ban | Install, configure SSH jail (3 attempts, 2h ban) |
| 14 | 🔧 Sudo | Dedicated log file, pam_wheel for su, timeout |
| 15 | 🕐 Cron | Fix permissions (og-rwx, root:root) |
| 16 | ⏱️ TMOUT | Auto-disconnect idle sessions (15 min) |
| 17 | 📢 Legal banners | /etc/issue and /etc/issue.net |
| 18 | 🛡️ AppArmor / SELinux | Enable and enforce MAC (distro-aware) |
| 19 | 🔄 Auto-updates | unattended-upgrades or dnf-automatic (security-only) |
| 20 | 📄 File permissions | shadow, passwd, sudoers, grub — correct owner + mode |
| 21 | 🧩 Kernel modules | Blacklist dccp, sctp, rds, tipc, cramfs, hfs, usb-storage |
| 22 | 🔎 Post-hardening scan | World-writable files + non-standard SUID/SGID binaries |

---

### What it does NOT do

- **Force SSH key-only auth** — `PasswordAuthentication` is never touched. If you use password+2FA, that's respected. Adjust manually if needed.
- **Touch your firewall** — existing UFW, firewalld and iptables rules are not modified.
- **Auto-apply anything** — every action requires explicit confirmation.

---

### Compatibility

| Distribution | Status |
|-------------|--------|
| Ubuntu 22.04 / 24.04 | ✅ |
| Debian 11 / 12 | ✅ |
| AlmaLinux / Rocky 8 / 9 | ✅ |
| Fedora 39+ | ✅ |
| openSUSE Leap / Tumbleweed | ✅ |
| Arch Linux / Manjaro | ✅ |

---

### Sources

| Source | Contribution |
|--------|-------------|
| [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | sysctl values, PAM config, file permissions, cron, auditd rules |
| [ANSSI R41+](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-un-systeme-gnulinux/) | Password complexity, audit rules, login banner |
| [dev-sec/linux-baseline](https://github.com/dev-sec/linux-baseline) | sysctl hardening, module blacklist |
| [captainzero93/security_harden_linux](https://github.com/captainzero93/security_harden_linux) | Service disabling logic, dry-run approach |
| [trimstray/linux-hardening-guide](https://github.com/trimstray/the-practical-linux-hardening-guide) | hidepid, umask, SysRq, Ctrl+Alt+Del |
| [Wazuh hardening](https://github.com/wazuh) | /dev/shm, PAM faillock, auditd, cron permissions |
| [DISA STIG](https://public.cyber.mil/stigs/) | SHA-512 hashing, BPF hardening, TMOUT |

---

### After Running

```bash
# 1. Open a new SSH session to test before closing the current one

# 2. Reboot to apply sysctl, kernel modules and fstab changes
sudo reboot

# 3. Full audit with Lynis
sudo apt install lynis   # or dnf/pacman
sudo lynis audit system

# 4. Check auditd logs
ausearch -k auth_files | aureport -f
ausearch -k priv_esc
```

---

### Restoring Backups

Every modified file gets a `.harden.bak` copy before any change.

```bash
# List all backups
find / -maxdepth 6 -name "*.harden.bak" 2>/dev/null

# Restore a file
cp /etc/ssh/sshd_config.harden.bak /etc/ssh/sshd_config
systemctl restart sshd
```

---

### Contributing

PRs welcome. Each new section should follow the existing pattern:

```bash
info()    # describe what it does
risk()    # low / medium / high — explain why it matters
ask()     # confirm before applying
applied() # or skipped() — track the result
```

---

<div align="center">

**MIT License — © [Grujowmi](https://github.com/Grujowmi)**

*Made with 🛡️ for sysadmins who want security without surprises.*

</div>
