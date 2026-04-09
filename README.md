# 🛡️ HardenKit

**Interactive Linux hardening script — audit your system, then fix it one question at a time.**

Aggregates the best practices from CIS Benchmarks, ANSSI R41+, dev-sec/linux-baseline, Wazuh, captainzero93/security_harden_linux, trimstray's practical hardening guide, and DISA STIG — in a single interactive script that explains every action and its risk level before applying it.

---

## Features

- **Phase 1 — Audit**: scans your current security state across all critical areas and produces a `PASS / FAIL / WARN` report
- **Phase 2 — Interactive hardening**: 22 sections, one question per action, each with a risk level and explanation
- **Non-destructive**: every modified file gets a `.harden.bak` backup before any change
- **Full log**: every action is recorded to `/var/log/linux-hardening-YYYYMMDD_HHMMSS.log`
- **Multi-distro**: Debian · Ubuntu · RHEL · CentOS · AlmaLinux · Rocky · Fedora · openSUSE · Arch · Manjaro
- **Bilingual**: French (`linux-hardening-fr.sh`) and English (`linux-hardening-en.sh`)

---

## Hardening Sections

| # | Section | Key actions |
|---|---------|-------------|
| 1 | SSH | PermitRootLogin, MaxAuthTries, LoginGraceTime, X11/TCP forwarding, ciphers, banner |
| 2 | Password policy | pwquality (minlen=14, 4 classes), faillock (lockout), expiration |
| 3 | Password hashing | Enforce SHA-512 / yescrypt (migrate away from MD5/DES) |
| 4 | sysctl — network | ICMP redirects, source routing, SYN cookies, Martian logging |
| 5 | sysctl — kernel | ASLR, ptrace, kptr_restrict, dmesg, BPF, IP forwarding |
| 6 | Magic SysRq & Ctrl+Alt+Del | Disable low-level keyboard attack vectors |
| 7 | Secure mounts | /dev/shm and /tmp with nodev, nosuid, noexec |
| 8 | /proc hidepid | Hide other users' processes and command-line arguments |
| 9 | Core dumps | Disable via limits.conf + sysctl + systemd |
| 10 | Umask | Tighten default file creation permissions (022 → 027) |
| 11 | Services | Disable avahi, CUPS, configure NTP, disable apport |
| 12 | Auditd | Install, enable, load CIS/ANSSI baseline rules |
| 13 | Fail2ban | Install, configure SSH jail (3 attempts, 2h ban) |
| 14 | Sudo | Dedicated log file, pam_wheel for su, timeout |
| 15 | Cron | Fix permissions (og-rwx, root:root) |
| 16 | TMOUT | Auto-disconnect idle sessions (15 min) |
| 17 | Legal banners | /etc/issue and /etc/issue.net |
| 18 | AppArmor / SELinux | Enable and enforce MAC (distro-aware) |
| 19 | Auto-updates | unattended-upgrades or dnf-automatic (security-only) |
| 20 | File permissions | shadow, passwd, sudoers, grub (correct owner + mode) |
| 21 | Kernel modules | Blacklist dccp, sctp, rds, tipc, cramfs, hfs, usb-storage |
| 22 | Post-hardening scan | World-writable files + non-standard SUID/SGID binaries |

---

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/HardenKit.git
cd HardenKit

# English version — audit only (no changes)
sudo bash linux-hardening-en.sh --audit

# English version — simulate without applying
sudo bash linux-hardening-en.sh --dry-run

# English version — full interactive hardening
sudo bash linux-hardening-en.sh

# French version
sudo bash linux-hardening-fr.sh
```

> ⚠️ **Always open a new SSH session to test connectivity before closing the current one.**

---

## Modes

| Flag | Description |
|------|-------------|
| *(none)* | Full interactive mode — audit then harden |
| `--audit` | Audit only, no changes made |
| `--dry-run` | Shows what would be done without applying anything |

---

## What it does NOT do

- **Force SSH key-only auth** — `PasswordAuthentication` is never touched. If you use password + 2FA, that's respected. Adjust manually if needed.
- **Break your firewall** — the script doesn't touch existing firewall rules (UFW, firewalld, iptables).
- **Auto-apply everything** — every single action requires explicit confirmation.

---

## Sources

| Source | What was taken |
|--------|---------------|
| [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | sysctl values, PAM config, file permissions, cron, auditd rules |
| [ANSSI R41+](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-un-systeme-gnulinux/) | Password complexity, audit rules, login banner |
| [dev-sec/linux-baseline](https://github.com/dev-sec/linux-baseline) | sysctl hardening, module blacklist |
| [captainzero93/security_harden_linux](https://github.com/captainzero93/security_harden_linux) | Service disabling logic, dry-run approach |
| [trimstray/linux-hardening-guide](https://github.com/trimstray/the-practical-linux-hardening-guide) | hidepid, umask, SysRq, Ctrl+Alt+Del |
| [Wazuh hardening script](https://github.com/wazuh) | /dev/shm, PAM faillock, auditd, cron permissions |
| [DISA STIG](https://public.cyber.mil/stigs/) | SHA-512 hashing, BPF hardening, TMOUT |

---

## Compatibility

| Distribution | Tested |
|-------------|--------|
| Ubuntu 22.04 / 24.04 | ✔ |
| Debian 11 / 12 | ✔ |
| AlmaLinux / Rocky 8 / 9 | ✔ |
| Fedora 39+ | ✔ |
| openSUSE Leap / Tumbleweed | ✔ |
| Arch Linux / Manjaro | ✔ |

---

## After Running

1. **Open a new SSH session** to verify connectivity before closing your current session
2. **Reboot** to apply sysctl, kernel modules and fstab changes
3. **Run Lynis** for a comprehensive post-hardening audit:
   ```bash
   sudo apt install lynis  # or dnf/pacman
   sudo lynis audit system
   ```
4. **Check auditd logs**:
   ```bash
   ausearch -k auth_files | aureport -f
   ausearch -k priv_esc
   ```

---

## Restoring Backups

Every modified file has a `.harden.bak` copy:

```bash
# List all backups
find / -maxdepth 6 -name "*.harden.bak" 2>/dev/null

# Restore a specific file
cp /etc/ssh/sshd_config.harden.bak /etc/ssh/sshd_config
systemctl restart sshd
```

---

## License

MIT — use freely, modify freely, no warranty.

---

## Contributing

PRs welcome. Each new section should follow the existing pattern:
- `info()` — what it does
- `risk level medium/high/low` — why it matters
- `ask()` — confirm before applying
- `applied()` / `skipped()` — track the result
