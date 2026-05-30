#!/usr/bin/env bash
# collect_linux.sh
# Linux Forensic Artifact Collector
# Part of the Incident Response Triage Toolkit
#
# Collects: bash history, auth logs, running processes, cron jobs,
#           network connections, login history, persistence, and more.
#
# Usage:
#   bash collect_linux.sh                    # prints to stdout
#   bash collect_linux.sh > report.txt       # save to file
#   Called automatically by triage.py

set -o pipefail

SEP="================================================================"
MINI="----------------------------------------------------------------"

# ── helpers ──────────────────────────────────────────────────────────
section() {
    echo ""
    echo "$SEP"
    printf "  SECTION: %s\n" "$1"
    printf "  Collected: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
    echo "$SEP"
}

try_cmd() {
    # Run a command; print a warning if it fails
    eval "$@" 2>/dev/null || echo "[!] Command unavailable or requires elevated privileges: $*"
}

# ── report header ─────────────────────────────────────────────────────
echo "$SEP"
echo "  LINUX INCIDENT RESPONSE TRIAGE REPORT"
printf "  Host     : %s\n" "$(hostname)"
printf "  Timestamp: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
printf "  Analyst  : %s\n" "$(whoami)"
printf "  Kernel   : %s\n" "$(uname -r)"
echo "$SEP"

# ═══════════════════════════════════════════════════════════════════════
section "SYSTEM INFORMATION"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] OS details:"
echo "$MINI"
if [ -f /etc/os-release ]; then
    cat /etc/os-release
elif [ -f /etc/issue ]; then
    cat /etc/issue
else
    uname -a
fi

echo ""
echo "[+] System uptime and load:"
echo "$MINI"
uptime

echo ""
echo "[+] Disk usage:"
echo "$MINI"
df -h 2>/dev/null || echo "[!] df not available"

echo ""
echo "[+] Memory usage:"
echo "$MINI"
free -h 2>/dev/null || echo "[!] free not available"

# ═══════════════════════════════════════════════════════════════════════
section "RUNNING PROCESSES"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] All running processes sorted by CPU (ps aux):"
echo "$MINI"
ps aux --sort=-%cpu 2>/dev/null || ps aux

echo ""
echo "[+] Process tree (pstree):"
echo "$MINI"
pstree -p 2>/dev/null || echo "[!] pstree not installed — install with: apt install psmisc"

echo ""
echo "[+] Processes with open network connections (lsof -i):"
echo "$MINI"
lsof -i 2>/dev/null | head -60 || echo "[!] lsof not available or requires root"

# ═══════════════════════════════════════════════════════════════════════
section "NETWORK CONNECTIONS"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] Listening and established sockets (ss -tulnp):"
echo "$MINI"
if command -v ss &>/dev/null; then
    ss -tulnp
    echo ""
    echo "[+] All TCP connections (ss -antp):"
    ss -antp 2>/dev/null
elif command -v netstat &>/dev/null; then
    netstat -tulnp 2>/dev/null
else
    echo "[!] Neither ss nor netstat found"
fi

echo ""
echo "[+] Network interfaces (ip addr):"
echo "$MINI"
ip addr 2>/dev/null || ifconfig 2>/dev/null || echo "[!] ip/ifconfig not available"

echo ""
echo "[+] ARP cache:"
echo "$MINI"
arp -a 2>/dev/null || ip neigh 2>/dev/null || echo "[!] arp not available"

echo ""
echo "[+] Routing table:"
echo "$MINI"
ip route 2>/dev/null || route -n 2>/dev/null || echo "[!] route/ip not available"

echo ""
echo "[+] /etc/hosts:"
echo "$MINI"
cat /etc/hosts

echo ""
echo "[+] DNS resolvers (/etc/resolv.conf):"
echo "$MINI"
cat /etc/resolv.conf 2>/dev/null || echo "[!] /etc/resolv.conf not found"

# ═══════════════════════════════════════════════════════════════════════
section "USER ACCOUNTS"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] /etc/passwd (all accounts):"
echo "$MINI"
cat /etc/passwd

echo ""
echo "[+] Users with login shells (non-system accounts):"
echo "$MINI"
grep -vE "nologin|false" /etc/passwd | grep -v "^#"

echo ""
echo "[+] Groups with elevated membership (/etc/group):"
echo "$MINI"
grep -E "^(sudo|wheel|adm|root|shadow):" /etc/group 2>/dev/null

echo ""
echo "[+] Currently logged-in users (who / w):"
echo "$MINI"
who
echo ""
w 2>/dev/null

# ═══════════════════════════════════════════════════════════════════════
section "LOGIN HISTORY"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] Successful logins — last 50 entries:"
echo "$MINI"
last -n 50 2>/dev/null || echo "[!] last not available"

echo ""
echo "[+] Failed login attempts — lastb (last 50):"
echo "$MINI"
lastb -n 50 2>/dev/null || echo "[!] lastb not available (may require root)"

echo ""
echo "[+] Sudo usage from auth log:"
echo "$MINI"
grep -i "sudo" /var/log/auth.log 2>/dev/null | tail -50 \
    || grep -i "sudo" /var/log/secure 2>/dev/null | tail -50 \
    || journalctl _COMM=sudo --since "7 days ago" 2>/dev/null | tail -50 \
    || echo "[!] Could not retrieve sudo log entries"

# ═══════════════════════════════════════════════════════════════════════
section "BASH HISTORY (ALL USERS)"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] Root bash history (/root/.bash_history):"
echo "$MINI"
if [ -r /root/.bash_history ]; then
    cat /root/.bash_history
else
    echo "[!] Cannot read /root/.bash_history — run as root for full access"
fi

echo ""
echo "[+] Shell history for all home-directory users:"
echo "$MINI"
for HIST in /home/*/.bash_history /home/*/.zsh_history /home/*/.sh_history; do
    [ -f "$HIST" ] || continue
    USER_HOME=$(dirname "$HIST")
    USER_NAME=$(basename "$USER_HOME")
    echo "--- User: $USER_NAME | File: $HIST ---"
    cat "$HIST" 2>/dev/null || echo "    [!] Permission denied"
    echo ""
done

echo ""
echo "[+] All shell history files found on system:"
echo "$MINI"
find /home /root -maxdepth 3 \( -name ".bash_history" -o -name ".zsh_history" -o -name ".*_history" \) 2>/dev/null

# ═══════════════════════════════════════════════════════════════════════
section "AUTHENTICATION LOGS"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] Auth log — last 200 lines:"
echo "$MINI"
if [ -r /var/log/auth.log ]; then
    tail -200 /var/log/auth.log
elif [ -r /var/log/secure ]; then
    tail -200 /var/log/secure
else
    echo "[!] Standard auth log not found — trying journalctl..."
    journalctl _COMM=sshd --since "24 hours ago" 2>/dev/null | tail -100 \
        || echo "[!] journalctl also unavailable"
fi

echo ""
echo "[+] Failed SSH / login attempts (grep for 'Failed' / 'Invalid'):"
echo "$MINI"
grep -iE "Failed|Invalid|authentication failure|Connection closed" /var/log/auth.log 2>/dev/null | tail -60 \
    || grep -iE "Failed|Invalid|authentication failure" /var/log/secure 2>/dev/null | tail -60 \
    || journalctl _COMM=sshd 2>/dev/null | grep -iE "Failed|Invalid" | tail -60 \
    || echo "[!] Could not retrieve SSH failure logs"

echo ""
echo "[+] Successful SSH logins:"
echo "$MINI"
grep -i "Accepted\|session opened for user" /var/log/auth.log 2>/dev/null | tail -30 \
    || grep -i "Accepted" /var/log/secure 2>/dev/null | tail -30 \
    || echo "[!] Could not retrieve successful login entries"

# ═══════════════════════════════════════════════════════════════════════
section "CRON JOBS"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] System crontab (/etc/crontab):"
echo "$MINI"
cat /etc/crontab 2>/dev/null || echo "[!] /etc/crontab not readable"

echo ""
echo "[+] /etc/cron.d/ entries:"
echo "$MINI"
ls -la /etc/cron.d/ 2>/dev/null
for CRON_FILE in /etc/cron.d/*; do
    [ -f "$CRON_FILE" ] || continue
    echo "  --- $CRON_FILE ---"
    cat "$CRON_FILE"
    echo ""
done

echo ""
echo "[+] Periodic cron directories:"
echo "$MINI"
for PERIOD in hourly daily weekly monthly; do
    echo "  /etc/cron.$PERIOD/ :"
    ls -la "/etc/cron.$PERIOD/" 2>/dev/null || echo "    [not found]"
done

echo ""
echo "[+] User crontabs:"
echo "$MINI"
while IFS=: read -r USER _ UID _ _ HOME _; do
    [ "$UID" -ge 1000 ] 2>/dev/null || [ "$USER" = "root" ] || continue
    CRONTAB_OUT=$(crontab -l -u "$USER" 2>/dev/null)
    if [ -n "$CRONTAB_OUT" ]; then
        echo "  --- Crontab for: $USER ---"
        echo "$CRONTAB_OUT"
        echo ""
    fi
done < /etc/passwd

echo ""
echo "[+] Systemd timers:"
echo "$MINI"
systemctl list-timers --all 2>/dev/null | head -40 || echo "[!] systemctl not available"

# ═══════════════════════════════════════════════════════════════════════
section "PERSISTENCE MECHANISMS"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] /etc/rc.local:"
echo "$MINI"
cat /etc/rc.local 2>/dev/null || echo "[!] /etc/rc.local not present"

echo ""
echo "[+] Systemd enabled services:"
echo "$MINI"
systemctl list-unit-files --state=enabled 2>/dev/null | head -60 || echo "[!] systemctl not available"

echo ""
echo "[+] SSH authorized_keys files (all users):"
echo "$MINI"
find /home /root -name "authorized_keys" 2>/dev/null | while read -r AK_FILE; do
    echo "  === $AK_FILE ==="
    cat "$AK_FILE" 2>/dev/null || echo "    [!] Permission denied"
done

echo ""
echo "[+] /etc/profile and /etc/profile.d/ (startup scripts):"
echo "$MINI"
echo "  --- /etc/profile (last 20 lines) ---"
tail -20 /etc/profile 2>/dev/null
echo "  --- /etc/profile.d/ ---"
ls -la /etc/profile.d/ 2>/dev/null

echo ""
echo "[+] ~/.bashrc and ~/.profile for home users:"
echo "$MINI"
for HOME_DIR in /home/* /root; do
    [ -d "$HOME_DIR" ] || continue
    for RCFILE in .bashrc .profile .bash_profile; do
        RCPATH="$HOME_DIR/$RCFILE"
        [ -r "$RCPATH" ] || continue
        echo "  --- $RCPATH (last 15 lines) ---"
        tail -15 "$RCPATH"
        echo ""
    done
done

# ═══════════════════════════════════════════════════════════════════════
section "SUSPICIOUS FILE INDICATORS"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] SUID/SGID files (review for unexpected entries):"
echo "$MINI"
find / -type f \( -perm -4000 -o -perm -2000 \) \
    -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | sort

echo ""
echo "[+] World-writable files (excluding /proc /sys /dev):"
echo "$MINI"
find / -type f -perm -o+w \
    -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
    2>/dev/null | head -50

echo ""
echo "[+] Contents of /tmp, /var/tmp, /dev/shm:"
echo "$MINI"
echo "  --- /tmp ---"
ls -la /tmp/ 2>/dev/null
echo "  --- /var/tmp ---"
ls -la /var/tmp/ 2>/dev/null
echo "  --- /dev/shm ---"
ls -la /dev/shm/ 2>/dev/null

echo ""
echo "[+] Recently modified files in temp directories (newer than /etc/passwd):"
echo "$MINI"
find /tmp /var/tmp /dev/shm -type f -newer /etc/passwd 2>/dev/null | head -30

echo ""
echo "[+] Hidden files in home directories (non-standard):"
echo "$MINI"
find /home /root -maxdepth 3 -name ".*" -type f 2>/dev/null \
    | grep -vE "\.(bash|zsh|profile|ssh|config|local|mozilla|gnome|kde|cache|viminfo|lesshst|wget|netrc|Xauth)" \
    | head -30

# ═══════════════════════════════════════════════════════════════════════
section "LOADED KERNEL MODULES"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] Currently loaded kernel modules (lsmod):"
echo "$MINI"
lsmod 2>/dev/null || echo "[!] lsmod not available"

# ═══════════════════════════════════════════════════════════════════════
section "OPEN FILES"
# ═══════════════════════════════════════════════════════════════════════
echo "[+] Network-connected file descriptors (lsof -i):"
echo "$MINI"
lsof -i 2>/dev/null | head -80 || echo "[!] lsof not available or requires root"

echo ""
echo "[+] Files opened by suspicious locations:"
echo "$MINI"
lsof 2>/dev/null | grep -E "/tmp|/dev/shm|/var/tmp" | head -30 \
    || echo "[!] lsof not available"

# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "$SEP"
echo "  END OF LINUX TRIAGE REPORT"
printf "  Completed: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
echo "$SEP"
