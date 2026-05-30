#!/usr/bin/env python3
"""
triage.py
Master Incident Response Wrapper
Part of the Incident Response Triage Toolkit

Detects the host OS, runs the correct collection script, streams output
live to the terminal, and saves everything to a timestamped report.

Usage:
    python triage.py                  # auto-detect OS, run collection
    python triage.py --windows        # force Windows collection (testing)
    python triage.py --linux          # force Linux collection
    python triage.py --output DIR     # override output directory
"""

import argparse
import datetime
import io
import os
import platform
import subprocess
import sys
from pathlib import Path

# Force stdout to UTF-8 so that replacement characters (�) from
# subprocess output don't crash on narrow-encoding terminals (e.g. cp1252).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SCRIPT_DIR  = Path(__file__).parent.resolve()
TRIAGE_DIR  = SCRIPT_DIR / "triage"
LINUX_SCRIPT   = SCRIPT_DIR / "linux"   / "collect_linux.sh"
WINDOWS_SCRIPT = SCRIPT_DIR / "windows" / "collect_windows.py"

BANNER = r"""
  _____ ____  ___ _    ____ _____
 |_   _|  _ \|_ _/ \  / ___| ____|
   | | | |_) || |/ _ \| |  _|  _|
   | | |  _ < | / ___ \ |_| | |___
   |_| |_| \_\/_/_/   \_\____|_____|

  Incident Response Triage Toolkit
  github.com/aditya777-dev/ir-triage-toolkit
"""


# ── helpers ──────────────────────────────────────────────────────────────────

def log(msg: str):
    print(msg, flush=True)


def create_output_dir(override: str | None = None) -> tuple[Path, str]:
    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if override:
        output_dir = Path(override).resolve()
    else:
        output_dir = TRIAGE_DIR / f"triage_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir, timestamp


def stream_to_file(proc: "subprocess.Popen[str]", report_file: Path):
    """Stream a subprocess's stdout to screen AND a file simultaneously."""
    with open(report_file, "w", encoding="utf-8", errors="replace") as fh:
        for line in proc.stdout:  # type: ignore[union-attr]
            print(line, end="", flush=True)
            fh.write(line)
    proc.wait()


# ── collection runners ────────────────────────────────────────────────────────

def run_linux(output_dir: Path) -> Path:
    if not LINUX_SCRIPT.exists():
        log(f"[ERROR] Linux script not found: {LINUX_SCRIPT}")
        sys.exit(1)

    # Ensure it is executable
    LINUX_SCRIPT.chmod(LINUX_SCRIPT.stat().st_mode | 0o111)

    report_file = output_dir / "linux_triage.txt"
    log(f"[*] Running Linux collection script ...")

    env = {**os.environ, "OUTPUT_DIR": str(output_dir)}
    proc = subprocess.Popen(
        ["bash", str(LINUX_SCRIPT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    stream_to_file(proc, report_file)

    if proc.returncode and proc.returncode != 0:
        log(f"[WARN] Script exited with code {proc.returncode} — some items may be missing.")

    return report_file


def run_windows(output_dir: Path) -> Path:
    if not WINDOWS_SCRIPT.exists():
        log(f"[ERROR] Windows script not found: {WINDOWS_SCRIPT}")
        sys.exit(1)

    report_file = output_dir / "windows_triage.txt"
    log(f"[*] Running Windows collection script ...")

    proc = subprocess.Popen(
        [sys.executable, str(WINDOWS_SCRIPT), "--output", str(output_dir)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    stream_to_file(proc, report_file)
    return report_file


# ── summary ───────────────────────────────────────────────────────────────────

def write_summary(output_dir: Path, timestamp: str, os_name: str, report_file: Path) -> Path:
    summary_file = output_dir / "SUMMARY.txt"
    artifacts_linux = [
        "Bash history (all users)",
        "Auth logs (/var/log/auth.log or /var/log/secure)",
        "Running processes (ps aux + pstree)",
        "Cron jobs (system, user, and systemd timers)",
        "Network connections (ss / netstat)",
        "Login history (last / lastb)",
        "SUID/SGID files",
        "World-writable files",
        "Files in /tmp, /var/tmp, /dev/shm",
        "/etc/passwd and group memberships",
        "SSH authorized_keys",
        "Startup scripts and systemd services",
        "Loaded kernel modules",
        "Open file descriptors (lsof)",
    ]
    artifacts_windows = [
        "Prefetch files (C:\\Windows\\Prefetch\\)",
        "Windows Event Logs (Security 4624/4625/4688, System, PowerShell 4103/4104)",
        "Running processes (tasklist + Get-Process with paths)",
        "Scheduled tasks (schtasks + Get-ScheduledTask)",
        "Network connections (netstat -ano + Get-NetTCPConnection)",
        "DNS client cache",
        "Registry Run keys (HKLM/HKCU)",
        "Startup folders",
        "Running services",
        "WMI event subscriptions",
        "Local user accounts and group memberships",
        "PowerShell command history (all users)",
        "Suspicious executables in temp/appdata locations",
        "Alternate Data Streams (ADS)",
    ]

    artifacts = artifacts_linux if os_name == "Linux" else artifacts_windows
    lines = [
        "=" * 68,
        "  INCIDENT RESPONSE TRIAGE — SUMMARY",
        "=" * 68,
        f"  Timestamp  : {timestamp}",
        f"  Host OS    : {os_name}",
        f"  Hostname   : {platform.node()}",
        f"  Output Dir : {output_dir}",
        f"  Report     : {report_file.name}",
        "=" * 68,
        "",
        "Artifacts collected:",
        "",
    ]
    for art in artifacts:
        lines.append(f"  [+] {art}")
    lines += [
        "",
        "=" * 68,
        "  Next steps for the analyst:",
        "",
        "  1. Search the report for known-bad IPs, domains, and hashes",
        "  2. Flag processes running from unusual paths (Temp, AppData, ProgramData)",
        "  3. Review unexpected cron jobs / scheduled tasks",
        "  4. Check for accounts created at unusual times",
        "  5. Correlate prefetch timestamps with the incident window",
        "  6. Pivot on event IDs 4624/4625 for lateral movement indicators",
        "=" * 68,
    ]

    summary_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary_file


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Incident Response Triage Toolkit — Master Wrapper"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--windows", action="store_true", help="Force Windows collection")
    group.add_argument("--linux",   action="store_true", help="Force Linux collection")
    parser.add_argument("--output", help="Override triage output directory")
    args = parser.parse_args()

    print(BANNER)
    print("=" * 68)

    # Determine OS
    if args.windows:
        detected_os = "Windows"
    elif args.linux:
        detected_os = "Linux"
    else:
        detected_os = platform.system()

    log(f"[*] Detected OS  : {detected_os}")
    log(f"[*] Python       : {sys.version.split()[0]}")

    output_dir, timestamp = create_output_dir(args.output)
    log(f"[*] Output dir   : {output_dir}")
    log(f"[*] Timestamp    : {timestamp}")
    log("")

    # Run appropriate collection
    if detected_os == "Linux":
        report_file = run_linux(output_dir)
    elif detected_os == "Windows":
        report_file = run_windows(output_dir)
    else:
        log(f"[ERROR] Unsupported OS: {detected_os}")
        log("        This toolkit supports Linux and Windows only.")
        sys.exit(1)

    summary_file = write_summary(output_dir, timestamp, detected_os, report_file)

    log("")
    log("=" * 68)
    log("[+] Collection complete!")
    log(f"[+] Summary      : {summary_file}")
    log(f"[+] Full report  : {report_file}")
    log(f"[+] Output folder: {output_dir}")
    log("=" * 68)
    log("")
    log("Tip: Review SUMMARY.txt first, then search the full report for IOCs.")


if __name__ == "__main__":
    main()
