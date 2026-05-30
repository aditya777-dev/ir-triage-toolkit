#!/usr/bin/env python3
"""
collect_windows.py
Windows Forensic Artifact Collector
Part of the Incident Response Triage Toolkit

Collects: prefetch files, event logs, running processes, scheduled tasks,
          network connections, startup items, user accounts, PS history.

Usage:
    python collect_windows.py              # prints to stdout
    python collect_windows.py --output DIR # also save sub-artifacts to DIR
    Called automatically by triage.py
"""

import os
import sys
import subprocess
import datetime
import platform

# Ensure stdout uses UTF-8 on narrow-encoding terminals (e.g. Windows cp1252)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import argparse
from pathlib import Path

SEP   = "=" * 68
MINI  = "-" * 68


# ── helpers ──────────────────────────────────────────────────────────────────

def section(name: str):
    print(f"\n{SEP}")
    print(f"  SECTION: {name}")
    print(f"  Collected: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(SEP)


def run_cmd(cmd: str, timeout: int = 30) -> str:
    """Run a shell command and return combined stdout/stderr."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        output = (result.stdout or "").strip()
        err    = (result.stderr or "").strip()
        return output if output else (err if err else "[No output]")
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s: {cmd}"
    except Exception as exc:
        return f"[ERROR] {exc}"


def run_ps(ps_cmd: str, timeout: int = 30) -> str:
    """Run a PowerShell expression and return its output."""
    cmd = [
        "powershell",
        "-NonInteractive",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", ps_cmd,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        output = (result.stdout or "").strip()
        err    = (result.stderr or "").strip()
        return output if output else (err if err else "[No output]")
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] PowerShell command exceeded {timeout}s"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ── collection functions ──────────────────────────────────────────────────────

def collect_system_info():
    section("SYSTEM INFORMATION")
    print(f"[+] Hostname    : {platform.node()}")
    print(f"[+] OS          : {platform.version()}")
    print(f"[+] Architecture: {platform.machine()}")
    print(f"[+] Python      : {platform.python_version()}")

    print()
    is_admin = run_ps(
        "([Security.Principal.WindowsPrincipal]"
        "[Security.Principal.WindowsIdentity]::GetCurrent())"
        ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    )
    print(f"[+] Admin rights: {is_admin}")
    if is_admin.strip().lower() != "true":
        print("    [!] Some artifacts (Prefetch, Security Events) require Administrator.")

    print()
    print("[+] Full system info (systeminfo):")
    print(MINI)
    print(run_cmd("systeminfo", timeout=60))


def collect_running_processes():
    section("RUNNING PROCESSES")

    print("[+] Processes with paths (PowerShell Get-Process):")
    print(MINI)
    ps_cmd = (
        "Get-Process | Sort-Object CPU -Descending | "
        "Select-Object Name,Id,"
        "@{N='CPU(s)';E={[math]::Round($_.CPU,2)}},"
        "@{N='WS(MB)';E={[math]::Round($_.WorkingSet/1MB,1)}},"
        "Path | Format-Table -AutoSize | Out-String -Width 250"
    )
    print(run_ps(ps_cmd, timeout=30))

    print()
    print("[+] Full tasklist with services:")
    print(MINI)
    print(run_cmd("tasklist /svc", timeout=30))

    print()
    print("[+] Processes with parent PID (WMIC):")
    print(MINI)
    print(run_cmd(
        'wmic process get Name,ProcessId,ParentProcessId,ExecutablePath /format:list',
        timeout=30
    ))


def collect_network_connections():
    section("NETWORK CONNECTIONS")

    print("[+] Active connections with PIDs (netstat -ano):")
    print(MINI)
    print(run_cmd("netstat -ano", timeout=20))

    print()
    print("[+] Connections mapped to process names (PowerShell):")
    print(MINI)
    ps_cmd = (
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,"
        "@{N='Process';E={(Get-Process -Id $_.OwningProcess -EA 0).Name}},"
        "OwningProcess | Sort-Object State | "
        "Format-Table -AutoSize | Out-String -Width 250"
    )
    print(run_ps(ps_cmd, timeout=30))

    print()
    print("[+] DNS client cache:")
    print(MINI)
    print(run_ps(
        "Get-DnsClientCache -ErrorAction SilentlyContinue | "
        "Format-Table -AutoSize | Out-String -Width 200",
        timeout=15
    ))

    print()
    print("[+] Network adapter configuration (ipconfig /all):")
    print(MINI)
    print(run_cmd("ipconfig /all", timeout=15))

    print()
    print("[+] ARP cache:")
    print(MINI)
    print(run_cmd("arp -a", timeout=10))

    print()
    print("[+] Routing table:")
    print(MINI)
    print(run_cmd("route print", timeout=15))


def collect_prefetch_files():
    section("PREFETCH FILES")
    prefetch_dir = Path(r"C:\Windows\Prefetch")

    if not prefetch_dir.exists():
        print(f"[!] Prefetch directory not found: {prefetch_dir}")
        print("    Prefetch may be disabled (common on SSDs) or requires Admin.")
        return

    try:
        files = []
        for entry in os.scandir(prefetch_dir):
            if entry.name.lower().endswith(".pf"):
                st = entry.stat()
                files.append({
                    "name":     entry.name,
                    "size_kb":  round(st.st_size / 1024, 1),
                    "modified": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "created":  datetime.datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                })

        files.sort(key=lambda x: x["modified"], reverse=True)

        print(f"[+] {len(files)} prefetch files found (sorted by last run time):")
        print(MINI)
        print(f"{'Filename':<52} {'KB':>6}  {'Last Modified':<22}  {'First Seen':<22}")
        print(MINI)
        for f in files:
            print(f"{f['name']:<52} {f['size_kb']:>6}  {f['modified']:<22}  {f['created']:<22}")

    except PermissionError:
        print("[!] Access denied — run as Administrator to read Prefetch.")
    except Exception as exc:
        print(f"[!] Error reading Prefetch directory: {exc}")


def collect_event_logs():
    section("WINDOWS EVENT LOGS")

    queries = [
        ("Successful Logons (4624)", "Security", [4624], 25),
        ("Failed Logons (4625)", "Security", [4625], 25),
        ("Account Created/Modified (4720,4722,4728,4732,4756)", "Security",
         [4720, 4722, 4728, 4732, 4756], 20),
        ("Process Creation (4688)", "Security", [4688], 20),
        ("PowerShell Script Block (4103,4104)",
         "Microsoft-Windows-PowerShell/Operational", [4103, 4104], 20),
        ("System Log — recent entries", "System", None, 30),
    ]

    for title, logname, event_ids, max_events in queries:
        print(f"\n[+] {title}:")
        print(MINI)

        if event_ids:
            ids_str = ",".join(str(i) for i in event_ids)
            filter_part = f"@{{LogName='{logname}'; Id={ids_str}}}"
        else:
            filter_part = f"'{logname}'"
            ps_cmd = (
                f"Get-WinEvent -LogName {filter_part} -MaxEvents {max_events} "
                f"-ErrorAction SilentlyContinue | "
                "ForEach-Object { "
                "  $msg = $_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)) -replace '\\s+', ' ';"
                "  \"$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | ID:$($_.Id) | $($_.LevelDisplayName) | $msg\""
                "} | Out-String -Width 300"
            )
            print(run_ps(ps_cmd, timeout=30))
            continue

        ps_cmd = (
            f"Get-WinEvent -FilterHashtable {filter_part} -MaxEvents {max_events} "
            f"-ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "  $msg = $_.Message.Substring(0,[Math]::Min(250,$_.Message.Length)) -replace '\\s+', ' ';"
            "  \"$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | ID:$($_.Id) | $msg\""
            "} | Out-String -Width 350"
        )
        print(run_ps(ps_cmd, timeout=30))


def collect_scheduled_tasks():
    section("SCHEDULED TASKS")

    print("[+] Enabled scheduled tasks (PowerShell):")
    print(MINI)
    ps_cmd = (
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
        "Select-Object TaskName, TaskPath, State, "
        "@{N='LastRun';E={($_ | Get-ScheduledTaskInfo -EA 0).LastRunTime}}, "
        "@{N='NextRun';E={($_ | Get-ScheduledTaskInfo -EA 0).NextRunTime}}, "
        "@{N='Actions';E={($_.Actions | ForEach-Object {$_.Execute + ' ' + $_.Arguments}) -join '; '}} | "
        "Sort-Object TaskPath | Format-Table -AutoSize | Out-String -Width 300"
    )
    print(run_ps(ps_cmd, timeout=60))

    print()
    print("[+] Full schtasks output (all tasks):")
    print(MINI)
    print(run_cmd("schtasks /query /fo LIST /v", timeout=60))


def collect_startup_items():
    section("STARTUP ITEMS & PERSISTENCE")

    print("[+] Registry Run keys — HKLM (all users):")
    print(MINI)
    print(run_cmd(r"reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
    print(run_cmd(r"reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"))

    print()
    print("[+] Registry Run keys — HKCU (current user):")
    print(MINI)
    print(run_cmd(r"reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
    print(run_cmd(r"reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"))

    print()
    print("[+] Startup folder contents:")
    print(MINI)
    startup_dirs = [
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for sdir in startup_dirs:
        print(f"  Path: {sdir}")
        if os.path.isdir(sdir):
            items = os.listdir(sdir)
            if items:
                for item in items:
                    print(f"    -> {item}")
            else:
                print("    (empty)")
        else:
            print("    [!] Directory not found")
        print()

    print("[+] Running services (non-disabled):")
    print(MINI)
    ps_cmd = (
        "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
        "Select-Object Name, DisplayName, StartType | "
        "Sort-Object Name | Format-Table -AutoSize | Out-String -Width 200"
    )
    print(run_ps(ps_cmd, timeout=20))

    print()
    print("[+] WMI event subscriptions (common persistence vector):")
    print(MINI)
    ps_cmd = (
        "Get-WMIObject -Namespace root\\subscription -Class __EventFilter -EA SilentlyContinue | "
        "Select-Object Name, Query | Format-Table -AutoSize | Out-String -Width 200"
    )
    print(run_ps(ps_cmd, timeout=15))


def collect_user_accounts():
    section("USER ACCOUNTS")

    print("[+] Local users (net user):")
    print(MINI)
    print(run_cmd("net user"))

    print()
    print("[+] Local Administrators group members:")
    print(MINI)
    print(run_cmd("net localgroup administrators"))

    print()
    print("[+] Detailed local user info (PowerShell Get-LocalUser):")
    print(MINI)
    ps_cmd = (
        "Get-LocalUser | "
        "Select-Object Name, Enabled, LastLogon, PasswordLastSet, "
        "PasswordExpires, PasswordRequired, Description | "
        "Format-Table -AutoSize | Out-String -Width 200"
    )
    print(run_ps(ps_cmd, timeout=15))


def collect_powershell_history():
    section("POWERSHELL COMMAND HISTORY")

    history_files = []

    # Current user's history
    current_user_hist = os.path.expandvars(
        r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    )
    if os.path.isfile(current_user_hist):
        history_files.append(current_user_hist)

    # All users
    users_root = Path(r"C:\Users")
    if users_root.is_dir():
        for user_dir in users_root.iterdir():
            candidate = (
                user_dir
                / "AppData" / "Roaming"
                / "Microsoft" / "Windows" / "PowerShell"
                / "PSReadLine" / "ConsoleHost_history.txt"
            )
            if candidate.is_file() and str(candidate) not in history_files:
                history_files.append(str(candidate))

    if not history_files:
        print("[!] No PowerShell history files found.")
        return

    for hist_path in history_files:
        print(f"[+] History file: {hist_path}")
        print(MINI)
        try:
            content = Path(hist_path).read_text(encoding="utf-8", errors="replace")
            # Show last 5000 chars if the file is very large
            if len(content) > 5000:
                print("[...truncated — showing last 5000 characters...]")
                print(content[-5000:])
            else:
                print(content)
        except Exception as exc:
            print(f"[!] Error reading {hist_path}: {exc}")
        print()


def collect_suspicious_indicators():
    section("SUSPICIOUS FILE INDICATORS")

    print("[+] Recently modified files in temp directories (last 24 h):")
    print(MINI)
    ps_cmd = r"""
$since = (Get-Date).AddHours(-24)
$tempPaths = @($env:TEMP, $env:TMP, 'C:\Windows\Temp', 'C:\Temp', 'C:\Users\Public')
foreach ($p in $tempPaths) {
    if (Test-Path $p) {
        $files = Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -gt $since -and -not $_.PSIsContainer }
        if ($files) {
            Write-Output "--- $p ---"
            $files | Select-Object FullName, LastWriteTime, Length |
            Format-Table -AutoSize | Out-String -Width 250
        }
    }
}
"""
    print(run_ps(ps_cmd, timeout=30))

    print()
    print("[+] Executable files in user-writable locations:")
    print(MINI)
    ps_cmd = r"""
$suspectPaths = @($env:TEMP, $env:APPDATA, 'C:\Users\Public', 'C:\ProgramData')
foreach ($p in $suspectPaths) {
    if (Test-Path $p) {
        $exes = Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in '.exe','.bat','.ps1','.vbs','.js','.hta' -and
                               -not $_.PSIsContainer }
        if ($exes) {
            Write-Output "--- $p ---"
            $exes | Select-Object FullName, LastWriteTime, Length |
            Format-Table -AutoSize | Out-String -Width 250
        }
    }
}
"""
    print(run_ps(ps_cmd, timeout=30))

    print()
    print("[+] Alternate data streams on common temp paths:")
    print(MINI)
    ps_cmd = r"""
Get-Item $env:TEMP\* -Stream * -ErrorAction SilentlyContinue |
Where-Object { $_.Stream -ne ':$DATA' } |
Select-Object FileName, Stream, Length |
Format-Table -AutoSize | Out-String -Width 200
"""
    print(run_ps(ps_cmd, timeout=15))


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Windows Forensic Artifact Collector")
    parser.add_argument("--output", help="Directory to save sub-artifacts", default=None)
    args = parser.parse_args()

    # Report banner
    print(SEP)
    print("  WINDOWS INCIDENT RESPONSE TRIAGE REPORT")
    print(f"  Host     : {platform.node()}")
    print(f"  Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  User     : {os.environ.get('USERNAME', os.environ.get('USER', 'unknown'))}")
    print(f"  OS       : {platform.version()}")
    print(SEP)

    collect_system_info()
    collect_running_processes()
    collect_network_connections()
    collect_prefetch_files()
    collect_event_logs()
    collect_scheduled_tasks()
    collect_startup_items()
    collect_user_accounts()
    collect_powershell_history()
    collect_suspicious_indicators()

    print(f"\n{SEP}")
    print("  END OF WINDOWS TRIAGE REPORT")
    print(f"  Completed: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(SEP)


if __name__ == "__main__":
    main()
