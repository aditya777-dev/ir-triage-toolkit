# IR Triage Toolkit
### Incident Response Automation Script for Linux and Windows Log Triage

A cross-platform forensic artifact collection toolkit built for SOC analysts. Runs a single command and produces a structured triage report covering the key artifacts first responders need during a live incident.

---

## What It Collects

| Artifact | Linux | Windows |
|---|---|---|
| Shell history | `~/.bash_history` / `.zsh_history` | PowerShell `ConsoleHost_history.txt` |
| Auth / logon logs | `/var/log/auth.log` / `/var/log/secure` | Event IDs 4624, 4625, 4688 |
| Running processes | `ps aux`, `pstree` | `Get-Process`, `tasklist /svc` |
| Network connections | `ss -tulnp`, `netstat` | `netstat -ano`, `Get-NetTCPConnection` |
| Cron / scheduled tasks | crontab, systemd timers | `schtasks`, `Get-ScheduledTask` |
| Startup/persistence | `rc.local`, systemd, Run keys | Registry Run keys, startup folders, WMI |
| Prefetch files | N/A | `C:\Windows\Prefetch\` (sorted by last run) |
| User accounts | `/etc/passwd`, `/etc/group` | `net user`, `Get-LocalUser` |
| SUID/SGID files | `find / -perm -4000` | N/A |
| SSH keys | `authorized_keys` (all users) | N/A |
| Open files | `lsof -i` | N/A |
| Alternate Data Streams | N/A | `Get-Item -Stream *` |
| DNS cache | `/etc/resolv.conf` | `Get-DnsClientCache` |

---

## Project Structure

```
ir-triage-toolkit/
├── triage.py                  ← Master wrapper (start here)
├── linux/
│   └── collect_linux.sh       ← Linux artifact collector (Bash)
├── windows/
│   └── collect_windows.py     ← Windows artifact collector (Python)
├── simulate/
│   ├── simulate_windows.py    ← Plant harmless test artifacts on Windows
│   └── simulate_linux.sh      ← Plant harmless test artifacts on Linux
├── triage/                    ← Reports saved here (auto-created)
├── examples/
│   └── example_triage_report.txt  ← Sample output with analyst annotations
├── requirements.txt
└── README.md
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.8+ | Required for `triage.py` and `collect_windows.py` |
| Bash | Required for `collect_linux.sh` and `simulate_linux.sh` |
| PowerShell 5+ | Windows collection uses PS cmdlets |
| Administrator / root | Prefetch, Security events, and some Linux files need elevated access |

No third-party Python packages are required. The toolkit uses only the standard library.

---

## Quick Start

### On Windows

```powershell
# 1. Clone the repo
git clone https://github.com/aditya777-dev/ir-triage-toolkit.git
cd ir-triage-toolkit

# 2. (Optional) Plant harmless test artifacts first
python simulate\simulate_windows.py

# 3. Run the triage collector
python triage.py

# 4. Review the report
#    Output is saved to: triage\triage_YYYYMMDD_HHMMSS\
```

> Run as Administrator for full coverage (Prefetch + Security Event Log).

### On Linux (in a VM)

```bash
# 1. Clone the repo
git clone https://github.com/aditya777-dev/ir-triage-toolkit.git
cd ir-triage-toolkit

# 2. (Optional) Plant harmless test artifacts first
bash simulate/simulate_linux.sh

# 3. Run the triage collector
python3 triage.py

# 4. Review the report
#    Output is saved to: triage/triage_YYYYMMDD_HHMMSS/
```

> Run as root (`sudo python3 triage.py`) for full coverage (auth logs, shadow file check, lsof).

---

## Detailed Usage

### triage.py (Master Wrapper)

```
python triage.py                  # auto-detect OS, run collection
python triage.py --windows        # force Windows mode (useful for testing)
python triage.py --linux          # force Linux mode
python triage.py --output /path   # custom output directory
```

Each run creates a new timestamped folder inside `triage/` containing:
- `windows_triage.txt` or `linux_triage.txt` — full artifact dump
- `SUMMARY.txt` — quick-look summary with analyst next-steps

### Running the Linux Collector Standalone

```bash
bash linux/collect_linux.sh                      # stream to terminal
bash linux/collect_linux.sh > my_report.txt      # save to file
sudo bash linux/collect_linux.sh > full_report.txt  # root for full access
```

### Running the Windows Collector Standalone

```powershell
python windows\collect_windows.py
python windows\collect_windows.py --output C:\IR\case001
```

---

## Simulated Compromise Scenario

The `simulate/` scripts create **harmless** test artifacts so you can run the toolkit and see a realistic-looking report without needing a real incident.

### Windows Simulation

```powershell
# Plant artifacts
python simulate\simulate_windows.py

# Check what was created
python simulate\simulate_windows.py --status

# Collect and inspect
python triage.py

# Remove everything when done
python simulate\simulate_windows.py --cleanup
```

**What gets planted:**
- Suspicious PowerShell history entries (recon commands, a commented-out download cradle)
- Text files in `%TEMP%\ir_simulation\` with attacker-like names (`recon_output.txt`, `implant_sim.ps1`, `c2_config.txt`)
- A harmless scheduled task that echoes text to a log file

### Linux Simulation

```bash
bash simulate/simulate_linux.sh           # plant
bash simulate/simulate_linux.sh --status  # verify
python3 triage.py                         # collect
bash simulate/simulate_linux.sh --cleanup # clean up
```

**What gets planted:**
- Suspicious bash history entries (recon, simulated download cradle)
- Files in `/tmp/ir_simulation/` and `/dev/shm/`
- A commented-out cron entry (won't execute)
- A commented-out SSH key entry in `~/.ssh/authorized_keys`

---

## Understanding the Output

Open `triage/triage_<timestamp>/SUMMARY.txt` first — it lists every artifact category collected and gives you analyst next steps.

Then search the full report for red flags:

| What to look for | Why it matters |
|---|---|
| Processes running from `Temp`, `AppData`, `Public` | Legitimate programs rarely run from these paths |
| `svchost` / system names with typos | Name masquerading (e.g. `svchost32.exe`) |
| New processes in Prefetch with `First Seen = Last Modified` | Executed for the first time during the incident window |
| Burst of Event ID 4625 followed by 4624 | Brute force followed by successful login |
| Event ID 4688 showing `net user`, `whoami`, `mimikatz` | Classic attacker recon and credential dumping |
| Scheduled tasks with vague names (`WindowsUpdate`, `SecurityCacheSvc`) | Attackers masquerade as Windows components |
| Cron entries or startup scripts added recently | Persistence |
| SSH `authorized_keys` modified | Attacker added SSH key for re-entry |
| Connections to non-standard ports (4444, 1234, 8080, 9999) | C2 callbacks |

See `examples/example_triage_report.txt` for an annotated sample showing all of these indicators.

---

## Blog Post Walkthrough

> *Companion post: "Building an Incident Response Triage Toolkit from Scratch"*

### Scenario

You receive an alert: a Windows server in your environment is making outbound connections to an unknown IP on port 4444 at 2 AM. You need to triage the host quickly to determine scope and timeline.

### Step 1 — Understand what to collect

Before writing code, SOC analysts think in terms of artifact categories:

- **Processes** — what is running and where did it come from?
- **Network** — what is talking to the outside world?
- **Persistence** — how will the attacker survive a reboot?
- **Timeline** — when did this happen and in what order?
- **Accounts** — did the attacker create or escalate an account?

### Step 2 — Run the collector

```powershell
python triage.py
```

The master wrapper auto-detects Windows, spawns `collect_windows.py`, streams the output live, and saves everything to a timestamped folder.

### Step 3 — Read the Prefetch section first

Prefetch files tell you **exactly what ran and when** — even if the binary has since been deleted. Sort by `Last Modified` (newest first) and look for:
- Programs running from unusual directories
- Tools like `mimikatz`, `psexec`, `procdump`
- Recon binaries (`whoami`, `net`, `ipconfig`, `netstat`) executed in rapid succession

### Step 4 — Correlate with Event Logs

Cross-reference Prefetch timestamps with Event Log entries:
- ID **4624** = successful logon (who logged in and from where?)
- ID **4625** = failed logon (was there a brute force?)
- ID **4688** = process creation (what did they run?)
- ID **4720** = new account created (backdoor?)

### Step 5 — Check persistence

Search the report for scheduled tasks, registry Run keys, and startup folder entries that appeared during the incident window. Attackers always try to survive a reboot.

### Step 6 — Build the IOC list

By the end of your review you should have:
- **Host IOCs**: malicious file paths, hashes, attacker user accounts
- **Network IOCs**: C2 IP addresses and ports
- **Timeline**: minute-by-minute reconstruction of the attack

This goes into your incident ticket, SIEM rule tuning, and threat-intel platform.

---

## Script Reference

### `collect_linux.sh` — Bash, no dependencies

| Section | Commands used |
|---|---|
| System info | `uname`, `uptime`, `df`, `free` |
| Processes | `ps aux`, `pstree`, `lsof -i` |
| Network | `ss`, `netstat`, `ip addr`, `arp`, `ip route` |
| Users | `/etc/passwd`, `who`, `w` |
| Login history | `last`, `lastb` |
| Auth logs | `/var/log/auth.log`, `/var/log/secure`, `journalctl` |
| Bash history | `~/.bash_history`, `/root/.bash_history` |
| Cron | `crontab -l`, `/etc/cron.*`, `systemctl list-timers` |
| Persistence | `systemctl list-unit-files`, `authorized_keys`, `/etc/profile.d` |
| Suspicious files | `find` (SUID, world-writable, /tmp, /dev/shm) |
| Kernel modules | `lsmod` |

### `collect_windows.py` — Python 3, standard library only

| Section | Methods used |
|---|---|
| System info | `platform`, `systeminfo` |
| Processes | `Get-Process`, `tasklist /svc`, `wmic` |
| Network | `netstat -ano`, `Get-NetTCPConnection`, `Get-DnsClientCache` |
| Prefetch | `os.scandir(C:\Windows\Prefetch)` |
| Event logs | `Get-WinEvent` (PowerShell) |
| Scheduled tasks | `schtasks`, `Get-ScheduledTask` |
| Startup/persistence | `reg query`, startup folders, `Get-Service`, WMI subscriptions |
| Users | `net user`, `Get-LocalUser` |
| PS history | `ConsoleHost_history.txt` (all users) |
| Suspicious files | `Get-ChildItem` on Temp/AppData, ADS check |

---

## Tested On

- Windows 11 / Windows 10 Pro (Python 3.11, PowerShell 5.1)
- Ubuntu 22.04 LTS (Bash 5.1)
- Kali Linux 2024.1

---

## Author

**Aditya Satam** — aspiring SOC Analyst  
GitHub: [@aditya777-dev](https://github.com/aditya777-dev)

---

## License

MIT License — free to use, modify, and share with attribution.

---

## Disclaimer

This toolkit is intended for authorized incident response and security education only. Do not run on systems you do not own or do not have explicit written permission to test. All simulation scripts create harmless test artifacts only.
