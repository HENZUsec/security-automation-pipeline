# OS Security Automation Pipeline

A small multi-language automation pipeline that reduces manual OS security checks.

- **Bash** collects Linux telemetry
- **PowerShell** collects Windows telemetry
- **Python** correlates the outputs and generates a risk assessed report

Each script finds the repo root based on its own file location, so it can be executed from any working directory.

## Repository layout

```
.
├─ bash/
│  └─ linux_check.sh
├─ powershell/
│  └─ windows_check.ps1
├─ python/
│  └─ analysis_engine.py
├─ fakedata/              (optional example input files)
├─ data/                  (created by collectors)
└─ report/                (created by analysis)
```

## What gets generated

Running the collectors creates files under `data/`.

### Linux collector output

- `data/linux_processes.json`
- `data/linux_security_events.log`
- `data/auth.log`
- `data/anomalies.log`
- `data/critical_alerts.log`

### Windows collector output

- `data/windows_services.csv`
- `data/windows_security_events.log`
- `data/auth.log` 
- `data/anomalies.log` 
- `data/critical_alerts.log`

Running the analysis creates files under `report/`.

- `report/final_report_<timestamp>.txt`
- `report/webhook_alerts_<timestamp>.json` (simulated webhook payload)

## Requirements

### Linux

- Bash
- Typical core tools (`ps`, `grep`, `ss`, `journalctl`)

(OR)

### Windows

- PowerShell 5.1 or PowerShell 7

### Analysis

- Python 3.10+ (works on Windows, Linux, macOS)

## Quick start

### 1) Clone the repo

```bash
git clone <your-repo-url>
cd <repo-folder>
```

### 2) Run the collector for your OS

You normally run **one** collector depending on where you are.

#### Linux (native Linux or WSL)

```bash
bash bash/linux_check.sh
```

If you prefer running it directly:

```bash
chmod +x bash/linux_check.sh
./bash/linux_check.sh
```

#### Windows (PowerShell)

From the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File .\powershell\windows_check.ps1
```

PowerShell 7 (`pwsh`) also works:

```powershell
pwsh -File .\powershell\windows_check.ps1
```

### 3) Run the analysis engine

From the repo root:

```bash
python python/analysis_engine.py
```

The script will read what exists in `data/` and generate a report in `report/`.

## Fake data mode

If you want to demo the pipeline without running the collectors on real machines, add example files under `fakedata/`.

The analysis engine is written so it can fall back to fake inputs if the real files are missing.

A typical fake set is:

- `fakedata/linux_processes.json`
- `fakedata/windows_services.csv`
- `fakedata/auth.log`
- `fakedata/anomalies.log`
- `fakedata/windows_security_events.log` (optional)
- `fakedata/linux_security_events.log` (optional)

Then run:

```bash
python python/analysis_engine.py
```

## Notes

### Do I need `chmod +x`?

- On Linux, `bash bash/linux_check.sh` works even if the file is not executable.
- If you want to run it as `./bash/linux_check.sh`, you must make it executable with `chmod +x`.

### PowerShell execution policy

If Windows blocks script execution, use one of these:

- Run with `-ExecutionPolicy Bypass` as shown above
- Or set a user scoped policy:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Safety and scope

These scripts are designed for **collection and analysis**. They do not apply hardening automatically.

A natural next step is to add a remediation mode (for example disabling SMBv1, enforcing firewall profiles, enabling unattended upgrades), but that is intentionally left as an extension.

## Extending the project

Ideas that fit the same pipeline:

- Add more collectors (installed patches, local users, audit settings)
- Add CIS aligned checks and map findings to specific recommendations
- Add a remediation mode with a `-Fix` flag (PowerShell) or `--remediate` (Bash)
- Add scheduled runs (Task Scheduler or cron) and rotate logs
