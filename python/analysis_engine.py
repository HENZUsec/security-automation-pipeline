#!/usr/bin/env python3
"""
analysis_engine.py - Reads outputs from /data and writes a report to /report
"""

import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Simple rules 
RISKY_PROCESSES = {
    "nc": ("CRITICAL", "often used for reverse shells"),
    "netcat": ("CRITICAL", "often used for reverse shells"),
    "hydra": ("HIGH", "brute force / password spraying tool"),
    "john": ("HIGH", "password cracking tool"),
}

RISKY_SERVICES = {
    "RemoteRegistry": ("HIGH", "increases attack surface"),
    "Telnet": ("HIGH", "insecure protocol"),
    "Spooler": ("MEDIUM", "common hardening target"),
    "TermService": ("MEDIUM", "RDP service, review exposure"),
    "LanmanServer": ("MEDIUM", "SMB server, review exposure"),
}

LOG_PATTERNS = [
    ("CRITICAL", r"\b(smbv1|smb1)\b", "SMBv1 mentioned"),
    ("HIGH", r"\b(bruteforce|password spray|spraying)\b", "brute force wording"),
    ("MEDIUM", r"\b(failed|failure|denied|unauthorized|invalid user)\b", "auth failure indicator"),
    ("LOW", r"\b(error|warn|warning)\b", "error/warning indicator"),
]

SEV_SCORE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def utc_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def repo_paths():
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    data_dir = repo_root / "data"
    report_dir = repo_root / "report"
    return repo_root, data_dir, report_dir


def read_text(path: Path):
    # Read lines from a log file
    try:
        if not path.exists():
            return []
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []


def read_json(path: Path):
    # Read JSON from data/linux_processes.json
    try:
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def read_csv(path: Path):
    # Read CSV from data/windows_services.csv
    try:
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


def add_finding(findings, severity, text):
    findings.append((severity, text))


def scan_linux_processes(linux_json, findings):
    score = 0
    highest = "LOW"

    # Read processes from linux_processes.json
    processes = linux_json.get("processes", [])
    names = []
    for p in processes:
        if isinstance(p, dict):
            names.append((p.get("name") or "").strip())
        else:
            names.append(str(p).strip())

    for name in names:
        if not name:
            continue
        key = name.lower()
        if key in RISKY_PROCESSES:
            sev, reason = RISKY_PROCESSES[key]
            add_finding(findings, sev, f"Linux process: {name} ({reason})")
            score += SEV_SCORE.get(sev, 0)
            if SEV_ORDER[sev] > SEV_ORDER[highest]:
                highest = sev

    return score, highest


def scan_windows_services(rows, findings):
    score = 0
    highest = "LOW"

    # Read services from windows_services.csv
    for row in rows:
        name = (row.get("Name") or "").strip()
        if not name:
            continue

        if name in RISKY_SERVICES:
            sev, reason = RISKY_SERVICES[name]
            state = (row.get("State") or "").strip()
            startmode = (row.get("StartMode") or "").strip()
            add_finding(findings, sev, f"Windows service: {name} (State={state}, StartMode={startmode}) ({reason})")
            score += SEV_SCORE.get(sev, 0)
            if SEV_ORDER[sev] > SEV_ORDER[highest]:
                highest = sev

    return score, highest


def scan_logs(lines, findings):
    score = 0
    highest = "LOW"

    compiled = [(sev, re.compile(rx, re.IGNORECASE), reason) for (sev, rx, reason) in LOG_PATTERNS]

    # Count auth failures per IP
    ip_fails = {}

    for line in lines:
        # Match one pattern per line
        for sev, rx, reason in compiled:
            if rx.search(line):
                add_finding(findings, sev, f"Log: {reason} | {line[:180]}")
                score += SEV_SCORE.get(sev, 0)
                if SEV_ORDER[sev] > SEV_ORDER[highest]:
                    highest = sev
                break

        # Extract IPs on failed-like lines
        if re.search(r"\bfailed\b|\bfailure\b|\bdenied\b|\bunauthorized\b", line, re.IGNORECASE):
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if m:
                ip = m.group(1)
                ip_fails[ip] = ip_fails.get(ip, 0) + 1

    # Simple brute-force thresholds
    for ip, count in sorted(ip_fails.items(), key=lambda x: x[1], reverse=True):
        if count >= 10:
            add_finding(findings, "CRITICAL", f"Possible brute force from {ip} ({count} fails)")
            score += SEV_SCORE["CRITICAL"]
            if SEV_ORDER["CRITICAL"] > SEV_ORDER[highest]:
                highest = "CRITICAL"
        elif count >= 5:
            add_finding(findings, "HIGH", f"Suspicious failed burst from {ip} ({count} fails)")
            score += SEV_SCORE["HIGH"]
            if SEV_ORDER["HIGH"] > SEV_ORDER[highest]:
                highest = "HIGH"

    return score, highest


def write_report(path: Path, inputs_used, findings, overall, total_score):
    groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for sev, txt in findings:
        groups.setdefault(sev, []).append(txt)

    out = []
    out.append("OS Security Automation - Analysis Report")
    out.append("=" * 42)
    out.append(f"Generated (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    out.append(f"Overall risk: {overall}")
    out.append(f"Total score: {total_score}")
    out.append("")
    out.append("Inputs used:")
    for p in inputs_used:
        out.append(f"- {p}")
    out.append("")
    out.append("Findings:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = groups.get(sev, [])
        if not items:
            continue
        out.append(f"{sev} ({len(items)})")
        for it in items[:50]:
            out.append(f"  - {it}")
        if len(items) > 50:
            out.append(f"  ... ({len(items) - 50} more)")
        out.append("")

    out.append("Recommended actions:")
    if overall == "CRITICAL":
        out.append("- Investigate immediately, validate authorization, consider containment")
    elif overall == "HIGH":
        out.append("- Investigate within 24 hours and verify hardening/changes")
    elif overall == "MEDIUM":
        out.append("- Review during next cycle and document findings")
    else:
        out.append("- No immediate action required (monitor and keep baseline)")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main():
    repo_root, data_dir, report_dir = repo_paths()

    linux_json_path = data_dir / "linux_processes.json"
    win_csv_path = data_dir / "windows_services.csv"

    linux_log_path = data_dir / "linux_security_events.log"
    win_log_path = data_dir / "windows_security_events.log"
    anomalies_path = data_dir / "anomalies.log"
    critical_path = data_dir / "critical_alerts.log"

    # Read data from /data
    linux_json = read_json(linux_json_path)
    win_rows = read_csv(win_csv_path)

    # Read logs from /data
    lines = []
    lines += read_text(linux_log_path)
    lines += read_text(win_log_path)
    lines += read_text(anomalies_path)
    lines += read_text(critical_path)

    # Track which inputs exist
    inputs_used = []
    for p in [linux_json_path, win_csv_path, linux_log_path, win_log_path, anomalies_path, critical_path]:
        if p.exists():
            inputs_used.append(str(p.relative_to(repo_root)))

    findings = []
    total = 0
    overall = "LOW"

    s, h = scan_linux_processes(linux_json, findings)
    total += s
    if SEV_ORDER[h] > SEV_ORDER[overall]:
        overall = h

    s, h = scan_windows_services(win_rows, findings)
    total += s
    if SEV_ORDER[h] > SEV_ORDER[overall]:
        overall = h

    s, h = scan_logs(lines, findings)
    total += s
    if SEV_ORDER[h] > SEV_ORDER[overall]:
        overall = h

    # Write report to /report
    report_path = report_dir / f"security_report_{utc_stamp()}.txt"
    write_report(report_path, inputs_used, findings, overall, total)

    print(f"[OK] Report created: {report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[X] Analysis failed: {e}", file=sys.stderr)
        raise SystemExit(1)
