#!/usr/bin/env python3
"""
analysis_engine_test.py - Reads ONLY /fakedata and writes a report to /report
"""

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

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
    fake_dir = repo_root / "fakedata"
    report_dir = repo_root / "report"
    return repo_root, fake_dir, report_dir


def read_text(path: Path):
    # Read lines from fakedata/*.log
    try:
        if not path.exists():
            return []
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []


def read_json(path: Path):
    # Read JSON from fakedata/fake_linux_processes.json
    try:
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def read_csv(path: Path):
    # Read CSV from fakedata/fake_windows_services.csv
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

    # Read processes from fake_linux_processes.json
    processes = linux_json.get("processes", [])
    for p in processes:
        name = (p.get("name") if isinstance(p, dict) else str(p)).strip()
        if not name:
            continue
        key = name.lower()
        if key in RISKY_PROCESSES:
            sev, reason = RISKY_PROCESSES[key]
            add_finding(findings, sev, f"Linux process: {name} ({reason})")
            score += SEV_SCORE[sev]
            if SEV_ORDER[sev] > SEV_ORDER[highest]:
                highest = sev

    return score, highest


def scan_windows_services(rows, findings):
    score = 0
    highest = "LOW"

    # Read services from fake_windows_services.csv
    for row in rows:
        name = (row.get("Name") or "").strip()
        if not name:
            continue
        if name in RISKY_SERVICES:
            sev, reason = RISKY_SERVICES[name]
            state = (row.get("State") or "").strip()
            startmode = (row.get("StartMode") or "").strip()
            add_finding(findings, sev, f"Windows service: {name} (State={state}, StartMode={startmode}) ({reason})")
            score += SEV_SCORE[sev]
            if SEV_ORDER[sev] > SEV_ORDER[highest]:
                highest = sev

    return score, highest


def scan_logs(lines, findings):
    score = 0
    highest = "LOW"
    compiled = [(sev, re.compile(rx, re.IGNORECASE), reason) for (sev, rx, reason) in LOG_PATTERNS]

    ip_fails = {}

    for line in lines:
        for sev, rx, reason in compiled:
            if rx.search(line):
                add_finding(findings, sev, f"Log: {reason} | {line[:180]}")
                score += SEV_SCORE[sev]
                if SEV_ORDER[sev] > SEV_ORDER[highest]:
                    highest = sev
                break

        if re.search(r"\bfailed\b|\bfailure\b|\bdenied\b|\bunauthorized\b", line, re.IGNORECASE):
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if m:
                ip = m.group(1)
                ip_fails[ip] = ip_fails.get(ip, 0) + 1

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
    out.append("OS Security Automation - Fake Data Report")
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
        for it in items:
            out.append(f"  - {it}")
        out.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main():
    repo_root, fake_dir, report_dir = repo_paths()

    linux_json_path = fake_dir / "fake_linux_processes.json"
    win_csv_path = fake_dir / "fake_windows_services.csv"
    fake_log_path = fake_dir / "fake_security_logs.log"

    # Read data from /fakedata
    linux_json = read_json(linux_json_path)
    win_rows = read_csv(win_csv_path)
    lines = read_text(fake_log_path)

    inputs_used = []
    for p in [linux_json_path, win_csv_path, fake_log_path]:
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
    report_path = report_dir / f"fake_report_{utc_stamp()}.txt"
    write_report(report_path, inputs_used, findings, overall, total)

    print(f"[OK] Fake report created: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
