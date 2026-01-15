#!/usr/bin/env bash
# linux_check.sh - Linux collector (writes to ../data)

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DATA_DIR="${REPO_ROOT}/data"

OUT_JSON="${DATA_DIR}/linux_processes.json"
SEC_LOG="${DATA_DIR}/linux_security_events.log"
AUTH_LOG="${DATA_DIR}/auth.log"
ANOMALY_LOG="${DATA_DIR}/anomalies.log"
CRITICAL_LOG="${DATA_DIR}/critical_alerts.log"

ts() { date +"%Y-%m-%d %H:%M:%S"; }

log_auth()     { printf "%s AUTH: %s\n"     "$(ts)" "$1" >> "$AUTH_LOG"     2>/dev/null || true; }
log_anomaly()  { printf "%s ANOMALY: %s\n"  "$(ts)" "$1" >> "$ANOMALY_LOG"  2>/dev/null || true; }
log_critical() {
  printf "%s CRITICAL: %s\n" "$(ts)" "$1" >> "$CRITICAL_LOG" 2>/dev/null || true
  log_anomaly "$1"
}

json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf "%s" "$s"
}

mkdir -p "$DATA_DIR" 2>/dev/null || true
: > "$SEC_LOG" 2>/dev/null || true
[[ -f "$AUTH_LOG" ]] || : > "$AUTH_LOG" 2>/dev/null || true
[[ -f "$ANOMALY_LOG" ]] || : > "$ANOMALY_LOG" 2>/dev/null || true
[[ -f "$CRITICAL_LOG" ]] || : > "$CRITICAL_LOG" 2>/dev/null || true

log_auth "Linux check started (user=$(id -un 2>/dev/null || echo unknown))"
log_auth "Repo root: $REPO_ROOT"

# Read processes from ps
if ! command -v ps >/dev/null 2>&1; then
  log_critical "Missing command: ps"
else
  procs="$(ps -eo comm= 2>/dev/null || true)"

  # Write linux_processes.json
  json="{\"generated_utc\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"processes\":["
  first=1
  while IFS= read -r p; do
    [[ -z "${p// }" ]] && continue
    if [[ $first -eq 1 ]]; then first=0; else json+=","; fi
    json+="{\"name\":\"$(json_escape "$p")\"}"
  done <<< "$procs"
  json+="]}"

  printf "%s\n" "$json" > "$OUT_JSON" 2>/dev/null || log_critical "Failed to write $OUT_JSON"
  log_auth "Wrote: data/linux_processes.json"
fi

# Read security logs into linux_security_events.log
{
  echo "=== linux_security_events.log (snapshot) ==="
  echo

  if command -v journalctl >/dev/null 2>&1; then
    echo "=== journalctl -n 200 ==="
    journalctl -n 200 --no-pager 2>/dev/null || true
    echo
  fi

  if [[ -f /var/log/auth.log ]]; then
    echo "=== /var/log/auth.log (last 200) ==="
    tail -n 200 /var/log/auth.log 2>/dev/null || true
    echo
  fi

  if [[ -f /var/log/syslog ]]; then
    echo "=== /var/log/syslog (last 200) ==="
    tail -n 200 /var/log/syslog 2>/dev/null || true
    echo
  fi
} >> "$SEC_LOG" 2>/dev/null || true

if [[ ! -s "$SEC_LOG" ]]; then
  echo "No logs collected (permissions or missing sources)." >> "$SEC_LOG" 2>/dev/null || true
  log_anomaly "linux_security_events.log is empty"
fi

# Simple detections (easy to explain)
risky=("nc" "netcat" "hydra" "john")

if command -v ps >/dev/null 2>&1; then
  for r in "${risky[@]}"; do
    if ps -eo comm= 2>/dev/null | grep -qiE "^${r}$"; then
      log_critical "Risky Linux process detected: $r"
    fi
  done
fi

fail_hits="$(grep -iE "failed|failure|invalid user|unauthorized|denied" "$SEC_LOG" 2>/dev/null | wc -l | tr -d ' ' || true)"
if [[ -n "$fail_hits" && "$fail_hits" -ge 20 ]]; then
  log_critical "High volume of auth-failure indicators in Linux logs: $fail_hits hits"
elif [[ -n "$fail_hits" && "$fail_hits" -ge 5 ]]; then
  log_anomaly "Some auth-failure indicators in Linux logs: $fail_hits hits"
fi

stamp="$(ts)"
log_auth "END OF CHECK $stamp"
log_anomaly "END OF CHECK $stamp"

echo "[OK] Linux collector finished. Outputs in data/"
exit 0
