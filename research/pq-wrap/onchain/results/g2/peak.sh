#!/usr/bin/env bash
# usage: peak.sh LOG -- CMD...   runs CMD, samples VmHWM/VmRSS of it every 0.2 s, prints peak (kB) and wall time
set -uo pipefail
LOG="$1"; shift 2
s=$(date +%s.%N)
"$@" > "$LOG" 2>&1 &
pid=$!
peak=0
while kill -0 $pid 2>/dev/null; do
  h=$(awk '/VmHWM/{print $2}' /proc/$pid/status 2>/dev/null || echo 0)
  [ -n "$h" ] && [ "$h" -gt "$peak" ] && peak=$h
  sleep 0.2
done
wait $pid; rc=$?
e=$(date +%s.%N)
echo "rc=$rc peak_hwm_kB=$peak wall_s=$(echo "$e - $s" | bc)"
