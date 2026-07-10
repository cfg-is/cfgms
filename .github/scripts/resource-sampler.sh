#!/usr/bin/env bash
# Resource sampler for CFGMS self-hosted CI runners (Linux).
# Backgrounds a CPU+memory sampling loop during a job; reports peak values on completion.
#
# Usage:
#   resource-sampler.sh start <state-dir>
#       Background a sampling loop that writes time-series samples to
#       <state-dir>/samples.txt.  Saves the background PID to
#       <state-dir>/sampler.pid.  Creates <state-dir> if absent.
#       State dir should be $RUNNER_TEMP-scoped (job-unique) — not /tmp.
#
#   resource-sampler.sh report <state-dir> <artifact-out-file>
#       Kill the background sampler, compute peak CPU% and peak memory from
#       <state-dir>/samples.txt, emit exactly one RESOURCE_PROFILE: line to
#       stdout, and copy (or touch) <artifact-out-file>.  Always exits 0.
#
# RESOURCE_PROFILE: line formats:
#   success: os=linux cpu_peak_pct=<n> mem_peak_mb=<peak>/<total> vm=<n>vCPU/<n>GB
#   error:   os=linux error=<reason> vm=<n>vCPU/<n>GB
#   reason values: sampler_start_failed | no_samples_collected
#
# Loop characteristics:
#   - Bounded at 720 iterations (~60 min at 5 s each) so a cancelled or crashed
#     job cannot leave an orphaned sampler running indefinitely on a persistent
#     self-hosted runner.
#   - Every per-iteration read is individually guarded (|| true / || echo 0) so
#     a single transient /proc failure skips one 5 s sample without killing the
#     loop.  Do NOT use set -e inside the background subshell; the guards must
#     be the sole protection so their presence is testable (AC2, Issue #2485).
#
# Style follows .github/scripts/install-trivy.sh.

set -euo pipefail

MODE="${1:?usage: resource-sampler.sh start|report <state-dir> [artifact-out-file]}"
STATE_DIR="${2:?usage: resource-sampler.sh start|report <state-dir> [artifact-out-file]}"

VCPU=$(nproc 2>/dev/null || echo "0")
MEM_TOTAL_GB=$(awk '/^MemTotal:/{print int($2/1024/1024); exit}' /proc/meminfo 2>/dev/null || echo "0")
VM_SPEC="${VCPU}vCPU/${MEM_TOTAL_GB}GB"

SAMPLES_FILE="${STATE_DIR}/samples.txt"
PID_FILE="${STATE_DIR}/sampler.pid"

case "$MODE" in
  start)
    mkdir -p "$STATE_DIR"

    # The background loop intentionally does NOT inherit set -e from this script.
    # set +e is explicit here so any future addition to the loop body is also safe.
    # Individual guards (|| true / || echo 0) on every read are the primary fix
    # and are directly tested by the AC2 regression test (Issue #2485).
    (
      set +e
      PREV=""
      ITER=0
      MAX_ITER=720
      while [ "$ITER" -lt "$MAX_ITER" ]; do
        CURR=$(awk 'NR==1{print $2,$3,$4,$5,$6,$7,$8; exit}' /proc/stat 2>/dev/null || true)
        if [ -n "$PREV" ] && [ -n "$CURR" ]; then
          CPU_PCT=$(awk -v p="$PREV" -v c="$CURR" 'BEGIN{
            split(p,pa); split(c,ca)
            tot=0; for(i=1;i<=7;i++) tot+=ca[i]-pa[i]
            idle=(ca[4]-pa[4])+(ca[5]-pa[5])
            print (tot>0)?int(100*(tot-idle)/tot):0
          }' 2>/dev/null || echo 0)
          MEM_TOTAL=$(awk '/^MemTotal:/{print int($2/1024); exit}' /proc/meminfo 2>/dev/null || echo 0)
          MEM_AVAIL=$(awk '/^MemAvailable:/{print int($2/1024); exit}' /proc/meminfo 2>/dev/null || echo 0)
          MEM_USED=$(( ${MEM_TOTAL:-0} - ${MEM_AVAIL:-0} ))
          printf '%s cpu_pct=%d mem_used_mb=%d/%d\n' \
            "$(date -u +%H:%M:%S 2>/dev/null || echo time)" \
            "${CPU_PCT:-0}" "$MEM_USED" "${MEM_TOTAL:-0}" \
            >> "$SAMPLES_FILE" || true
        fi
        PREV="$CURR"
        ITER=$(( ITER + 1 ))
        sleep 5
      done
    ) &
    echo $! > "$PID_FILE"
    echo "resource-sampler: started (pid=$(cat "$PID_FILE"), state=${STATE_DIR})"
    ;;

  report)
    ARTIFACT_OUT="${3:?usage: resource-sampler.sh report <state-dir> <artifact-out-file>}"

    # Kill the sampler (best-effort; may already have exited or never started).
    if [ -f "$PID_FILE" ]; then
      SAMPLER_PID=$(cat "$PID_FILE" 2>/dev/null || true)
      [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2>/dev/null || true
    fi

    # Determine error case vs success and emit the RESOURCE_PROFILE line.
    if [ ! -f "$PID_FILE" ]; then
      echo "RESOURCE_PROFILE: os=linux error=sampler_start_failed vm=${VM_SPEC}"
      touch "$ARTIFACT_OUT"
    elif [ ! -f "$SAMPLES_FILE" ] || [ ! -s "$SAMPLES_FILE" ]; then
      echo "RESOURCE_PROFILE: os=linux error=no_samples_collected vm=${VM_SPEC}"
      touch "$ARTIFACT_OUT"
    else
      CPU_PEAK=$(awk -F'cpu_pct=' 'NF>1{n=split($2,a," ");v=a[1]+0;if(v>m)m=v}END{print m+0}' \
        "$SAMPLES_FILE" 2>/dev/null || echo 0)
      MEM_PEAK=$(awk -F'mem_used_mb=' 'NF>1{split($2,a,"/");v=a[1]+0;if(v>m)m=v}END{print m+0}' \
        "$SAMPLES_FILE" 2>/dev/null || echo 0)
      MEM_TOTAL_MB=$(awk -F'mem_used_mb=' 'NF>1{split($2,a,"/");t=a[2]+0}END{print t}' \
        "$SAMPLES_FILE" 2>/dev/null || echo 0)
      echo "RESOURCE_PROFILE: os=linux cpu_peak_pct=${CPU_PEAK} mem_peak_mb=${MEM_PEAK}/${MEM_TOTAL_MB} vm=${VM_SPEC}"
      cp "$SAMPLES_FILE" "$ARTIFACT_OUT"
    fi
    ;;

  *)
    echo "resource-sampler: unknown mode '${MODE}' (expected start|report)" >&2
    exit 2
    ;;
esac
