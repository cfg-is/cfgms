#!/usr/bin/env bash
# Helper for /dispatch and /isoagents skills.
# Wraps commands that contain $() or Go-template quotes so Claude Code
# can invoke them without triggering manual-approval prompts.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKTREE_BASE="$(cd "$REPO_ROOT/.." && pwd)/worktrees"

usage() {
  cat <<'EOF'
Usage: agent-dispatch.sh <command> [args...]

Commands:
  check-conflicts <NUM> [NUM...]   Check for existing containers/clones
  create-clone    <NUM>            Clone repo and create feature branch
  launch          <NUM>            Launch agent container
  wait-for-auth   <NUM> [NUM...]   Poll containers until past auth phase (~30s)
  cleanup-issue   <NUM>            Remove container and clone for a specific issue
  list-running                     List running agent containers
  list-exited                      List exited agent containers
  inspect-exit    <NUM>            Print exit code of container
  inspect-detail  <NUM>            Print stats + last 30 log lines
  health-check                     Check image age, Claude version, creds staleness
EOF
  exit 1
}

[[ $# -ge 1 ]] || usage

cmd="$1"; shift

case "$cmd" in

  check-conflicts)
    [[ $# -ge 1 ]] || { echo "check-conflicts requires issue numbers"; exit 1; }
    for num in "$@"; do
      # Container check
      existing=$(docker ps -a --filter "name=cfg-agent-${num}" --format "{{.Names}}: {{.Status}}" 2>/dev/null || true)
      if [[ -n "$existing" ]]; then
        echo "CONTAINER_EXISTS:${num}:${existing}"
      fi
      # Clone check
      if [[ -d "${WORKTREE_BASE}/story-${num}" ]]; then
        echo "CLONE_EXISTS:${num}:${WORKTREE_BASE}/story-${num}"
      fi
    done
    echo "CHECK_DONE"
    ;;

  create-clone)
    [[ $# -eq 1 ]] || { echo "create-clone requires exactly one issue number"; exit 1; }
    num="$1"
    dest="${WORKTREE_BASE}/story-${num}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)
    git clone --local --branch develop "$REPO_ROOT" "$dest"
    cd "$dest"
    git remote set-url origin "$github_url"
    git checkout -b "feature/story-${num}-agent"
    echo "CLONE_OK:${num}:$(git branch --show-current)"
    ;;

  launch)
    [[ $# -eq 1 ]] || { echo "launch requires exactly one issue number"; exit 1; }
    num="$1"
    clone_path="${WORKTREE_BASE}/story-${num}"
    real_path=$(realpath "$clone_path")
    gh_token=$(gh auth token)
    if container_id=$(docker run -d \
      --name "cfg-agent-${num}" \
      --label "cfg-agent=true" \
      --label "issue=${num}" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "claude-creds:/persist" \
      -e "GH_TOKEN=${gh_token}" \
      --cap-add NET_ADMIN \
      cfg-agent:latest \
      "${num}" 2>&1); then
      echo "LAUNCHED:${num}:${container_id}"
    else
      # Launch failed — clean up orphaned clone to prevent blocking future dispatches
      echo "LAUNCH_FAILED:${num}:${container_id}"
      rm -rf "$clone_path"
      echo "CLEANED:clone:${clone_path}"
      exit 1
    fi
    ;;

  wait-for-auth)
    [[ $# -ge 1 ]] || { echo "wait-for-auth requires at least one issue number"; exit 1; }
    # Poll containers every 5s for up to 30s to confirm they survive past auth.
    # Auth failures cause exit within ~10s. If still running at 30s, auth succeeded.
    max_wait=30
    interval=5
    elapsed=0
    nums=("$@")
    while [[ $elapsed -lt $max_wait ]]; do
      sleep "$interval"
      elapsed=$((elapsed + interval))
      all_resolved=true
      for num in "${nums[@]}"; do
        status=$(docker inspect --format "{{.State.Status}}" "cfg-agent-${num}" 2>/dev/null || echo "not_found")
        if [[ "$status" == "exited" ]]; then
          exit_code=$(docker inspect --format "{{.State.ExitCode}}" "cfg-agent-${num}" 2>/dev/null || echo "?")
          last_log=$(docker logs --tail 5 "cfg-agent-${num}" 2>/dev/null || echo "(no logs)")
          echo "AUTH_FAILED:${num}:exit_code=${exit_code}:${last_log}"
        elif [[ "$status" == "running" ]]; then
          if [[ $elapsed -ge $max_wait ]]; then
            echo "AUTH_OK:${num}:running after ${elapsed}s"
          else
            all_resolved=false
          fi
        else
          echo "AUTH_UNKNOWN:${num}:status=${status}"
        fi
      done
      if $all_resolved; then
        break
      fi
    done
    # Final check for any still running (in case loop ended by time)
    for num in "${nums[@]}"; do
      status=$(docker inspect --format "{{.State.Status}}" "cfg-agent-${num}" 2>/dev/null || echo "not_found")
      if [[ "$status" == "running" ]]; then
        echo "AUTH_OK:${num}:running after ${elapsed}s"
      fi
    done
    echo "WAIT_DONE"
    ;;

  cleanup-issue)
    [[ $# -eq 1 ]] || { echo "cleanup-issue requires exactly one issue number"; exit 1; }
    num="$1"
    # Copy result file (best-effort)
    docker cp "cfg-agent-${num}:/tmp/agent-result.json" "/tmp/agent-result-${num}.json" 2>/dev/null || true
    # Remove container (works for both running and exited)
    if docker rm -f "cfg-agent-${num}" >/dev/null 2>&1; then
      echo "CLEANED:container:cfg-agent-${num}"
    else
      echo "SKIP:container:cfg-agent-${num} not found"
    fi
    # Remove clone directory
    clone_dir="${WORKTREE_BASE}/story-${num}"
    if [[ -d "$clone_dir" ]]; then
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
    else
      echo "SKIP:clone:${clone_dir} not found"
    fi
    echo "CLEANUP_DONE:${num}"
    ;;

  list-running)
    docker ps --filter "label=cfg-agent=true" \
      --format "{{.Names}}\t{{.Status}}\t{{.Label \"issue\"}}" 2>/dev/null || true
    ;;

  list-exited)
    docker ps -a --filter "label=cfg-agent=true" --filter "status=exited" \
      --format "{{.Names}}\t{{.Label \"issue\"}}" 2>/dev/null || true
    ;;

  inspect-exit)
    [[ $# -eq 1 ]] || { echo "inspect-exit requires exactly one issue number"; exit 1; }
    docker inspect --format "{{.State.ExitCode}}" "cfg-agent-$1"
    ;;

  inspect-detail)
    [[ $# -eq 1 ]] || { echo "inspect-detail requires exactly one issue number"; exit 1; }
    echo "=== Stats ==="
    docker stats --no-stream "cfg-agent-$1" 2>/dev/null || echo "(container not running)"
    echo "=== Last 30 log lines ==="
    docker logs --tail 30 "cfg-agent-$1" 2>/dev/null || echo "(no logs available)"
    ;;

  health-check)
    warnings=0

    # Image age check (warn if >7 days)
    created=$(docker inspect cfg-agent:latest --format "{{.Created}}" 2>/dev/null || true)
    if [[ -z "$created" ]]; then
      echo "WARN:image:Image cfg-agent:latest not found — run /agent-setup"
      warnings=$((warnings + 1))
    else
      created_epoch=$(date -d "$created" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "${created%%.*}" +%s 2>/dev/null || echo 0)
      now_epoch=$(date +%s)
      age_days=$(( (now_epoch - created_epoch) / 86400 ))
      echo "INFO:image_age:${age_days} days old (built ${created%%T*})"
      if [[ $age_days -ge 7 ]]; then
        echo "WARN:image_age:Image is ${age_days} days old — Trivy DB and Go modules may be stale. Run /agent-setup rebuild"
        warnings=$((warnings + 1))
      fi
    fi

    # Claude version comparison
    host_version=$(claude --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "unknown")
    container_version=$(docker run --rm --entrypoint claude cfg-agent:latest --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "unknown")
    echo "INFO:claude_version:host=${host_version} container=${container_version}"
    if [[ "$host_version" != "unknown" && "$container_version" != "unknown" && "$host_version" != "$container_version" ]]; then
      echo "WARN:claude_version:Host Claude (${host_version}) differs from container (${container_version}). Run /agent-setup rebuild"
      warnings=$((warnings + 1))
    fi

    # Credentials check
    if docker run --rm -v claude-creds:/persist --entrypoint test cfg-agent:latest -f /persist/.credentials.json 2>/dev/null; then
      echo "INFO:creds:Credentials present in claude-creds volume"
    else
      echo "WARN:creds:No credentials found — run /agent-setup creds"
      warnings=$((warnings + 1))
    fi

    echo "HEALTH_DONE:warnings=${warnings}"
    ;;

  *)
    echo "Unknown command: $cmd"
    usage
    ;;
esac
