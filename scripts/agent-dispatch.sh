#!/usr/bin/env bash
# Helper for /dispatch and /isoagents skills.
# Wraps commands that contain $() or Go-template quotes so Claude Code
# can invoke them without triggering manual-approval prompts.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKTREE_BASE="$(cd "$REPO_ROOT/.." && pwd)/worktrees"

# Ensure clone is based on latest remote develop, not stale local state.
# Called inside fresh clones after setting the remote URL.
sync_to_remote_develop() {
  git fetch origin develop
  git reset --hard origin/develop
}

# Validate branch name: only allow safe characters (alphanumeric, /, -, ., _)
validate_branch() {
  local branch="$1"
  if [[ ! "$branch" =~ ^[a-zA-Z0-9/_.-]+$ ]]; then
    echo "ERROR: Invalid branch name '${branch}'. Only alphanumeric, '/', '-', '.', and '_' are allowed."
    exit 1
  fi
}

# Sanitize branch name for use in container/directory names: / → --
sanitize_branch() {
  echo "$1" | sed 's|/|--|g'
}

usage() {
  cat <<'EOF'
Usage: agent-dispatch.sh <command> [args...]

Commands:
  check-conflicts <NUM> [NUM...]            Check for existing containers/clones (issue mode)
  check-conflicts --branch <NAME>           Check for existing containers/clones (branch mode)
  check-conflicts --pr <NUM>                Check for existing containers/clones (PR-fix mode)
  create-clone    <NUM>                     Clone repo and create feature branch (issue mode)
  create-clone-branch <BRANCH>              Clone repo and checkout/create branch
  create-clone-pr <PR_NUM>                  Clone repo and checkout PR branch
  launch          <NUM>                     Launch agent container (issue mode)
  launch-generic  <NAME> <DIR> [ARGS...]    Launch agent container with custom name and args
  launch-interactive <BRANCH>               Print docker run command for interactive session
  wait-for-auth   <NUM> [NUM...]            Poll containers until past auth phase (~30s)
  wait-for-auth   --container <NAME> [...]  Poll named containers until past auth phase
  check-creds                                Check OAuth credential validity and remaining time
  cleanup-issue   <NUM>                     Remove container and clone for a specific issue
  cleanup-container <NAME>                  Remove container and associated clone by name
  list-running                              List running agent containers
  list-exited                               List exited agent containers
  inspect-exit    <NUM>                     Print exit code of container
  inspect-detail  <NUM>                     Print stats + last 30 log lines
  inspect-container <NAME>                  Print stats + last 30 log lines for named container
  health-check                              Check image age, Claude version, creds staleness
EOF
  exit 1
}

[[ $# -ge 1 ]] || usage

cmd="$1"; shift

case "$cmd" in

  check-conflicts)
    [[ $# -ge 1 ]] || { echo "check-conflicts requires arguments"; exit 1; }
    case "$1" in
      --branch)
        [[ $# -ge 2 ]] || { echo "check-conflicts --branch requires a branch name"; exit 1; }
        branch="$2"
        validate_branch "$branch"
        sanitized=$(sanitize_branch "$branch")
        container_name="cfg-agent-branch-${sanitized}"
        clone_dir="${WORKTREE_BASE}/${sanitized}"
        existing=$(docker ps -a --filter "name=${container_name}" --format "{{.Names}}: {{.Status}}" 2>/dev/null || true)
        if [[ -n "$existing" ]]; then
          echo "CONTAINER_EXISTS:${branch}:${existing}"
        fi
        if [[ -d "$clone_dir" ]]; then
          echo "CLONE_EXISTS:${branch}:${clone_dir}"
        fi
        echo "CHECK_DONE"
        ;;
      --pr)
        [[ $# -ge 2 ]] || { echo "check-conflicts --pr requires a PR number"; exit 1; }
        pr_num="$2"
        container_name="cfg-agent-pr-fix-${pr_num}"
        clone_dir="${WORKTREE_BASE}/pr-fix-${pr_num}"
        existing=$(docker ps -a --filter "name=${container_name}" --format "{{.Names}}: {{.Status}}" 2>/dev/null || true)
        if [[ -n "$existing" ]]; then
          echo "CONTAINER_EXISTS:pr-${pr_num}:${existing}"
        fi
        if [[ -d "$clone_dir" ]]; then
          echo "CLONE_EXISTS:pr-${pr_num}:${clone_dir}"
        fi
        echo "CHECK_DONE"
        ;;
      *)
        # Original issue-number mode
        for num in "$@"; do
          existing=$(docker ps -a --filter "name=cfg-agent-${num}" --format "{{.Names}}: {{.Status}}" 2>/dev/null || true)
          if [[ -n "$existing" ]]; then
            echo "CONTAINER_EXISTS:${num}:${existing}"
          fi
          if [[ -d "${WORKTREE_BASE}/story-${num}" ]]; then
            echo "CLONE_EXISTS:${num}:${WORKTREE_BASE}/story-${num}"
          fi
        done
        echo "CHECK_DONE"
        ;;
    esac
    ;;

  create-clone)
    [[ $# -eq 1 ]] || { echo "create-clone requires exactly one issue number"; exit 1; }
    num="$1"
    dest="${WORKTREE_BASE}/story-${num}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)
    trap "rm -rf '$dest'" ERR
    git clone --local --branch develop "$REPO_ROOT" "$dest"
    cd "$dest"
    git remote set-url origin "$github_url"
    sync_to_remote_develop
    git checkout -b "feature/story-${num}-agent"
    trap - ERR
    echo "CLONE_OK:${num}:$(git branch --show-current)"
    ;;

  create-clone-branch)
    [[ $# -eq 1 ]] || { echo "create-clone-branch requires exactly one branch name"; exit 1; }
    branch="$1"
    validate_branch "$branch"
    sanitized=$(sanitize_branch "$branch")
    dest="${WORKTREE_BASE}/${sanitized}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Check if branch exists on remote
    trap "rm -rf '$dest'" ERR
    if git -C "$REPO_ROOT" ls-remote --heads origin "$branch" | grep -q .; then
      # Branch exists: clone develop, then fetch and checkout the branch
      git clone --local --branch develop "$REPO_ROOT" "$dest"
      cd "$dest"
      git remote set-url origin "$github_url"
      sync_to_remote_develop
      git fetch origin "$branch"
      git checkout "$branch"
      trap - ERR
      echo "CLONE_OK:${sanitized}:${branch}"
    else
      # Branch does not exist: clone develop, create new branch
      git clone --local --branch develop "$REPO_ROOT" "$dest"
      cd "$dest"
      git remote set-url origin "$github_url"
      sync_to_remote_develop
      git checkout -b "$branch"
      trap - ERR
      echo "CLONE_NEW:${sanitized}:${branch}"
    fi
    ;;

  create-clone-pr)
    [[ $# -eq 1 ]] || { echo "create-clone-pr requires exactly one PR number"; exit 1; }
    pr_num="$1"
    dest="${WORKTREE_BASE}/pr-fix-${pr_num}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Get branch from PR
    pr_branch=$(gh pr view "$pr_num" --json headRefName -q '.headRefName' 2>/dev/null) || {
      echo "ERROR: Failed to get branch for PR #${pr_num}"
      exit 1
    }

    # Extract issue number from PR body
    pr_body=$(gh pr view "$pr_num" --json body -q '.body' 2>/dev/null || echo "")
    issue_num=$(echo "$pr_body" | grep -oP 'Fixes #\K[0-9]+' | head -1 || true)
    if [[ -z "$issue_num" ]] && [[ "$pr_branch" =~ story-([0-9]+) ]]; then
      issue_num="${BASH_REMATCH[1]}"
    fi

    # Clone and checkout the PR branch
    trap "rm -rf '$dest'" ERR
    git clone --local --branch develop "$REPO_ROOT" "$dest"
    cd "$dest"
    git remote set-url origin "$github_url"
    sync_to_remote_develop
    git fetch origin "$pr_branch"
    git checkout "$pr_branch"
    trap - ERR

    echo "CLONE_OK:pr-fix-${pr_num}:${pr_branch}:issue=${issue_num:-none}"
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
      --label "mode=issue" \
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

  launch-generic)
    [[ $# -ge 2 ]] || { echo "launch-generic requires <CONTAINER_NAME> <CLONE_DIR> [ENTRYPOINT_ARGS...]"; exit 1; }
    container_name="$1"; shift
    clone_dir="$1"; shift
    entrypoint_args=("$@")

    real_path=$(realpath "$clone_dir")
    gh_token=$(gh auth token)

    # Derive mode and metadata labels from entrypoint args
    mode_label="branch"
    extra_labels=()
    for i in "${!entrypoint_args[@]}"; do
      case "${entrypoint_args[$i]}" in
        --fix-pr) mode_label="fix-pr"; extra_labels+=(--label "pr=${entrypoint_args[$((i+1))]}") ;;
        --branch) extra_labels+=(--label "branch=${entrypoint_args[$((i+1))]}") ;;
        --issue)  extra_labels+=(--label "issue=${entrypoint_args[$((i+1))]}") ;;
      esac
    done

    if container_id=$(docker run -d \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=${mode_label}" \
      "${extra_labels[@]}" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "claude-creds:/persist" \
      -e "GH_TOKEN=${gh_token}" \
      --cap-add NET_ADMIN \
      cfg-agent:latest \
      "${entrypoint_args[@]}" 2>&1); then
      echo "LAUNCHED:${container_name}:${container_id}"
    else
      echo "LAUNCH_FAILED:${container_name}:${container_id}"
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
      exit 1
    fi
    ;;

  launch-interactive)
    [[ $# -ge 1 ]] || { echo "launch-interactive requires a branch name and optional clone dir"; exit 1; }
    branch="$1"
    validate_branch "$branch"
    sanitized=$(sanitize_branch "$branch")
    clone_dir="${2:-${WORKTREE_BASE}/${sanitized}}"
    real_path=$(realpath "$clone_dir")
    gh_token=$(gh auth token)
    container_name="cfg-agent-interactive-${sanitized}"

    # Inline setup script — can't reference /workspace files since the cloned
    # branch may not contain our tooling files
    setup_cmds="init-firewall.sh"
    setup_cmds+=" && mkdir -p ~/.claude"
    setup_cmds+=" && cp /persist/.credentials.json ~/.claude/.credentials.json 2>/dev/null || echo 'WARN: No credentials'"
    # Restore trust state and Claude config saved by /agent-setup
    setup_cmds+=" && if [ -f /persist/.claude-config.json ]; then cp /persist/.claude-config.json ~/.claude.json 2>/dev/null || true; fi"
    setup_cmds+=" && if [ -d /persist/.claude-state ]; then cp -rn /persist/.claude-state/. ~/.claude/ 2>/dev/null || true; fi"
    setup_cmds+=" && if [ ! -f ~/.claude.json ]; then echo '{\"hasCompletedOnboarding\":true,\"installMethod\":\"native\"}' > ~/.claude.json; fi"
    setup_cmds+=" && git config --global user.name cfg-agent"
    setup_cmds+=" && git config --global user.email agent@cfg.is"
    setup_cmds+=" && git config --global push.autoSetupRemote true"
    setup_cmds+=" && echo '================================================'"
    setup_cmds+=" && echo ' CFGMS Interactive Agent Session'"
    setup_cmds+=" && echo ' Branch: ${branch}'"
    setup_cmds+=" && echo ' Starting remote-control server...'"
    setup_cmds+=" && echo ' Connect at: https://claude.ai/code'"
    setup_cmds+=" && echo '================================================'"
    setup_cmds+=" && echo 'Warming up workspace trust...'"
    setup_cmds+=" && claude -p 'ready' --dangerously-skip-permissions 2>&1 || echo 'WARN: trust warmup failed (non-fatal)'"
    setup_cmds+=" && echo 'Starting remote-control...'"
    setup_cmds+=" && exec claude remote-control --permission-mode bypassPermissions --name '${branch}' 2>&1"

    # Launch container in detached mode with remote-control server
    if container_id=$(docker run -d \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=interactive" \
      --label "branch=${branch}" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "claude-creds:/persist" \
      -e "GH_TOKEN=${gh_token}" \
      -e "CFGMS_AGENT_MODE=true" \
      --cap-add NET_ADMIN \
      --entrypoint /bin/bash \
      cfg-agent:latest \
      -c "$setup_cmds" 2>&1); then
      echo "LAUNCHED:${container_name}:${container_id}"
      echo ""
      echo "Interactive session starting with remote-control mode."
      echo "Connect from your browser at: https://claude.ai/code"
      echo "Look for session named: ${branch}"
      echo ""
      echo "To view the session URL and QR code:"
      echo "  docker logs ${container_name}"
      echo ""
      echo "To drop into a shell inside the container:"
      echo "  docker exec -it ${container_name} bash"
    else
      echo "LAUNCH_FAILED:${container_name}:${container_id}"
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
      exit 1
    fi
    ;;

  wait-for-auth)
    [[ $# -ge 1 ]] || { echo "wait-for-auth requires at least one argument"; exit 1; }

    # Parse container names — either --container <name> [<name>...] or issue numbers
    container_mode=false
    containers=()
    if [[ "$1" == "--container" ]]; then
      container_mode=true
      shift
      containers=("$@")
    else
      for num in "$@"; do
        containers+=("cfg-agent-${num}")
      done
    fi

    max_wait=30
    interval=5
    elapsed=0
    while [[ $elapsed -lt $max_wait ]]; do
      sleep "$interval"
      elapsed=$((elapsed + interval))
      all_resolved=true
      for cname in "${containers[@]}"; do
        # Derive display name (strip cfg-agent- prefix for issue mode)
        display="$cname"
        if [[ "$cname" =~ ^cfg-agent-([0-9]+)$ ]]; then
          display="${BASH_REMATCH[1]}"
        fi
        status=$(docker inspect --format "{{.State.Status}}" "$cname" 2>/dev/null || echo "not_found")
        if [[ "$status" == "exited" ]]; then
          exit_code=$(docker inspect --format "{{.State.ExitCode}}" "$cname" 2>/dev/null || echo "?")
          last_log=$(docker logs --tail 5 "$cname" 2>/dev/null || echo "(no logs)")
          echo "AUTH_FAILED:${display}:exit_code=${exit_code}:${last_log}"
        elif [[ "$status" == "running" ]]; then
          if [[ $elapsed -ge $max_wait ]]; then
            echo "AUTH_OK:${display}:running after ${elapsed}s"
          else
            all_resolved=false
          fi
        else
          echo "AUTH_UNKNOWN:${display}:status=${status}"
        fi
      done
      if $all_resolved; then
        break
      fi
    done
    # Final check for any still running
    for cname in "${containers[@]}"; do
      display="$cname"
      if [[ "$cname" =~ ^cfg-agent-([0-9]+)$ ]]; then
        display="${BASH_REMATCH[1]}"
      fi
      status=$(docker inspect --format "{{.State.Status}}" "$cname" 2>/dev/null || echo "not_found")
      if [[ "$status" == "running" ]]; then
        echo "AUTH_OK:${display}:running after ${elapsed}s"
      fi
    done
    echo "WAIT_DONE"
    ;;

  check-creds)
    # Check OAuth credential validity in the shared volume
    if ! docker volume inspect claude-creds >/dev/null 2>&1; then
      echo "CREDS_MISSING:no claude-creds volume"
    elif ! docker run --rm -v claude-creds:/persist --entrypoint test cfg-agent:latest -f /persist/.credentials.json 2>/dev/null; then
      echo "CREDS_MISSING:no credentials file"
    else
      result=$(docker run --rm -v claude-creds:/persist --entrypoint python3 cfg-agent:latest -c "
import json, time
d = json.load(open('/persist/.credentials.json'))
oauth = d.get('claudeAiOauth', {})
exp_ms = oauth.get('expiresAt', 0)
exp_s = exp_ms / 1000
now = time.time()
remaining_min = int((exp_s - now) / 60)
if remaining_min < 0:
    print(f'CREDS_EXPIRED:{remaining_min}')
elif remaining_min < 15:
    print(f'CREDS_LOW:{remaining_min}')
else:
    print(f'CREDS_OK:{remaining_min}')
" 2>/dev/null || echo "CREDS_ERROR:failed to parse")
      echo "$result"
    fi
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

  cleanup-container)
    [[ $# -eq 1 ]] || { echo "cleanup-container requires exactly one container name"; exit 1; }
    container_name="$1"
    # Copy result file (best-effort)
    docker cp "${container_name}:/tmp/agent-result.json" "/tmp/agent-result-${container_name}.json" 2>/dev/null || true
    # Remove container
    if docker rm -f "$container_name" >/dev/null 2>&1; then
      echo "CLEANED:container:${container_name}"
    else
      echo "SKIP:container:${container_name} not found"
    fi
    # Derive clone directory from container name
    clone_dir=""
    if [[ "$container_name" =~ ^cfg-agent-pr-fix-(.+)$ ]]; then
      clone_dir="${WORKTREE_BASE}/pr-fix-${BASH_REMATCH[1]}"
    elif [[ "$container_name" =~ ^cfg-agent-branch-(.+)$ ]]; then
      clone_dir="${WORKTREE_BASE}/${BASH_REMATCH[1]}"
    elif [[ "$container_name" =~ ^cfg-agent-interactive-(.+)$ ]]; then
      clone_dir="${WORKTREE_BASE}/${BASH_REMATCH[1]}"
    fi
    if [[ -n "$clone_dir" ]] && [[ -d "$clone_dir" ]]; then
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
    elif [[ -n "$clone_dir" ]]; then
      echo "SKIP:clone:${clone_dir} not found"
    fi
    echo "CLEANUP_DONE:${container_name}"
    ;;

  list-running)
    docker ps --filter "label=cfg-agent=true" \
      --format "{{.Names}}\t{{.Status}}\t{{.Label \"issue\"}}\t{{.Label \"mode\"}}\t{{.Label \"branch\"}}\t{{.Label \"pr\"}}" 2>/dev/null || true
    ;;

  list-exited)
    docker ps -a --filter "label=cfg-agent=true" --filter "status=exited" \
      --format "{{.Names}}\t{{.Label \"issue\"}}\t{{.Label \"mode\"}}\t{{.Label \"branch\"}}\t{{.Label \"pr\"}}" 2>/dev/null || true
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

  inspect-container)
    [[ $# -eq 1 ]] || { echo "inspect-container requires exactly one container name"; exit 1; }
    echo "=== Stats ==="
    docker stats --no-stream "$1" 2>/dev/null || echo "(container not running)"
    echo "=== Last 30 log lines ==="
    docker logs --tail 30 "$1" 2>/dev/null || echo "(no logs available)"
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
