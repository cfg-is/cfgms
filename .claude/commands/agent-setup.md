---
name: agent-setup
description: One-time setup for agent dispatch infrastructure
parameters:
  - name: action
    description: "Optional: 'rebuild' to force rebuild the container image, 'creds' to refresh Claude credentials only"
    required: false
---

# Agent Setup Command

One-time bootstrap for agent dispatch. Builds the container image, sets up credentials, and creates required directories. Safe to run multiple times (idempotent).

## Execution Flow

1. **Check prerequisites**:
   ```bash
   docker info >/dev/null 2>&1  # Docker running?
   gh auth status               # GitHub authenticated?
   ```
   If either fails, provide specific fix instructions and stop.

2. **If `$ARGUMENTS` is 'creds'**: Tell the user to run the refresh script directly in their terminal:
   ```
   ./.claude/scripts/refresh-agent-creds.sh
   ```
   This script handles Docker volume creation, OAuth login, workspace trust, and remote-control consent interactively. It requires a TTY and cannot be run via the Bash tool. After the user confirms completion, verify credentials with `./.claude/scripts/agent-dispatch.sh check-creds` and stop (skip all other steps).

3. **Health check** (runs when image already exists and `$ARGUMENTS` is NOT 'rebuild'):
   ```bash
   ./.claude/scripts/agent-dispatch.sh health-check
   ```
   Parse the output lines:
   - `WARN:image_age:...` — Image is stale, recommend rebuild
   - `WARN:claude_version:...` — Version mismatch, recommend rebuild
   - `WARN:creds:...` — Credentials missing
   - If any `WARN:image_age` or `WARN:claude_version` lines appear, recommend: "Image is stale. Run `/agent-setup rebuild` to refresh Trivy DB, Go modules, and Claude Code."
   - If the only warning is `WARN:creds`, proceed normally (step 5 handles it)
   - If no warnings, print "Image is healthy" and proceed

4. **If `$ARGUMENTS` is 'rebuild'**: Force rebuild with `--no-cache` (refreshes Trivy DB and Go modules).

5. **Build agent container image** (use `run_in_background` since this takes 3-5 minutes):
   ```bash
   docker build -t cfg-agent:latest -f .devcontainer/Dockerfile .
   ```
   For rebuild: `docker build --no-cache -t cfg-agent:latest -f .devcontainer/Dockerfile .`

   While waiting, proceed with steps 6-8 (they're independent).

6. **Set up Claude credentials and workspace trust**:
   **IMPORTANT**: This step requires a real TTY. Do NOT attempt to run it via the Bash tool.

   - Check if credentials already exist:
     ```bash
     docker run --rm -v claude-creds:/persist --entrypoint test cfg-agent:latest \
       -f /persist/.credentials.json && echo "exists"
     ```
   - If credentials exist and `$ARGUMENTS` is not 'creds': skip
   - If credentials missing: tell the user to run `./.claude/scripts/refresh-agent-creds.sh` in their terminal, then confirm when done.

7. **Create directories**:
   ```bash
   mkdir -p ../worktrees
   ```

8. **Verify GitHub labels exist** (idempotent):
   ```bash
   gh label create "agent:ready" --color "0E8A16" --description "Story ready for agent dispatch" --force
   gh label create "agent:in-progress" --color "FBCA04" --description "Agent container running" --force
   gh label create "agent:success" --color "0075CA" --description "Agent completed, PR created" --force
   gh label create "agent:failed" --color "D73A4A" --description "Agent failed, draft PR created" --force
   gh label create "agent:blocked" --color "E4E669" --description "Needs human intervention" --force
   ```

9. **Verify setup** (after image build completes):
   ```bash
   docker run --rm --entrypoint claude cfg-agent:latest --version  # Should print claude version
   ```

10. **Print summary**:
   - Image: built/exists
   - Credentials: configured/missing
   - Labels: created
   - Worktree dir: ready
   - "Setup complete. Use `/dispatch <issue#>` to launch agents."

## Error Handling

- **Docker not installed**: Provide install link, stop
- **GitHub not authenticated**: Tell user to run `gh auth login`, stop
- **Image build fails**: Show build output, suggest checking Dockerfile
- **OAuth flow fails**: Tell user to retry with `./.claude/scripts/refresh-agent-creds.sh`
- **Network issues during build**: Suggest checking internet connection
