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

2. **If `$ARGUMENTS` is 'creds'**: Skip to step 5 (credentials only).

3. **Health check** (runs when image already exists and `$ARGUMENTS` is NOT 'rebuild'):
   ```bash
   ./scripts/agent-dispatch.sh health-check
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
   **IMPORTANT**: This step requires a real TTY for interactive login and trust acceptance. The Bash tool CANNOT provide this. Do NOT attempt to run the `docker run --rm -it` command via the Bash tool — it will fail with "the input device is not a TTY". Instead, print the command and tell the user to run it manually in their terminal.

   - Create Docker volume: `docker volume create claude-creds` (idempotent)
   - Check if credentials already exist in the volume:
     ```bash
     docker run --rm -v claude-creds:/persist --entrypoint test cfg-agent:latest \
       -f /persist/.credentials.json && echo "exists"
     ```
   - If credentials exist and `$ARGUMENTS` is not 'creds': skip
   - If credentials missing or refreshing:
     - Tell user: "Claude credentials need setup. This requires interactive login, workspace trust acceptance, and remote-control approval."
     - Print the following command for the user to run manually in their terminal:
       ```bash
       docker run --rm -it \
         -v claude-creds:/persist \
         -w /workspace \
         --cap-add NET_ADMIN \
         --user root \
         --entrypoint bash \
         cfg-agent:latest \
         -c "mkdir -p /workspace && npm update -g @anthropic-ai/claude-code && su agent -c '
           init-firewall.sh
           echo \"\"
           echo \"Step 1/4: OAuth login...\"
           claude --dangerously-skip-permissions -p ready
           echo \"\"
           echo \"Step 2/4: Accepting workspace trust...\"
           echo \"  → Type yes to trust /workspace, then /exit to quit\"
           cd /workspace && claude
           echo \"\"
           echo \"Step 3/4: Accepting remote-control consent...\"
           echo \"  → Type y to enable remote control, then Ctrl+C after it starts\"
           cd /workspace && claude remote-control --permission-mode bypassPermissions --name setup-test || true
           echo \"\"
           echo \"Step 4/4: Saving all state...\"
           cp ~/.claude/.credentials.json /persist/
           cp ~/.claude.json /persist/.claude-config.json 2>/dev/null || true
           cp -r ~/.claude /persist/.claude-state
           echo \"Done! Credentials, trust, and remote-control consent saved.\"
         '"
       ```
     - **What the user will experience**:
       1. OAuth browser login (automatic redirect)
       2. Workspace trust dialog — type `yes`, then `/exit`
       3. Remote-control consent — type `y`, then `Ctrl+C` after it starts listening
     - The `npm update` ensures the container's Claude Code matches the latest version.
     - `~/.claude.json` (trust + remote consent) and `~/.claude/` (sessions, plugins) are saved to the volume.

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
- **OAuth flow fails**: Tell user to retry with `/agent-setup creds`
- **Network issues during build**: Suggest checking internet connection
