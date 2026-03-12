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

3. **If `$ARGUMENTS` is 'rebuild'**: Force rebuild with `--no-cache` (refreshes Trivy DB and Go modules).

4. **Build agent container image** (use `run_in_background` since this takes 3-5 minutes):
   ```bash
   docker build -t cfg-agent:latest -f .devcontainer/Dockerfile .
   ```
   For rebuild: `docker build --no-cache -t cfg-agent:latest -f .devcontainer/Dockerfile .`

   While waiting, proceed with steps 5-7 (they're independent).

5. **Set up Claude credentials**:
   - Create Docker volume: `docker volume create claude-creds` (idempotent)
   - Check if credentials already exist in the volume:
     ```bash
     docker run --rm -v claude-creds:/persist cfg-agent:latest \
       test -f /persist/.credentials.json && echo "exists"
     ```
   - If credentials exist and not `$ARGUMENTS` == 'creds': skip
   - If credentials missing or refreshing:
     - Tell user: "Claude credentials need setup. This requires an interactive login."
     - Run interactive container for OAuth:
       ```bash
       docker run --rm -it \
         -v claude-creds:/persist \
         --entrypoint bash \
         cfg-agent:latest \
         -c "claude --dangerously-skip-permissions && cp ~/.claude/.credentials.json /persist/"
       ```
     - **IMPORTANT**: This step requires user interaction (OAuth flow). Tell the user what to expect.

6. **Create directories**:
   ```bash
   mkdir -p ../worktrees
   ```

7. **Verify GitHub labels exist** (idempotent):
   ```bash
   gh label create "agent:ready" --color "0E8A16" --description "Story ready for agent dispatch" --force
   gh label create "agent:in-progress" --color "FBCA04" --description "Agent container running" --force
   gh label create "agent:success" --color "0075CA" --description "Agent completed, PR created" --force
   gh label create "agent:failed" --color "D73A4A" --description "Agent failed, draft PR created" --force
   gh label create "agent:blocked" --color "E4E669" --description "Needs human intervention" --force
   ```

8. **Verify setup** (after image build completes):
   ```bash
   docker run --rm --entrypoint claude cfg-agent:latest --version  # Should print claude version
   ```

9. **Print summary**:
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
