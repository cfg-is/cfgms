#!/usr/bin/env bash
# Setup for interactive agent sessions.
# Restores credentials, configures git, prints usage help.
set -euo pipefail

# Initialize firewall
init-firewall.sh

# Restore Claude credentials from mounted volume
mkdir -p ~/.claude
if [ -f /persist/.credentials.json ]; then
    cp /persist/.credentials.json ~/.claude/.credentials.json
else
    echo "WARN: No credentials found at /persist/.credentials.json"
    echo "Run: /agent-setup creds on host to configure"
fi
cat > ~/.claude/.claude.json <<'EOF'
{"hasCompletedOnboarding":true,"installMethod":"native"}
EOF

# Git identity for agent commits
git config --global user.name "cfg-agent"
git config --global user.email "agent@cfg.is"
git config --global push.autoSetupRemote true

# Ensure agent mode is set for the interactive shell
export CFGMS_AGENT_MODE=true

echo "================================================"
echo " CFGMS Interactive Agent Session"
echo " Branch: $(git branch --show-current)"
echo ""
echo " Starting remote-control server..."
echo " Connect at: https://claude.ai/code"
echo "================================================"
echo ""
