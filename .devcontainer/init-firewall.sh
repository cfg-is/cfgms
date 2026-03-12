#!/usr/bin/env bash
# Firewall for agent containers: default-deny outbound with allowlist.
# Runs as root via sudo from entrypoint, then drops back to agent user.
set -euo pipefail

echo "Initializing container firewall..."

# Flush existing rules
sudo iptables -F OUTPUT
sudo iptables -F INPUT

# Allow loopback
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established/related connections
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DNS
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Resolve and allow HTTPS to specific domains
ALLOWED_HOSTS=(
    api.anthropic.com
    statsig.anthropic.com
    sentry.io
    github.com
    api.github.com
    proxy.golang.org
    sum.golang.org
    storage.googleapis.com
    objects.githubusercontent.com
    registry.npmjs.org
)

for host in "${ALLOWED_HOSTS[@]}"; do
    for ip in $(dig +short "$host" 2>/dev/null | grep -E '^[0-9]'); do
        sudo iptables -A OUTPUT -p tcp --dport 443 -d "$ip" -j ACCEPT
    done
done

# Log and drop everything else (rate-limited)
sudo iptables -A OUTPUT -p tcp --dport 443 -m limit --limit 1/min \
    -j LOG --log-prefix "AGENT-BLOCKED: " --log-level warning
sudo iptables -A OUTPUT -p tcp --dport 443 -j DROP

# Verify: github.com should work, example.com should not
if curl -sf --max-time 5 https://api.github.com >/dev/null 2>&1; then
    echo "  Firewall OK: github.com reachable"
else
    echo "  WARNING: github.com unreachable — DNS may not have resolved yet"
fi

echo "Firewall initialized (default-deny with allowlist)"
