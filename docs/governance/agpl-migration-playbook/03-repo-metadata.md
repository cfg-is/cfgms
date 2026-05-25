## Track 2 Artifact 3: GitHub repo description + topics diff

### Current state

```text
description: Configuration Management System designed to be able to fully deploy
             to any endpoint w/ no dependancies
topics:      [configuration-management, devops, golang, infrastructure,
              mqtt, msp, multi-tenant, quic, zero-trust]
```

### Observations

- "dependancies" is a typo. Fix during this pass since you're touching it anyway.
- "mqtt" topic is **stale**: cfgms uses gRPC-over-QUIC, not MQTT. Per CLAUDE.md: "Communication: gRPC-over-QUIC with mTLS (internal), REST API with HTTPS (external)". The 0.7.0 CHANGELOG entry "gRPC removal - migrated to MQTT+QUIC protocol" was followed by a return to gRPC. Topic must go.
- No license-related topic today. GitHub's `agpl-3-0` topic is the canonical one (used by 6k+ repos). Add it.
- "msp" is good — keeps target-customer signal. "zero-trust" is good. The rest are accurate.

### Proposed state

```text
description: AGPL-3.0 zero-trust configuration management system for MSPs —
             one binary, no agent dependencies, fleet scale on Windows/Linux/macOS.
topics:      [agpl-3-0, configuration-management, devops, golang, grpc,
              infrastructure, msp, multi-tenant, quic, zero-trust]
```

Description rewrite rationale:
- Lead with the license — readers scanning the GitHub repo sidebar see AGPL-3.0 at a glance, matches the LICENSE file.
- "zero-trust" + "MSP" make the target audience and design discipline immediate.
- "one binary, no agent dependencies" — keeps the original "no deps" claim, but reframed positively, drops the typo, and signals operational simplicity.
- "fleet scale" + the three OS targets — concrete product surface.
- Stays under GitHub's 350-char description limit.

Topic changes:
- **Remove**: `mqtt` (incorrect)
- **Add**: `agpl-3-0` (license signal), `grpc` (actual transport)
- **Keep all others**

### Commands

```bash
gh repo edit cfg-is/cfgms \
  --description "AGPL-3.0 zero-trust configuration management system for MSPs — one binary, no agent dependencies, fleet scale on Windows/Linux/macOS."

# Topics is set-replace, not add — list the FULL desired set
gh repo edit cfg-is/cfgms \
  --remove-topic mqtt \
  --add-topic agpl-3-0 \
  --add-topic grpc
```

If the `--remove-topic` flag isn't supported in your `gh` version, fall back to:

```bash
gh api -X PUT repos/cfg-is/cfgms/topics -f names[]=agpl-3-0 \
  -f names[]=configuration-management -f names[]=devops -f names[]=golang \
  -f names[]=grpc -f names[]=infrastructure -f names[]=msp \
  -f names[]=multi-tenant -f names[]=quic -f names[]=zero-trust
```

### Verification

```bash
gh repo view cfg-is/cfgms --json description,repositoryTopics
```

Expected output should match the "Proposed state" block above. The GitHub sidebar should display "AGPL-3.0 license" as the License field — this updates automatically once the new `LICENSE` file is on `develop`/`main` (PR #1747 merge handles this).
