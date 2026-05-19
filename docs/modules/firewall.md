# Firewall Module

## Overview

The Firewall module manages host-based firewall rules on CFGMS-managed endpoints. Each
module instance represents a single named rule — `action`, `direction`, `protocol`/`service`,
and address constraints — that the steward applies to the operating-system firewall.

**Platform Support:** This module is **Linux only**. The implementation ships two
executors: `executor_linux.go` (iptables, via `exec.Command("iptables", ...)`) and
`executor_stub.go` for all other platforms. On Windows and macOS the stub executor
returns `modules.ErrUnsupportedPlatform` — all calls fail immediately. Use platform
targeting in your CFGMS configuration to restrict firewall modules to Linux steward
endpoints.

> **Note:** `module.yaml` lists `darwin` and `windows` under `platforms:`, but the
> stub executor actively rejects all operations on those platforms at runtime.
> nftables is **not** currently supported; the Linux executor uses iptables only.

## Implementation References

- Schema: [`features/modules/firewall/module.yaml`](../../features/modules/firewall/module.yaml)
- Implementation: [`features/modules/firewall/module.go`](../../features/modules/firewall/module.go)
- Linux executor: [`features/modules/firewall/executor_linux.go`](../../features/modules/firewall/executor_linux.go)
- Non-Linux stub: [`features/modules/firewall/executor_stub.go`](../../features/modules/firewall/executor_stub.go)

## Platform Support

| Platform | `applyRule` | `deleteRule` | `ruleExists` | Backend |
|----------|------------|--------------|--------------|---------|
| Linux    | ✓ | ✓ | ✓ | iptables |
| macOS    | ✗ (`ErrUnsupportedPlatform`) | ✗ | ✗ | — |
| Windows  | ✗ (`ErrUnsupportedPlatform`) | ✗ | ✗ | — |

## Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Unique rule identifier. Alphanumeric, `_`, and `-` only; max 64 characters. |
| `action` | string | **Yes** | `allow` or `deny` |
| `direction` | string | **Yes** | `input`, `output`, or `forward` |
| `source` | string | **Yes** | Source IP address or CIDR (e.g. `10.0.0.0/8`, `192.168.1.5`) |
| `destination` | string | **Yes** | Destination IP address or CIDR |
| `protocol` | string | Conditional | `tcp`, `udp`, or `icmp`. Required when `service` is not set. |
| `service` | string | Conditional | Named service (e.g. `https`). Alternative to `protocol` + `port`. |
| `port` | int | Conditional | Single port number (0–65535). Required when `protocol` is set and `service` is not. |
| `ports` | []int | Conditional | List of port numbers. Use instead of `port` to match multiple ports in one rule. |
| `description` | string | No | Human-readable description of the rule. Max 256 characters. |
| `enabled` | bool | No | Whether the rule is active. Default: `false` (Go zero value; omit this field or set `enabled: true` to activate). |
| `state` | string | No | `present` (default) creates or updates the rule; `absent` deletes it. |

### Validation Rules

- `name`, `action`, `direction`, `source`, and `destination` are always required.
- Exactly one of `protocol` or `service` must be provided — not both, not neither.
- When `protocol` is set (and `service` is not set), at least one of `port` or `ports` must be provided.
- `source` and `destination` must be valid IP addresses or CIDR notation.

## Examples

### Example: Allow inbound HTTPS from a specific source

**Use Case:** Permit TCP port 443 traffic arriving from a corporate network CIDR while
leaving the default policy unchanged for all other sources.

**Configuration:**

```yaml
modules:
  allow_corporate_https:
    type: firewall
    config:
      name: allow-corporate-https
      action: allow
      direction: input
      protocol: tcp
      port: 443
      source: 10.10.0.0/16
      destination: 0.0.0.0/0
      description: Allow inbound HTTPS from corporate network
      enabled: true
```

**Expected Outcome:** An iptables rule is inserted that accepts inbound TCP
traffic on port 443 originating from `10.10.0.0/16`. Traffic from sources outside that
CIDR is not matched by this rule and falls through to the next rule in the chain.
Subsequent convergence cycles are idempotent — the rule is not duplicated if it already
matches the desired state.

### Example: Block outbound traffic on a port range

**Use Case:** Prevent endpoints from initiating outbound connections on commonly abused
plaintext and alternate HTTP ports, reducing the attack surface for data exfiltration.

**Configuration:**

```yaml
modules:
  block_outbound_http_variants:
    type: firewall
    config:
      name: block-outbound-http-variants
      action: deny
      direction: output
      protocol: tcp
      ports:
        - 80
        - 8080
        - 8443
      source: 0.0.0.0/0
      destination: 0.0.0.0/0
      description: Block outbound connections on plaintext and alternate HTTP ports
      enabled: true
```

**Expected Outcome:** Outbound TCP connections on ports 80, 8080, and 8443 are dropped
before they leave the host. Steward-managed services cannot initiate cleartext HTTP or
alternate HTTPS connections to external destinations. The rule covers all source and
destination addresses (`0.0.0.0/0`) so it applies regardless of the endpoint's own IP.
