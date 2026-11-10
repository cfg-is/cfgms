# Steward DNA Collection

Developer entry for the flat host collector and the fragment assembler. The
[steward operating model](../../../docs/architecture/steward-operating-model.md)
owns runtime observation/convergence and sync behavior;
[ADR-017](../../../docs/architecture/decisions/017-dna-composition-and-sync.md) and
[ADR-024](../../../docs/architecture/decisions/024-module-observation-vs-convergence.md)
own fragment/observation decisions. A raw collector field list is not the wire
contract or desired-state comparison schema.

## Sources and lifecycle

[`Collector`](dna.go) collects basic/environment and fast host facts synchronously,
caches hardware results and starts background work for slower software/security
collection. Platform factories choose the concrete hardware, network, software
and security collectors. The `*_linux.go`, `*_windows.go`, `*_darwin.go` sources
and their tests own exact field names and failure/platform availability.

The collector covers host identity/hardware, network interfaces/routing/DNS,
software/packages/services/processes, and local security facts. A platform stub,
permission failure or unfinished background pass can leave facts unavailable;
do not treat a table's GREEN/YELLOW marker as a completeness/freshness guarantee.
Do not duplicate the hundreds of generated keys in a manually maintained matrix.

[`Assembler`](assembler.go) composes module observations into canonical fragments.
Module Get output must be deterministic and exclude ephemeral runtime fields
from desired-state comparison. Raw host collection can contain timestamps and
process state; that does not make those values valid governed-resource fields.
Observation time, synchronization state and current live state are distinct.

The canonical fragment encoding and decoding, fragment and aggregate hashing,
bucket hashing and the fragment constructors (`CanonicalizeFragment`,
`DecodeCanonicalFragment`, `FragmentHash`, `AggregateRoot`, `BucketRoots`,
`BulkRoot`, `NewFragment`, `FlattenFragments`, `MapState`) live in
[`pkg/dna`](../../../pkg/dna), which the controller imports; this package keeps
the collector, the assembler and the host-fact partitioning.

## Sensitivity and logs

Inventory can expose host identifiers, usernames, addresses and installed software.
Keep it in the authorized tenant scope. PII is not made public by being a DNA field;
never dump an attribute map into an error or diagnostic log. The register below
captures relevant collection/consumption boundaries; callers still sanitize
request/host-derived log values with the central logging helpers.

## Sanitization Register

The following attributes contain raw values that must be sanitized before any log output. Values marked "YES at collection" are sanitized in the collector before being stored in `dna.Attributes`; downstream callers reading `dna.Attributes` directly still receive sanitized strings. Attributes marked "NO — raw" are stored as-is and must be sanitized at the consumption point.

| Attribute | Sanitized at collection? | Source entry |
|---|---|---|
| `default_gateway` | YES | `network_linux.go`, `network_windows.go` |
| `dns_servers` | YES | `network_linux.go:118`, `network_windows.go:156` |
| `dns_search_domains` | YES | `network_linux.go:121` |
| `dns_domain` | YES | `network_windows.go:177` |
| `domain_name` | YES | `security_linux.go:135` (realm), `:144` (sssd), `security_windows.go:106` |
| `av_products_detected` (Windows) | YES | `security_windows.go:190` |
| `ip_addresses`, `primary_ip` | NO — raw | Callers must sanitize before logging |
| `mac_addresses`, `primary_mac` | NO — raw | Callers must sanitize before logging |
| `hostname` | NO — raw | Callers must sanitize before logging |
| `dns_nameservers` (macOS) | NO — raw | `parseDNSConfig` stores raw; callers must sanitize before logging |
| `dns_servers_wi-fi`, `dns_servers_ethernet` (macOS) | NO — raw | `collectDNSServers` stores raw; callers must sanitize before logging |
| `search_domains_wi-fi`, `search_domains_ethernet` (macOS) | NO — raw | `collectSearchDomains` stores raw; callers must sanitize before logging |
| `regular_users_sample`, `logged_in_users`, `admin_users` | NO — raw | Never log; pii |

---


## Must-Collect Attributes

These attributes are the minimum set that a compliant steward binary must emit.
An attribute is must-collect if its absence prevents device identity, controller
targeting or drift detection from working.
[`test/integration/dna_snapshot_test.go`](../../../test/integration/dna_snapshot_test.go)
asserts that each one is present and non-empty on the platforms it covers. Change
this list and that test together.

### All platforms

| Attribute Key | Expected value | Rationale |
|---|---|---|
| `timestamp` | RFC3339 string | Required for cache validity and delta freshness checks |
| `runtime_os` | `linux`, `windows`, or `darwin` | Required for platform-specific config targeting |
| `runtime_arch` | `amd64` or `arm64` | Required for binary delivery targeting |
| `hostname` | non-empty string | Required for device display and log correlation |
| `num_cpu` | integer string ≥ 1 | Core identity signal; used in system ID derivation |
| `primary_mac` | MAC address string | Primary input to `generateSystemID()` — absence produces a time-varying ID |
| `ip_addresses` | non-empty string | Required for network reachability targeting |
| `network_interface_count` | integer string ≥ 1 | Required for connectivity classification |
| `default_gateway` | IP address string | Required for network topology classification |
| `os` | non-empty string | Required for OS-level config targeting |

### Linux

| Attribute Key | Expected value | Rationale |
|---|---|---|
| `os_name` OR `os_pretty_name` | non-empty string | Required for distro-specific config targeting |
| `kernel_version` | non-empty string | Required for kernel-version-based policy targeting |
| `memory_total_gb` | decimal string | Required for resource capacity targeting |
| `local_user_count` | integer string ≥ 1 | Security baseline assertion |
| `domain_joined` | `"true"` or `"false"` | Required for AD-based policy targeting |
| `av_products_detected` | non-empty string | Security compliance baseline (value `"none"` is acceptable) |
| `luks_encrypted_devices` | integer string ≥ 0 | Encryption baseline |
| `ufw_firewall_state` OR `iptables_rule_count` OR `firewall_state` | non-empty string | At least one firewall signal must be present |

### Windows

| Attribute Key | Expected value | Rationale |
|---|---|---|
| `windows_caption` OR `windows_version` | non-empty string | Required for Windows version targeting |
| `windows_build_number` | integer string | Required for patch-level targeting |
| `memory_total_gb` | decimal string | Required for resource capacity targeting |
| `local_user_count` | integer string ≥ 1 | Security baseline assertion |
| `domain_joined` | `"true"` or `"false"` | Required for AD-based policy targeting |
| `av_products_detected` | non-empty string | Security compliance baseline (value `"none"` on Server SKU is acceptable) |
| `bitlocker_enabled` | `"true"` or `"false"` | Encryption baseline |
| `windows_firewall_domain_profile` | `"enabled"` or `"disabled"` | Firewall baseline |

### macOS

| Attribute Key | Expected value | Rationale |
|---|---|---|
| `macos_version` | version string (e.g., `14.5`) | Required for macOS version targeting |
| `hardware_model` | non-empty string (e.g., `MacBookPro18,3`) | Required for hardware-specific policy targeting |
| `memory_total_gb` | decimal string | Required for resource capacity targeting |
| `total_user_count` | integer string ≥ 1 | Security baseline assertion |
| `sip_status` | `"enabled"`, `"disabled"`, or `"unknown"` | Security integrity baseline |
| `gatekeeper_status` | non-empty string | Security integrity baseline |
| `macos_firewall_state` | non-empty string | Firewall baseline |

## Verify a change

Run source-adjacent parser/collector/assembler tests and the affected platform
suite. Check missing-tool/permission failures, deterministic fragments, sensitive
error redaction and unchanged/partial observations. A Linux run does not prove
Windows WMI or macOS command behavior; use native evidence for those paths.
