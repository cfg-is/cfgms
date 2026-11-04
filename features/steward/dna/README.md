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


## Verify a change

Run source-adjacent parser/collector/assembler tests and the affected platform
suite. Check missing-tool/permission failures, deterministic fragments, sensitive
error redaction and unchanged/partial observations. A Linux run does not prove
Windows WMI or macOS command behavior; use native evidence for those paths.
