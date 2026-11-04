# Module Reference

Operator reference for each stdlib module: resource fields, examples, and platform notes. The module design layer (manifest fields, distribution, behavioural envelope) lives in [architecture/modules](../architecture/modules/README.md).

## Modules

- [cert_trust](cert_trust.md) - System trust store: install and trust CA certificates
- [file](file.md) - File content, directories, and permissions
- [firewall](firewall.md) - Firewall rules and policies
- [hostname](hostname.md) - Host system name and Windows workgroup
- [package](../../features/modules/stdlib/package/README.md) - Package installation, removal and provider selection
- [service](../../features/modules/stdlib/service/README.md) - Service runtime and boot-enable state
- [script](script-module.md) - Cross-platform, file-based script execution
- [time](time.md) - Timezone and NTP/time-sync configuration
- [user](user.md) - Local users and groups

The stdlib set defined by ADR-016 also includes `patch`, which does not yet have an operator reference page. See the [stdlib inventory](../architecture/modules/README.md#current-stdlib-members).
