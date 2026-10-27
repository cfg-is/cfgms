# Directory

Pluggable directory services (Active Directory, Entra ID). Business logic imports `pkg/directory/interfaces` only. `interfaces.DirectoryProvider` is the sole directory contract; there is no separate controller-side facade.

## Contract

`interfaces.DirectoryProvider` covers connection management, users, groups, membership, OUs, search, bulk operations, cross-directory sync and schema. Providers register a constructor with the factory (`RegisterDirectoryProviderConstructor`) in `init()`.

## DirectoryProviderManager

`DirectoryProviderManager` holds several providers by name.

- `AddProvider(name, config)` builds a provider through the factory, which connects and health-checks it.
- `RegisterProvider(name, provider, resolver)` registers an already-built provider without calling `Connect` or `HealthCheck`. It rejects an empty name, a nil provider and a duplicate name. `resolver` (`ConfigResolver`) supplies the `ProviderConfig` used to connect later; nil connects with a zero `ProviderConfig`.

### Default provider

The first provider registered becomes the default. `SetDefaultProvider` overrides it (unknown name is an error), `GetDefaultProvider` reads it, and `GetProviderOrDefault("")` resolves an empty name to it. Removing the default provider clears the default.

### Lazy connect

`ConnectedProvider(ctx, name)` asks the provider `IsConnected` on every call and, when false, calls the resolver and then `Connect` under a per-provider mutex, so concurrent first calls connect once. A provider that was disconnected reconnects on the next call. Resolver and `Connect` failures return `*ProviderConnectError`; the provider stays registered and the next call retries.

### Statistics

`ExecuteProviderOp(ctx, name, fn)` resolves the provider (empty means default), connects it lazily, runs `fn`, and records one request, its latency and its error. A resolve or connect failure counts as one request and one error. There is no exported way to record an operation directly.

`GetProviderStatistics(ctx, name)` returns `ProviderStatistics`: live `UserCount` and `GroupCount` (from `ListUsers`/`ListGroups` with `Limit: 1`, reading `TotalCount`), plus `RequestCount`, `ErrorCount` and `AverageLatency`. When a provider leaves `TotalCount` at 0 while returning items or `HasMore`, the count is `UnknownCount` (`-1`).

## Providers

| Provider | Package | Notes |
|----------|---------|-------|
| Active Directory | `pkg/directory/providers/network_activedirectory` | Read-only; OUs supported |
| Microsoft Entra ID | `features/workflow/modules/m365` (`EntraIDDirectoryProvider`) | No OUs; administrative units are managed by the `entra_admin_unit` module |

### Entra ID execution tenant

`EntraIDDirectoryProvider` holds no tenant or credential. `Connect` accepts only an optional `graph_url` (in `ProviderConfig.ProviderConfig`) and makes no Graph call. Every operation obtains its Graph token from `authProvider.GetAccessToken` for the CFGMS execution tenant in the context (`ctxkeys.TenantID`); credentials are resolved by the auth provider from the credential store. A missing or empty tenant fails closed before any Graph call.

`HealthCheck` follows the same rule: without an execution tenant in the context it reports unhealthy by design. `GetProviderStatuses` calls it with a bare context, so Entra shows unhealthy there until a tenant-scoped check exists.

## Controller registration

`NewServer` builds one `DirectoryProviderManager` (`registerDirectoryProviders` in `features/controller/server/directory_wiring.go`), holds it on the `Server` and closes it on `Stop`. Registered providers:

| Name | Provider | State at startup |
|------|----------|------------------|
| `entraid` | `EntraIDDirectoryProvider` | Registered, not connected |

The Entra provider is built over an `OAuth2Provider` on the controller's secret store with a nil default config, and a rate-limited Graph HTTP client. No `Connect` or `HealthCheck` runs at startup; the manager connects it on the first `ExecuteProviderOp` call. Each call resolves the credential of the CFGMS tenant in the context (`ctxkeys.TenantID`), never a connect-time tenant; a tenant with no M365 connection on file fails. With no secret store the Entra registration is skipped with a warning and startup continues. Active Directory is not registered by the controller yet.
