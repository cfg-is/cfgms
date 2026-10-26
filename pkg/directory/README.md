# Directory

Pluggable directory services (Active Directory, Entra ID). Business logic imports `pkg/directory/interfaces` only.

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
