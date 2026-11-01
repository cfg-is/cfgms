# Steward

The steward is the endpoint agent for CFGMS. It runs on managed devices and
converges the local system to the desired configuration state using the
Get→Compare→Set→Verify cycle.

## Entry Points

**Standalone mode** (`NewStandalone`) — local operation using `hostname.cfg` files
discovered from the filesystem. This is the production entry point used by
`cmd/steward/main.go`.

```go
steward, err := steward.NewStandalone(configPath, logger)
if err != nil {
    log.Fatal(err)
}
if err := steward.Start(ctx); err != nil {
    log.Fatal(err)
}
```

**Controller-connected mode** (`client.NewTransportClient`) — gRPC-over-QUIC
connection to a CFGMS controller. This is a separate entry point in the
`features/steward/client` package; it does not go through `steward.NewStandalone`.
See `cmd/steward/main.go` for the production registration and connection pattern.

```go
transportClient, err := client.NewTransportClient(&client.TransportConfig{
    ControllerURL:     transportAddress,
    RegistrationToken: token,
    CertManager:       certMgr,
    SecretStore:       secretStore,
    Logger:            logger,
})
```

## Configuration

Standalone configuration is loaded from `hostname.cfg` YAML files. The steward
searches platform-specific locations if no path is provided:

1. Provided `configPath` argument
2. Current working directory
3. User configuration directories
4. System configuration directories

See `features/steward/config/config.go` for the `StewardSettings` struct and all
available fields.

## Architecture

- **Convergence loop** — runs at the interval configured in `StewardSettings.ConvergeInterval`
- **Module discovery** — finds available modules from paths in `StewardSettings.ModulePaths`
- **DNA drift detection** — detects unmanaged system attribute changes between convergence cycles
- **Secret store** — injects secrets into modules that require them

## Removed APIs

The following APIs were removed as part of the deprecation of the controller-mode
bootstrap path (Story #922, parent epic #749):

- `steward.Config`, `steward.CertificateConfig`, `steward.ProvisioningConfig` — legacy controller config structs
- `steward.DefaultConfig()` — returned defaults for the removed Config struct
- `steward.New()` — deprecated since Story #198; unconditionally returned an error
- `steward.NewForControllerTesting()` — integration tests now use `client.NewTransportClient` directly
- `steward.GetPerformanceMetrics()` — performance subpackage removed (Story #922)
- `steward.SyncDNAWithController()` — controller mode removed
- `steward.GetControllerConnectionStatus()` — controller mode removed
- `steward.SetTransportClientForTesting()` — no longer needed; tests use `client.TransportClient` directly

The `features/steward/performance/` subpackage (`AlertManager`, `RemediationEngine`,
`MemoryStorageBackend`, `NoOpStorageBackend`) was also removed — it had zero non-test
callers and `RemediationEngine.TriggerRemediation` simulated work with `time.Sleep`.

The `features/steward/config/SimpleStorageAdapter` was removed — it had zero callers
anywhere in the codebase.
