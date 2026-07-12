# tagstore

Package `tagstore` provides a durable controller-side tag store keyed by steward ID.

## Purpose

Tags are controller-owned metadata assigned to stewards by operators. They are:

- **Controller-owned, not steward-reported.** The controller replaces a steward's DNA wholesale on every DNA refresh cycle (see `controller_service.go:SyncDNA`). Any tag written into `DNA.Attributes` would be clobbered on the next cycle. This store is the clobber-proof source of truth.
- **Durable across restarts.** Tags are persisted to a SQLite database and survive controller restarts.
- **Selector-safe.** Tag values are validated against `^[a-z0-9][a-z0-9-]{0,63}$` (lowercase alphanumeric, optionally followed by hyphens and alphanumerics, 1–64 chars total) so they are safe to use as selector operands without escaping.

## API

```go
// Construct and initialize.
store, err := tagstore.NewFromDSN("file:/var/lib/cfgms/tags.db", logger)
if err != nil { ... }
if err := store.Initialize(ctx); err != nil { ... }
defer store.Close()

// CRUD
store.Set(ctx, stewardID, []string{"env-prod", "region-eu"})
tags, err := store.Get(ctx, stewardID)
store.Delete(ctx, stewardID)
all, err := store.GetAll(ctx)

// Convenience accessor (no error return — logs and returns [] on failure).
tags := store.TagsFor(stewardID)
```

## Tag Format

`^[a-z0-9][a-z0-9-]{0,63}$`

- Starts with a lowercase letter or digit.
- Followed by 0–63 lowercase letters, digits, or hyphens.
- Total length 1–64 characters.
- No uppercase, underscores, dots, or spaces.

Examples: `env-prod`, `region-eu`, `role-web`, `zone1`.

## Wiring

The store is injected into `ControllerService` via `SetTagStore(store)` after server startup. Later stories access it via `controllerService.TagStore()`.

## Architecture

Tags survive DNA refresh because this store is separate from the DNA/steward-attributes path. The invariant: **admin sets tags here; DNA refresh never touches this store.**
