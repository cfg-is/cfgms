# Reports

Report generation for CFGMS DNA monitoring data: compliance reports, executive
dashboards, and drift analysis, with multi-format export and REST API access.

## Architecture

```
features/reports/
├── api/                  # REST API endpoints
│   └── handlers.go       # Dashboard and report HTTP handlers
├── engine/               # Report generation engine
│   ├── engine.go         # Core report generation logic
│   └── advanced.go       # Audit-integrated, multi-tenant report generation (not yet wired to an API endpoint)
├── interfaces/           # Shared types and interface contracts
│   ├── interfaces.go     # Core report types (ReportRequest, Report, DataQuery, ...)
│   ├── advanced.go       # Advanced/audit-integrated report types
│   └── custom.go         # Custom and scheduled report type contracts
├── provider/             # Data integration layer
│   ├── provider.go       # DNA storage and drift detection integration
│   └── advanced.go       # Audit data integration and cross-system metrics
├── templates/            # Built-in report templates (compliance, executive, drift)
├── exporters/            # Multi-format export (JSON, CSV, HTML, PDF)
└── cache/                # Report caching
```

Only `api`, `engine`, `interfaces`, `provider`, `templates`, `exporters`, and `cache` are
part of the live report path — every binary in the module reaches report generation
through `features/reports/api`, which imports `features/reports/interfaces`, with
`features/reports/engine` behind it.

## Key features

- **Template-based report generation** for compliance, executive, and drift report types
- **Multi-format export**: JSON, CSV, HTML, PDF
- **REST API** for dashboard and report access, backed directly by `engine.Engine`
- **Report caching** for improved performance (write-through, configurable TTL)
- **Tenant and device scoping** enforced at the API boundary (`api/handlers.go`):
  a tenant-scoped caller is pinned to its own tenant, and every requested device ID is
  authorized against that tenant's subtree before it reaches the engine

## REST API endpoints

- `POST /api/v1/reports/generate` — generate a report and export it in the requested format
- `GET /api/v1/reports/templates` — list available report templates
- `GET /api/v1/reports/templates/{template}` — get a specific template's info
- `GET /api/v1/reports/dashboard/overview` — executive KPI summary
- `GET /api/v1/reports/dashboard/trends` — trend charts and analysis
- `GET /api/v1/reports/dashboard/alerts` — active drift alerts, with acknowledge/silence state
- `GET /api/v1/reports/compliance/status` — compliance score and summary
- `GET /api/v1/reports/drift/summary` — drift event summary

## Integration

- **Entity Graph**: `GetDNAData`, `GetDeviceStats`, and `GetDriftEvents` read device
  identity, observation history, and drift state from
  `pkg/entitygraph/interfaces.EntityGraphProvider` (ADR-022).
- **Templates**: `features/reports/templates` processes report templates into
  `interfaces.Report` values.
- **REST API**: registered on the controller API server
  (`features/controller/server/server.go`).
- **Multi-tenancy**: tenant scope always comes from the authenticated caller, not from a
  caller-supplied request field; see `api/handlers.go`'s `parseTenantIDs` and
  `enforceDeviceTenant`.

### Query scoping

Every report read carries exactly one authorization cut, and a read that carries none is
refused rather than widened (ADR-022 §7):

- **Device selector** (`DataQuery.DeviceIDs`) — the narrowest cut. Each device ID is
  authorized against the caller's tenant subtree at the API boundary before the query
  reaches the data provider, and results cover only those devices.
- **Tenant scope** (`DataQuery.TenantIDs`) — used when no device is named. Hosts are
  discovered through `QueryEntities` with `EntityFilter.TenantFilter` set to the tenant
  subtree, and drift through `ListDrifted` with `DriftFilter.TenantFilter`; several
  tenants mean one filtered query each, never one unfiltered query.
- **Neither** — refused. An empty tenant filter means "every tenant" to the entity graph
  providers, so such a query would return the whole deployment.

## Advanced (audit-integrated, multi-tenant) reporting

`engine.AdvancedEngine` and `provider.AdvancedProvider` (`engine/advanced.go`,
`provider/advanced.go`) implement compliance/security/executive/multi-tenant report
generation with audit-data integration and RBAC-validated tenant access. They are fully
implemented and tested but are not yet constructed by any server wiring or reachable
through `features/reports/api` — see Issue #4333 for the tracked follow-up that reaches
the remaining unimplemented capability (scheduled reports, custom report building, custom
template management) through this same live path.

## Testing

- Unit tests for engine, provider, exporter, cache, and template logic
- API handler tests, including tenant/device scoping enforcement
- No mocks — tests use real CFGMS components per CLAUDE.md
