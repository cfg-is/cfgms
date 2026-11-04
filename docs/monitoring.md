# Controller Monitoring

Inspect current controller health, telemetry and logs using the appropriate
listener and authorization. This is an operator read path, not a claim that every
exporter, alert workflow or production SLO is delivered.

## Health versus readiness

Public HTTPS endpoints return overall state without client-tenant detail:

```bash
curl --fail --cacert /path/to/controller-ca.crt https://controller.example.com:9080/api/v1/health
curl --fail --cacert /path/to/controller-ca.crt https://controller.example.com:9080/api/v1/ready
```

`/health` checks component presence and the drain gate; `/ready` round-trips
persistent storage. A running process, successful TLS handshake or healthy
liveness response alone is not durable readiness or proof of a steward operation.
Use the actual configured hostname, ports and CA.

## Authenticated detail and private metrics

| Surface | Listener and permission |
|---|---|
| `/api/v1/health/detailed` | Product REST; `monitoring:read-detailed-health` |
| `/api/v1/health/alerts`, `/alerts/history` | Product REST; `monitoring:read-alerts` / `read-alert-history` |
| `/api/v1/health/trace/{request_id}`, `/health/traces` | Product REST; `monitoring:read-trace` / `read-traces` |
| `/api/v1/monitoring/metrics` | Private metrics listener; authorized metrics access |
| `/api/v1/monitoring/components/{component}/metrics` | Private metrics listener; route-specific metrics permission |
| `/api/v1/health/metrics`, `/health/metrics/history` | Private metrics listener; route-specific health metrics permission |

The canonical private metrics listener is host-loopback HTTPS on `9090`. It is
not registered on the public product listener; startup validates private listener
configuration. See [canonical config](deployment/controller.cfg) and
[route registration](../features/controller/api/routes_health_detail.go).

With a suitable current operator credential:

```bash
cfg controller metrics --url https://localhost:9090 --tls-ca-cert /path/to/controller-ca.crt
```

`CFGMS_METRICS_URL` can select the private metrics listener where supported by
that command. A development credential or a root principal does not bypass the
registered permission/assurance checks. Never expose the metrics listener by
copying a wildcard bind from an old example.

## Logging and tracing

Use [logging integration](development/logging-architecture-guide.md),
[logging payload examples](examples/logging-configuration.md) and
[pkg/logging](../pkg/logging/README.md) for context, providers and sanitization.
Telemetry/monitoring code lives under `pkg/telemetry` and `features/monitoring`;
configure only implemented options wired by the process you are operating.
Exporter libraries or example dashboards do not prove an endpoint is registered.

Correlate a request with its redacted/sanitized identifiers and actual trace/log
output. Avoid dumping credentials, tenant inventory or terminal recordings into
monitoring logs. Local system-log fallback is distinct from network syslog.

## Diagnose and validate

Use [connectivity diagnosis](troubleshooting/connectivity.md) for endpoint traffic,
[production operations](operations/production-runbooks.md) for procedure selection
and [monitoring examples](examples/monitoring/README.md) for external stack setup.
The health/metric APIs report controller platform state; they are not a substitute
for checking an incident's authorized endpoint/SaaS observations.

Record revision, environment, actual failure and observed recovery. Do not turn
an unavailable component metric into zero or infer automatic alert remediation
from the existence of health data. Timing/capacity targets need measured evidence
for the actual deployed shape.
