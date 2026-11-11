# Service-Level Signals and Markers

This is the canonical list of the service-level signals a controller exports and
of the marker routes that annotate them. Tooling and operators use these names.
`TestSignalDocMatchesRegistry` fails when this document and the controller's
signal registry disagree, so a signal is not added, renamed or removed without
changing this page.

## Where to read them

| Surface | Route | Listener | Permission |
|---|---|---|---|
| Signals | `GET /api/v1/health/metrics/prometheus` | Private metrics listener only | `monitoring:read-metrics` |
| Record a marker | `POST /api/v1/monitoring/markers` | Private metrics listener only | `monitoring:write-markers` |
| List markers | `GET /api/v1/monitoring/markers` | Private metrics listener only | `monitoring:read-markers` |

None of these routes exists on the public product listener. See
[Controller Monitoring](../monitoring.md) for the listener, credentials and how
to query it.

The signals route returns the Prometheus text exposition format. It renders the
built-in collector series first, then the registered signals below ordered by
metric name and label values.

## Signals

Every registered signal declares its label names and the closed set of values
each label may take. A sample that names an undeclared label or value is
rejected and records nothing, so series cardinality is fixed by the code. No
signal carries a tenant, steward, command or path identifier.

| Metric | Type | Labels | Buckets (seconds) | Meaning |
|---|---|---|---|---|
| `cfgms_build_info` | gauge | `revision`, `version` | — | Build information of the running controller; the value is always 1. |
| `cfgms_command_completion_seconds` | histogram | `command_type`, `outcome` | 0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300 | Seconds from command send to a terminal steward event or timeout, by command type and outcome. |
| `cfgms_command_send_total` | counter | `command_type`, `outcome` | — | Commands handed to the control plane, by command type and send outcome. |
| `cfgms_config_apply_failed_total` | counter | — | — | Config push deliveries the steward reported as failed to apply. |
| `cfgms_config_convergence_seconds` | histogram | — | 0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600 | Seconds from a config push delivery row being issued to the steward reporting its command completed. |
| `cfgms_has_leadership` | gauge | — | — | 1 when this controller holds cluster leadership (lease-backed), 0 otherwise. |
| `cfgms_leadership_changes_total` | counter | — | — | Leadership changes observed on this controller at the sampler interval; a change that reverts within one interval is not counted. |
| `cfgms_process_start_time_seconds` | gauge | — | — | Start time of the controller process in seconds since the Unix epoch. |
| `cfgms_storage_connected` | gauge | — | — | Whether the last storage probe reached the database (1) or not (0). |
| `cfgms_storage_probe_duration_seconds` | histogram | — | 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 | Duration of storage probes in seconds, including failed and timed-out probes. |
| `cfgms_storage_probe_failures_total` | counter | — | — | Total storage probes that failed or exceeded their deadline. |
| `cfgms_stewards_heartbeat_fresh` | gauge | — | — | Stewards whose latest heartbeat was received on this controller node within the steward offline timeout. |
| `cfgms_transport_delivery_failures_total` | counter | — | — | Total message delivery failures on this controller node's control plane transport. |
| `cfgms_transport_events_dropped_total` | counter | — | — | Total steward events shed on this controller node's control plane transport. |
| `cfgms_transport_heartbeats_dropped_total` | counter | — | — | Total steward heartbeats shed on this controller node's control plane transport. |
| `cfgms_transport_responses_dropped_total` | counter | — | — | Total steward responses shed on this controller node's control plane transport. |

A histogram is exported as `<name>_bucket` (with an `le` label, cumulative, plus
`+Inf`), `<name>_sum` and `<name>_count`.

### Label values

| Label | Metrics | Values |
|---|---|---|
| `command_type` | `cfgms_command_send_total`, `cfgms_command_completion_seconds` | `sync_config`, `sync_dna`, `reconnect`, `execute_script`, `relay_response`, `push_signing_cert`, `push_steward_binary`, `open_terminal`, `steward_action`, `observe_modules`, and `other` for any command type outside this set |
| `outcome` | `cfgms_command_send_total` | `sent`, `send_failed` |
| `outcome` | `cfgms_command_completion_seconds` | `completed`, `failed`, `timeout` |
| `revision` | `cfgms_build_info` | A hex commit id, optionally suffixed `-dirty`, or `unknown`; any other build value is exported as `unknown` |
| `version` | `cfgms_build_info` | The controller version string |

### Built-in collector series

The same route also renders the controller health collector's snapshot. These
series are unlabeled and are not registered signals; a signal cannot take one of
these names.

| Metric | Type |
|---|---|
| `cfgms_transport_connected_stewards` | gauge |
| `cfgms_transport_stream_errors` | counter |
| `cfgms_transport_messages_sent` | counter |
| `cfgms_transport_messages_received` | counter |
| `cfgms_transport_reconnection_attempts` | counter |
| `cfgms_storage_pool_utilization` | gauge |
| `cfgms_storage_query_latency_avg_ms` | gauge |
| `cfgms_storage_query_latency_p95_ms` | gauge |
| `cfgms_storage_slow_queries` | counter |
| `cfgms_workflow_queue_depth` | gauge |
| `cfgms_script_queue_depth` | gauge |
| `cfgms_active_workflows` | gauge |
| `cfgms_active_scripts` | gauge |
| `cfgms_cpu_percent` | gauge |
| `cfgms_memory_percent` | gauge |
| `cfgms_memory_bytes` | gauge |
| `cfgms_goroutines` | gauge |
| `cfgms_heap_bytes` | gauge |

A storage series the configured provider does not instrument is omitted rather
than reported as zero. Before the collector's first snapshot only the registered
signals are rendered.

## Limits

- **Per controller node.** Every value describes the controller that served the
  scrape. Cluster totals are summed by the collector across nodes.
  Counters and histograms restart from zero with the process; use
  `cfgms_process_start_time_seconds` to detect a restart.
- **Leadership and storage resolution is 30 seconds.** The controller's health
  collector samples every 30 seconds. `cfgms_has_leadership` and
  `cfgms_leadership_changes_total` see leadership only at those ticks, so a
  change that reverts inside one interval is not counted. The storage probe
  runs once per tick, with a 5 second deadline per probe; a probe still running
  at the next tick is recorded as a failure. The heartbeat-fresh gauge and the
  transport counters are also refreshed on these ticks.
- **Absent is not zero.** A signal whose backing component is missing is not
  registered: no heartbeat service means no `cfgms_stewards_heartbeat_fresh`, no
  control plane means no `cfgms_transport_*_total`, no command publisher means
  no `cfgms_command_*`, and no controller service means no `cfgms_storage_*`.
- **Config push has two signals.** The send outcome is
  `cfgms_command_send_total{command_type="sync_config"}`. Convergence time is
  `cfgms_config_convergence_seconds`, measured from the delivery row being
  issued to the steward's command-completed event, and only for pushes that
  have a delivery row. On-connect and periodic applies, and stewards that do not
  emit the event, record nothing. A command-failed event increments
  `cfgms_config_apply_failed_total` and is not observed in the histogram. The
  dedupe is durable: the row is marked terminal before anything is recorded, so
  a duplicate or redelivered event, including after a restart, records nothing.
  The issued and receipt times can come from different nodes' clocks; a negative
  difference is recorded as 0.
- **Tenant-scoped rollouts are not markers.** A rollout scoped to a tenant is an
  audit event under that tenant. Markers are platform signals recorded under
  the system tenant.

## Markers

A marker is a time-stamped platform event used to line a change up against the
signals. Markers are audit events under the system tenant, so they carry no
tenant path and survive a restart.

`POST /api/v1/monitoring/markers` records a marker. The body is JSON with
unknown fields rejected and a maximum size of 4 KiB:

| Field | Required | Rule |
|---|---|---|
| `kind` | yes | One of `deploy`, `rollback`, `chaos_start`, `chaos_end` |
| `revision` | yes | A hex commit id of 7 to 64 digits or a semantic version, at most 64 characters |
| `note` | no | At most 256 characters, no control characters |

The response is `201` with `id`, `time`, `kind`, `revision`, `principal`,
`resource` (the marker id) and `note`. The principal is the authenticated
caller. `monitoring:write-markers` requires a strong-assurance session or an
API key.

`GET /api/v1/monitoring/markers` lists markers oldest first, with optional
`since` and `until` (RFC 3339, inclusive) and `kind` (lowercase letters, digits
and underscores) filters. It returns the audit rows whose action is
`marker_<kind>` or `controller_start`; the controller records `controller_start`
at each startup. At most 1000 markers are returned; when more match, the newest
are kept. `resource` is a marker or rollout identifier, never a tenant path.
