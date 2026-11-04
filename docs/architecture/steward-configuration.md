# Authoring Steward Configuration

Use the [configuration schema](../reference/config-schema.md) for field definitions
and the [canonical steward boot config](../deployment/steward.cfg) for startup
settings. This page owns the short authoring path, not another complete field table.

## Choose the document boundary

- **Local/standalone startup:** `cfgms-steward --config PATH` loads a local document.
- **Managed startup:** install with the platform service and trust procedure;
  stored identity supports later reconnect without re-enrollment. Managed desired
  state is delivered by the controller, not selected by adding `--config`.
- **Desired state:** named `resources` and their module payloads describe governed
  objects. Their module references own required fields and platform limits.

See [steward runtime](steward-operating-model.md) for boot versus delivered-state
behavior and [fleet deployment](../deployment/fleet/walkthrough.md) for enrollment.

## Local file selection

An explicit path is loaded directly. Without one, the config loader uses
[`BootConfigDirs` and `BootConfigFileNames`](../../pkg/security/bootconfig.go):
current directory first, then platform configuration locations; within each
directory `<hostname>.cfg` precedes `steward.cfg`. The implementation is shared
with the boot-config write guard. Do not maintain a separate environment-variable
or search-order table here. An unselected shadow config has no effect; the loader
warns about existing candidates it did not load.

## Write and verify a resource

```yaml
resources:
  - name: application-settings
    module: file
    config:
      allowed_base_path: /var/lib/cfgms/example
      path: /var/lib/cfgms/example/settings.conf
      state: present
      content: "enabled=true\n"
```

Adapt the example to a permitted path/platform and retain all required fields.
A child override with the same resource name replaces the entire earlier block;
see [inheritance](../guides/configuration-inheritance.md). File path permissions
and module validation still apply.

Validate with the actual loader/module checks and inspect errors; YAML syntax
alone does not establish valid resource semantics. After delivery, inspect
resource results and current observations. A controller write is not evidence
that an endpoint applied it. Do not put secrets directly in configuration; use
the supported secret references and signing/trust controls.
