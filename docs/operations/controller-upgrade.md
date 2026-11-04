# Controller Upgrade Runbook

Upgrade one installed controller and verify that it can serve durable state.
For multiple controllers, follow the [rolling cluster procedure](rolling-cluster-upgrade.md)
so peers can continue serving while this node restarts.

The supported single-controller path is an in-place restart. It interrupts this
node's connections; downtime depends on shutdown, startup and state loading.
The port-swap command `cfg controller upgrade run` is experimental and frozen,
not the production procedure. [ADR-007](../architecture/decisions/007-controller-upgrade-and-state-externalization.md)
owns the decision and its constraints.

## Prerequisites

- Obtain the intended binary using [release artifact verification](../deployment/release-artifact-verification.md).
- Preserve the current binary and back up durable state using the procedure for
  your storage backend. Keep the same config, trust material and storage paths.
- Confirm the service install path, API address and CA path. Examples below use
  the [single-controller deployment](../deployment/single-controller/walkthrough.md):
  `/usr/local/bin/cfgms-controller`, `/etc/cfgms/controller.cfg`, and HTTPS on `9080`.
- Run service and binary replacement commands with host administrative privileges.

## Credential-backed systemd service

The canonical service uses `LoadCredentialEncrypted=`. The CLI's restart
smoketest runs a candidate outside that unit and cannot receive its systemd
credentials. `cfg controller upgrade restart` therefore refuses this service
before modifying files. Replace the binary and let systemd supply the credentials:

```bash
# Set this to the verified binary you intend to deploy.
NEW_BINARY=/opt/cfgms/cfgms-controller-new
sudo cp -p /usr/local/bin/cfgms-controller /usr/local/bin/cfgms-controller.prev
sudo install -m 0755 "$NEW_BINARY" /usr/local/bin/cfgms-controller
sudo systemctl restart cfgms-controller
sudo systemctl status cfgms-controller --no-pager
sudo curl --fail --cacert /var/lib/cfgms/certs/ca/ca.crt \
  https://localhost:9080/api/v1/ready
```

Use a hostname covered by the controller certificate and the configured CA.
Wait for readiness during startup; a process being present is not proof that
its durable storage is available. `/api/v1/ready` performs a storage round trip.
Inspect `journalctl -u cfgms-controller` if readiness does not recover.

If startup or readiness fails, restore the preserved binary and restart:

```bash
sudo install -m 0755 /usr/local/bin/cfgms-controller.prev /usr/local/bin/cfgms-controller
sudo systemctl restart cfgms-controller
sudo curl --fail --cacert /var/lib/cfgms/certs/ca/ca.crt \
  https://localhost:9080/api/v1/ready
```

Verify storage-format compatibility before downgrading. A previous executable
is not a substitute for a recoverable data backup. Do not remove identity or
trust storage to make a failed upgrade start.

## Service without systemd credential directives

For an installed service that does not use `LoadCredential=` or
`LoadCredentialEncrypted=`, the CLI supports a readiness-gated restart:

```bash
sudo cfg controller upgrade restart \
  --binary /opt/cfgms/cfgms-controller-new \
  --config /etc/cfgms/controller.cfg \
  --canonical-api-addr 127.0.0.1:9080
```

The command starts a side-port candidate, checks HTTPS `/api/v1/ready`, stops
the candidate, stages the binary through the service manager, restarts, and
checks readiness again. If staging or the final probe fails, it attempts to
restore the previous executable. A failed restoration is reported as requiring
manual intervention; inspect the error and service logs.

The canonical probe defaults to `:8080`; set `--canonical-api-addr` for the
actual service port. `--url` does not change this local probe address. Candidate
ports default to `:8081` and `:4434`; choose unused addresses with
`--candidate-api-addr` and `--candidate-transport-addr`. The default smoketest
timeout is 30 seconds, configurable with `--smoketest-timeout`.

This path removes its temporary `.prev` backup after success. It does not
populate the experimental cutover quarantine or history file. Keep your own
verified prior artifact for later rollback, and repeat the supported procedure
with it when a downgrade is compatible.

## Verify the outcome

Check readiness, service logs, and that expected stewards reconnect and can
complete a query. In a cluster, verify the node rejoins and is admitted by the
load balancer before proceeding to another node. Do not treat a successful
restart as evidence that an interrupted fleet rollout resumed.

[Upgrade lifecycle reference](upgrade-lifecycle.md) distinguishes local
experimental history, steward launcher events and durable upgrade dispatch status.
