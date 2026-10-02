# Hardened Container Deployment

This deployment publishes the authenticated HTTPS API (`9080/tcp`) and mTLS
QUIC steward transport (`4433/udp`) publicly. Product metrics use a distinct
HTTPS listener (`9090/tcp`) bound to the container's fixed private bridge IP
and published only on host loopback. It does not publish a separate Raft,
database, object-storage management, or secret-management port.
Both initialization and runtime select the `public-beta` security profile,
which blocks startup without valid signing roots and rejects unsigned ad-hoc
execution.

## Prepare

Build or obtain the exact release image and set its immutable digest:

```bash
export CFGMS_CONTROLLER_IMAGE='ghcr.io/cfg-is/cfgms-controller@sha256:CHANGE'

# Provision the external encryption key as the container's fixed UID/GID.
# Store and back it up separately from controller-data.
sudo install -d -o 1001 -g 1001 -m 0700 /etc/cfgms-container
sudo openssl rand -out /etc/cfgms-container/secrets.key 32
sudo chown 1001:1001 /etc/cfgms-container/secrets.key
sudo chmod 0600 /etc/cfgms-container/secrets.key
export CFGMS_SECRETS_KEY_FILE=/etc/cfgms-container/secrets.key
```

Do not use `latest` or a tag alone. Verify the release signature, identity,
provenance, and checksum before setting this value.

The key bytes never belong in an environment variable. Compose receives only
the host path and mounts that file read-only at
`/run/secrets/cfgms-secrets-key`. Loss of the key makes stored secrets
unrecoverable; disclosure compromises every secret encrypted with it.

**Why this shape differs from the systemd deployments.**
[ADR-030](../../architecture/decisions/030-controller-secret-material-at-rest.md)
seals the key with `systemd-creds` and delivers it through
`LoadCredentialEncrypted=`, which is a systemd facility and has no equivalent
inside a container runtime. The container path therefore keeps a key file on the
*host* and mounts it in — the key never lands on the container's own filesystem
or in its image, but it is not sealed to host hardware the way the single-node
and cluster deployments are. Where your orchestrator provides a sealed or
externally-managed secret (a Docker/Swarm secret, a Kubernetes secret backed by a
KMS, a CSI secrets driver), mount that at `/run/secrets/cfgms-secrets-key`
instead of a plain host file: the container reads a path either way, so nothing
in the image changes.

Edit `controller.cfg`, replacing the example hostname, certificate SANs,
external address, and organization. Keep `localhost` in the certificate SANs
so the in-container readiness check can verify the server certificate.
If `172.30.0.0/24` overlaps an existing Docker/host network, change the Compose
subnet, service `ipv4_address`, and `metrics_listen_addr` together; the metrics
address must remain a numeric RFC 1918 address.

## Initialize once

Initialization is a separate one-shot job. It has no network and returns any
error instead of hiding it:

```bash
docker compose --profile init run --rm controller-init
```

Copy `/var/lib/cfgms/admin.bundle.yaml` from the `controller-data` volume to
an encrypted operator credential store, confirm the copy, then remove the
bundle from the runtime volume. Regenerate and revoke it through the documented
admin recovery workflow if it is exposed.

## Start and verify

```bash
docker compose up -d controller
docker compose ps
docker compose logs controller
```

Verify HTTPS from the host using the generated CA and the configured public
hostname. Never use `curl -k`:

```bash
curl --fail --cacert ./ca.crt \
  https://controller.example.com:9080/api/v1/health
```

Verify that the product listener has no metrics route, then query the private
listener with a key carrying `monitoring:read-metrics`:

```bash
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cacert ./ca.crt -H "X-API-Key: ${CFGMS_MONITORING_API_KEY}" \
  https://controller.example.com:9080/api/v1/monitoring/metrics)" = 404

curl --fail --cacert ./ca.crt \
  -H "X-API-Key: ${CFGMS_MONITORING_API_KEY}" \
  https://localhost:9090/api/v1/monitoring/metrics
```

Do not proxy or publish port 9090 on a non-loopback host address. Remote
monitoring systems should reach it through an authenticated host-local tunnel
or an equivalently restricted private network path.

The runtime uses a fixed non-root UID/GID, a read-only root filesystem,
no Linux capabilities, `no-new-privileges`, bounded PID/CPU/memory resources,
and explicit state/log volumes. The default Docker seccomp profile remains
enabled; configure an enforced AppArmor or SELinux policy appropriate to the
host before public exposure.

## Backup and restore

A recoverable container backup contains all three of these items:

- the `cfgms_controller-data` volume;
- the deployment's exact `controller.cfg`;
- the host file named by `CFGMS_SECRETS_KEY_FILE`.

The secrets key must be escrowed separately from the data snapshot under
equivalent or stronger access control. Loss of it makes encrypted data
unrecoverable. Stop the controller before taking a plain volume archive unless
the storage platform provides a crash-consistent or application-consistent
snapshot:

```bash
docker compose stop controller
docker volume inspect cfgms_controller-data
```

Snapshot or archive the inspected volume with a trusted, immutable-digest
backup image running with no network, no capabilities, and a read-only source
mount. Store the result only in encrypted, access-controlled off-host storage,
then restart and health-check the controller:

```bash
docker compose start controller
docker compose ps
```

Restore into an isolated volume first. Verify the archive checksum and member
list before extraction, supply the matching configuration and exact secrets
key, and start the same controller image digest that produced the backup.
Validate health, audit-chain integrity, tenant inventory, certificate validity,
steward reconnection, and a signed configuration operation. Only then repeat
the tested volume replacement during an approved outage. Do not delete or
overwrite the original volume until the restored copy passes those checks.

## Upgrade and rollback

Keep the old immutable image digest and a restore-tested cold backup. Set
`CFGMS_CONTROLLER_IMAGE` to the verified new digest, render the Compose model,
pull, and replace only the controller service:

```bash
docker compose config
docker compose pull controller
docker compose up -d --no-deps controller
docker compose ps
docker compose logs controller
```

Run the health, metrics-isolation, steward reconnect, and signed-operation
checks above. To roll back a state-compatible release, reset
`CFGMS_CONTROLLER_IMAGE` to the preserved old digest and repeat the same
`config`, `pull`, and `up` sequence. If the upgrade changed state incompatibly,
stop the controller and restore the pre-upgrade data volume, configuration,
and secrets key together before starting the old digest.

Exercise backup/restore and both image directions with the exact candidate and
previous release before launch. Exercise signing-certificate rotation using
[`certificate-rotation.md`](../../security/certificate-rotation.md), including
an online steward and one that reconnects after rotation. Admin credential
recovery must likewise be tested without leaving the recovery bundle in the
runtime volume.
