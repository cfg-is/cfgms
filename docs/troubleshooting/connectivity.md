# Controller–Steward Connectivity Troubleshooting

Diagnose connection, trust, identity and configuration-delivery failures without
replacing identity or trust material as a generic restart fix. Internal traffic
uses gRPC over QUIC with mTLS on the configured transport port (normally `4433/UDP`);
the external HTTPS API normally listens on `9080/TCP`.

## 1. Establish which service failed

On a systemd host:

```bash
sudo systemctl status cfgms-controller --no-pager
sudo systemctl status cfgms-steward --no-pager
sudo journalctl -u cfgms-controller -n 100 --no-pager
sudo journalctl -u cfgms-steward -n 100 --no-pager
```

Use the corresponding service manager on Windows/macOS, or the actual Compose
service names for a [container deployment](../deployment/container/README.md).
Do not assume a container named `steward-standalone` exists in a host deployment.
Record the failure phase and error before changing configuration.

## 2. Check routing and listeners

- Confirm the steward uses the intended controller URL and trust source. For
  initial installation, follow the [fleet walkthrough](../deployment/fleet/walkthrough.md).
- Check the controller transport listener and firewall allow the configured UDP
  port. On Linux, `sudo ss -lunp` lists UDP listeners. TCP reachability to the
  HTTPS API does not establish QUIC connectivity.
- Check NAT/container UDP publication and load-balancer routing. A generic UDP
  `nc` probe is not a QUIC handshake test.
- For a cluster, verify the configured public endpoint routes to healthy peers;
  clustering by itself does not provide endpoint failover.

Inspect the public health/readiness gates using the trusted controller CA and a
hostname covered by its certificate:

```bash
curl --fail --cacert /path/to/controller-ca.crt \
  https://controller.example.com:9080/api/v1/health
curl --fail --cacert /path/to/controller-ca.crt \
  https://controller.example.com:9080/api/v1/ready
```

Health reflects component presence and the drain gate. Readiness performs a
durable-storage round trip. Neither public response proves an individual steward
has authenticated or applied its configuration.

## 3. Separate certificate and trust failures

| Error | Check and recovery path |
|---|---|
| Unknown authority or pin mismatch | Verify the install-pinned/compiled trust anchor and controller CA through a trusted channel. Restarting does not authorize accepting a replacement CA. Investigate deliberate CA changes using the current trust/rotation procedure. |
| Expired/not-yet-valid certificate | Check host clocks and the actual installed credential's validity. Steward renewal normally runs automatically; inspect renewal failures and use the registration-refresh procedure when re-admission is needed. |
| Hostname mismatch | Correct the public URL or issue a certificate covering that hostname/IP; do not disable verification. |
| Identity already in use/provenance divergence | Follow the clone-identity response; do not repeatedly enroll the same copied credential. |
| Pending registration/refresh | Resolve the authorized approval queue, token scope and admission policy rather than treating pending state as a transport outage. |

Follow [registration refresh](../deployment/steward-refresh-management.md),
[clone registration](clone-registration.md), and the
[clone incident runbook](../runbooks/steward-identity-clone.md) for their distinct cases.
Use [image preparation](../deployment/steward-image-preparation.md) before cloning
an installed steward. Do not delete controller CA or steward identity storage to
work around a connection error.

## 4. Check managed startup and reconnect

A registered steward can start with its stored identity without a fresh token.
Missing `--regtoken-file` is not proof that it is standalone; explicit `--config`
selects standalone mode. Inspect service arguments, identity-store access and
connection logs. The old `--regtoken` flag is removed.

For a new install, use `cfgms-steward install --regtoken-file PATH` with the
required platform access controls and configured trust. Do not reinstall a
working identity merely to trigger a retry. A service restart can retry a
connection but does not resolve an invalid credential, unapproved refresh or
changed trust anchor.

## 5. Trace configuration delivery separately

1. Confirm the steward is connected in the controller's fleet view and inspect
   per-endpoint errors from an authorized live query.
2. Inspect `GET /api/v1/stewards/{id}/config/effective` and its source metadata.
   See [configuration inheritance](../guides/configuration-inheritance.md).
3. Check controller delivery and steward signature/validation logs. A successful
   API write or accepted push is not proof of successful endpoint application.
4. Inspect resource/module errors, required privileges, configured convergence
   timing and any drift policy that deliberately avoids enforcement.
5. Verify current state after correction. DNA synchronization and observation
   freshness are distinct; matching hashes only establish synchronization of
   reported state, not a new live observation of every field.

Current configuration storage is selected through the controller's configured
providers. Do not diagnose delivery by looking for the removed Git-storage backend
or by invoking old test names. For maintained reproducible suites, use the
[testing index](../testing/README.md).
