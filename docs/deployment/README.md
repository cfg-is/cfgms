# CFGMS Deployment

Choose the deployment that matches your scenario.

## Canonical Config Examples

Two fully-commented config files to copy and customize:

- [`controller.cfg`](controller.cfg) — canonical controller boot config. Copy to `/etc/cfgms/controller.cfg`.
- [`steward.cfg`](steward.cfg) — canonical steward boot config. Copy to `/etc/cfgms/steward.cfg` on each endpoint.

## Deployment Modes

### [Single Controller](single-controller/walkthrough.md)

One controller with a controller-steward managing the node. Stewards across your environment connect to this controller for centralized configuration management.

**Use when**: You're setting up CFGMS for the first time, running a lab, or managing a fleet from a single controller.

**You'll deploy**: controller binary, controller-steward, config files, systemd service.

### [Fleet Deployment](fleet/walkthrough.md)

Controller with remote stewards: register two Linux endpoints, push a fleet config, and
observe convergence and drift correction end to end.

**Use when**: You have a working single-controller deployment and want to connect remote
stewards, push configs, and verify the full fleet management loop.

### [Controller Cluster](controller-cluster/walkthrough.md) *(planned)*

Geo-redundant controller deployment with failover. Starts from a working single-controller environment.

**Use when**: You need high availability or regional distribution.

## Role Config Recipes

### [Role Config Recipes](../examples/role-configs/README.md)

Ready-to-use fleet configs for common server roles — domain controller, file server,
SQL server, Hyper-V host, web server, database server, Docker host. Push these to
stewards from the controller once your environment is set up.

**These are NOT steward boot configs.** See [`steward.cfg`](steward.cfg) for the
canonical boot config.

**Use when**: You have a working controller and want a starting point for managing specific server roles.

## Secrets

CFGMS supports pluggable secrets backends. The default is SOPS (file-based, git-integrated).

### OpenBao (dev setup)

[OpenBao](https://github.com/openbao/openbao) is an Apache 2.0-licensed Vault fork supported
as a secrets backend for development and production.

**Dev-mode quickstart** (integration tests and local development):

```bash
# Start OpenBao dev mode on host port 8201
docker compose --profile openbao -f docker-compose.test.yml up -d openbao-test

# Verify it is healthy
curl http://localhost:8201/v1/sys/health
```

Configure the controller to use OpenBao:

```yaml
secrets:
  provider: openbao
  config:
    address: http://127.0.0.1:8201
    token: root          # dev mode only — use a service token in production
    mount_path: secret
```

> **Warning**: The `root` token and dev mode are for local development only.
> In production, set `CFGMS_TELEMETRY_ENVIRONMENT=production`; the provider
> will refuse to start if a dev-mode token or `BAO_DEV_MODE=true` is detected.
> See `pkg/secrets/providers/openbao/README.md` for production configuration.

## Reference

- [Platform Support](platform-support.md) — supported operating systems, architectures, and platform-specific notes
