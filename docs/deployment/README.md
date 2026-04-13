# CFGMS Deployment

Choose the deployment that matches your scenario.

## Deployment Modes

### [Single Controller](single-controller/walkthrough.md)

One controller with a controller-steward managing the node. Stewards across your environment connect to this controller for centralized configuration management.

**Use when**: You're setting up CFGMS for the first time, running a lab, or managing a fleet from a single controller.

**You'll deploy**: controller binary, controller-steward, config files, systemd service.

### [Controller Cluster](controller-cluster/walkthrough.md) *(planned)*

Geo-redundant controller deployment with failover. Starts from a working single-controller environment.

**Use when**: You need high availability or regional distribution.

## Steward Examples

### [Steward Examples](steward-examples/README.md)

Example steward configurations for common server roles — domain controller, file server, SQL server, Hyper-V host, web server, database server, Docker host. Each example can be used standalone or pushed from a controller.

**Use when**: You have a working controller and want a starting point for managing specific server roles.

## Reference

- [Platform Support](platform-support.md) — supported operating systems, architectures, and platform-specific notes
