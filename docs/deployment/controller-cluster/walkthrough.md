# Controller Cluster Deployment

Deploy a geo-redundant CFGMS controller cluster for high availability and regional failover.

**Prerequisite**: Complete [Single Controller](../single-controller/walkthrough.md) first. This guide assumes you have a validated single-controller environment and covers turning it into a multi-node cluster.

## Status

This deployment mode is planned. Documentation will be added when controller clustering is implemented.

**Tracking**: [Issue #1517](https://github.com/cfg-is/cfgms/issues/1517) — steward multi-controller/failover support (one binary = one controller URL is the current constraint).

For current cluster formation and steward HA test patterns, see `test/integration/ha/` in the repository.

## What this will cover

- Adding controller nodes to an existing single-controller deployment
- Shared CA and certificate distribution across nodes
- Storage replication between controller nodes
- Steward failover when a controller becomes unavailable
- Regional deployment patterns for geographically distributed fleets
