# Controller Cluster Deployment

Deploy a geo-redundant CFGMS controller cluster for high availability and regional failover.

**Prerequisite**: Complete [Single Controller](../single-controller/walkthrough.md) first. This guide assumes you have a validated single-controller environment and covers turning it into a multi-node cluster.

## Status

This deployment mode is planned. The walkthrough will be added when controller clustering is implemented.

## What this will cover

- Adding controller nodes to an existing single-controller deployment
- Shared CA and certificate distribution across nodes
- Storage replication between controller nodes
- Steward failover when a controller becomes unavailable
- Regional deployment patterns for geographically distributed fleets
