# Testing

Testing strategy, E2E guides, benchmarks, and live-validation runbooks.

## Strategy and Guides

- [Testing Strategy](testing-strategy.md) - Overall testing approach: philosophy, categories, and commands
- [Testing Standards](../development/standards/testing-standards.md) - Testing requirements and patterns
- [E2E Testing Guide](e2e-testing-guide.md) - End-to-end test setup and execution
- [Fleet E2E Upgrade Tests](e2e-fleet.md) - Docker-based steward upgrade tests in `test/e2e/fleet`
- [Cluster Benchmark](cluster-benchmark.md) - Repeatable controller-cluster benchmarks
- [Release Validation Checklist](release-validation-checklist.md) - Manual validation procedure to run before every release

## Live-Validation Runbooks

- [Controller HA Real-Cluster Runbook](controller-ha-real-cluster-runbook.md) - Controller HA validation on a real cluster (epic #3090)

### Hyper-V live validation

- [Hyper-V cluster.cfg Cascade + Failover](hyperv-cluster-cascade-runbook.md) - Fleet-e2e live validation of the cluster.cfg cascade
- [Hyper-V Role Promotion](hyperv-role-promotion-runbook.md) - Standalone to failover-cluster role promotion
