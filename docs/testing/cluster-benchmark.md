# Cluster Benchmark

`test/integration/cluster/cluster_benchmark_test.go` — repeatable benchmarks for
Epic #3751 (ADR-031, controller cluster service model). The epic's own Scope
section names the gap this closes: "no benchmarks exist" proving that adding a
controller node adds serving capacity. These two `func Benchmark*` functions are
that evidence, plus a baseline others can reproduce and compare future changes
against.

Both benchmarks drive real components — real `*controllerapi.Server` instances,
a real OSS storage manager (flatfile + file-backed SQLite), real mTLS, and the
real internal-delivery gRPC service. No mocks, per the project's testing
standard. They are not part of `make test` / `make test-complete`'s pass/fail
gate — `go test` only runs benchmarks when `-bench` is passed — so they add no
runtime to the blocking suite; they only need to compile and execute cleanly,
which `make test-complete` does verify (`go build ./...` covers compilation, and
CI's `go vet`/`golangci-lint` passes cover the file like any other Go source).

## Running

```bash
# Both benchmarks, one pass each, from repo root:
go test ./test/integration/cluster/... -run '^$' -bench . -benchtime=1x -v

# Longer, steadier sample (recommended for numbers you intend to cite):
go test ./test/integration/cluster/... -run '^$' -bench . -benchtime=2s
```

`-run '^$'` skips the (nonexistent) `Test*` functions in this file so only
benchmarks execute. `-bench .` runs every benchmark in the package;
narrow to one with `-bench BenchmarkCrossNodeDeliveryLatency` or
`-bench BenchmarkAPIThroughput_SingleVsMultiNode` when iterating.

Both benchmarks provision their own ephemeral secrets store and temp
directories per run (via `b.TempDir()` / `pkg/testutil.ProvisionSecretsEnv`) —
no external services, Docker, or environment setup required.

## What each one measures

### `BenchmarkAPIThroughput_SingleVsMultiNode`

Two sub-benchmarks, `1-node` and `3-node`, each driving concurrent
`GET /api/v1/stewards` requests (an admin-authenticated, real-storage-backed
list read — the minimum genuinely "any-node service" request per S7) through
that many independent `*controllerapi.Server` instances, all wired to **one**
shared storage manager — the same shared-DB-as-serialization-point shape
production clusters use (ADR-007). Read the sub-benchmark's `ns/op` and the
implied ops/sec (`1e9 / ns/op`) to compare 1-node vs. 3-node capacity.

**Reading the numbers honestly:** this benchmark runs all simulated nodes as
Go objects in one OS process on one machine, so `b.RunParallel`'s goroutines
share the same CPU core count regardless of node count — a request-handling
in-process simulation cannot demonstrate the *hardware* capacity increase a
real N-machine cluster gets, because there's only one machine's CPU here. What
it does prove, every run: identical request handling succeeds on every node
(no leadership gate, no serialization onto one instance — the property S7
actually delivered), against real storage, with a reproducible per-request
cost baseline. A regression in per-request cost, or a request that only
succeeds against one particular node index, is what this benchmark exists to
catch. Validating literal multi-machine throughput scaling is a separate,
infrastructure-heavy exercise (see `test/integration/ha/`'s Docker-Compose
multi-controller setup) — out of scope for a fast, dependency-free benchmark.

### `BenchmarkCrossNodeDeliveryLatency`

Measures real end-to-end delivery time: `b.N` iterations of
`publisher.PublishCommand` on node A's `ClusterAwareSender`, timed until the
steward — connected only to peer node B — receives it on its
`SubscribeCommands` handler. Node A deliberately has no local connection for
the steward, so every iteration is forced through the real S10 path: routing
table lookup → mTLS gRPC forwarding to node B → node B's local control-plane
delivery to its connected steward. `ns/op` here is the real cross-node
dispatch-to-receipt latency for this deployment shape (one process, loopback
TCP, mTLS handshake reused across the connection pool).

## Baseline (this story's own run)

Measured on the story's dev container, `go test ... -bench . -benchtime=2s`,
4 logical CPUs:

| Benchmark | Iterations | ns/op | Approx. ops/sec |
|---|---|---|---|
| `BenchmarkAPIThroughput_SingleVsMultiNode/1-node` | 24,226 | 100,641 | ~9,936 |
| `BenchmarkAPIThroughput_SingleVsMultiNode/3-node` | 24,540 | 98,432 | ~10,159 |
| `BenchmarkCrossNodeDeliveryLatency` | 20,734 | 117,295 | ~8.5k ops/sec (~117µs/delivery) |

The 1-node vs. 3-node throughput is within noise of each other in this
single-machine, CPU-core-bound run — expected per the reading-honestly note
above, since all simulated nodes compete for the same 4 cores here. Re-run
locally with `-benchtime=2s` or higher for your own hardware's numbers before
citing them elsewhere; treat this table as this story's own evidence snapshot,
not a permanent target.
