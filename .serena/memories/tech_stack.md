# Tech Stack

- Language: Go. Module path `github.com/cfgis/cfgms`. `go 1.25.0`, toolchain `go1.26.4` (pinned in go.mod — toolchain/pin bumps go through the `refresh-pins` workflow + per-pin stories).
- Build: GNU Make (root `Makefile` is the orchestrator; do not modify root targets unless story requires).
- Protobuf/gRPC codegen via `make proto` (needs proto tools; `make proto-gen`, `proto-gen-modules`).

## Key deps
- `spf13/cobra` — CLI framework.
- `quic-go/quic-go` — QUIC transport.
- `google.golang.org/grpc`, `google.golang.org/protobuf`.
- `stretchr/testify` — test assertions (real components still required; testify is for asserts only).
- `go-git/go-git/v5`, AWS SDK v2 (s3/config/credentials), `go-acme/lego/v4` (ACME), `Microsoft/go-winio`, `creack/pty`.

Do not add Go module deps without story justification.
