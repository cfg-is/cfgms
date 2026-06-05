# Module gRPC Contract

This document defines the gRPC wire contract for CFGMS out-of-process modules.
Two service variants exist: `ModuleService` (steward/outpost modules) and
`WorkflowModuleService` (controller workflow modules).  Both are defined in
`api/proto/modules/` and generated Go bindings are in the same directory.
Go consumers should import the stable wrapper types from `pkg/modules/contract`
rather than the generated package directly.

For module system overview and available modules, see [Module System](README.md).
For ADR design rationale, see [ADR-006](../../adr/ADR-006-module-packaging-and-distribution.md).

## Overview

Every CFGMS module is a separate process that the host runtime (steward or
workflow engine) dials over a local socket.  The host calls a standard set of
RPCs to drive the module: `Handshake` (capability exchange), `Get`/`Set`/`Test`
(resource lifecycle), and `Shutdown` (clean exit).

The two contract variants share all lifecycle RPCs but differ only in how
`Handshake` identifies the calling context:

| Variant | `HandshakeRequest` context | Used by |
|---------|---------------------------|---------|
| `ModuleService` | `host_runtime` ("steward" or "outpost") | Steward runtime (S7), Outpost runtime |
| `WorkflowModuleService` | `tenant_id` + `auth_token` | Controller workflow engine |

## Steward / Outpost Contract — `ModuleService`

Proto source: `api/proto/modules/module.proto`
Go package: `github.com/cfgis/cfgms/api/proto/modules`
Wrapper types: `pkg/modules/contract.StewardModuleClient`, `StewardModuleServer`

### Service definition

```protobuf
service ModuleService {
  rpc Handshake(HandshakeRequest)   returns (HandshakeResponse);
  rpc Get(GetRequest)               returns (GetResponse);
  rpc Set(SetRequest)               returns (SetResponse);
  rpc Test(TestRequest)             returns (TestResponse);
  rpc Shutdown(ShutdownRequest)     returns (ShutdownResponse);
}
```

### Handshake sequence

1. Host runtime dials the module process on a local socket.
2. Host sends `HandshakeRequest` identifying the module name/version and its
   `host_runtime` ("steward" or "outpost").
3. Module replies with `HandshakeResponse` listing its capabilities and a
   YAML-serialised `BehavioralEnvelope`.
4. Session is established; host proceeds to `Get`/`Set`/`Test` calls.
5. On shutdown the host calls `Shutdown`; the module process exits.

### Message shapes

```protobuf
message HandshakeRequest {
  string module_name    = 1;
  string module_version = 2;
  string publisher      = 3;
  string host_runtime   = 4;  // "steward" or "outpost"
}

message HandshakeResponse {
  repeated string capabilities    = 1;
  string behavioral_envelope_yaml = 2;  // YAML-serialised BehavioralEnvelope
}

message GetRequest  { string resource_id = 1; }
message GetResponse { string config_data = 1; }  // YAML-serialised ConfigState

message SetRequest  { string resource_id = 1; string config_data = 2; }
message SetResponse { bool applied = 1; string error = 2; }

message TestRequest  { string resource_id = 1; string config_data = 2; }
message TestResponse { bool in_compliance = 1; string diff = 2; }

message ShutdownRequest  {}
message ShutdownResponse {}
```

### RPC semantics

| RPC | Description |
|-----|-------------|
| `Get` | Returns the current resource state as YAML-serialised `ConfigState`. Must be idempotent and side-effect free. |
| `Set` | Applies `config_data` to the resource. `SetResponse.applied` is `true` when changes were made. `SetResponse.error` is non-empty on failure. |
| `Test` | Checks compliance without applying changes. `in_compliance` is `true` when no drift is detected. `diff` is a human-readable description of detected drift. |
| `Shutdown` | Requests clean exit. The module process must release resources and exit after responding. |

## Workflow Contract — `WorkflowModuleService`

Proto source: `api/proto/modules/workflow_module.proto`
Go package: `github.com/cfgis/cfgms/api/proto/modules`
Wrapper types: `pkg/modules/contract.WorkflowModuleClient`, `WorkflowModuleServer`

### Service definition

```protobuf
service WorkflowModuleService {
  rpc Handshake(WorkflowHandshakeRequest)   returns (WorkflowHandshakeResponse);
  rpc Get(GetRequest)                       returns (GetResponse);
  rpc Set(SetRequest)                       returns (SetResponse);
  rpc Test(TestRequest)                     returns (TestResponse);
  rpc Shutdown(ShutdownRequest)             returns (ShutdownResponse);
}
```

`Get`, `Set`, `Test`, `Shutdown` share the same message types as `ModuleService`.
Only the `Handshake` messages differ.

### Message shapes (handshake only)

```protobuf
message WorkflowHandshakeRequest {
  string module_name    = 1;
  string module_version = 2;
  string publisher      = 3;
  string tenant_id      = 4;  // scopes the session to a specific tenant
  string auth_token     = 5;  // controller-issued credential for the module
}

message WorkflowHandshakeResponse {
  repeated string capabilities    = 1;
  string behavioral_envelope_yaml = 2;
}
```

## Using the contract wrappers

Import `pkg/modules/contract` rather than the generated package to insulate your
code from generated-path changes:

```go
import "github.com/cfgis/cfgms/pkg/modules/contract"

// Steward runtime holds one client per active module session.
var client contract.StewardModuleClient = modules.NewModuleServiceClient(conn)

// Module binary implements the server interface.
type myModule struct {
    modules.UnimplementedModuleServiceServer
}
var _ contract.StewardModuleServer = (*myModule)(nil)
```

## Proto regeneration

To regenerate the Go bindings after editing the `.proto` files:

```bash
make proto-gen-modules
```

This requires `protoc` and `protoc-gen-go-grpc` to be installed.
