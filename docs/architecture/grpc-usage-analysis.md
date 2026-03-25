# gRPC Usage Analysis

> **⚠️ HISTORICAL DOCUMENT**
>
> This document is preserved for historical reference and explains the analysis that led to the initial gRPC-to-MQTT+QUIC migration (Story #220), and later to the gRPC-over-QUIC unified transport.
>
> **Analysis Date**: 2025-10-15
> **Context**: v0.7.0 Pre-OSS preparation — Analysis that led to gRPC removal (Story #220)
>
> **Implementation History**:
> - v0.7.0 (Story #220): gRPC service layer removed, replaced with MQTT+QUIC hybrid
> - v0.9.x (Phase 10.11, Stories #519–#522): MQTT removed, gRPC re-introduced as the **transport** over QUIC
>
> **Current Protocol**: gRPC-over-QUIC unified transport (see [communication-layer-migration.md](communication-layer-migration.md))
>
> **Key Insight**: The analysis below correctly identified that the gRPC _service layer_ added unnecessary complexity. What it did not anticipate was that gRPC as a _serialization and RPC framework_ over QUIC (rather than HTTP/2) would become the ideal solution — retaining protobuf type safety and bidirectional streaming while eliminating the HTTP/2 and broker overhead that motivated the original removal.
>
> ---

**Context**: v0.7.0 Pre-OSS preparation - Task to review gRPC usage and remove if not justified

## Executive Summary

**Recommendation: REMOVE gRPC from codebase**

gRPC is **not actively used** in CFGMS. The system migrated to MQTT+QUIC for controller-steward communication in Story #198, but gRPC artifacts (proto files, generated code, service implementations) were left behind.

## Current Architecture

The controller uses:

- **MQTT**: Control plane communication (commands, heartbeats, DNA sync)
- **QUIC**: Data plane communication (configuration sync, bulk data transfer)
- **HTTP REST**: External API, registration, management endpoints
- **gRPC**: NOT USED (but code remains)

Reference: `features/controller/server/server.go:350-468`

## gRPC Artifacts in Codebase

### 1. Protocol Buffer Definitions (7 files)

```
api/proto/common/common.proto
api/proto/common/auth.proto
api/proto/common/rbac.proto
api/proto/controller/rbac.proto
api/proto/controller/controller.proto
api/proto/controller/config.proto
api/proto/steward/steward.proto
```

**Status**: Active use for data structures (protobuf messages)
**Usage**: Message definitions used by MQTT+QUIC handlers
**Keep**: YES - proto messages are used, but gRPC service definitions should be removed

### 2. Generated gRPC Code (4 files)

```
api/proto/controller/controller_grpc.pb.go
api/proto/controller/config_grpc.pb.go
api/proto/controller/rbac_grpc.pb.go
api/proto/steward/steward_grpc.pb.go
```

**Status**: Auto-generated, not used
**Keep**: NO - should be removed

### 3. Service Implementations (3 files)

```
features/controller/service/controller_service.go
features/controller/service/config_service.go
features/controller/service/rbac_service.go
```

**Status**: Active use BUT not as gRPC services
**Details**:

- These implement business logic used by MQTT/QUIC/HTTP handlers
- They embed `UnimplementedXServer` for interface conformance (unused)
- Methods take `context.Context` and return proto messages (still useful)
- NOT registered with any gRPC server

**Keep**: YES - but remove gRPC interface conformance

### 4. RBAC Middleware (1 file)

```
features/rbac/middleware.go
```

**Status**: Uses gRPC interceptor pattern
**Details**:

- Implements `grpc.UnaryServerInterceptor` and `grpc.StreamServerInterceptor`
- Extracts metadata using `metadata.FromIncomingContext`
- NOT actually used with gRPC server

**Keep**: NO - redesign for HTTP/MQTT middleware

### 5. Dependencies

**go.mod includes**:

```
google.golang.org/grpc
google.golang.org/protobuf
```

**Status**:

- `protobuf` is actively used (proto messages)
- `grpc` is NOT needed (only used in unused code)

**Keep**: protobuf YES, grpc NO

## Impact Analysis

### Code Removal Required

1. **Remove gRPC service definitions from .proto files**
   - Keep message definitions
   - Remove `service` blocks
   - Regenerate proto code without gRPC

2. **Remove generated *_grpc.pb.go files**
   - Delete 4 auto-generated files
   - Update build process to skip gRPC generation

3. **Refactor service implementations**
   - Remove `UnimplementedXServer` embeddings
   - Keep business logic methods
   - Update method signatures if needed

4. **Redesign RBAC middleware**
   - Create HTTP middleware for REST API
   - Create MQTT authorization handler
   - Remove gRPC interceptor code

5. **Remove gRPC dependency**
   - Remove `google.golang.org/grpc` from go.mod
   - Keep `google.golang.org/protobuf`

### Files to Modify

| File | Action | Reason |
|------|--------|--------|
| `api/proto/controller/*.proto` | Edit | Remove `service` definitions, keep messages |
| `api/proto/steward/*.proto` | Edit | Remove `service` definitions, keep messages |
| `api/proto/*_grpc.pb.go` | Delete | Auto-generated gRPC code not needed |
| `features/controller/service/controller_service.go` | Refactor | Remove `UnimplementedControllerServer` |
| `features/controller/service/config_service.go` | Refactor | Remove `UnimplementedConfigurationServiceServer` |
| `features/controller/service/rbac_service.go` | Refactor | Remove `UnimplementedRBACServiceServer` |
| `features/rbac/middleware.go` | Redesign | Create HTTP/MQTT middleware, remove gRPC |
| `go.mod` | Edit | Remove `google.golang.org/grpc` dependency |
| `Makefile` | Edit | Update proto generation to skip gRPC |

### Test Impact

**Search for gRPC in tests**:

```bash
grep -r "grpc\." test/ features/*/test*.go
```

Expected: Minimal impact (no gRPC server tests exist)

### Backward Compatibility

**Breaking Change**: YES - if external clients use gRPC (none exist)

**Current Communication Methods**:

1. **Steward → Controller**: MQTT+QUIC (Story #198)
2. **CLI → Controller**: HTTP REST API
3. **Web UI → Controller**: HTTP REST API (future)

**Conclusion**: No backward compatibility concerns - gRPC was never exposed externally

## Justification for Keeping gRPC

**Question**: Is there any strong justification to keep gRPC?

**Answer**: NO

| Criterion | gRPC | Current Architecture |
|-----------|------|---------------------|
| **Performance** | High | QUIC provides equivalent performance |
| **Streaming** | Bidirectional | MQTT provides pub/sub, QUIC provides streams |
| **Type Safety** | Proto messages | Proto messages (without gRPC services) |
| **Code Generation** | Yes | Still available for messages only |
| **Mobile/Web** | gRPC-web needed | HTTP REST works everywhere |
| **MSP Market Fit** | Uncommon | MQTT widely adopted in RMM/IoT space |

**Additional Considerations**:

1. **Market Positioning**: MSPs are familiar with MQTT (used by RMMs)
2. **Network Traversal**: MQTT+TLS easier through firewalls than gRPC
3. **Pub/Sub Model**: MQTT's pub/sub better for controller→steward commands
4. **Reduced Complexity**: Fewer dependencies, simpler architecture
5. **Open Source Readiness**: Cleaner codebase without unused tech

## Recommended Actions

### Phase 1: Analysis and Planning (1 day)

- [x] Document current gRPC usage (this document)
- [ ] Verify no external gRPC dependencies
- [ ] Create migration checklist

### Phase 2: Code Removal (2-3 days)

- [ ] Remove service definitions from .proto files
- [ ] Regenerate proto code without gRPC
- [ ] Refactor service implementations
- [ ] Redesign RBAC middleware for HTTP/MQTT
- [ ] Update Makefile and build scripts
- [ ] Remove gRPC from go.mod

### Phase 3: Testing (1 day)

- [ ] Run full test suite
- [ ] Test MQTT+QUIC communication
- [ ] Test HTTP REST API
- [ ] Test RBAC authorization

### Phase 4: Documentation (1 day)

- [ ] Update architecture docs
- [ ] Update API documentation
- [ ] Update contributor guide

**Total Effort**: 5-6 days

## Alternative: Minimal Cleanup

If full removal is too aggressive for v0.7.0, consider minimal cleanup:

1. Add comments marking gRPC code as deprecated
2. Remove from go.mod (since it's not imported in main paths)
3. Keep files for reference but don't maintain
4. Remove in v0.8.0 or v0.9.0

**Recommendation**: Do full removal now - cleaner for open source launch

## Conclusion

gRPC artifacts in CFGMS are **legacy code from pre-MQTT+QUIC architecture**. They provide no value and add:

- Unnecessary dependencies
- Confusing code structure
- Maintenance burden
- Larger binary size

**Recommendation**: Remove all gRPC code before v0.7.0 open source launch.

This aligns with the roadmap task: *"Review use of gRPC and finish removing from codebase unless there is strong justification to keep it."*

There is **no strong justification** to keep gRPC.

---

**Next Steps**: Review this analysis and proceed with gRPC removal if approved.
