# MQTT+QUIC Hybrid Communication Protocol (Story #198)

## Overview

This document defines the communication protocol for replacing gRPC with a hybrid MQTT+QUIC architecture.

**Goals:**

- 40% bandwidth reduction (Story #198 requirement)
- <15s failover detection (Story #198 requirement)
- Bi-directional communication (controller → steward and steward → controller)
- Support for large data transfers (configurations, DNA)
- Real-time command/control capabilities

## Architecture

### Communication Channels

```
┌──────────────┐                                    ┌──────────────┐
│  Controller  │                                    │   Steward    │
│              │                                    │              │
│  ┌────────┐  │  MQTT (Control Plane)             │  ┌────────┐  │
│  │ MQTT   │◄─┼────────────────────────────────────┼─►│ MQTT   │  │
│  │ Broker │  │  - Heartbeats (push-based)         │  │ Client │  │
│  └────────┘  │  - Commands (controller → steward) │  └────────┘  │
│              │  - Status updates (steward → ctrl) │              │
│              │                                    │              │
│  ┌────────┐  │  QUIC (Data Plane)                │  ┌────────┐  │
│  │ QUIC   │◄─┼────────────────────────────────────┼─►│ QUIC   │  │
│  │ Server │  │  - Configuration sync              │  │ Client │  │
│  └────────┘  │  - DNA sync                        │  └────────┘  │
│              │  - Large data transfers            │              │
│              │  - Bi-directional streams          │              │
└──────────────┘                                    └──────────────┘
```

## MQTT Control Plane

### Topic Structure

```
cfgms/
├── steward/
│   ├── {steward-id}/
│   │   ├── heartbeat        # Steward → Controller (QoS 1)
│   │   ├── will             # LWT for disconnect detection (QoS 1)
│   │   ├── status           # Steward status updates (QoS 1)
│   │   └── commands         # Controller → Steward commands (QoS 1)
│   └── +/heartbeat          # Controller subscribes to all heartbeats
└── controller/
    └── broadcast            # Controller → All Stewards (QoS 0)
```

### Message Types

#### 1. Heartbeat (Steward → Controller)

**Topic:** `cfgms/steward/{id}/heartbeat`
**QoS:** 1 (at least once)
**Payload:**

```json
{
  "steward_id": "steward-abc123",
  "status": "healthy|degraded|error",
  "timestamp": "2025-10-05T12:34:56Z",
  "metrics": {
    "cpu_percent": "25.3",
    "memory_mb": "512",
    "uptime_seconds": "86400"
  }
}
```

#### 2. Commands (Controller → Steward)

**Topic:** `cfgms/steward/{id}/commands`
**QoS:** 1 (at least once)
**Payload:**

```json
{
  "command_id": "cmd-xyz789",
  "type": "sync_config|sync_dna|connect_quic|execute_task|shutdown",
  "timestamp": "2025-10-05T12:34:56Z",
  "params": {
    "quic_address": "controller:4433",
    "session_id": "session-abc123",
    "timeout_seconds": 30
  }
}
```

**Command Types:**

- `sync_config` - Request configuration sync (triggers QUIC connection)
- `sync_dna` - Request DNA sync (triggers QUIC connection)
- `connect_quic` - Establish QUIC connection for data transfer
- `execute_task` - Execute specific task/module
- `shutdown` - Graceful shutdown request

#### 3. Status Updates (Steward → Controller)

**Topic:** `cfgms/steward/{id}/status`
**QoS:** 1 (at least once)
**Payload:**

```json
{
  "steward_id": "steward-abc123",
  "timestamp": "2025-10-05T12:34:56Z",
  "event": "config_applied|dna_synced|task_completed|error",
  "details": {
    "config_version": "v1.2.3",
    "module_count": 15,
    "execution_time_ms": 1250
  }
}
```

#### 4. Will Message (LWT - Steward disconnect)

**Topic:** `cfgms/steward/{id}/will`
**QoS:** 1 (at least once)
**Retain:** false
**Payload:**

```json
{
  "steward_id": "steward-abc123",
  "status": "disconnected",
  "timestamp": "2025-10-05T12:34:56Z"
}
```

## QUIC Data Plane

### Connection Model

**Steward-Initiated Connections:**

- Steward ALWAYS initiates QUIC connections to controller
- Controller cannot directly connect to steward (NAT/firewall friendly)
- Controller triggers connections via MQTT commands

**Connection Flow:**

1. Controller sends `connect_quic` command via MQTT
2. Steward receives command with session_id and QUIC address
3. Steward establishes QUIC connection to controller
4. Controller accepts connection, validates session_id
5. Bi-directional streams for data transfer
6. Connection closed after transfer or timeout

### Stream Types

```
QUIC Connection
├── Stream 0: Control Stream (bidirectional)
│   └── Session negotiation, keepalive, errors
├── Stream 1: Configuration Sync (controller → steward)
│   └── Push configuration data
├── Stream 2: DNA Sync (steward → controller)
│   └── Push DNA updates
├── Stream 3: Configuration Status (steward → controller)
│   └── Report configuration application status
└── Stream N: Ad-hoc transfers
    └── Large payloads, module data, logs, etc.
```

### QUIC Protocol Messages

All messages use Protocol Buffers (same as gRPC).

#### Control Stream (Stream 0)

```protobuf
message QUICHandshake {
  string session_id = 1;
  string steward_id = 2;
  common.Credentials credentials = 3;
}

message QUICHandshakeResponse {
  common.Status status = 1;
  repeated StreamCapability capabilities = 2;
}

message StreamCapability {
  int32 stream_id = 1;
  string purpose = 2;  // "config_sync", "dna_sync", etc.
  Direction direction = 3;
  enum Direction {
    BIDIRECTIONAL = 0;
    CLIENT_TO_SERVER = 1;
    SERVER_TO_CLIENT = 2;
  }
}
```

#### Configuration Stream (Stream 1)

```protobuf
// Reuse existing ConfigResponse from config.proto
message ConfigSyncRequest {
  string steward_id = 1;
  repeated string modules = 2;
}
```

#### DNA Stream (Stream 2)

```protobuf
// Reuse existing DNA from common.proto
message DNASyncRequest {
  string steward_id = 1;
}
```

## Migration Strategy

### Phase 1: MQTT Broker (✅ Complete)

- Embedded mochi-mqtt broker in controller
- Auto-generated test certificates
- mTLS authentication

### Phase 2: Controller Integration (✅ Complete)

- MQTT broker lifecycle management
- Default enabled as core infrastructure

### Phase 3: MQTT Heartbeats (✅ Complete)

- Heartbeat service in controller
- MQTT client in steward
- <15s failover detection
- gRPC heartbeat fallback

### Phase 4: MQTT Command/Control (Current)

- [ ] Command handler in steward
- [ ] Command publisher in controller
- [ ] QUIC connection triggering via MQTT

### Phase 5: QUIC Data Plane

- [ ] QUIC server in controller
- [ ] QUIC client in steward
- [ ] Configuration sync over QUIC
- [ ] DNA sync over QUIC

### Phase 6: Remove gRPC

- [ ] Migrate all remaining gRPC operations
- [ ] Remove gRPC dependencies
- [ ] Update tests for MQTT+QUIC only

## Security

### MQTT Security

- **Transport:** TLS 1.2+ with mTLS
- **Authentication:** Client certificate verification
- **Authorization:** ACL based on steward ID
- **Message Signing:** Optional HMAC for critical commands

### QUIC Security

- **Transport:** Built-in TLS 1.3 with mTLS
- **Session Tokens:** Short-lived session IDs (30s TTL)
- **Connection Verification:** Certificate + session_id validation
- **Replay Protection:** Timestamp + nonce validation

## Performance Characteristics

### MQTT (Control Plane)

- **Latency:** <50ms for commands
- **Throughput:** ~10K messages/sec per broker
- **Message Size:** <1KB typical, 256KB max
- **Reliability:** QoS 1 (at least once delivery)

### QUIC (Data Plane)

- **Latency:** ~20ms connection establishment
- **Throughput:** ~1GB/s for large transfers
- **Message Size:** Unlimited (streamed)
- **Reliability:** Built-in retransmission and flow control

## Bandwidth Reduction Analysis

### Current gRPC (Baseline)

- Heartbeat every 30s: ~500 bytes × 2 (req+resp) = 1KB per heartbeat
- HTTP/2 overhead: ~15% additional
- Total: ~1.15KB per heartbeat cycle

### New MQTT+QUIC

- Heartbeat via MQTT: ~250 bytes (JSON, QoS 1)
- No response required (fire-and-forget)
- MQTT overhead: ~5%
- Total: ~263 bytes per heartbeat cycle

**Heartbeat Bandwidth Reduction:** 77% (1150 → 263 bytes)

### Configuration Sync

- Current gRPC: HTTP/2 + protobuf + metadata = ~25% overhead
- New QUIC: TLS 1.3 + protobuf only = ~5% overhead

**Config Sync Bandwidth Reduction:** ~20%

**Overall Expected Reduction:** ~40% (Story #198 requirement ✓)

## Error Handling

### MQTT Connection Loss

1. Steward detects MQTT disconnect
2. Automatic reconnect with exponential backoff
3. Resubscribe to command topic
4. Heartbeat service marks steward unhealthy after 15s

### QUIC Connection Failure

1. Steward reports error via MQTT status topic
2. Controller retries with new session_id
3. Exponential backoff (1s, 2s, 4s, 8s, max 30s)
4. Fallback to next scheduled sync if persistent failure

### Command Timeout

1. Steward sends status update when command received
2. Controller expects completion status within timeout
3. If timeout exceeded, command marked as failed
4. Steward continues processing but result may be ignored

## Monitoring

### Metrics to Track

- MQTT message rate (messages/second)
- MQTT message size distribution
- QUIC connection establishment time
- QUIC data transfer rate
- Command execution latency
- Heartbeat latency (publish to controller receipt)
- Failover detection time (must be <15s)

### Logging

- All MQTT commands logged with command_id
- All QUIC sessions logged with session_id
- All errors logged with context and steward_id
- Performance metrics logged at INFO level
