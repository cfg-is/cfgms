# Terminal Module - Secure Remote Access System

## Overview
The Terminal module provides secure remote terminal access to managed Stewards through a WebSocket-based proxy system. It integrates with the existing CFGMS architecture to enable real-time interactive shell access while maintaining security and audit compliance.

## Architecture

### Component Design
```
[Web Client] <--WebSocket--> [Controller Terminal API] <--gRPC--> [Steward Terminal Handler]
     |                              |                                    |
     |                              |                                    |
 xterm.js                    Session Manager                      Process Manager
                                   |                                    |
                            Session Recorder                     Shell Executor
                                   |                                    |
                            Audit Storage                     bash/zsh/PowerShell/cmd
```

### Integration Points
1. **Controller REST API** (`features/controller/api/server.go:200`): Add terminal WebSocket endpoints
2. **gRPC Services** (`api/proto/controller/controller.proto:22`): Extend with terminal operations
3. **Steward Service** (`api/proto/steward/steward.proto:18`): Add terminal execution support
4. **RBAC System** (`features/rbac/manager.go`): Terminal access permissions
5. **Certificate Management** (`pkg/cert/manager.go`): mTLS for terminal streams

## Security Model

### Authentication & Authorization
- **REST API**: API key authentication for WebSocket upgrade
- **RBAC Integration**: `terminal:access`, `terminal:record` permissions
- **mTLS**: End-to-end encryption for all terminal data
- **Session Isolation**: Per-user/per-steward session boundaries

### Audit & Compliance
- **Session Recording**: All terminal I/O captured for audit
- **Access Logging**: Who accessed which steward and when
- **Command Filtering**: Optional command validation/blocking
- **Session Timeout**: Automatic cleanup after inactivity

## Protocol Design

### WebSocket Messages
```go
type TerminalMessage struct {
    Type      MessageType `json:"type"`
    SessionID string      `json:"session_id"`
    Data      []byte      `json:"data,omitempty"`
    Error     string      `json:"error,omitempty"`
}

type MessageType string
const (
    MessageTypeData   MessageType = "data"
    MessageTypeResize MessageType = "resize" 
    MessageTypeClose  MessageType = "close"
    MessageTypeError  MessageType = "error"
)
```

### gRPC Extensions
```protobuf
service Controller {
  // Terminal management
  rpc StartTerminal(StartTerminalRequest) returns (StartTerminalResponse);
  rpc TerminalData(stream TerminalDataRequest) returns (stream TerminalDataResponse);
  rpc EndTerminal(EndTerminalRequest) returns (common.Status);
}

service Steward {
  // Terminal execution
  rpc ExecuteTerminal(stream TerminalExecuteRequest) returns (stream TerminalExecuteResponse);
}
```

## Performance Targets
- **Latency**: <100ms for typical terminal commands
- **Concurrency**: Support 100+ concurrent sessions per controller
- **Resource Usage**: <10MB memory per session
- **Session Recording**: Zero data loss guarantee

## Implementation Phases
1. **Core Terminal Module**: Session management, WebSocket handling
2. **gRPC Integration**: Controller-Steward terminal communication
3. **Shell Support**: Multi-platform shell execution (bash, zsh, PowerShell, cmd)
4. **Security Features**: Session recording, access control, encryption
5. **Performance Optimization**: Session multiplexing, resource cleanup

## File Structure
```
features/terminal/
├── README.md                    # This file
├── manager.go                   # Session manager
├── manager_test.go              # Session manager tests
├── websocket.go                 # WebSocket handler
├── websocket_test.go            # WebSocket tests
├── session.go                   # Terminal session
├── session_test.go              # Session tests
├── recorder.go                  # Session recording
├── recorder_test.go             # Recording tests
├── shell/                       # Shell executors
│   ├── executor.go              # Base executor interface
│   ├── unix.go                  # Unix shell support
│   ├── windows.go               # Windows shell support
│   └── executor_test.go         # Executor tests
└── proto/                       # Protocol definitions
    ├── terminal.proto           # Terminal service definitions
    └── terminal.pb.go           # Generated Go code
```

## Dependencies
- `github.com/gorilla/websocket`: WebSocket implementation
- `github.com/creack/pty`: Cross-platform PTY support
- Existing CFGMS components: RBAC, certificates, logging, telemetry