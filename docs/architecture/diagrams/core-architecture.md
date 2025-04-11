# Core Architecture Diagram

## System Overview

```txt
                                +------------------+
                                |                  |
                                |    Controller    |
                                |                  |
                                +--------+---------+
                                            |
                                            |
                +------------------------+------------------------+
                |                        |                        |
                |                        |                        |
        +-------v-------+        +-------v-------+        +-------v-------+
        |               |        |               |        |               |
        |    Outpost    |        |    Outpost    |        |    Outpost    |
        |               |        |               |        |               |
        +-------+-------+        +-------+-------+        +-------+-------+
                |                        |                        |
                |                        |                        |
        +-------v-------+        +-------v-------+        +-------v-------+
        |               |        |               |        |               |
        |   Steward     |        |   Steward     |        |   Steward     |
        |               |        |               |        |               |
        +---------------+        +---------------+        +---------------+
```

## Component Relationships

### Controller

- Central management component
- Manages Outposts and Stewards
- Handles configuration distribution
- Controls workflow execution
- Manages multi-tenancy

### Outpost

- Intermediate management layer
- Caches configurations and binaries
- Proxies commands to Stewards
- Handles agentless endpoints
- Manages network segments

### Steward

- Endpoint management component
- Executes configuration changes
- Runs workflows
- Reports state changes
- Maintains persistent connection to Controller/Outpost

## Communication Flow

```txt
Controller <-> Outpost: gRPC with mTLS
Outpost <-> Steward:   gRPC with mTLS
Steward <-> Endpoint:  Local execution
```

## Security Boundaries

```txt
+------------------+  +------------------+  +------------------+
|                  |  |                  |  |                  |
|    Controller    |  |     Outpost      |  |     Steward      |
|                  |  |                  |  |                  |
+------------------+  +------------------+  +------------------+
        ^                       ^                       ^
        |                       |                       |
        v                       v                       v
+------------------+  +------------------+  +------------------+
|                  |  |                  |  |                  |
|   mTLS Auth      |  |   mTLS Auth      |  |   Local Auth     |
|                  |  |                  |  |                  |
+------------------+  +------------------+  +------------------+
```

## Version Information

- Version: 1.0
- Last Updated: 2024-04-11
- Status: Draft
