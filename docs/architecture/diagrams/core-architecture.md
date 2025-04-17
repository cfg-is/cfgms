# Core Architecture Diagram

## System Overview

```mermaid
graph TD
    C[Controller] --> O1[Outpost 1]
    C --> O2[Outpost 2]
    C --> O3[Outpost 3]
    O1 --> S1[Steward 1]
    O2 --> S2[Steward 2]
    O3 --> S3[Steward 3]
    
    style C fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style O1 fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style O2 fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style O3 fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style S1 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style S2 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style S3 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
```

## External Access Layer

```mermaid
graph TD
    C[Controller] --> O1[Outpost 1]
    C --> O2[Outpost 2]
    C --> O3[Outpost 3]
    O1 --> S1[Steward 1]
    O2 --> S2[Steward 2]
    O3 --> S3[Steward 3]
    
    C <--> EA[External API]
    C <--> SS[SaaS Steward v2]
    C <--> CS[Cloud Steward v2]
    
    style C fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style O1 fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style O2 fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style O3 fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style S1 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style S2 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style S3 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style EA fill:#bfb,stroke:#333,stroke-width:2px,color:#000
    style SS fill:#fbf,stroke:#333,stroke-width:2px,color:#000
    style CS fill:#fbf,stroke:#333,stroke-width:2px,color:#000
```

## Hierarchical Controller Architecture

```mermaid
graph TD
    PC[Parent Controller] --> CC1[Child Controller 1]
    PC --> CC2[Child Controller 2]
    PC --> CC3[Child Controller 3]
    
    CC1 --> O1[Outpost 1]
    CC2 --> O2[Outpost 2]
    CC3 --> O3[Outpost 3]
    
    O1 --> S1[Steward 1]
    O2 --> S2[Steward 2]
    O3 --> S3[Steward 3]
    
    style PC fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style CC1 fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style CC2 fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style CC3 fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style O1 fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style O2 fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style O3 fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style S1 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style S2 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style S3 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
```

## Component Relationships

### Controller

- Central management component
- Manages Outposts and Stewards
- Handles configuration distribution
- Controls workflow execution
- Manages multi-tenancy
- Provides external API access
- Supports hierarchical deployment

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

### Specialized Stewards (v2)

- SaaS Steward: Manages SaaS environments
- Cloud Steward: Manages cloud infrastructure
- Deployable as Controller plugins or standalone services

## Communication Flow

```mermaid
graph LR
    C[Controller] <--> O[Outpost]
    O <--> S[Steward]
    S <--> E[Endpoint]
    C <--> EA[External API]
    C <--> SS[SaaS Steward]
    C <--> CS[Cloud Steward]
    
    style C fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style O fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style S fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style E fill:#bfb,stroke:#333,stroke-width:2px,color:#000
    style EA fill:#bfb,stroke:#333,stroke-width:2px,color:#000
    style SS fill:#fbf,stroke:#333,stroke-width:2px,color:#000
    style CS fill:#fbf,stroke:#333,stroke-width:2px,color:#000
    
    subgraph Communication Protocols
        C <-->|gRPC + mTLS| O
        O <-->|gRPC + mTLS| S
        S <-->|Local| E
        C <-->|HTTPS + API Key| EA
        C <-->|Internal API| SS
        C <-->|Internal API| CS
    end
```

## Security Boundaries

```mermaid
graph TD
    subgraph Controller
        C[Controller Component]
        MA[mTLS Auth]
        KA[API Key Auth]
    end
    
    subgraph Outpost
        O[Outpost Component]
        OA[mTLS Auth]
    end
    
    subgraph Steward
        S[Steward Component]
        LA[Local Auth]
    end
    
    C --> MA
    C --> KA
    O --> OA
    S --> LA
    
    style C fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style O fill:#fbb,stroke:#333,stroke-width:2px,color:#000
    style S fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style MA fill:#bfb,stroke:#333,stroke-width:2px,color:#000
    style KA fill:#bfb,stroke:#333,stroke-width:2px,color:#000
    style OA fill:#bfb,stroke:#333,stroke-width:2px,color:#000
    style LA fill:#bfb,stroke:#333,stroke-width:2px,color:#000
```

## Version Information

- Version: 1.3
- Last Updated: 2024-04-17
- Status: Draft
