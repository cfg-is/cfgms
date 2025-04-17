# Security Architecture

## Authentication Flow

```mermaid
sequenceDiagram
    participant S as Steward
    participant C as Controller
    participant CA as Certificate Authority
    
    S->>CA: [1] Request Certificate
    CA-->>S: [2] Issue Certificate
    S->>C: [3] Register with Certificate
    C->>CA: [4] Verify Certificate
    CA-->>C: [5] Certificate Valid
    C-->>S: [6] Registration Accepted
    
    Note over S,C: All subsequent communication uses mTLS
```

## RBAC Implementation

```mermaid
classDiagram
    class User {
        +ID string
        +Name string
        +Email string
        +TenantID string
        +Roles []Role
    }
    
    class Role {
        +ID string
        +Name string
        +Permissions []Permission
        +TenantID string
    }
    
    class Permission {
        +Resource string
        +Action string
        +Effect string
    }
    
    class Tenant {
        +ID string
        +Name string
        +ParentID string
    }
    
    User --> Role : has
    Role --> Permission : contains
    User --> Tenant : belongs to
    Role --> Tenant : scoped to
```

## API Authentication Flow

```mermaid
sequenceDiagram
    participant Client
    participant API as API Gateway
    participant Auth as Auth Service
    participant C as Controller
    
    Client->>API: [1] API Request with API Key
    API->>Auth: [2] Validate API Key
    Auth-->>API: [3] API Key Valid
    API->>C: [4] Forward Request
    C-->>API: [5] Response
    API-->>Client: [6] Response
```

## Certificate Management

```mermaid
sequenceDiagram
    participant S as Steward
    participant C as Controller
    participant CA as Certificate Authority
    
    S->>CA: [1] Request Initial Certificate
    CA-->>S: [2] Issue Certificate
    S->>C: [3] Register with Certificate
    C->>CA: [4] Verify Certificate
    CA-->>C: [5] Certificate Valid
    C-->>S: [6] Registration Accepted
    
    Note over S,C: Certificate Rotation
    S->>CA: [7] Request New Certificate
    CA-->>S: [8] Issue New Certificate
    S->>C: [9] Update Registration
    C->>CA: [10] Verify New Certificate
    CA-->>C: [11] Certificate Valid
    C-->>S: [12] Registration Updated
```

## Multi-Tenant Security Isolation

```mermaid
graph TD
    subgraph "Tenant A"
        A1[User A1]
        A2[User A2]
        A3[Role A1]
        A4[Role A2]
        A5[Permission A1]
        A6[Permission A2]
    end
    
    subgraph "Tenant B"
        B1[User B1]
        B2[User B2]
        B3[Role B1]
        B4[Role B2]
        B5[Permission B1]
        B6[Permission B2]
    end
    
    A1 --> A3
    A2 --> A4
    A3 --> A5
    A4 --> A6
    
    B1 --> B3
    B2 --> B4
    B3 --> B5
    B4 --> B6
    
    style A1 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style A2 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style A3 fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style A4 fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style A5 fill:#bfb,stroke:#333,stroke-width:2px,color:#000
    style A6 fill:#bfb,stroke:#333,stroke-width:2px,color:#000
    
    style B1 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style B2 fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style B3 fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style B4 fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style B5 fill:#bfb,stroke:#333,stroke-width:2px,color:#000
    style B6 fill:#bfb,stroke:#333,stroke-width:2px,color:#000
```

## Version Information

- Version: 1.0
- Last Updated: 2024-04-17
- Status: Draft
