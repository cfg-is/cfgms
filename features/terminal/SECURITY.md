# Terminal Security Controls

This document describes the comprehensive security controls implemented for CFGMS terminal access, addressing Story #83: Remote Access - Add Terminal Security Controls and RBAC.

## Overview

The terminal security system provides granular access controls, command filtering, real-time session monitoring, and tamper-proof audit logging for all terminal sessions. It integrates with the existing mTLS authentication framework and implements multiple layers of security controls.

## Security Architecture

### Multi-Layer Security Model

```
┌─────────────────────────────────────────┐
│           Client Connection             │
├─────────────────────────────────────────┤
│    1. mTLS Certificate Authentication   │
│    2. RBAC Permission Validation        │
│    3. Anti-Hijacking Session Tokens    │
├─────────────────────────────────────────┤
│         Terminal Session Layer         │
├─────────────────────────────────────────┤
│    4. Real-time Command Filtering      │
│    5. Session Activity Monitoring      │
│    6. Tamper-proof Audit Logging       │
├─────────────────────────────────────────┤
│      Shell Execution & Recording       │
└─────────────────────────────────────────┘
```

## Key Components

### 1. RBAC Permission Model (`security.go`)

**Terminal-Specific Permissions:**
- `terminal.session.create` - Create new terminal sessions
- `terminal.session.read` - View session information and status
- `terminal.session.terminate` - Terminate active sessions
- `terminal.session.monitor` - Real-time session monitoring
- `terminal.recording.read` - Access session recordings
- `terminal.admin` - Full terminal administration

**Permission Integration:**
- Permissions are added to existing tenant roles (admin, operator, viewer)
- Granular access control per device/group using resource-based permissions
- Hierarchical permission inheritance through tenant structure

### 2. Command Filtering System (`interceptor.go`)

**Command Interception:**
- Real-time command filtering using regex-based rules
- Three-tier filtering actions: Allow, Block, Audit
- Context-aware filtering based on user permissions and device type

**Default Security Rules:**
```go
// Critical Blocks
"rm -rf" patterns          -> BLOCK (Critical)
Disk formatting commands   -> BLOCK (Critical)
Network scanning tools     -> BLOCK (High)
Privilege escalation      -> BLOCK (High)

// Audit Required
Sudo commands             -> AUDIT (High)
System config changes    -> AUDIT (High)
SSH/Remote access         -> AUDIT (Medium)
```

**Custom Rule Engine:**
- Tenant-specific rule configuration
- Device/group-specific overrides
- Risk-based severity classification
- Performance-optimized compiled regex patterns

### 3. Session Monitoring (`monitor.go`)

**Real-time Monitoring:**
- Activity pattern analysis and anomaly detection
- Threat level assessment (Low, Medium, High, Critical)
- Automatic session termination for critical threats
- Command rate and failure rate monitoring

**Monitoring Metrics:**
- Commands per minute (rate limiting)
- Failed command percentage
- Privileged command usage
- Session duration and idle time
- Data transfer volumes

**Alert System:**
- Real-time security alerts for suspicious activity
- Configurable auto-termination policies
- Integration with external SIEM systems
- Escalation procedures for critical threats

### 4. Audit Logging System (`audit.go`)

**Tamper-Proof Logging:**
- HMAC-based integrity protection
- Cryptographic hash chaining
- Sequential audit entry numbering
- Content-addressable storage

**Comprehensive Audit Events:**
```go
SessionStart/End          -> User access tracking
CommandExecuted          -> Full command history
CommandBlocked           -> Security violations
SecurityViolation        -> Threat detection
PrivilegeEscalation     -> Suspicious activity
```

**Audit Features:**
- Immutable log entries with integrity verification
- Configurable retention policies (default 90 days)
- Compressed storage with optional encryption
- Multi-format export (JSON, CSV, PDF)

### 5. WebSocket Origin Enforcement (`websocket.go`)

**Same-Origin Policy:**
The WebSocket upgrader enforces origin validation on every upgrade request. Connections are accepted only when the `Origin` header host matches `r.Host` (same-origin) or appears in the configured `originAllowlist`. Requests with a missing or unparseable `Origin` header are rejected with HTTP 403.

- Default allowlist: empty (same-origin only)
- Allowlist is a constructor parameter: `NewWebSocketHandler(sessionManager, logger, originAllowlist)`
- The allowlist is sourced from controller configuration; the terminal feature does not read config directly

### 6. mTLS Integration (`auth_integration.go`)

**Certificate-Based Authentication:**
- Client certificate requirement for terminal access
- Certificate validation using existing CA infrastructure
- User identity extraction from certificate attributes
- Certificate-based session binding

**Anti-Hijacking Measures:**
- IP address binding with session tokens
- TLS fingerprint validation
- User agent consistency checking
- Heartbeat-based session validation
- Token rotation with configurable intervals

**Session Token Security:**
```go
type SessionToken struct {
    Token           string      // 32-byte crypto/rand, base64url-encoded (44 chars)
    ClientIP        string      // Bound IP address
    TLSFingerprint  string      // TLS connection fingerprint
    CertificateHash string      // Client certificate hash
    ExpiresAt       time.Time   // Token expiration
    LastRotated     time.Time   // Last rotation time
}
```

Token generation uses `crypto/rand.Read` over 32 bytes (256 bits of entropy), base64-URL-encoded. `time.Now()`, `os.Getpid()`, and formatted strings are not used in the token generation path.

## Security Controls Configuration

### Default Security Policies

```go
// Authentication Configuration
RequireMTLS:           true,
ClientCertRequired:    true,
SessionTimeout:        4 * time.Hour,
MaxConcurrentSessions: 5,

// Anti-Hijacking
IPBindingEnabled:      true,
TLSFingerprintCheck:   true,
TokenRotationInterval: 1 * time.Hour,

// Monitoring
AutoTerminateOnCritical: true,
MaxCommandRate:         100.0, // per minute
MaxFailureRate:         10.0,  // per minute
MaxIdleTime:           30 * time.Minute,
```

### Command Filter Configuration

```go
// High-Risk Command Patterns
BlockedPatterns := []string{
    `rm\s+.*-[^-]*r[^-]*f`,              // rm -rf variations
    `\b(format|mkfs|fdisk|parted)\b`,     // Disk operations
    `\b(nmap|masscan|nc|netcat)\b`,       // Network tools
    `chmod\s+[0-7]*[4-7][0-7][0-7]`,      // Dangerous permissions
}

// Audit-Required Patterns
AuditPatterns := []string{
    `^\s*sudo\b`,                         // Sudo commands
    `\b(vi|vim|nano|emacs|sed)\s+.*passwd`, // System file edits
    `\b(ssh|scp|sftp)\s`,                 // Remote access
}
```

## Security Validation

### Access Control Validation

1. **Certificate Authentication**: Validates client certificate against CA
2. **Permission Check**: Verifies user has required terminal permissions
3. **Resource Authorization**: Checks access to specific steward/device
4. **Time-based Access**: Optional time window restrictions
5. **Geofencing**: Optional country/region restrictions
6. **Concurrent Session Limits**: Prevents session abuse

### Command Security Validation

1. **Pattern Matching**: Real-time regex matching against security rules
2. **Context Analysis**: User permissions and device context consideration
3. **Risk Assessment**: Dynamic threat level calculation
4. **Action Enforcement**: Block, audit, or allow based on rules
5. **Audit Generation**: Tamper-proof logging of all decisions

## Implementation Details

### Performance Optimizations

- **Compiled Regex**: Pre-compiled patterns for fast matching
- **Buffered Channels**: Asynchronous audit logging with batching
- **Connection Pooling**: Efficient database connections for audit storage
- **Caching**: Permission and rule caching to reduce RBAC queries

### Error Handling

- **Graceful Degradation**: Terminal continues functioning even if recording fails
- **Circuit Breakers**: Prevent cascade failures in audit systems
- **Retry Logic**: Automatic retry for transient failures
- **Fallback Mechanisms**: Local logging when central audit unavailable

### Scalability Considerations

- **Horizontal Scaling**: Stateless design allows multiple terminal servers
- **Load Balancing**: Session affinity for consistent security contexts
- **Database Partitioning**: Time-based partitioning for audit logs
- **Resource Limits**: Configurable limits to prevent resource exhaustion

## Testing

Comprehensive test coverage includes:

- **Unit Tests**: Individual component functionality
- **Integration Tests**: Cross-component interactions
- **Security Tests**: Penetration testing scenarios
- **Performance Tests**: Load testing and benchmarks
- **Regression Tests**: Ensuring security controls remain effective

### Test Coverage Areas

```go
// Security Validation Tests
TestSecurityValidator_ValidateSessionAccess()
TestSecurityValidator_ValidateCommand()

// Command Filtering Tests  
TestCommandFilterRules()
TestCommandInterceptor_InputFiltering()

// Session Monitoring Tests
TestSessionMonitor_ThreatLevelCalculation()

// Audit System Tests
TestAuditLogger_IntegrityProtection()

// Performance Tests
BenchmarkCommandValidation()
```

## Compliance and Standards

The terminal security implementation meets various compliance requirements:

- **SOC 2**: Comprehensive audit logging and access controls
- **ISO 27001**: Security management system requirements
- **NIST Cybersecurity Framework**: Detection and response capabilities
- **PCI DSS**: Access control and monitoring requirements
- **GDPR**: Data protection and audit trail requirements

## Monitoring and Alerting

### Security Metrics

- **Authentication Failures**: Failed certificate validations
- **Command Blocks**: Security rule violations
- **Session Anomalies**: Unusual activity patterns
- **Privilege Escalations**: Suspicious permission usage
- **Audit Integrity**: Log tampering attempts

### Alert Integration

- **Real-time Alerts**: Immediate notification of critical threats
- **SIEM Integration**: Export to external security systems
- **Webhook Notifications**: Custom alert handling
- **Email/SMS Alerts**: Multi-channel notification system

## Future Enhancements

1. **Machine Learning**: AI-powered anomaly detection
2. **Behavioral Analysis**: User behavior profiling
3. **Zero Trust**: Enhanced identity verification
4. **Quantum Resistance**: Post-quantum cryptographic protection
5. **Federation**: Cross-tenant session management

---

## Quick Start

### Basic Usage

```go
// Create security validator
rbacManager := rbac.NewManager()
validator := terminal.NewSecurityValidator(rbacManager)

// Validate session access
ctx := context.Background()
securityContext, err := validator.ValidateSessionAccess(ctx, userID, stewardID, tenantID)
if err != nil {
    return fmt.Errorf("access denied: %w", err)
}

// Validate commands
result, err := validator.ValidateCommand(ctx, securityContext, "sudo systemctl restart nginx")
if err != nil {
    return fmt.Errorf("command validation failed: %w", err)
}

if !result.Allowed {
    return fmt.Errorf("command blocked: %s", result.BlockReason)
}
```

### Advanced Configuration

```go
// Custom security configuration
config := &terminal.AuthConfig{
    RequireMTLS:           true,
    SessionTimeout:        2 * time.Hour,
    MaxConcurrentSessions: 3,
    IPBindingEnabled:      true,
    TLSFingerprintCheck:   true,
    TimeBasedAccess:       true,
    AllowedHours:         []int{9, 10, 11, 14, 15, 16, 17},
}

// Create authenticated manager
manager, err := terminal.NewAuthenticatedTerminalManager(
    baseManager, rbacManager, certValidator, config)
```

This comprehensive security system ensures that all terminal access is properly authenticated, authorized, monitored, and audited, providing defense-in-depth protection for critical system access.