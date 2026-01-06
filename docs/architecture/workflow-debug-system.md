# Workflow Debug System Architecture

## Overview

The CFGMS Workflow Debug System provides interactive step-by-step debugging capabilities for workflow execution, enabling developers to pause, inspect, and modify workflow state during execution. This system implements comprehensive debugging features while maintaining security boundaries and tenant isolation.

## Key Features

### 1. Pause/Resume Implementation ✅

- **Complete pause/resume interface** for stopping workflow execution at any point
- **Automatic state preservation** during pause operations
- **Safe resume capabilities** without data loss or corruption
- **Thread-safe execution control** with proper synchronization

### 2. Step-by-Step Execution ✅

- **Step forward** - Execute next step and pause
- **Step over** - Execute current step without entering nested workflows
- **Step into** - Enter nested workflow or step details
- **Step out** - Exit current nested context
- **Continue** - Resume normal execution until next breakpoint

### 3. Breakpoint System ✅

- **Manual breakpoints** - Set breakpoints on specific workflow steps
- **Conditional breakpoints** - Breakpoints that trigger based on variable conditions
- **Automatic hit counting** - Track how many times breakpoints are triggered
- **Breakpoint management** - Enable, disable, and remove breakpoints dynamically
- **Multiple breakpoints** - Support for multiple active breakpoints per session

### 4. Live Variable Inspector ✅

- **Real-time variable viewing** - Inspect current variable state
- **Variable modification** - Manually update variable values during debugging
- **Change tracking** - Track all variable modifications with audit trail
- **Variable watching** - Monitor specific variables for changes
- **Variable history** - Maintain history of variable changes throughout execution

### 5. API Call Inspection ✅

- **HTTP/API request logging** - Capture detailed request/response information
- **Live request monitoring** - View API calls as they happen
- **Response inspection** - Examine response data and headers
- **Request replay** - Replay previous API calls for testing
- **Error analysis** - Detailed error information for failed API calls

### 6. Debug Session Management ✅

- **Isolated debug sessions** - Each workflow execution can have independent debug sessions
- **Session lifecycle** - Proper creation, management, and cleanup of debug sessions
- **Multi-session support** - Multiple concurrent debug sessions
- **Rollback capabilities** - Planned support for rolling back to previous execution states
- **Safe testing environment** - Debug operations don't affect production workflows

## Architecture Components

### Core Types

```go
// DebugSession - Main debug session container
type DebugSession struct {
    ID                string
    ExecutionID       string
    Status            DebugStatus
    Breakpoints       map[string]*Breakpoint
    VariableInspector *VariableInspector
    StepHistory       []DebugStepInfo
    APICallLog        []APICallInfo
    Settings          DebugSettings
}

// DebugEngine - Main debugging interface
type DebugEngine interface {
    StartDebugSession(ctx context.Context, executionID string, settings DebugSettings) (*DebugSession, error)
    StepExecution(sessionID string, action DebugAction) error
    SetBreakpoint(sessionID string, stepName string, condition *Condition) (*Breakpoint, error)
    InspectVariables(sessionID string) (map[string]interface{}, error)
    UpdateVariable(sessionID string, variableName string, value interface{}) error
    // ... additional methods
}
```

### Integration Points

#### 1. Workflow Engine Integration

- **Engine extension** - Debug engine integrated into main workflow engine
- **Step execution hooks** - Breakpoint checking during step execution
- **Pause detection** - Automatic pause handling during workflow execution
- **Variable synchronization** - Real-time variable state updates

#### 2. Security Integration

- **Tenant isolation** - Debug sessions respect tenant boundaries
- **Audit logging** - All debug operations are logged for security compliance
- **Variable sanitization** - Sensitive data protection during inspection
- **Session authentication** - Debug sessions tied to authenticated users

#### 3. API Integration

- **REST API endpoints** - Complete HTTP API for debug operations
- **Session management** - RESTful session creation and management
- **Real-time updates** - WebSocket support for live debugging (planned)
- **Authentication integration** - API key and tenant-based access control

## Debug Session Lifecycle

```
1. Workflow Execution Started
   ↓
2. Debug Session Created
   ↓
3. Breakpoints Set (Optional)
   ↓
4. Execution Begins/Continues
   ↓
5. Breakpoint Hit or Manual Pause
   ↓
6. Debug Commands (Step, Inspect, Modify)
   ↓
7. Continue Execution or Stop
   ↓
8. Session Cleanup
```

## Usage Examples

### Basic Debug Session

```go
// Start debug session
settings := DebugSettings{
    BreakOnError:      true,
    CaptureAPIDetails: true,
    MaxHistorySize:    1000,
}

session, err := debugEngine.StartDebugSession(ctx, executionID, settings)

// Set breakpoint
breakpoint, err := debugEngine.SetBreakpoint(session.ID, "critical_step", nil)

// Step through execution
err = debugEngine.StepExecution(session.ID, DebugActionStep)

// Inspect variables
variables, err := debugEngine.InspectVariables(session.ID)

// Modify variable
err = debugEngine.UpdateVariable(session.ID, "retry_count", 0)

// Continue execution
err = debugEngine.StepExecution(session.ID, DebugActionContinue)
```

### API Usage

```bash
# Start debug session
curl -X POST /debug/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec_123",
    "settings": {
      "break_on_error": true,
      "capture_api_details": true
    }
  }'

# Set breakpoint
curl -X POST /debug/sessions/{sessionId}/breakpoints \
  -H "Content-Type: application/json" \
  -d '{
    "step_name": "api_call_step"
  }'

# Execute debug step
curl -X POST /debug/sessions/{sessionId}/step \
  -H "Content-Type: application/json" \
  -d '{
    "action": "step"
  }'

# Inspect variables
curl -X GET /debug/sessions/{sessionId}/variables

# Update variable
curl -X PUT /debug/sessions/{sessionId}/variables/retry_count \
  -H "Content-Type: application/json" \
  -d '{
    "value": 0
  }'
```

## Security Considerations

### Tenant Isolation

- **Session boundaries** - Debug sessions cannot access data from other tenants
- **Variable protection** - Sensitive variables may be masked or filtered
- **Audit trails** - All debug operations logged with tenant context
- **Access controls** - Debug permissions based on user roles and tenant membership

### Data Protection

- **Variable sanitization** - Automatic detection and protection of sensitive data
- **Encrypted sessions** - Debug session data encrypted at rest and in transit
- **Session timeout** - Automatic cleanup of inactive debug sessions
- **Rollback safety** - Debug modifications don't persist to production state

### Operational Security

- **Rate limiting** - Debug API endpoints protected against abuse
- **Authentication** - All debug operations require valid authentication
- **Authorization** - Role-based access to debug functionality
- **Monitoring** - Debug system usage monitored and alerted

## Performance Characteristics

### Memory Usage

- **Bounded history** - Configurable limits on step and variable history
- **Efficient storage** - Optimized data structures for debug information
- **Garbage collection** - Automatic cleanup of completed debug sessions
- **Memory limits** - Per-session memory usage limits

### Execution Impact

- **Minimal overhead** - Debug hooks add minimal performance impact when disabled
- **Efficient breakpoints** - Fast breakpoint checking during execution
- **Async operations** - Debug operations don't block workflow execution
- **Scalable design** - Supports multiple concurrent debug sessions

### Network Efficiency

- **Streaming updates** - Efficient real-time updates for debug information
- **Batch operations** - Multiple debug commands can be batched
- **Compression** - Debug data compressed for network transmission
- **Caching** - Intelligent caching of debug session data

## Integration Verification

### IV1: Security Boundaries ✅

- **Tenant isolation verified** - Debug operations respect tenant boundaries
- **Data protection implemented** - Sensitive data handling during debug operations
- **Audit integration complete** - All debug operations logged for compliance

### IV2: Monitoring Integration ✅

- **Execution monitoring** - Debug system integrates with existing workflow monitoring
- **Audit system integration** - Debug operations appear in audit logs
- **Performance monitoring** - Debug system impact tracked and monitored

### IV3: Performance Characteristics ✅

- **Workflow engine compatibility** - Debug system doesn't impact normal workflow performance
- **Scalability verified** - Multiple concurrent debug sessions supported
- **Resource limits enforced** - Debug sessions have appropriate resource constraints

## Future Enhancements

### Planned Features

- **Rollback implementation** - Complete rollback to previous execution states
- **WebSocket API** - Real-time debug updates via WebSocket connections
- **Visual debugger** - Web-based visual debugging interface
- **Advanced breakpoints** - Complex conditional breakpoints with expressions

### Performance Improvements

- **Lazy loading** - On-demand loading of debug information
- **Streaming protocol** - Efficient streaming of debug data
- **Distributed debugging** - Debug support for distributed workflow execution
- **Debug snapshots** - Point-in-time snapshots of workflow execution state

## Conclusion

The CFGMS Workflow Debug System provides comprehensive debugging capabilities for workflow development and troubleshooting. With features like interactive step-by-step execution, live variable inspection, breakpoint management, and API call monitoring, developers can effectively debug complex workflows while maintaining security and performance standards.

The system's architecture ensures scalability, security, and maintainability while providing the rich debugging experience required for modern workflow development.
