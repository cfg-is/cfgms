# Controller Component

The Controller is the central management server of the CFGMS system, responsible for orchestrating the entire configuration management infrastructure.

## Overview

The Controller serves as the brain of the CFGMS system, managing all Stewards and Outposts, executing workflows, and monitoring the state of the infrastructure. It is designed for high availability, scalability, and resilience.

## Primary Responsibilities

### Configuration Management

- Distributes configuration data to Stewards and Outposts
- Processes and validates configuration changes
- Manages the tenant hierarchy
- Implements configuration inheritance and resolution
- Provides version control for configuration data

### Steward and Outpost Management

- Manages the lifecycle of all Stewards and Outposts
- Handles Steward registration and authentication
- Distributes updates and new modules to Stewards
- Monitors Steward health and performance
- Implements self-managed blue-green upgrades for Stewards

### Workflow Execution

- Executes workflows across multiple Stewards
- Manages workflow dependencies and ordering
- Handles workflow failures and retries
- Provides workflow status and reporting
- Supports both scheduled and event-driven workflows

### Security and Access Control

- Implements the REST API for external access
- Handles authentication and authorization
- Manages API keys and certificates
- Enforces role-based access control
- Provides audit logging for all operations

### DNA Management

- Processes DNA (system-specific metadata) information
- Maintains the DNA database
- Provides DNA-based targeting for operations
- Supports DNA-based filtering and querying
- Enables DNA-driven automation

## Technical Implementation

### Communication

- Command communications with Stewards occur over gRPC with mTLS
- Protocol Buffers used for efficient data serialization
- REST API for external access with API key authentication
- WebSocket support for real-time updates and notifications

### Scalability

- Designed to handle 10,000+ Stewards per controller instance
- Supports geo-distributed deployment
- Implements hierarchical Controller management for scaling
- Provides load balancing and failover capabilities

### Storage

- Pluggable configuration storage (Git by default)
- Database options for large-scale deployments
- Efficient caching for frequently accessed data
- Supports offline operation with local configuration

### Resilience

- Self-healing architecture with automatic recovery
- Implements health checks for all critical components
- Provides detailed metrics and telemetry
- Supports graceful degradation during partial failures

## Workflow Engine

The Workflow Engine is a powerful system integration platform that acts as the glue between various systems, enabling complex automation and data sync across different platforms and services.

### Core Concepts

1. **Workflows**: Defined sequences of operations that automate tasks across multiple systems
2. **Nodes**: Individual steps within a workflow that perform specific actions
3. **Connectors**: Standardized integrations that provide consistent interfaces to external systems and APIs
4. **Triggers**: Events that initiate workflow execution (webhooks, schedules, manual, or Module monitor)
5. **Data Flow**: How data moves between nodes in a workflow
6. **Error Handling**: How workflows handle failures and retries
7. **Conditional Logic**: Decision points that determine workflow branching

### Workflow Definition Format

Workflows are defined in YAML files with a `.wrkf` extension. The format is designed to be both human-readable and machine-processable, with consideration for future visual workflow building tools.

```yaml
# Workflow metadata
meta:
  name: "New Employee Onboarding"
  description: "Automates the onboarding process for new employees"
  version: "1.0"
  author: "IT Operations"
  created: "2024-04-11"
  modified: "2024-04-11"

# Workflow variables
vars:
  userName: ""
  userEmail: ""
  userDepartment: ""
  deviceType: "laptop"
  deviceName: ""

# Workflow nodes
nodes:
  start:
    trigger: schedule
    next: "validate_input"

  validate_input:
    switch:
      condition: "{{ .Vars.userName != '' && .Vars.userEmail != '' }}"
      true: "create_user"
      false: "log_error"

  create_user:
    connector: "entra-id"
    action: "createUser"
    params:
      displayName: "{{ .Vars.userName }}"
      email: "{{ .Vars.userEmail }}"
      department: "{{ .Vars.userDepartment }}"
    next: "assign_license"

  assign_license:
    connector: "entra-id"
    action: "assignLicense"
    params:
      userEmail: "{{ .Vars.userEmail }}"
      licenseType: "E3"
    next: "add_to_groups"

  add_to_groups:
    connector: "entra-id"
    action: "addToGroups"
    params:
      userEmail: "{{ .Vars.userEmail }}"
      groups:
        - "All Employees"
        - "{{ .Vars.userDepartment }}"
    next: "assign_device"

  assign_device:
    connector: "intune"
    action: "assignDevice"
    params:
      userEmail: "{{ .Vars.userEmail }}"
      deviceType: "{{ .Vars.deviceType }}"
    next: "rename_device"

  rename_device:
    connector: "intune"
    action: "renameDevice"
    params:
      userEmail: "{{ .Vars.userEmail }}"
      deviceName: "{{ .Vars.userName }}-{{ .Vars.deviceType }}"
    next: "update_dna"

  update_dna:
    connector: "dna"
    action: "updateUserDNA"
    params:
      userEmail: "{{ .Vars.userEmail }}"
      groups:
        - "All Employees"
        - "{{ .Vars.userDepartment }}"
    next: "update_config"

  update_config:
    connector: "config"
    action: "updateUserConfig"
    params:
      userEmail: "{{ .Vars.userEmail }}"
      groups:
        - "All Employees"
        - "{{ .Vars.userDepartment }}"
    next: "end"

  log_error:
    connector: "logging"
    action: "logError"
    params:
      message: "Invalid input parameters for new employee onboarding"
    next: "end"

  end:
    end: true
```

### Node Types

The workflow system supports the following node types:

1. **Trigger Nodes**
   - Initiates workflow execution
   - Examples: `trigger: schedule`, `trigger: webhook`, `trigger: manual`, `trigger: monitor`

2. **Switch Nodes**
   - Implements conditional logic with branching
   - Can be used as an if/else statement with boolean conditions
   - Can also function as a traditional switch statement with multiple cases
   - All match values directly specify the next node to execute
   - Example (if/else): `switch: { condition: ""{{ .Vars.userName != '' }}", true: "next_node_if_true", false: "next_node_if_false" }`
   - Example (switch): `switch: { condition: "{{ .Vars.userRole }}", "admin": "admin_flow", "user": "user_flow", "guest": "guest_flow", default: "standard_flow" }`

3. **Connector Nodes**
   - Connect to external systems and services
   - Execute actions via standardized interfaces
   - Examples: `connector: "entra-id"`, `connector: "intune"`

4. **Transform Nodes**
   - Transform data between nodes
   - Format data for specific connectors
   - Examples: `transform: "json-to-yaml"`, `transform: "csv-to-json"`

5. **Error Nodes**
   - Handle errors and exceptions
   - Examples: `error: "retry"`, `error: "notify"`

6. **End Nodes**
   - Mark the end of workflow execution
   - Example: `end: true`

### Connector System

Connectors provide standardized interfaces to external systems and services:

1. **Authentication Connectors**
   - OAuth Connector
   - API Key Connector
   - Certificate Connector

2. **Service Connectors**
   - Directory Service Connector (AD, Entra ID)
   - Ticketing System Connector
   - Asset Management Connector
   - Steward Command Connector
   - Script Execution Connector

3. **Data Connectors**
   - Database Connector
   - File System Connector
   - DNA Connector
   - Configuration Connector

### Workflow Execution Flow

1. **Workflow Trigger**:
   - Workflow is triggered by an event (webhook, schedule, manual, or Module monitor)
   - Controller identifies the workflow to execute
   - Controller initializes the workflow execution environment
   - Controller begins executing workflow nodes

2. **Node Execution**:
   - Controller selects the appropriate node type
   - For connector nodes, the appropriate connector is selected
   - Connector executes the requested action
   - Results are passed to the next node

3. **Workflow Completion**:
   - Controller executes all workflow nodes
   - Controller handles any errors or retries
   - Controller reports workflow completion status
   - Controller stores workflow execution history

### Future Web Interface

While not included in v1, the workflow system is designed with a future web interface in mind:

1. **Visual Workflow Builder**
   - Drag-and-drop interface for building workflows
   - Automatic node arrangement in horizontal or vertical graphs
   - Visual representation of workflow nodes and connections
   - Real-time validation of workflow definitions

2. **Node Configuration**
   - Visual configuration of node parameters
   - Connector selection and configuration
   - Parameter mapping and data transformation

3. **Workflow Testing**
   - Test workflow execution with sample data
   - Debug workflow execution
   - View execution logs and results

4. **Workflow Management**
   - Enable/disable workflows
   - Schedule workflow execution
   - Monitor workflow execution status
   - View workflow execution history

### Security Considerations

1. **Authentication and Authorization**
   - Workflows inherit Controller's authentication and authorization
   - Role-based access control for workflow execution
   - Connector-specific authentication

2. **Data Protection**
   - Sensitive data is encrypted at rest
   - Secrets are managed securely
   - Audit logging for all workflow operations

3. **Error Handling**
   - Graceful error handling
   - Automatic retry for transient failures
   - Notification of workflow failures

## Deployment Options

### Single Controller

- Suitable for small to medium deployments
- Simple setup with minimal configuration
- Good for proof-of-concept and testing

### High Availability Controller

- Multiple Controller instances for redundancy
- Load balancing across Controller instances
- Automatic failover in case of Controller failure
- Suitable for production environments

### Distributed Controller

- Geo-distributed Controller deployment
- Hierarchical Controller management
- Regional Controller instances for reduced latency
- Suitable for global deployments

## Configuration

The Controller can be configured through:

1. **Command-line arguments**: For basic configuration
2. **Configuration file**: For detailed configuration
3. **Environment variables**: For containerized deployments
4. **API**: For dynamic configuration changes

## Monitoring and Observability

The Controller provides comprehensive monitoring and observability:

1. **Health checks**: For all critical components
2. **Metrics**: For performance and resource usage
3. **Logs**: Structured logging for all operations
4. **Traces**: For debugging and performance analysis
5. **Alerts**: For critical issues and failures

## Version Information

- **Document Version:** 1.0
- **Last Updated:** 2024-04-11
- **Status:** Draft
