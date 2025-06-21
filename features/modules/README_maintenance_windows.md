# Maintenance Windows

This document describes the maintenance windows configuration for CFGMS.

## Overview

Maintenance windows define when system changes (like package updates and reboots) can occur. They can be defined at different levels:

1. **Default**: Applies to all endpoints unless overridden
2. **Tenant**: Specific to a client/tenant
3. **Group**: Specific to a group of endpoints (e.g., database clusters)

## Configuration Structure

### Default Windows

```yaml
maintenance_windows:
  - name: "default"
    schedule:
      time: "0 2 * * *"  # Daily at 2 AM
      duration: "2h"
    allowed_operations:
      - "package_update"
      - "reboot"
```

### Tenant Overrides

```yaml
tenants:
  client_name:
    maintenance:
      windows:
        - name: "client-patches"
          schedule:
            time: "0 2 * * 1,3,5"  # Mon, Wed, Fri
```

### Group-Specific Windows

```yaml
groups:
  group_name:
    maintenance:
      windows:
        - name: "group-patches"
          schedule:
            time: "0 2 * * 1"
          cluster:
            min_nodes: 2
            max_concurrent: 1
```

## Key Features

1. **Default Daily Window**
   - Daily patch and reboot window
   - Configurable time and duration
   - Can be overridden per tenant

2. **Client-Specific Windows**
   - Override default schedule
   - Specify custom days/times
   - Maintain separate configurations

3. **Cluster-Aware Windows**
   - Ensure cluster quorum
   - Control concurrent updates
   - Health check integration

## Usage

1. **Package Updates**
   - Package module checks maintenance windows
   - Only applies updates during allowed windows
   - Respects cluster constraints

2. **System Reboots**
   - Scheduled during maintenance windows
   - Cluster-aware rebooting
   - Health check verification

## Version Information

- **Version**: 1.0
- **Last Updated**: 2024-04-20
- **Status**: Draft 