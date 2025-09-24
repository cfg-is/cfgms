# Advanced Reporting Framework Integration Guide

## Overview

The Advanced Reporting Framework (Story #173) extends CFGMS reporting capabilities by integrating audit data with existing DNA monitoring reports. This provides comprehensive multi-tenant reporting with compliance, security, and executive analytics.

## Architecture

### Components

1. **AdvancedService** (`advanced.go`)
   - Main service orchestrating advanced reporting capabilities
   - Extends existing Service for backward compatibility
   - Integrates DNA monitoring with audit data

2. **AdvancedDataProvider** (`provider/advanced.go`)
   - Provides unified data access across DNA and audit systems
   - Implements comprehensive querying with multi-tenant support
   - Handles data correlation and cross-system metrics

3. **AdvancedReportEngine** (`engine/advanced.go`)
   - Generates advanced reports with RBAC validation
   - Supports compliance frameworks (CIS, HIPAA, PCI-DSS)
   - Implements security analysis and anomaly detection

4. **Advanced Interfaces** (`interfaces/advanced.go`)
   - Extended type definitions for audit integration
   - Compliance, security, and cross-system metric types
   - Multi-tenant aggregation structures

## Integration Points

### Existing Systems
- **DNA Monitoring** (Story #81): Extends existing device monitoring reports
- **Audit System**: Integrates pkg/audit for comprehensive event tracking
- **RBAC**: Multi-tenant access control and validation
- **Storage**: Uses pluggable storage architecture consistently

### Data Sources
- DNA records from device monitoring
- Audit events from all CFGMS components
- Cross-system correlation metrics
- Compliance baseline data

## Key Features

### 1. Compliance Reporting
- Multi-framework support (CIS, HIPAA, PCI-DSS)
- Baseline comparison and violation tracking
- Trend analysis and scoring
- Exception handling and remediation tracking

### 2. Security Analysis
- Anomaly detection in audit data
- Risk assessment and scoring
- Security event correlation
- Threat level evaluation

### 3. Executive Dashboards
- High-level KPIs and metrics
- Cross-tenant comparisons
- Trend visualization
- Risk summaries and recommendations

### 4. Multi-Tenant Support
- Hierarchical tenant aggregation
- RBAC-validated data access
- Comparative analysis across tenants
- Scalable to 50+ tenants per report

## Usage Examples

### Basic Service Creation
```go
// Create advanced service
advancedService := reports.NewAdvancedService(
    storageManager, driftDetector, auditManager, auditStore,
    rbacManager, cache, logger,
)
```

### Compliance Report Generation
```go
complianceReq := interfaces.ComplianceReportRequest{
    TimeRange:  interfaces.TimeRange{Start: start, End: end},
    TenantIDs:  []string{"tenant1", "tenant2"},
    Frameworks: []string{"CIS", "HIPAA"},
    Format:     interfaces.FormatHTML,
}

report, err := advancedService.GenerateComplianceReport(ctx, complianceReq)
```

### Security Analysis
```go
securityReq := interfaces.SecurityReportRequest{
    TimeRange:    interfaces.TimeRange{Start: start, End: end},
    TenantIDs:    []string{"tenant1"},
    AnalysisType: "comprehensive",
}

securityReport, err := advancedService.GenerateSecurityReport(ctx, securityReq)
```

### Executive Dashboard
```go
execReq := interfaces.ExecutiveReportRequest{
    TimeRange:     interfaces.TimeRange{Start: start, End: end},
    TenantIDs:     []string{"tenant1", "tenant2"},
    KPIs:          []string{"compliance", "security", "availability"},
    IncludeCharts: true,
    IncludeTrends: true,
}

dashboard, err := advancedService.GenerateExecutiveReport(ctx, execReq)
```

## Configuration

### Service Configuration
```go
config := AdvancedServiceConfig{
    EnableAuditIntegration:    true,
    EnableRBACValidation:      true,
    EnableCrossSystemMetrics:  true,
    MaxTenantsPerReport:       50,
    ComplianceFrameworks:      []string{"CIS", "HIPAA", "PCI-DSS"},
    SecurityEventRetention:    90 * 24 * time.Hour,
}

service := NewAdvancedServiceWithConfig(
    storageManager, driftDetector, auditManager, auditStore,
    rbacManager, cache, config, logger,
)
```

### Caching Configuration
```go
cacheConfig := AdvancedCacheConfig{
    EnableAdvancedCaching: true,
    ComplianceReportTTL:   4 * time.Hour,
    SecurityReportTTL:     30 * time.Minute,
    ExecutiveReportTTL:    1 * time.Hour,
    MaxCacheSize:          1000,
}
```

## Performance Considerations

### Caching Strategy
- Compliance reports: 4-hour TTL (relatively stable data)
- Security reports: 30-minute TTL (dynamic threat landscape)
- Executive reports: 1-hour TTL (balanced freshness/performance)
- Multi-tenant reports: 2-hour TTL (complex aggregations)

### Query Optimization
- Data provider implements efficient cross-system joins
- RBAC pre-filtering reduces data processing overhead
- Pagination support for large result sets
- Parallel processing for multi-tenant aggregations

### Resource Management
- Configurable tenant limits per report
- Memory-efficient streaming for large datasets
- Background processing for complex analytics
- Graceful degradation under high load

## Security

### RBAC Integration
- All report requests validated against user permissions
- Tenant-scoped data access enforcement
- Resource-level permission checking
- Audit trail for all report access

### Data Protection
- Sensitive data filtering in reports
- Encryption in transit and at rest
- Compliance with data retention policies
- Privacy-preserving aggregations

## Error Handling

### Validation
- Request parameter validation
- Template existence verification
- RBAC permission checks
- Data source availability

### Graceful Degradation
- Partial data reporting when sources unavailable
- Fallback to cached data when appropriate
- Clear error messaging for failures
- Retry logic for transient failures

## Testing

### Test Structure
- Comprehensive mock implementations for all dependencies
- End-to-end integration test scenarios
- Performance benchmarks for large datasets
- Security validation test cases

### Current Status
Tests compile and run successfully. Full integration tests require:
- Real RBAC manager setup with tenant configuration
- Audit store with sample data
- Drift detector with mock DNA data
- Multi-tenant test scenarios

## Migration Path

### From Existing DNA Reports
1. No breaking changes to existing DNA monitoring reports
2. Advanced features accessible through new service methods
3. Backward compatibility maintained for all existing APIs
4. Gradual migration to enhanced capabilities

### Deployment Strategy
1. Deploy advanced service alongside existing reporting
2. Configure audit integration and RBAC validation
3. Enable advanced templates and compliance frameworks
4. Migrate high-value use cases first

## Monitoring and Observability

### Metrics
- Report generation performance
- Cache hit rates and effectiveness
- Cross-system data correlation success
- RBAC validation latency

### Health Checks
- Data source connectivity
- Template availability
- Cache system health
- RBAC service status

### Alerting
- Report generation failures
- Performance degradation
- Security anomalies in report access
- Compliance threshold breaches

## Future Enhancements

### Planned Features
- Machine learning-based anomaly detection
- Predictive compliance scoring
- Automated remediation recommendations
- Real-time streaming reports

### Extension Points
- Custom compliance framework support
- Additional export formats
- Third-party integration APIs
- Advanced visualization components

## Support

### Documentation
- API reference in features/reports/interfaces/
- Template documentation in features/reports/templates/
- Configuration examples in this guide

### Troubleshooting
- Check service health endpoints
- Verify RBAC permissions
- Validate audit data availability
- Review cache configuration

---

This integration guide provides comprehensive coverage of the Advanced Reporting Framework implementation for Story #173, enabling teams to effectively deploy and utilize the enhanced reporting capabilities.