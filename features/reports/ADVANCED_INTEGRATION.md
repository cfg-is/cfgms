# Advanced Reporting Framework Integration Guide

## Overview

The Advanced Reporting Framework extends CFGMS reporting capabilities by integrating
audit data with existing DNA monitoring reports. This provides comprehensive
multi-tenant reporting with compliance, security, and executive analytics.

`AdvancedDataProvider` and `AdvancedReportEngine` are fully implemented and tested, but
are not yet constructed by any server wiring or reachable through `features/reports/api`
— see Issue #4333, which reaches the report-generation capability this framework doesn't
yet expose (scheduled reports, custom report building, custom template management)
through the live `features/reports/api` → `engine` → `interfaces` path.

## Architecture

### Components

1. **AdvancedDataProvider** (`provider/advanced.go`)
   - Provides unified data access across DNA and audit systems
   - Implements comprehensive querying with multi-tenant support
   - Handles data correlation and cross-system metrics

2. **AdvancedReportEngine** (`engine/advanced.go`)
   - Generates advanced reports with RBAC validation
   - Supports compliance frameworks (CIS, HIPAA, PCI-DSS)
   - Implements security analysis and anomaly detection

3. **Advanced Interfaces** (`interfaces/advanced.go`)
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

These construct `engine.AdvancedEngine`/`provider.AdvancedProvider` directly — the
package that constructed and exposed them as a service (`reports.AdvancedService`) was
deleted as an orphan (Issue #4332); nothing wires these into `features/reports/api` yet
(Issue #4333).

### Basic Construction
```go
advancedProvider := provider.NewAdvancedProvider(egProvider, auditManager, auditStore, logger)
advancedEngine := engine.NewAdvancedEngine(
    advancedProvider, templateProcessor, exporter, cache, rbacManager, logger,
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

report, err := advancedEngine.GenerateComplianceReport(ctx, complianceReq)
```

### Security Analysis
```go
securityReq := interfaces.SecurityReportRequest{
    TimeRange:    interfaces.TimeRange{Start: start, End: end},
    TenantIDs:    []string{"tenant1"},
    AnalysisType: "comprehensive",
}

securityReport, err := advancedEngine.GenerateSecurityReport(ctx, securityReq)
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

dashboard, err := advancedEngine.GenerateExecutiveReport(ctx, execReq)
```

## Configuration

### Engine Configuration
```go
config := engine.AdvancedConfig{
    Config:                   engine.DefaultConfig(),
    EnableAuditIntegration:   true,
    EnableRBACValidation:     true,
    EnableCrossSystemMetrics: true,
    MaxTenantsPerReport:      50,
    ComplianceFrameworks:     []string{"CIS", "HIPAA", "PCI-DSS"},
    SecurityEventRetention:   90 * 24 * time.Hour,
}

advancedEngine = advancedEngine.WithAdvancedConfig(config)
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