// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package reports

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/reports/cache"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	storageInterfaces "github.com/cfgis/cfgms/pkg/storage/interfaces"
	// Import storage providers to register them
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// TestAdvancedServiceCreation tests the creation of AdvancedService
func TestAdvancedServiceCreation(t *testing.T) {
	service := createTestAdvancedService(t)

	assert.NotNil(t, service)
	assert.NotNil(t, service.Service)
	assert.NotNil(t, service.advancedEngine)
	assert.NotNil(t, service.advancedProvider)
	assert.NotNil(t, service.rbacManager)
	assert.NotNil(t, service.auditManager)

	// Test configuration
	config := service.GetConfiguration()
	assert.True(t, config.EnableAuditIntegration)
	assert.False(t, config.EnableRBACValidation) // Disabled for integration testing
	assert.True(t, config.EnableCrossSystemMetrics)
	assert.Equal(t, 50, config.MaxTenantsPerReport)
	assert.Contains(t, config.ComplianceFrameworks, "CIS")
	assert.Contains(t, config.ComplianceFrameworks, "HIPAA")
}

// TestAdvancedServiceWithConfig tests service creation with custom configuration
func TestAdvancedServiceWithConfig(t *testing.T) {
	logger := &testLogger{}

	// Create DNA storage manager
	dnaStorageConfig := &storage.Config{
		Backend:                storage.BackendSQLite,
		DataDir:                t.TempDir(),
		CompressionLevel:       6,
		CompressionType:        "gzip",
		TargetCompressionRatio: 0.7, // More relaxed target for testing
		EnableDeduplication:    true,
		BlockSize:              64 * 1024,
		HashAlgorithm:          "sha256",
		RetentionPeriod:        24 * time.Hour,
		ArchivalPeriod:         1 * time.Hour,
		MaxRecordsPerDevice:    100,
		EnableSharding:         false, // Disable sharding for simplicity
		ShardCount:             1,
		ShardingStrategy:       "device_id",
		BatchSize:              10,
		FlushInterval:          1 * time.Minute,
		CacheSize:              100,
		MaxStoragePerMonth:     10 * 1024 * 1024, // 10MB
	}
	dnaStorageManager, err := storage.NewManager(dnaStorageConfig, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dnaStorageManager.Close() })

	// Create real components
	driftDetector, err := drift.NewDetector(drift.DefaultDetectorConfig(), logger)
	require.NoError(t, err)

	// Create audit components using git storage for testing
	tmpDir := t.TempDir()
	globalStorageManager, err := storageInterfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)

	auditStore := globalStorageManager.GetAuditStore()
	auditManager := audit.NewManager(auditStore, "test-reports")

	rbacManager := rbac.NewManagerWithStorage(
		auditStore,
		globalStorageManager.GetClientTenantStore(),
		globalStorageManager.GetRBACStore(),
	)
	require.NotNil(t, rbacManager)

	reportCache := cache.NewMemoryCache()

	// Create custom configuration
	serviceConfig := AdvancedServiceConfig{
		ServiceConfig:            DefaultServiceConfig(),
		EnableAuditIntegration:   false,
		EnableRBACValidation:     false,
		EnableCrossSystemMetrics: true,
		MaxTenantsPerReport:      25,
		ComplianceFrameworks:     []string{"CIS"},
		SecurityEventRetention:   30 * 24 * time.Hour,
		AdvancedCacheConfig: interfaces.AdvancedCacheConfig{
			EnableAdvancedCaching: true,
			ComplianceReportTTL:   2 * time.Hour,
			SecurityReportTTL:     15 * time.Minute,
			MaxCacheSize:          500,
		},
	}

	// Test service creation with config
	service := NewAdvancedServiceWithConfig(
		dnaStorageManager, driftDetector, auditManager, auditStore,
		rbacManager, reportCache, serviceConfig, logger,
	)

	assert.NotNil(t, service)

	// Verify configuration was applied
	updatedConfig := service.GetConfiguration()
	assert.False(t, updatedConfig.EnableAuditIntegration)
	assert.False(t, updatedConfig.EnableRBACValidation)
	assert.True(t, updatedConfig.EnableCrossSystemMetrics)
	assert.Equal(t, 25, updatedConfig.MaxTenantsPerReport)
	assert.Equal(t, []string{"CIS"}, updatedConfig.ComplianceFrameworks)
	assert.Equal(t, 30*24*time.Hour, updatedConfig.SecurityEventRetention)
}

// TestGenerateComplianceReport tests compliance report generation
func TestGenerateComplianceReport(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	req := interfaces.ComplianceReportRequest{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		TenantIDs:         []string{"tenant1", "tenant2"},
		Frameworks:        []string{"CIS", "HIPAA"},
		IncludeBaselines:  true,
		IncludeExceptions: false,
		Format:            interfaces.FormatJSON,
		DetailLevel:       "detailed",
	}

	report, err := service.GenerateComplianceReport(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, report)

	// Verify report structure
	assert.NotEmpty(t, report.ID)
	assert.Equal(t, req.TenantIDs, report.TenantIDs)
	assert.Equal(t, req.Frameworks, report.Frameworks)
	assert.NotZero(t, report.GeneratedAt)
	assert.GreaterOrEqual(t, report.OverallScore, 0.0)
	assert.LessOrEqual(t, report.OverallScore, 100.0)
}

// TestGenerateSecurityReport tests security report generation
func TestGenerateSecurityReport(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	req := interfaces.SecurityReportRequest{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		TenantIDs:       []string{"tenant1"},
		IncludeResolved: false,
		Format:          interfaces.FormatJSON,
		AnalysisType:    "comprehensive",
	}

	report, err := service.GenerateSecurityReport(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, report)

	// Verify report structure
	assert.NotEmpty(t, report.ID)
	assert.Equal(t, req.TenantIDs, report.TenantIDs)
	assert.NotZero(t, report.GeneratedAt)
	assert.GreaterOrEqual(t, report.SecurityScore, 0.0)
	assert.LessOrEqual(t, report.SecurityScore, 100.0)
	assert.NotEmpty(t, report.ThreatLevel)
}

// TestGenerateExecutiveReport tests executive report generation
func TestGenerateExecutiveReport(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	req := interfaces.ExecutiveReportRequest{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-7 * 24 * time.Hour),
			End:   time.Now(),
		},
		TenantIDs:     []string{"tenant1", "tenant2"},
		KPIs:          []string{"compliance", "security", "availability"},
		IncludeCharts: true,
		IncludeTrends: true,
		Format:        interfaces.FormatJSON,
		Audience:      "executive",
	}

	report, err := service.GenerateExecutiveReport(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, report)

	// Verify report structure
	assert.NotEmpty(t, report.ID)
	assert.Equal(t, req.TenantIDs, report.TenantIDs)
	assert.NotZero(t, report.GeneratedAt)
	assert.NotEmpty(t, report.ExecutiveSummary)
	assert.NotNil(t, report.KPIs)
	assert.NotNil(t, report.RiskSummary)
}

// TestGenerateMultiTenantReport tests multi-tenant report generation
func TestGenerateMultiTenantReport(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	req := interfaces.MultiTenantReportRequest{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-7 * 24 * time.Hour),
			End:   time.Now(),
		},
		TenantIDs:       []string{"tenant1", "tenant2", "tenant3"},
		ReportType:      interfaces.AdvancedReportTypeMultiTenant,
		AggregationType: "comparative",
		IncludeDetails:  true,
		Format:          interfaces.FormatJSON,
	}

	report, err := service.GenerateMultiTenantReport(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, report)

	// Verify report structure
	assert.NotEmpty(t, report.ID)
	assert.Equal(t, req.TenantIDs, report.TenantIDs)
	assert.NotZero(t, report.GeneratedAt)
	assert.NotNil(t, report.Aggregation)
	assert.NotNil(t, report.Comparisons)
	assert.NotNil(t, report.BestPractices)
}

// TestGetTenantSummary tests single tenant summary retrieval
func TestGetTenantSummary(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	timeRange := interfaces.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	summary, err := service.GetTenantSummary(ctx, "tenant1", timeRange)
	assert.NoError(t, err)
	assert.NotNil(t, summary)

	// Verify summary structure
	assert.Equal(t, "tenant1", summary.TenantID)
	assert.Equal(t, timeRange, summary.TimeRange)
	assert.GreaterOrEqual(t, summary.DeviceCount, 0)
	assert.GreaterOrEqual(t, summary.UserCount, 0)
	assert.GreaterOrEqual(t, summary.ComplianceScore, 0.0)
	assert.LessOrEqual(t, summary.ComplianceScore, 100.0)
	assert.NotNil(t, summary.KeyMetrics)
	assert.NotNil(t, summary.Alerts)
}

// TestGetMultiTenantAggregation tests multi-tenant aggregation
func TestGetMultiTenantAggregation(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	tenantIDs := []string{"tenant1", "tenant2"}
	timeRange := interfaces.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	aggregation, err := service.GetMultiTenantAggregation(ctx, tenantIDs, timeRange)
	assert.NoError(t, err)
	assert.NotNil(t, aggregation)

	// Verify aggregation structure
	assert.Equal(t, tenantIDs, aggregation.TenantIDs)
	assert.Equal(t, timeRange, aggregation.TimeRange)
	assert.GreaterOrEqual(t, aggregation.TotalDevices, 0)
	assert.GreaterOrEqual(t, aggregation.TotalUsers, 0)
	assert.GreaterOrEqual(t, aggregation.AverageCompliance, 0.0)
	assert.LessOrEqual(t, aggregation.AverageCompliance, 100.0)
	assert.NotNil(t, aggregation.TenantSummaries)
	assert.NotNil(t, aggregation.Trends)
}

// TestAdvancedTemplates tests advanced template functionality
func TestAdvancedTemplates(t *testing.T) {
	service := createTestAdvancedService(t)

	// Test getting advanced templates
	templates := service.GetAdvancedTemplates()
	assert.NotEmpty(t, templates)

	// Verify template structure
	for _, template := range templates {
		assert.NotEmpty(t, template.Name)
		assert.NotEmpty(t, template.Type)
		assert.NotEmpty(t, template.Description)
		assert.NotNil(t, template.SupportedTenantTypes)
		assert.NotNil(t, template.DataSources)
		assert.NotNil(t, template.OutputFormats)
	}

	// Test template validation
	err := service.ValidateAdvancedTemplate("compliance-assessment", interfaces.AdvancedReportTypeCompliance)
	assert.NoError(t, err)

	// Test invalid template
	err = service.ValidateAdvancedTemplate("invalid-template", interfaces.AdvancedReportTypeCompliance)
	assert.Error(t, err)

	// Test template type mismatch
	err = service.ValidateAdvancedTemplate("compliance-assessment", interfaces.AdvancedReportTypeSecurity)
	assert.Error(t, err)
}

// TestServiceHealth tests service health reporting
func TestServiceHealth(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	health := service.Health(ctx)
	assert.NotNil(t, health)

	// Verify health structure
	assert.Equal(t, "healthy", health["status"])
	assert.NotNil(t, health["advanced_features"])
	assert.NotNil(t, health["templates_available"])
	assert.NotNil(t, health["advanced_templates_available"])

	advancedFeatures := health["advanced_features"].(map[string]interface{})
	assert.Contains(t, advancedFeatures, "audit_integration")
	assert.Contains(t, advancedFeatures, "rbac_validation")
	assert.Contains(t, advancedFeatures, "cross_system_metrics")
}

// TestServiceMetrics tests service metrics reporting
func TestServiceMetrics(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	metrics := service.GetMetrics(ctx)
	assert.NotNil(t, metrics)

	// Verify metrics structure
	assert.Equal(t, "advanced_reporting", metrics["service_type"])
	assert.NotNil(t, metrics["features"])
	assert.NotNil(t, metrics["configuration"])

	features := metrics["features"].(map[string]bool)
	assert.Contains(t, features, "audit_integration")
	assert.Contains(t, features, "rbac_validation")
	assert.Contains(t, features, "cross_system_metrics")

	configuration := metrics["configuration"].(map[string]interface{})
	assert.Contains(t, configuration, "max_tenants_per_report")
	assert.Contains(t, configuration, "compliance_frameworks")
}

// TestConfigurationUpdate tests configuration updates
func TestConfigurationUpdate(t *testing.T) {
	service := createTestAdvancedService(t)

	// Get initial configuration
	initialConfig := service.GetConfiguration()
	assert.True(t, initialConfig.EnableAuditIntegration)

	// Update configuration
	newConfig := initialConfig
	newConfig.EnableAuditIntegration = false
	newConfig.MaxTenantsPerReport = 25

	service.UpdateConfiguration(newConfig)

	// Verify configuration was updated
	updatedConfig := service.GetConfiguration()
	assert.False(t, updatedConfig.EnableAuditIntegration)
	assert.Equal(t, 25, updatedConfig.MaxTenantsPerReport)
}

// TestConvenienceMethods tests convenience methods for report generation
func TestConvenienceMethods(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	tenantIDs := []string{"tenant1"}
	timeRange := interfaces.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	// Test compliance assessment
	complianceData, err := service.GenerateComplianceAssessment(
		ctx, tenantIDs, []string{"CIS"}, timeRange, interfaces.FormatJSON,
	)
	assert.NoError(t, err)
	assert.NotNil(t, complianceData)

	// Test security analysis
	securityData, err := service.GenerateSecurityAnalysis(
		ctx, tenantIDs, timeRange, "comprehensive", interfaces.FormatJSON,
	)
	assert.NoError(t, err)
	assert.NotNil(t, securityData)

	// Test executive dashboard
	dashboardData, err := service.GenerateExecutiveDashboard(
		ctx, tenantIDs, timeRange, "executive", interfaces.FormatJSON,
	)
	assert.NoError(t, err)
	assert.NotNil(t, dashboardData)
}

// TestServiceClose tests service cleanup
func TestServiceClose(t *testing.T) {
	service := createTestAdvancedService(t)

	err := service.Close()
	assert.NoError(t, err)
}

// Test Data Access Methods

// TestGetComplianceData tests compliance data retrieval
func TestGetComplianceData(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	query := interfaces.ComplianceDataQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		TenantIDs:            []string{"tenant1"},
		ComplianceFrameworks: []string{"CIS"},
		IncludeBaselines:     true,
		IncludeExceptions:    false,
	}

	data, err := service.GetComplianceData(ctx, query)
	assert.NoError(t, err)
	assert.NotNil(t, data)

	// Verify compliance data structure
	assert.NotEmpty(t, data.Framework)
	assert.GreaterOrEqual(t, data.Score, 0.0)
	assert.LessOrEqual(t, data.Score, 100.0)
	assert.NotNil(t, data.Controls)
	assert.NotNil(t, data.Violations)
	assert.NotNil(t, data.TrendData)
}

// TestGetSecurityEvents tests security events retrieval
func TestGetSecurityEvents(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	query := interfaces.SecurityEventQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		TenantIDs:       []string{"tenant1"},
		IncludeResolved: false,
	}

	events, err := service.GetSecurityEvents(ctx, query)
	assert.NoError(t, err)
	assert.NotNil(t, events)

	// Verify event structure (if events exist)
	for _, event := range events {
		assert.NotEmpty(t, event.ID)
		assert.NotEmpty(t, event.Type)
		assert.NotEmpty(t, event.UserID)
		assert.NotEmpty(t, event.TenantID)
		assert.NotZero(t, event.Timestamp)
	}
}

// TestGetUserActivity tests user activity retrieval
func TestGetUserActivity(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	query := interfaces.UserActivityQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		TenantIDs:       []string{"tenant1"},
		IncludeFailures: true,
	}

	activities, err := service.GetUserActivity(ctx, query)
	assert.NoError(t, err)
	assert.NotNil(t, activities)

	// Verify activity structure (if activities exist)
	for _, activity := range activities {
		assert.NotEmpty(t, activity.UserID)
		assert.NotEmpty(t, activity.TenantID)
		assert.GreaterOrEqual(t, activity.ActionCount, 0)
		assert.GreaterOrEqual(t, activity.FailureCount, 0)
		assert.GreaterOrEqual(t, activity.RiskScore, 0.0)
		assert.NotNil(t, activity.Activities)
	}
}

// TestGetCrossSystemMetrics tests cross-system metrics retrieval
func TestGetCrossSystemMetrics(t *testing.T) {
	service := createTestAdvancedService(t)
	ctx := context.Background()

	query := interfaces.CrossSystemQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		TenantIDs:          []string{"tenant1"},
		CorrelationMetrics: []string{"drift_vs_changes", "access_vs_events"},
	}

	metrics, err := service.GetCrossSystemMetrics(ctx, query)
	assert.NoError(t, err)
	assert.NotNil(t, metrics)

	// Verify metrics structure
	assert.NotNil(t, metrics.DNAMetrics)
	assert.NotNil(t, metrics.AuditMetrics)
	assert.NotNil(t, metrics.Correlations)

	// Verify DNA metrics
	assert.GreaterOrEqual(t, metrics.DNAMetrics.DeviceCount, 0)
	assert.GreaterOrEqual(t, metrics.DNAMetrics.RecordCount, 0)
	assert.GreaterOrEqual(t, metrics.DNAMetrics.ComplianceScore, 0.0)
	assert.LessOrEqual(t, metrics.DNAMetrics.ComplianceScore, 100.0)

	// Verify audit metrics
	assert.GreaterOrEqual(t, metrics.AuditMetrics.EventCount, 0)
	assert.GreaterOrEqual(t, metrics.AuditMetrics.UserCount, 0)
	assert.GreaterOrEqual(t, metrics.AuditMetrics.FailureRate, 0.0)
	assert.LessOrEqual(t, metrics.AuditMetrics.FailureRate, 100.0)
}

// Helper Functions

// createTestAdvancedService creates a test instance of AdvancedService using minimal real components
func createTestAdvancedService(t *testing.T) *AdvancedService {
	logger := &testLogger{}

	// Create minimal real components needed for the service
	// Create DNA storage manager (which is what the constructor expects)
	dnaStorageConfig := &storage.Config{
		Backend:                storage.BackendSQLite,
		DataDir:                t.TempDir(),
		CompressionLevel:       6,
		CompressionType:        "gzip",
		TargetCompressionRatio: 0.7, // More relaxed target for testing
		EnableDeduplication:    true,
		BlockSize:              64 * 1024,
		HashAlgorithm:          "sha256",
		RetentionPeriod:        24 * time.Hour,
		ArchivalPeriod:         1 * time.Hour,
		MaxRecordsPerDevice:    100,
		EnableSharding:         false, // Disable sharding for simplicity
		ShardCount:             1,
		ShardingStrategy:       "device_id",
		BatchSize:              10,
		FlushInterval:          1 * time.Minute,
		CacheSize:              100,
		MaxStoragePerMonth:     10 * 1024 * 1024, // 10MB
	}
	dnaStorageManager, err := storage.NewManager(dnaStorageConfig, logger)
	require.NoError(t, err, "Failed to create DNA storage manager")
	t.Cleanup(func() { _ = dnaStorageManager.Close() })

	// Create minimal drift detector
	driftDetector, err := drift.NewDetector(drift.DefaultDetectorConfig(), logger)
	require.NoError(t, err, "Failed to create drift detector")

	// Create audit components using git storage for testing
	tmpDir := t.TempDir()
	globalStorageManager, err := storageInterfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err, "Failed to create global storage manager")

	auditStore := globalStorageManager.GetAuditStore()
	auditManager := audit.NewManager(auditStore, "test-reports")

	// Create RBAC manager
	rbacManager := rbac.NewManagerWithStorage(
		auditStore,
		globalStorageManager.GetClientTenantStore(),
		globalStorageManager.GetRBACStore(),
	)
	require.NotNil(t, rbacManager, "Failed to create RBAC manager")

	// Create real report cache
	reportCache := cache.NewMemoryCache()

	// Create advanced service with real components and test-friendly config
	serviceConfig := AdvancedServiceConfig{
		ServiceConfig:            DefaultServiceConfig(),
		EnableAuditIntegration:   true,
		EnableRBACValidation:     false, // Disable RBAC for integration testing
		EnableCrossSystemMetrics: true,
		MaxTenantsPerReport:      50,
		ComplianceFrameworks:     []string{"CIS", "HIPAA", "PCI-DSS"},
		SecurityEventRetention:   90 * 24 * time.Hour,
		AdvancedCacheConfig: interfaces.AdvancedCacheConfig{
			EnableAdvancedCaching: true,
			ComplianceReportTTL:   4 * time.Hour,
			SecurityReportTTL:     30 * time.Minute,
			ExecutiveReportTTL:    1 * time.Hour,
			MaxCacheSize:          1000,
		},
	}

	service := NewAdvancedServiceWithConfig(
		dnaStorageManager, driftDetector, auditManager, auditStore,
		rbacManager, reportCache, serviceConfig, logger,
	)
	require.NotNil(t, service, "Failed to create advanced service")

	return service
}

// testLogger implements logging.Logger for testing
type testLogger struct{}

// Ensure testLogger implements logging.Logger
var _ logging.Logger = (*testLogger)(nil)

func (l *testLogger) Debug(msg string, keysAndValues ...interface{})                         {}
func (l *testLogger) Info(msg string, keysAndValues ...interface{})                          {}
func (l *testLogger) Warn(msg string, keysAndValues ...interface{})                          {}
func (l *testLogger) Error(msg string, keysAndValues ...interface{})                         {}
func (l *testLogger) Fatal(msg string, keysAndValues ...interface{})                         {}
func (l *testLogger) DebugCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {}
func (l *testLogger) InfoCtx(ctx context.Context, msg string, keysAndValues ...interface{})  {}
func (l *testLogger) WarnCtx(ctx context.Context, msg string, keysAndValues ...interface{})  {}
func (l *testLogger) ErrorCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {}
func (l *testLogger) FatalCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {}
