// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package engine

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Mock implementations for testing
type MockDataProvider struct {
	mock.Mock
}

func (m *MockDataProvider) GetDNAData(ctx context.Context, query interfaces.DataQuery) ([]storage.DNARecord, error) {
	args := m.Called(ctx, query)
	return args.Get(0).([]storage.DNARecord), args.Error(1)
}

func (m *MockDataProvider) GetDriftEvents(ctx context.Context, query interfaces.DataQuery) ([]drift.DriftEvent, error) {
	args := m.Called(ctx, query)
	return args.Get(0).([]drift.DriftEvent), args.Error(1)
}

func (m *MockDataProvider) GetDeviceStats(ctx context.Context, deviceIDs []string, timeRange interfaces.TimeRange) (map[string]interfaces.DeviceStats, error) {
	args := m.Called(ctx, deviceIDs, timeRange)
	return args.Get(0).(map[string]interfaces.DeviceStats), args.Error(1)
}

func (m *MockDataProvider) GetTrendData(ctx context.Context, metric string, query interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	args := m.Called(ctx, metric, query)
	return args.Get(0).([]interfaces.TrendPoint), args.Error(1)
}

type MockTemplateProcessor struct {
	mock.Mock
}

func (m *MockTemplateProcessor) ProcessTemplate(ctx context.Context, templateName string, data interfaces.ReportData, params map[string]any) (*interfaces.Report, error) {
	args := m.Called(ctx, templateName, data, params)
	return args.Get(0).(*interfaces.Report), args.Error(1)
}

func (m *MockTemplateProcessor) GetTemplateInfo(templateName string) (*interfaces.TemplateInfo, error) {
	args := m.Called(templateName)
	return args.Get(0).(*interfaces.TemplateInfo), args.Error(1)
}

func (m *MockTemplateProcessor) ValidateTemplate(templateName string) error {
	args := m.Called(templateName)
	return args.Error(0)
}

type MockExporter struct {
	mock.Mock
}

func (m *MockExporter) Export(ctx context.Context, report *interfaces.Report, format interfaces.ExportFormat) ([]byte, error) {
	args := m.Called(ctx, report, format)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockExporter) SupportedFormats() []interfaces.ExportFormat {
	args := m.Called()
	return args.Get(0).([]interfaces.ExportFormat)
}

type MockCache struct {
	mock.Mock
}

func (m *MockCache) Get(ctx context.Context, key string) (*interfaces.Report, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*interfaces.Report), args.Error(1)
}

func (m *MockCache) Set(ctx context.Context, key string, report *interfaces.Report, ttl time.Duration) error {
	args := m.Called(ctx, key, report, ttl)
	return args.Error(0)
}

func (m *MockCache) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockCache) Clear(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func TestEngine_GenerateReport(t *testing.T) {
	tests := []struct {
		name           string
		request        interfaces.ReportRequest
		expectError    bool
		setupMocks     func(*MockDataProvider, *MockTemplateProcessor, *MockExporter, *MockCache)
		validateResult func(*testing.T, *interfaces.Report)
	}{
		{
			name: "successful compliance report generation",
			request: interfaces.ReportRequest{
				Type:     interfaces.ReportTypeCompliance,
				Template: "compliance-summary",
				TimeRange: interfaces.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: interfaces.FormatJSON,
			},
			expectError: false,
			setupMocks: func(dp *MockDataProvider, tp *MockTemplateProcessor, ex *MockExporter, cache *MockCache) {
				// Cache miss
				cache.On("Get", mock.Anything, mock.AnythingOfType("string")).Return(nil, assert.AnError)

				// Data provider returns
				dp.On("GetDNAData", mock.Anything, mock.AnythingOfType("interfaces.DataQuery")).Return([]storage.DNARecord{
					{DeviceID: "device1", StoredAt: time.Now()},
					{DeviceID: "device2", StoredAt: time.Now()},
				}, nil)

				dp.On("GetDriftEvents", mock.Anything, mock.AnythingOfType("interfaces.DataQuery")).Return([]drift.DriftEvent{
					{DeviceID: "device1", Severity: drift.SeverityCritical, Timestamp: time.Now()},
				}, nil)

				dp.On("GetDeviceStats", mock.Anything, mock.AnythingOfType("[]string"), mock.AnythingOfType("interfaces.TimeRange")).Return(map[string]interfaces.DeviceStats{
					"device1": {DeviceID: "device1", ComplianceScore: 0.7, RiskLevel: interfaces.RiskLevelMedium},
					"device2": {DeviceID: "device2", ComplianceScore: 0.9, RiskLevel: interfaces.RiskLevelLow},
				}, nil)

				dp.On("GetTrendData", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("interfaces.DataQuery")).Return([]interfaces.TrendPoint{
					{Timestamp: time.Now(), Value: 0.8},
				}, nil)

				// Template processor returns mock report
				mockReport := &interfaces.Report{
					Type:     interfaces.ReportTypeCompliance,
					Title:    "Test Compliance Report",
					Sections: []interfaces.ReportSection{},
					Summary:  interfaces.ReportSummary{DevicesAnalyzed: 2, ComplianceScore: 0.8},
				}
				tp.On("ProcessTemplate", mock.Anything, "compliance-summary", mock.AnythingOfType("interfaces.ReportData"), mock.AnythingOfType("map[string]interface {}")).Return(mockReport, nil)

				// Cache set
				cache.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*interfaces.Report"), mock.AnythingOfType("time.Duration")).Return(nil)
			},
			validateResult: func(t *testing.T, report *interfaces.Report) {
				assert.Equal(t, interfaces.ReportTypeCompliance, report.Type)
				assert.Equal(t, "Test Compliance Report", report.Title)
				assert.Equal(t, 2, report.Summary.DevicesAnalyzed)
				assert.Equal(t, 0.8, report.Summary.ComplianceScore)
				assert.False(t, report.Metadata.CacheHit)
				assert.GreaterOrEqual(t, report.Metadata.GenerationMS, int64(0))
			},
		},
		{
			name: "cache hit scenario",
			request: interfaces.ReportRequest{
				Type:     interfaces.ReportTypeExecutive,
				Template: "executive-dashboard",
				TimeRange: interfaces.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: interfaces.FormatJSON,
			},
			expectError: false,
			setupMocks: func(dp *MockDataProvider, tp *MockTemplateProcessor, ex *MockExporter, cache *MockCache) {
				// Cache hit
				cachedReport := &interfaces.Report{
					Type:     interfaces.ReportTypeExecutive,
					Title:    "Cached Executive Dashboard",
					Metadata: interfaces.ReportMetadata{CacheHit: false}, // Will be updated
				}
				cache.On("Get", mock.Anything, mock.AnythingOfType("string")).Return(cachedReport, nil)
			},
			validateResult: func(t *testing.T, report *interfaces.Report) {
				assert.Equal(t, interfaces.ReportTypeExecutive, report.Type)
				assert.Equal(t, "Cached Executive Dashboard", report.Title)
				assert.True(t, report.Metadata.CacheHit)
			},
		},
		{
			name: "invalid request validation",
			request: interfaces.ReportRequest{
				Type:     "invalid-type",
				Template: "compliance-summary",
				TimeRange: interfaces.TimeRange{
					Start: time.Now(),
					End:   time.Now().Add(-24 * time.Hour), // Invalid: start after end
				},
				Format: interfaces.FormatJSON,
			},
			expectError: true,
			setupMocks: func(dp *MockDataProvider, tp *MockTemplateProcessor, ex *MockExporter, cache *MockCache) {
				// No mocks needed for validation failure
			},
			validateResult: func(t *testing.T, report *interfaces.Report) {
				// Should not be called
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockDataProvider := &MockDataProvider{}
			mockTemplateProcessor := &MockTemplateProcessor{}
			mockExporter := &MockExporter{}
			mockCache := &MockCache{}
			mockLogger := logging.NewNoopLogger()

			// Setup mocks
			tt.setupMocks(mockDataProvider, mockTemplateProcessor, mockExporter, mockCache)

			// Create engine
			engine := New(mockDataProvider, mockTemplateProcessor, mockExporter, mockCache, mockLogger)

			// Execute test
			ctx := context.Background()
			report, err := engine.GenerateReport(ctx, tt.request)

			// Validate results
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, report)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, report)
				tt.validateResult(t, report)
			}

			// Verify mock expectations
			mockDataProvider.AssertExpectations(t)
			mockTemplateProcessor.AssertExpectations(t)
			mockExporter.AssertExpectations(t)
			mockCache.AssertExpectations(t)
		})
	}
}

func TestEngine_ValidateRequest(t *testing.T) {
	engine := New(nil, nil, nil, nil, logging.NewNoopLogger())

	tests := []struct {
		name    string
		request interfaces.ReportRequest
		wantErr bool
	}{
		{
			name: "valid request",
			request: interfaces.ReportRequest{
				Type:     interfaces.ReportTypeCompliance,
				Template: "compliance-summary",
				TimeRange: interfaces.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: interfaces.FormatJSON,
			},
			wantErr: false,
		},
		{
			name: "invalid report type",
			request: interfaces.ReportRequest{
				Type:     "invalid",
				Template: "compliance-summary",
				TimeRange: interfaces.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: interfaces.FormatJSON,
			},
			wantErr: true,
		},
		{
			name: "empty template",
			request: interfaces.ReportRequest{
				Type:     interfaces.ReportTypeCompliance,
				Template: "",
				TimeRange: interfaces.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: interfaces.FormatJSON,
			},
			wantErr: true,
		},
		{
			name: "invalid time range - start after end",
			request: interfaces.ReportRequest{
				Type:     interfaces.ReportTypeCompliance,
				Template: "compliance-summary",
				TimeRange: interfaces.TimeRange{
					Start: time.Now(),
					End:   time.Now().Add(-24 * time.Hour),
				},
				Format: interfaces.FormatJSON,
			},
			wantErr: true,
		},
		{
			name: "time range too large",
			request: interfaces.ReportRequest{
				Type:     interfaces.ReportTypeCompliance,
				Template: "compliance-summary",
				TimeRange: interfaces.TimeRange{
					Start: time.Now().Add(-60 * 24 * time.Hour), // 60 days
					End:   time.Now(),
				},
				Format: interfaces.FormatJSON,
			},
			wantErr: true,
		},
		{
			name: "invalid export format",
			request: interfaces.ReportRequest{
				Type:     interfaces.ReportTypeCompliance,
				Template: "compliance-summary",
				TimeRange: interfaces.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidateRequest(tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEngine_GetAvailableTemplates(t *testing.T) {
	engine := New(nil, nil, nil, nil, logging.NewNoopLogger())

	templates := engine.GetAvailableTemplates()

	assert.NotEmpty(t, templates)

	// Check that we have the expected built-in templates
	templateNames := make(map[string]bool)
	for _, template := range templates {
		templateNames[template.Name] = true
	}

	assert.True(t, templateNames["compliance-summary"])
	assert.True(t, templateNames["executive-dashboard"])
	assert.True(t, templateNames["drift-analysis"])
}

func TestEngine_GenerateReportSummary(t *testing.T) {
	engine := New(nil, nil, nil, nil, logging.NewNoopLogger())

	// Create test data
	data := &interfaces.ReportData{
		DNARecords: []storage.DNARecord{
			{DeviceID: "device1"},
			{DeviceID: "device2"},
		},
		DriftEvents: []drift.DriftEvent{
			{DeviceID: "device1", Severity: drift.SeverityCritical},
			{DeviceID: "device1", Severity: drift.SeverityWarning},
			{DeviceID: "device2", Severity: drift.SeverityInfo},
		},
		DeviceStats: map[string]interfaces.DeviceStats{
			"device1": {
				DeviceID:        "device1",
				ComplianceScore: 0.7,
				RiskLevel:       interfaces.RiskLevelHigh,
			},
			"device2": {
				DeviceID:        "device2",
				ComplianceScore: 0.9,
				RiskLevel:       interfaces.RiskLevelLow,
			},
		},
		TrendData: map[string][]interfaces.TrendPoint{
			"compliance_score": {
				{Value: 0.8, Timestamp: time.Now().Add(-24 * time.Hour)},
				{Value: 0.85, Timestamp: time.Now()},
			},
		},
	}

	summary := engine.generateReportSummary(data)

	assert.Equal(t, 2, summary.DevicesAnalyzed)
	assert.Equal(t, 3, summary.DriftEventsTotal)
	assert.Equal(t, 0.8, summary.ComplianceScore)                      // Average of 0.7 and 0.9
	assert.Equal(t, 0, summary.CriticalIssues)                         // No critical risk devices
	assert.Equal(t, interfaces.TrendImproving, summary.TrendDirection) // 0.8 -> 0.85
	assert.NotEmpty(t, summary.KeyInsights)
	assert.NotEmpty(t, summary.RecommendedActions)
}

func TestEngine_GenerateCacheKey(t *testing.T) {
	engine := New(nil, nil, nil, nil, logging.NewNoopLogger())

	req1 := interfaces.ReportRequest{
		Type:     interfaces.ReportTypeCompliance,
		Template: "compliance-summary",
		Format:   interfaces.FormatJSON,
	}

	req2 := interfaces.ReportRequest{
		Type:     interfaces.ReportTypeCompliance,
		Template: "compliance-summary",
		Format:   interfaces.FormatJSON,
	}

	req3 := interfaces.ReportRequest{
		Type:     interfaces.ReportTypeExecutive,
		Template: "executive-dashboard",
		Format:   interfaces.FormatJSON,
	}

	key1 := engine.generateCacheKey(req1)
	key2 := engine.generateCacheKey(req2)
	key3 := engine.generateCacheKey(req3)

	// Same requests should generate same cache key
	assert.Equal(t, key1, key2)

	// Different requests should generate different cache keys
	assert.NotEqual(t, key1, key3)

	// Cache keys should have expected format
	assert.Contains(t, key1, "report_")
	assert.Contains(t, key3, "report_")
}

func TestEngine_WithConfig(t *testing.T) {
	engine := New(nil, nil, nil, nil, logging.NewNoopLogger())

	customConfig := Config{
		CacheEnabled:    false,
		CacheTTL:        2 * time.Hour,
		MaxDevices:      500,
		MaxTimeRange:    15 * 24 * time.Hour,
		TimeoutDuration: 10 * time.Minute,
	}

	engineWithConfig := engine.WithConfig(customConfig)

	assert.Equal(t, customConfig, engineWithConfig.config)
	assert.False(t, engineWithConfig.config.CacheEnabled)
	assert.Equal(t, 2*time.Hour, engineWithConfig.config.CacheTTL)
	assert.Equal(t, 500, engineWithConfig.config.MaxDevices)
}
