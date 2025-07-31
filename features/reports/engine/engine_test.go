package engine

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/reports"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Mock implementations for testing
type MockDataProvider struct {
	mock.Mock
}

func (m *MockDataProvider) GetDNAData(ctx context.Context, query reports.DataQuery) ([]storage.DNARecord, error) {
	args := m.Called(ctx, query)
	return args.Get(0).([]storage.DNARecord), args.Error(1)
}

func (m *MockDataProvider) GetDriftEvents(ctx context.Context, query reports.DataQuery) ([]drift.DriftEvent, error) {
	args := m.Called(ctx, query)
	return args.Get(0).([]drift.DriftEvent), args.Error(1)
}

func (m *MockDataProvider) GetDeviceStats(ctx context.Context, deviceIDs []string, timeRange reports.TimeRange) (map[string]reports.DeviceStats, error) {
	args := m.Called(ctx, deviceIDs, timeRange)
	return args.Get(0).(map[string]reports.DeviceStats), args.Error(1)
}

func (m *MockDataProvider) GetTrendData(ctx context.Context, metric string, query reports.DataQuery) ([]reports.TrendPoint, error) {
	args := m.Called(ctx, metric, query)
	return args.Get(0).([]reports.TrendPoint), args.Error(1)
}

type MockTemplateProcessor struct {
	mock.Mock
}

func (m *MockTemplateProcessor) ProcessTemplate(ctx context.Context, templateName string, data reports.ReportData, params map[string]any) (*reports.Report, error) {
	args := m.Called(ctx, templateName, data, params)
	return args.Get(0).(*reports.Report), args.Error(1)
}

func (m *MockTemplateProcessor) GetTemplateInfo(templateName string) (*reports.TemplateInfo, error) {
	args := m.Called(templateName)
	return args.Get(0).(*reports.TemplateInfo), args.Error(1)
}

func (m *MockTemplateProcessor) ValidateTemplate(templateName string) error {
	args := m.Called(templateName)
	return args.Error(0)
}

type MockExporter struct {
	mock.Mock
}

func (m *MockExporter) Export(ctx context.Context, report *reports.Report, format reports.ExportFormat) ([]byte, error) {
	args := m.Called(ctx, report, format)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockExporter) SupportedFormats() []reports.ExportFormat {
	args := m.Called()
	return args.Get(0).([]reports.ExportFormat)
}

type MockCache struct {
	mock.Mock
}

func (m *MockCache) Get(ctx context.Context, key string) (*reports.Report, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*reports.Report), args.Error(1)
}

func (m *MockCache) Set(ctx context.Context, key string, report *reports.Report, ttl time.Duration) error {
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
		name          string
		request       reports.ReportRequest
		expectError   bool
		setupMocks    func(*MockDataProvider, *MockTemplateProcessor, *MockExporter, *MockCache)
		validateResult func(*testing.T, *reports.Report)
	}{
		{
			name: "successful compliance report generation",
			request: reports.ReportRequest{
				Type:      reports.ReportTypeCompliance,
				Template:  "compliance-summary",
				TimeRange: reports.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: reports.FormatJSON,
			},
			expectError: false,
			setupMocks: func(dp *MockDataProvider, tp *MockTemplateProcessor, ex *MockExporter, cache *MockCache) {
				// Cache miss
				cache.On("Get", mock.Anything, mock.AnythingOfType("string")).Return(nil, assert.AnError)
				
				// Data provider returns
				dp.On("GetDNAData", mock.Anything, mock.AnythingOfType("reports.DataQuery")).Return([]storage.DNARecord{
					{DeviceID: "device1", Timestamp: time.Now()},
					{DeviceID: "device2", Timestamp: time.Now()},
				}, nil)
				
				dp.On("GetDriftEvents", mock.Anything, mock.AnythingOfType("reports.DataQuery")).Return([]drift.DriftEvent{
					{DeviceID: "device1", Severity: drift.Critical, Timestamp: time.Now()},
				}, nil)
				
				dp.On("GetDeviceStats", mock.Anything, mock.AnythingOfType("[]string"), mock.AnythingOfType("reports.TimeRange")).Return(map[string]reports.DeviceStats{
					"device1": {DeviceID: "device1", ComplianceScore: 0.8, RiskLevel: reports.RiskLevelMedium},
					"device2": {DeviceID: "device2", ComplianceScore: 0.9, RiskLevel: reports.RiskLevelLow},
				}, nil)
				
				dp.On("GetTrendData", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("reports.DataQuery")).Return([]reports.TrendPoint{
					{Timestamp: time.Now(), Value: 0.85},
				}, nil)
				
				// Template processor returns mock report
				mockReport := &reports.Report{
					Type:      reports.ReportTypeCompliance,
					Title:     "Test Compliance Report",
					Sections:  []reports.ReportSection{},
					Summary:   reports.ReportSummary{DevicesAnalyzed: 2, ComplianceScore: 0.85},
				}
				tp.On("ProcessTemplate", mock.Anything, "compliance-summary", mock.AnythingOfType("reports.ReportData"), mock.AnythingOfType("map[string]interface {}")).Return(mockReport, nil)
				
				// Cache set
				cache.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*reports.Report"), mock.AnythingOfType("time.Duration")).Return(nil)
			},
			validateResult: func(t *testing.T, report *reports.Report) {
				assert.Equal(t, reports.ReportTypeCompliance, report.Type)
				assert.Equal(t, "Test Compliance Report", report.Title)
				assert.Equal(t, 2, report.Summary.DevicesAnalyzed)
				assert.Equal(t, 0.85, report.Summary.ComplianceScore)
				assert.False(t, report.Metadata.CacheHit)
				assert.Greater(t, report.Metadata.GenerationMS, int64(0))
			},
		},
		{
			name: "cache hit scenario",
			request: reports.ReportRequest{
				Type:      reports.ReportTypeExecutive,
				Template:  "executive-dashboard",
				TimeRange: reports.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: reports.FormatJSON,
			},
			expectError: false,
			setupMocks: func(dp *MockDataProvider, tp *MockTemplateProcessor, ex *MockExporter, cache *MockCache) {
				// Cache hit
				cachedReport := &reports.Report{
					Type:     reports.ReportTypeExecutive,
					Title:    "Cached Executive Dashboard",
					Metadata: reports.ReportMetadata{CacheHit: false}, // Will be updated
				}
				cache.On("Get", mock.Anything, mock.AnythingOfType("string")).Return(cachedReport, nil)
			},
			validateResult: func(t *testing.T, report *reports.Report) {
				assert.Equal(t, reports.ReportTypeExecutive, report.Type)
				assert.Equal(t, "Cached Executive Dashboard", report.Title)
				assert.True(t, report.Metadata.CacheHit)
			},
		},
		{
			name: "invalid request validation",
			request: reports.ReportRequest{
				Type:     "invalid-type",
				Template: "compliance-summary",
				TimeRange: reports.TimeRange{
					Start: time.Now(),
					End:   time.Now().Add(-24 * time.Hour), // Invalid: start after end
				},
				Format: reports.FormatJSON,
			},
			expectError: true,
			setupMocks: func(dp *MockDataProvider, tp *MockTemplateProcessor, ex *MockExporter, cache *MockCache) {
				// No mocks needed for validation failure
			},
			validateResult: func(t *testing.T, report *reports.Report) {
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
			mockLogger := logging.NewNopLogger()

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
	engine := New(nil, nil, nil, nil, logging.NewNopLogger())

	tests := []struct {
		name    string
		request reports.ReportRequest
		wantErr bool
	}{
		{
			name: "valid request",
			request: reports.ReportRequest{
				Type:     reports.ReportTypeCompliance,
				Template: "compliance-summary",
				TimeRange: reports.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: reports.FormatJSON,
			},
			wantErr: false,
		},
		{
			name: "invalid report type",
			request: reports.ReportRequest{
				Type:     "invalid",
				Template: "compliance-summary",
				TimeRange: reports.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: reports.FormatJSON,
			},
			wantErr: true,
		},
		{
			name: "empty template",
			request: reports.ReportRequest{
				Type:     reports.ReportTypeCompliance,
				Template: "",
				TimeRange: reports.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Format: reports.FormatJSON,
			},
			wantErr: true,
		},
		{
			name: "invalid time range - start after end",
			request: reports.ReportRequest{
				Type:     reports.ReportTypeCompliance,
				Template: "compliance-summary",
				TimeRange: reports.TimeRange{
					Start: time.Now(),
					End:   time.Now().Add(-24 * time.Hour),
				},
				Format: reports.FormatJSON,
			},
			wantErr: true,
		},
		{
			name: "time range too large",
			request: reports.ReportRequest{
				Type:     reports.ReportTypeCompliance,
				Template: "compliance-summary",
				TimeRange: reports.TimeRange{
					Start: time.Now().Add(-60 * 24 * time.Hour), // 60 days
					End:   time.Now(),
				},
				Format: reports.FormatJSON,
			},
			wantErr: true,
		},
		{
			name: "invalid export format",
			request: reports.ReportRequest{
				Type:     reports.ReportTypeCompliance,
				Template: "compliance-summary",
				TimeRange: reports.TimeRange{
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
	engine := New(nil, nil, nil, nil, logging.NewNopLogger())
	
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
	engine := New(nil, nil, nil, nil, logging.NewNopLogger())

	// Create test data
	data := &reports.ReportData{
		DNARecords: []storage.DNARecord{
			{DeviceID: "device1"},
			{DeviceID: "device2"},
		},
		DriftEvents: []drift.DriftEvent{
			{DeviceID: "device1", Severity: drift.Critical},
			{DeviceID: "device1", Severity: drift.Warning},
			{DeviceID: "device2", Severity: drift.Info},
		},
		DeviceStats: map[string]reports.DeviceStats{
			"device1": {
				DeviceID:        "device1",
				ComplianceScore: 0.7,
				RiskLevel:       reports.RiskLevelHigh,
			},
			"device2": {
				DeviceID:        "device2", 
				ComplianceScore: 0.9,
				RiskLevel:       reports.RiskLevelLow,
			},
		},
		TrendData: map[string][]reports.TrendPoint{
			"compliance_score": {
				{Value: 0.8, Timestamp: time.Now().Add(-24 * time.Hour)},
				{Value: 0.85, Timestamp: time.Now()},
			},
		},
	}

	summary := engine.generateReportSummary(data)

	assert.Equal(t, 2, summary.DevicesAnalyzed)
	assert.Equal(t, 3, summary.DriftEventsTotal)
	assert.Equal(t, 0.8, summary.ComplianceScore) // Average of 0.7 and 0.9
	assert.Equal(t, 0, summary.CriticalIssues)    // No critical risk devices
	assert.Equal(t, reports.TrendImproving, summary.TrendDirection) // 0.8 -> 0.85
	assert.NotEmpty(t, summary.KeyInsights)
	assert.NotEmpty(t, summary.RecommendedActions)
}

func TestEngine_GenerateCacheKey(t *testing.T) {
	engine := New(nil, nil, nil, nil, logging.NewNopLogger())

	req1 := reports.ReportRequest{
		Type:     reports.ReportTypeCompliance,
		Template: "compliance-summary",
		Format:   reports.FormatJSON,
	}

	req2 := reports.ReportRequest{
		Type:     reports.ReportTypeCompliance,
		Template: "compliance-summary",
		Format:   reports.FormatJSON,
	}

	req3 := reports.ReportRequest{
		Type:     reports.ReportTypeExecutive,
		Template: "executive-dashboard",
		Format:   reports.FormatJSON,
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
	engine := New(nil, nil, nil, nil, logging.NewNopLogger())
	
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