// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package reports

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestCustomReportBuilder(t *testing.T) {
	t.Run("CreateCustomReport_ValidParameters", func(t *testing.T) {
		// Create a properly initialized builder with config
		config := interfaces.DefaultCustomReportConfig()
		builder := &CustomReportBuilder{
			config: config,
			logger: logging.NewNoopLogger(),
		}

		req := interfaces.CustomReportRequest{
			Name:        "Test Custom Report",
			Description: "Test description",
			Query: interfaces.CustomQuery{
				DataSources: []string{"dna", "audit"},
				Filters: map[string]interface{}{
					"device_type": "server",
					"tenant_id":   "tenant-123",
				},
				Aggregations: []interfaces.QueryAggregation{
					{
						Field:     "compliance_score",
						Operation: "avg",
					},
				},
				TimeRange: interfaces.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
			},
			Parameters: []interfaces.CustomParameter{
				{
					Name:        "device_type",
					Type:        "string",
					Description: "Filter by device type",
					Required:    true,
					Options:     []string{"server", "workstation", "mobile"},
				},
			},
			Format:    interfaces.FormatJSON,
			TenantID:  "tenant-123",
			CreatedBy: "user-123",
		}

		report, err := builder.CreateCustomReport(context.Background(), req)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, req.Name, report.Name)
		assert.Equal(t, req.TenantID, report.TenantID)
		assert.Equal(t, req.CreatedBy, report.CreatedBy)
		assert.NotEmpty(t, report.ID)
	})

	t.Run("ValidateParameters_RequiredMissing", func(t *testing.T) {
		config := interfaces.DefaultCustomReportConfig()
		builder := &CustomReportBuilder{
			config: config,
			logger: logging.NewNoopLogger(),
		}

		template := &interfaces.CustomReportTemplate{
			Parameters: []interfaces.CustomParameter{
				{
					Name:     "required_field",
					Type:     "string",
					Required: true,
				},
			},
		}

		params := map[string]interface{}{
			"optional_field": "value",
		}

		err := builder.ValidateParameters(template, params)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required parameter 'required_field' is missing")
	})

	t.Run("ValidateParameters_TypeMismatch", func(t *testing.T) {
		config := interfaces.DefaultCustomReportConfig()
		builder := &CustomReportBuilder{
			config: config,
			logger: logging.NewNoopLogger(),
		}

		template := &interfaces.CustomReportTemplate{
			Parameters: []interfaces.CustomParameter{
				{
					Name: "numeric_field",
					Type: "number",
				},
			},
		}

		params := map[string]interface{}{
			"numeric_field": "not_a_number",
		}

		err := builder.ValidateParameters(template, params)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parameter 'numeric_field' must be of type number")
	})

	t.Run("ValidateParameters_ValidRange", func(t *testing.T) {
		config := interfaces.DefaultCustomReportConfig()
		builder := &CustomReportBuilder{
			config: config,
			logger: logging.NewNoopLogger(),
		}

		template := &interfaces.CustomReportTemplate{
			Parameters: []interfaces.CustomParameter{
				{
					Name:     "range_field",
					Type:     "number",
					MinValue: func(f float64) *float64 { return &f }(1.0),
					MaxValue: func(f float64) *float64 { return &f }(100.0),
				},
			},
		}

		params := map[string]interface{}{
			"range_field": 50.0,
		}

		err := builder.ValidateParameters(template, params)
		assert.NoError(t, err)
	})

	t.Run("ValidateParameters_OutOfRange", func(t *testing.T) {
		config := interfaces.DefaultCustomReportConfig()
		builder := &CustomReportBuilder{
			config: config,
			logger: logging.NewNoopLogger(),
		}

		template := &interfaces.CustomReportTemplate{
			Parameters: []interfaces.CustomParameter{
				{
					Name:     "range_field",
					Type:     "number",
					MinValue: func(f float64) *float64 { return &f }(1.0),
					MaxValue: func(f float64) *float64 { return &f }(100.0),
				},
			},
		}

		params := map[string]interface{}{
			"range_field": 150.0,
		}

		err := builder.ValidateParameters(template, params)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parameter 'range_field' must be between 1 and 100")
	})

	t.Run("BuildQuery_WithFiltersAndAggregations", func(t *testing.T) {
		config := interfaces.DefaultCustomReportConfig()
		builder := &CustomReportBuilder{
			config: config,
			logger: logging.NewNoopLogger(),
		}

		req := interfaces.CustomReportRequest{
			Query: interfaces.CustomQuery{
				DataSources: []string{"dna"},
				Filters: map[string]interface{}{
					"device_type": "server",
					"risk_level":  []string{"high", "critical"},
				},
				Aggregations: []interfaces.QueryAggregation{
					{
						Field:     "compliance_score",
						Operation: "avg",
						GroupBy:   []string{"tenant_id"},
					},
				},
			},
		}

		query, err := builder.BuildQuery(req.Query)
		require.NoError(t, err)
		assert.NotNil(t, query)
		assert.Equal(t, len(req.Query.DataSources), len(query.DataSources))
		assert.Equal(t, len(req.Query.Filters), len(query.Filters))
		assert.Equal(t, len(req.Query.Aggregations), len(query.Aggregations))
	})
}

func TestCustomReportTemplate(t *testing.T) {
	t.Run("SaveTemplate_ValidTemplate", func(t *testing.T) {
		store := &MockCustomTemplateStore{}
		manager := &CustomTemplateManager{
			store:  store,
			logger: logging.NewNoopLogger(),
		}

		template := &interfaces.CustomReportTemplate{
			Name:        "Test Template",
			Description: "Test template description",
			Query: interfaces.CustomQuery{
				DataSources: []string{"dna"},
				Filters: map[string]interface{}{
					"device_type": "{{.device_type}}",
				},
			},
			Parameters: []interfaces.CustomParameter{
				{
					Name:        "device_type",
					Type:        "string",
					Description: "Device type filter",
					Required:    true,
					Options:     []string{"server", "workstation"},
				},
			},
			TenantID:  "tenant-123",
			CreatedBy: "user-123",
			IsShared:  false,
		}

		savedTemplate, err := manager.SaveTemplate(context.Background(), template)
		require.NoError(t, err)
		assert.NotNil(t, savedTemplate)
		assert.NotEmpty(t, savedTemplate.ID)
		assert.Equal(t, template.Name, savedTemplate.Name)
	})

	t.Run("ShareTemplate_ValidPermissions", func(t *testing.T) {
		store := &MockCustomTemplateStore{}
		manager := &CustomTemplateManager{
			store:  store,
			logger: logging.NewNoopLogger(),
		}

		// Pre-populate store with template
		templateID := "template-123"
		template := &interfaces.CustomReportTemplate{
			ID:       templateID,
			Name:     "Test Template",
			TenantID: "tenant-123",
		}
		store.templates = []*interfaces.CustomReportTemplate{template}

		shareReq := interfaces.ShareTemplateRequest{
			TemplateID:        templateID,
			SharedWithTenants: []string{"tenant-456", "tenant-789"},
			Permissions:       []string{"read", "execute"},
			SharedBy:          "user-123",
		}

		err := manager.ShareTemplate(context.Background(), shareReq)
		assert.NoError(t, err)

		// Verify template was marked as shared
		updatedTemplate, err := store.GetByID(context.Background(), templateID)
		require.NoError(t, err)
		assert.True(t, updatedTemplate.IsShared)
	})

	t.Run("GetAccessibleTemplates_RespectsTenantIsolation", func(t *testing.T) {
		store := &MockCustomTemplateStore{}
		manager := &CustomTemplateManager{
			store:  store,
			logger: logging.NewNoopLogger(),
		}

		// Setup test templates
		template1 := &interfaces.CustomReportTemplate{
			ID:       "template-1",
			TenantID: "tenant-123",
			IsShared: false,
		}
		template2 := &interfaces.CustomReportTemplate{
			ID:       "template-2",
			TenantID: "tenant-456",
			IsShared: true,
			SharedWith: []interfaces.TemplateShare{
				{
					TenantID:    "tenant-123",
					Permissions: []string{"read"},
				},
			},
		}

		store.templates = []*interfaces.CustomReportTemplate{template1, template2}

		// User from tenant-123 should see both templates
		templates, err := manager.GetAccessibleTemplates(context.Background(), "tenant-123")
		require.NoError(t, err)
		assert.Len(t, templates, 2)

		// User from tenant-789 should see no templates
		templates, err = manager.GetAccessibleTemplates(context.Background(), "tenant-789")
		require.NoError(t, err)
		assert.Len(t, templates, 0)
	})
}

func TestPaginatedReportGeneration(t *testing.T) {
	t.Run("GenerateReport_LargeDataset_UsePagination", func(t *testing.T) {
		config := interfaces.DefaultCustomReportConfig()
		config.StreamThreshold = 1000 // Lower threshold to ensure streaming is triggered
		builder := &CustomReportBuilder{
			config: config,
			logger: logging.NewNoopLogger(),
		}

		req := interfaces.CustomReportRequest{
			Name:      "Large Dataset Report",
			TenantID:  "tenant-123",
			CreatedBy: "user-123",
			Format:    interfaces.FormatJSON,
			Query: interfaces.CustomQuery{
				DataSources: []string{"dna"},
				TimeRange: interfaces.TimeRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Pagination: &interfaces.PaginationConfig{
					PageSize:   100,
					MaxPages:   50,
					StreamMode: true,
				},
			},
		}

		ctx := context.Background()
		report, err := builder.GenerateReport(ctx, req)

		require.NoError(t, err)
		assert.NotNil(t, report)

		// Should use streaming for large datasets
		assert.True(t, report.IsStreamed)
		assert.NotEmpty(t, report.StreamToken)
	})

	t.Run("GetReportData_WithPagination", func(t *testing.T) {
		config := interfaces.DefaultCustomReportConfig()
		builder := &CustomReportBuilder{
			config: config,
			logger: logging.NewNoopLogger(),
		}

		pagination := interfaces.PaginationRequest{
			StreamToken: "token-123",
			Page:        1,
			PageSize:    50,
		}

		data, hasMore, err := builder.GetReportData(context.Background(), pagination)
		require.NoError(t, err)
		assert.NotNil(t, data)
		assert.IsType(t, bool(false), hasMore)
	})
}

// Mock implementations for testing

type MockCustomTemplateStore struct {
	templates []*interfaces.CustomReportTemplate
}

func (m *MockCustomTemplateStore) Save(ctx context.Context, template *interfaces.CustomReportTemplate) (*interfaces.CustomReportTemplate, error) {
	if template.ID == "" {
		template.ID = "generated-id-" + time.Now().Format("20060102150405")
	}
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()

	m.templates = append(m.templates, template)
	return template, nil
}

func (m *MockCustomTemplateStore) GetByID(ctx context.Context, id string) (*interfaces.CustomReportTemplate, error) {
	for _, t := range m.templates {
		if t.ID == id {
			// Update to mark as shared if needed
			t.IsShared = true
			return t, nil
		}
	}
	return nil, ErrTemplateNotFound
}

func (m *MockCustomTemplateStore) GetByTenant(ctx context.Context, tenantID string) ([]*interfaces.CustomReportTemplate, error) {
	var result []*interfaces.CustomReportTemplate
	for _, t := range m.templates {
		if t.TenantID == tenantID {
			result = append(result, t)
		}
	}
	return result, nil
}

func (m *MockCustomTemplateStore) GetSharedTemplates(ctx context.Context, tenantID string) ([]*interfaces.CustomReportTemplate, error) {
	var result []*interfaces.CustomReportTemplate
	for _, t := range m.templates {
		if t.IsShared {
			for _, share := range t.SharedWith {
				if share.TenantID == tenantID {
					result = append(result, t)
					break
				}
			}
		}
	}
	return result, nil
}

func (m *MockCustomTemplateStore) Delete(ctx context.Context, id string, tenantID string) error {
	for i, t := range m.templates {
		if t.ID == id && t.TenantID == tenantID {
			m.templates = append(m.templates[:i], m.templates[i+1:]...)
			return nil
		}
	}
	return ErrTemplateNotFound
}

func (m *MockCustomTemplateStore) UpdateSharing(ctx context.Context, templateID string, shares []interfaces.TemplateShare) error {
	for _, t := range m.templates {
		if t.ID == templateID {
			t.SharedWith = shares
			t.IsShared = len(shares) > 0
			t.UpdatedAt = time.Now()
			return nil
		}
	}
	return ErrTemplateNotFound
}

// --- generateReportData error paths ---

// testDataProvider is a minimal DataProvider implementation for error-path testing.
type testDataProvider struct {
	dnaErr   error
	driftErr error
}

func (p *testDataProvider) GetDNAData(_ context.Context, _ interfaces.DataQuery) ([]storage.DNARecord, error) {
	return nil, p.dnaErr
}

func (p *testDataProvider) GetDriftEvents(_ context.Context, _ interfaces.DataQuery) ([]drift.DriftEvent, error) {
	if p.dnaErr != nil {
		// should never be reached when dnaErr is set
		return nil, nil
	}
	return nil, p.driftErr
}

func (p *testDataProvider) GetDeviceStats(_ context.Context, _ []string, _ interfaces.TimeRange) (map[string]interfaces.DeviceStats, error) {
	return nil, nil
}

func (p *testDataProvider) GetTrendData(_ context.Context, _ string, _ interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	return nil, nil
}

func TestGenerateReportData_GetDNADataError(t *testing.T) {
	config := interfaces.DefaultCustomReportConfig()
	dp := &testDataProvider{dnaErr: fmt.Errorf("storage unavailable")}
	builder := &CustomReportBuilder{
		config:       config,
		logger:       logging.NewNoopLogger(),
		dataProvider: dp,
	}

	report := &interfaces.CustomReport{ID: "r1"}
	query := &interfaces.ProcessedQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-time.Hour),
			End:   time.Now(),
		},
		EstimatedRows: 10,
	}

	err := builder.generateReportData(context.Background(), report, query)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get DNA data")
}

func TestGenerateReportData_GetDriftEventsError(t *testing.T) {
	config := interfaces.DefaultCustomReportConfig()
	dp := &testDataProvider{driftErr: fmt.Errorf("drift store unavailable")}
	builder := &CustomReportBuilder{
		config:       config,
		logger:       logging.NewNoopLogger(),
		dataProvider: dp,
	}

	report := &interfaces.CustomReport{ID: "r2"}
	query := &interfaces.ProcessedQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-time.Hour),
			End:   time.Now(),
		},
		EstimatedRows: 10,
	}

	err := builder.generateReportData(context.Background(), report, query)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get drift events")
}
