package reports

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScheduledReportManager(t *testing.T) {
	t.Run("ScheduleReport_ValidRequest", func(t *testing.T) {
		store := &MockScheduledReportStore{}
		templateManager := &MockCustomTemplateManager{}
		reportBuilder := &MockCustomReportBuilder{}
		manager := &ScheduledReportManager{
			store:           store,
			templateManager: templateManager,
			reportBuilder:   reportBuilder,
			logger:          &MockLogger{},
		}

		req := interfaces.ScheduleReportRequest{
			Name:         "Weekly Compliance Report",
			TemplateID:   "template-123",
			Parameters:   map[string]interface{}{"threshold": 90.0},
			Schedule: interfaces.ReportSchedule{
				Type:       interfaces.ScheduleTypeInterval,
				Expression: "168h", // Every 7 days (7 * 24 hours)
				Timezone:   "UTC",
			},
			Format:       interfaces.FormatPDF,
			DeliveryMode: interfaces.DeliveryModeEmail,
			Recipients: []interfaces.ReportRecipient{
				{
					Type:    "email",
					Address: "admin@example.com",
					Name:    "Administrator",
				},
			},
			TenantID:  "tenant-123",
			CreatedBy: "user-123",
		}

		schedule, err := manager.ScheduleReport(context.Background(), req)
		require.NoError(t, err)
		assert.NotNil(t, schedule)
		assert.NotEmpty(t, schedule.ID)
		assert.Equal(t, req.Name, schedule.Name)
		assert.Equal(t, req.TemplateID, schedule.TemplateID)
		assert.True(t, schedule.IsActive)
		assert.NotNil(t, schedule.NextRun)
	})

	t.Run("ScheduleReport_InvalidSchedule", func(t *testing.T) {
		store := &MockScheduledReportStore{}
		templateManager := &MockCustomTemplateManager{}
		reportBuilder := &MockCustomReportBuilder{}
		manager := &ScheduledReportManager{
			store:           store,
			templateManager: templateManager,
			reportBuilder:   reportBuilder,
			logger:          &MockLogger{},
		}

		req := interfaces.ScheduleReportRequest{
			Name:       "Invalid Schedule Report",
			TemplateID: "template-123",
			Schedule: interfaces.ReportSchedule{
				Type:       interfaces.ScheduleTypeInterval,
				Expression: "invalid-duration",
			},
			Format:    interfaces.FormatJSON,
			TenantID:  "tenant-123",
			CreatedBy: "user-123",
		}

		_, err := manager.ScheduleReport(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid schedule")
	})

	t.Run("ExecuteScheduledReport_Success", func(t *testing.T) {
		store := &MockScheduledReportStore{}
		templateManager := &MockCustomTemplateManager{}
		reportBuilder := &MockCustomReportBuilder{}
		manager := &ScheduledReportManager{
			store:           store,
			templateManager: templateManager,
			reportBuilder:   reportBuilder,
			logger:          &MockLogger{},
		}

		// Setup scheduled report in store
		schedule := &interfaces.ScheduledReport{
			ID:         "schedule-123",
			Name:       "Test Schedule",
			TemplateID: "template-123",
			TenantID:   "tenant-123",
			Format:     interfaces.FormatJSON,
			Parameters: map[string]interface{}{"param1": "value1"},
		}
		store.schedules = []*interfaces.ScheduledReport{schedule}

		report, err := manager.ExecuteScheduledReport(context.Background(), "schedule-123")
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, interfaces.FormatJSON, report.Format)

		// Verify execution tracking was updated
		updatedSchedule, _ := store.GetByID(context.Background(), "schedule-123")
		assert.Equal(t, 1, updatedSchedule.RunCount)
		assert.NotNil(t, updatedSchedule.LastRun)
		assert.Empty(t, updatedSchedule.LastError)
	})

	t.Run("ValidateSchedule_CronExpression", func(t *testing.T) {
		manager := &ScheduledReportManager{
			logger: &MockLogger{},
		}

		// Valid cron expression
		schedule := interfaces.ReportSchedule{
			Type:       interfaces.ScheduleTypeCron,
			Expression: "0 9 * * 1", // Every Monday at 9 AM
			Timezone:   "UTC",
		}
		err := manager.validateSchedule(schedule)
		assert.NoError(t, err)

		// Invalid cron expression
		schedule.Expression = "0"
		err = manager.validateSchedule(schedule)
		assert.Error(t, err)
	})

	t.Run("ValidateSchedule_IntervalExpression", func(t *testing.T) {
		manager := &ScheduledReportManager{
			logger: &MockLogger{},
		}

		// Valid interval
		schedule := interfaces.ReportSchedule{
			Type:       interfaces.ScheduleTypeInterval,
			Expression: "1h",
		}
		err := manager.validateSchedule(schedule)
		assert.NoError(t, err)

		// Invalid interval
		schedule.Expression = "invalid"
		err = manager.validateSchedule(schedule)
		assert.Error(t, err)
	})

	t.Run("ValidateDeliveryMode_Email", func(t *testing.T) {
		manager := &ScheduledReportManager{
			logger: &MockLogger{},
		}

		// Valid email delivery
		recipients := []interfaces.ReportRecipient{
			{Type: "email", Address: "test@example.com"},
		}
		err := manager.validateDeliveryMode(interfaces.DeliveryModeEmail, recipients)
		assert.NoError(t, err)

		// Missing recipients
		err = manager.validateDeliveryMode(interfaces.DeliveryModeEmail, []interfaces.ReportRecipient{})
		assert.Error(t, err)

		// Wrong recipient type
		recipients[0].Type = "webhook"
		err = manager.validateDeliveryMode(interfaces.DeliveryModeEmail, recipients)
		assert.Error(t, err)
	})
}

// Mock implementations for testing

type MockScheduledReportStore struct {
	schedules []*interfaces.ScheduledReport
}

func (m *MockScheduledReportStore) Save(ctx context.Context, schedule *interfaces.ScheduledReport) (*interfaces.ScheduledReport, error) {
	if schedule.ID == "" {
		schedule.ID = "generated-id-" + time.Now().Format("20060102150405")
	}
	schedule.UpdatedAt = time.Now()

	// Update existing or add new
	for i, existing := range m.schedules {
		if existing.ID == schedule.ID {
			m.schedules[i] = schedule
			return schedule, nil
		}
	}

	m.schedules = append(m.schedules, schedule)
	return schedule, nil
}

func (m *MockScheduledReportStore) GetByID(ctx context.Context, id string) (*interfaces.ScheduledReport, error) {
	for _, schedule := range m.schedules {
		if schedule.ID == id {
			return schedule, nil
		}
	}
	return nil, ErrTemplateNotFound
}

func (m *MockScheduledReportStore) GetByTenant(ctx context.Context, tenantID string) ([]*interfaces.ScheduledReport, error) {
	var result []*interfaces.ScheduledReport
	for _, schedule := range m.schedules {
		if schedule.TenantID == tenantID {
			result = append(result, schedule)
		}
	}
	return result, nil
}

func (m *MockScheduledReportStore) GetDueReports(ctx context.Context, before time.Time) ([]*interfaces.ScheduledReport, error) {
	var result []*interfaces.ScheduledReport
	for _, schedule := range m.schedules {
		if schedule.IsActive && schedule.NextRun != nil && schedule.NextRun.Before(before) {
			result = append(result, schedule)
		}
	}
	return result, nil
}

func (m *MockScheduledReportStore) Delete(ctx context.Context, id string) error {
	for i, schedule := range m.schedules {
		if schedule.ID == id {
			m.schedules = append(m.schedules[:i], m.schedules[i+1:]...)
			return nil
		}
	}
	return ErrTemplateNotFound
}

type MockCustomTemplateManager struct {
	templates []*interfaces.CustomReportTemplate
}

func (m *MockCustomTemplateManager) SaveTemplate(ctx context.Context, template *interfaces.CustomReportTemplate) (*interfaces.CustomReportTemplate, error) {
	return template, nil
}

func (m *MockCustomTemplateManager) GetTemplate(ctx context.Context, templateID, tenantID string) (*interfaces.CustomReportTemplate, error) {
	// Return a mock template
	return &interfaces.CustomReportTemplate{
		ID:       templateID,
		Name:     "Mock Template",
		TenantID: tenantID,
		Query: interfaces.CustomQuery{
			DataSources: []string{"dna"},
			TimeRange: interfaces.TimeRange{
				Start: time.Now().Add(-24 * time.Hour),
				End:   time.Now(),
			},
		},
		Parameters: []interfaces.CustomParameter{
			{
				Name: "param1",
				Type: "string",
			},
		},
	}, nil
}

func (m *MockCustomTemplateManager) GetAccessibleTemplates(ctx context.Context, tenantID string) ([]*interfaces.CustomReportTemplate, error) {
	return m.templates, nil
}

func (m *MockCustomTemplateManager) ShareTemplate(ctx context.Context, req interfaces.ShareTemplateRequest) error {
	return nil
}

func (m *MockCustomTemplateManager) DeleteTemplate(ctx context.Context, templateID, tenantID string) error {
	return nil
}

type MockCustomReportBuilder struct{}

func (m *MockCustomReportBuilder) CreateCustomReport(ctx context.Context, req interfaces.CustomReportRequest) (*interfaces.CustomReport, error) {
	return m.GenerateReport(ctx, req)
}

func (m *MockCustomReportBuilder) GenerateReport(ctx context.Context, req interfaces.CustomReportRequest) (*interfaces.CustomReport, error) {
	return &interfaces.CustomReport{
		ID:          "report-" + time.Now().Format("20060102150405"),
		Name:        req.Name,
		TenantID:    req.TenantID,
		CreatedBy:   req.CreatedBy,
		CreatedAt:   time.Now(),
		Format:      req.Format,
		GeneratedAt: time.Now(),
		Data:        map[string]interface{}{"test": "data"},
	}, nil
}

func (m *MockCustomReportBuilder) ValidateParameters(template *interfaces.CustomReportTemplate, params map[string]interface{}) error {
	return nil // Mock always validates successfully
}

func (m *MockCustomReportBuilder) BuildQuery(query interfaces.CustomQuery) (*interfaces.ProcessedQuery, error) {
	return &interfaces.ProcessedQuery{
		DataSources:   query.DataSources,
		Filters:       query.Filters,
		Aggregations:  query.Aggregations,
		Sorting:       query.Sorting,
		TimeRange:     query.TimeRange,
		Pagination:    query.Pagination,
		EstimatedRows: 1000,
		Complexity:    "medium",
		CacheKey:      "test-cache-key",
		Timeout:       5 * time.Minute,
	}, nil
}

func (m *MockCustomReportBuilder) GetReportData(ctx context.Context, pagination interfaces.PaginationRequest) ([]byte, bool, error) {
	return []byte(`{"data": "test"}`), false, nil
}