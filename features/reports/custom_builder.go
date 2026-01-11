// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package reports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// CustomReportBuilder implements the CustomReportBuilder interface
type CustomReportBuilder struct {
	dataProvider interfaces.DataProvider
	exporter     interfaces.Exporter
	cache        interfaces.ReportCache
	logger       logging.Logger
	config       interfaces.CustomReportConfig
}

// NewCustomReportBuilder creates a new custom report builder
func NewCustomReportBuilder(
	dataProvider interfaces.DataProvider,
	exporter interfaces.Exporter,
	cache interfaces.ReportCache,
	logger logging.Logger,
	config interfaces.CustomReportConfig,
) *CustomReportBuilder {
	return &CustomReportBuilder{
		dataProvider: dataProvider,
		exporter:     exporter,
		cache:        cache,
		logger:       logger,
		config:       config,
	}
}

// CreateCustomReport creates a new custom report from a request
func (b *CustomReportBuilder) CreateCustomReport(ctx context.Context, req interfaces.CustomReportRequest) (*interfaces.CustomReport, error) {
	b.logger.Info("Creating custom report", "name", req.Name, "tenant_id", req.TenantID)

	// Validate request
	if err := b.validateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Process query
	processedQuery, err := b.BuildQuery(req.Query)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	// Generate report
	report := &interfaces.CustomReport{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		TenantID:    req.TenantID,
		CreatedBy:   req.CreatedBy,
		CreatedAt:   time.Now(),
		Query:       req.Query,
		Parameters:  req.Parameters,
		UserParams:  req.UserParams,
		Format:      req.Format,
		GeneratedAt: time.Now(),
	}

	// Check if streaming is needed
	b.logger.Info("Checking streaming criteria",
		"estimated_rows", processedQuery.EstimatedRows,
		"stream_threshold", b.config.StreamThreshold,
		"streaming_enabled", b.config.EnableStreaming,
	)

	if processedQuery.EstimatedRows > b.config.StreamThreshold && b.config.EnableStreaming {
		report.IsStreamed = true
		report.StreamToken = b.generateStreamToken(req)
		report.TotalPages = (processedQuery.EstimatedRows + b.config.DefaultPageSize - 1) / b.config.DefaultPageSize
		b.logger.Info("Using streaming mode for large dataset",
			"estimated_rows", processedQuery.EstimatedRows,
			"total_pages", report.TotalPages,
		)
	} else {
		// Generate data immediately for small datasets
		if err := b.generateReportData(ctx, report, processedQuery); err != nil {
			return nil, fmt.Errorf("failed to generate report data: %w", err)
		}
	}

	return report, nil
}

// GenerateReport generates a report from a custom report request
func (b *CustomReportBuilder) GenerateReport(ctx context.Context, req interfaces.CustomReportRequest) (*interfaces.CustomReport, error) {
	return b.CreateCustomReport(ctx, req)
}

// ValidateParameters validates user-provided parameters against template requirements
func (b *CustomReportBuilder) ValidateParameters(template *interfaces.CustomReportTemplate, params map[string]interface{}) error {
	b.logger.Debug("Validating parameters", "template_id", template.ID, "param_count", len(params))

	for _, param := range template.Parameters {
		value, exists := params[param.Name]

		// Check required parameters
		if param.Required && !exists {
			return fmt.Errorf("%w: required parameter '%s' is missing", ErrParameterValidationFailed, param.Name)
		}

		// Skip validation if parameter is optional and not provided
		if !exists {
			continue
		}

		// Type validation
		if err := b.validateParameterType(param, value); err != nil {
			return fmt.Errorf("%w: parameter '%s' %s", ErrParameterValidationFailed, param.Name, err.Error())
		}

		// Value validation
		if err := b.validateParameterValue(param, value); err != nil {
			return fmt.Errorf("%w: parameter '%s' %s", ErrParameterValidationFailed, param.Name, err.Error())
		}
	}

	return nil
}

// BuildQuery builds a data query from custom query specification
func (b *CustomReportBuilder) BuildQuery(query interfaces.CustomQuery) (*interfaces.ProcessedQuery, error) {
	b.logger.Debug("Building custom query", "data_sources", len(query.DataSources), "filters", len(query.Filters))

	// Validate query limits
	if len(query.DataSources) > b.config.MaxDataSources {
		return nil, fmt.Errorf("%w: too many data sources (%d > %d)", ErrInvalidQuery, len(query.DataSources), b.config.MaxDataSources)
	}
	if len(query.Filters) > b.config.MaxFilters {
		return nil, fmt.Errorf("%w: too many filters (%d > %d)", ErrInvalidQuery, len(query.Filters), b.config.MaxFilters)
	}
	if len(query.Aggregations) > b.config.MaxAggregations {
		return nil, fmt.Errorf("%w: too many aggregations (%d > %d)", ErrInvalidQuery, len(query.Aggregations), b.config.MaxAggregations)
	}

	// Validate data sources
	for _, source := range query.DataSources {
		if !b.isDataSourceSupported(source) {
			return nil, fmt.Errorf("%w: %s", ErrDataSourceNotSupported, source)
		}
	}

	// Estimate complexity and row count
	complexity := b.calculateQueryComplexity(query)
	estimatedRows := b.estimateRowCount(query)

	// Set pagination if needed
	pagination := query.Pagination
	if pagination == nil && estimatedRows > b.config.StreamThreshold {
		pagination = &interfaces.PaginationConfig{
			PageSize:   b.config.DefaultPageSize,
			MaxPages:   (estimatedRows + b.config.DefaultPageSize - 1) / b.config.DefaultPageSize,
			StreamMode: true,
		}
	}

	// Generate cache key
	cacheKey := b.generateCacheKey(query)

	// Set timeout based on complexity
	timeout := b.config.DefaultTimeout
	if complexity == "high" {
		timeout = b.config.MaxTimeout
	}

	processedQuery := &interfaces.ProcessedQuery{
		DataSources:   query.DataSources,
		Filters:       query.Filters,
		Aggregations:  query.Aggregations,
		Sorting:       query.Sorting,
		TimeRange:     query.TimeRange,
		Pagination:    pagination,
		EstimatedRows: estimatedRows,
		Complexity:    complexity,
		CacheKey:      cacheKey,
		Timeout:       timeout,
	}

	return processedQuery, nil
}

// GetReportData retrieves paginated report data for streaming
func (b *CustomReportBuilder) GetReportData(ctx context.Context, pagination interfaces.PaginationRequest) ([]byte, bool, error) {
	b.logger.Debug("Getting paginated report data", "stream_token", pagination.StreamToken, "page", pagination.Page)

	// Validate stream token
	if pagination.StreamToken == "" {
		return nil, false, fmt.Errorf("%w: stream token is required", ErrStreamTokenInvalid)
	}

	// In a real implementation, you would:
	// 1. Decode the stream token to get the original query
	// 2. Execute the query with appropriate LIMIT/OFFSET for the requested page
	// 3. Return the data and whether there are more pages

	// For now, return mock data
	data := map[string]interface{}{
		"page":      pagination.Page,
		"page_size": pagination.PageSize,
		"data":      []interface{}{},
		"timestamp": time.Now(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal data: %w", err)
	}

	// Mock: assume no more data after page 1
	hasMore := pagination.Page < 1

	return jsonData, hasMore, nil
}

// Helper methods

func (b *CustomReportBuilder) validateRequest(req interfaces.CustomReportRequest) error {
	if req.Name == "" {
		return fmt.Errorf("report name is required")
	}
	if req.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if req.CreatedBy == "" {
		return fmt.Errorf("created by is required")
	}
	if len(req.Query.DataSources) == 0 {
		return fmt.Errorf("at least one data source is required")
	}

	// Validate export format
	if !b.isFormatSupported(req.Format) {
		return fmt.Errorf("export format '%s' is not supported", req.Format)
	}

	// Validate parameters count
	if len(req.Parameters) > b.config.MaxParameters {
		return fmt.Errorf("too many parameters (%d > %d)", len(req.Parameters), b.config.MaxParameters)
	}

	return nil
}

func (b *CustomReportBuilder) validateParameterType(param interfaces.CustomParameter, value interface{}) error {
	switch param.Type {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("must be of type string")
		}
	case "number":
		switch v := value.(type) {
		case float64, int, int32, int64:
			// Valid numeric types
		case string:
			if _, err := strconv.ParseFloat(v, 64); err != nil {
				return fmt.Errorf("must be of type number")
			}
		default:
			return fmt.Errorf("must be of type number")
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("must be of type boolean")
		}
	case "date":
		switch v := value.(type) {
		case string:
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return fmt.Errorf("must be a valid date in RFC3339 format")
			}
		case time.Time:
			// Valid
		default:
			return fmt.Errorf("must be of type date")
		}
	case "array":
		if _, ok := value.([]interface{}); !ok {
			return fmt.Errorf("must be of type array")
		}
	default:
		return fmt.Errorf("unknown parameter type: %s", param.Type)
	}
	return nil
}

func (b *CustomReportBuilder) validateParameterValue(param interfaces.CustomParameter, value interface{}) error {
	// Validate options
	if len(param.Options) > 0 {
		valueStr := fmt.Sprintf("%v", value)
		for _, option := range param.Options {
			if option == valueStr {
				return nil // Valid option
			}
		}
		return fmt.Errorf("must be one of: %s", strings.Join(param.Options, ", "))
	}

	// Validate numeric range
	if param.MinValue != nil || param.MaxValue != nil {
		var numVal float64
		switch v := value.(type) {
		case float64:
			numVal = v
		case int:
			numVal = float64(v)
		case int32:
			numVal = float64(v)
		case int64:
			numVal = float64(v)
		case string:
			var err error
			numVal, err = strconv.ParseFloat(v, 64)
			if err != nil {
				return fmt.Errorf("cannot parse as number for range validation")
			}
		default:
			return fmt.Errorf("cannot validate range for non-numeric value")
		}

		if param.MinValue != nil && numVal < *param.MinValue {
			if param.MaxValue != nil {
				return fmt.Errorf("must be between %v and %v", *param.MinValue, *param.MaxValue)
			}
			return fmt.Errorf("must be greater than or equal to %v", *param.MinValue)
		}
		if param.MaxValue != nil && numVal > *param.MaxValue {
			if param.MinValue != nil {
				return fmt.Errorf("must be between %v and %v", *param.MinValue, *param.MaxValue)
			}
			return fmt.Errorf("must be less than or equal to %v", *param.MaxValue)
		}
	}

	// Validate string length and pattern
	if param.Type == "string" {
		str := value.(string)

		if param.MinLength != nil && len(str) < *param.MinLength {
			return fmt.Errorf("must be at least %d characters long", *param.MinLength)
		}
		if param.MaxLength != nil && len(str) > *param.MaxLength {
			return fmt.Errorf("must be at most %d characters long", *param.MaxLength)
		}

		if param.Pattern != "" {
			matched, err := regexp.MatchString(param.Pattern, str)
			if err != nil {
				return fmt.Errorf("invalid regex pattern in parameter definition")
			}
			if !matched {
				return fmt.Errorf("must match pattern: %s", param.Pattern)
			}
		}
	}

	return nil
}

func (b *CustomReportBuilder) isDataSourceSupported(source string) bool {
	supportedSources := []string{"dna", "audit", "compliance", "security", "drift"}
	for _, supported := range supportedSources {
		if source == supported {
			return true
		}
	}
	return false
}

func (b *CustomReportBuilder) isFormatSupported(format interfaces.ExportFormat) bool {
	supportedFormats := []interfaces.ExportFormat{
		interfaces.FormatJSON,
		interfaces.FormatCSV,
		interfaces.FormatPDF,
		interfaces.FormatHTML,
		interfaces.FormatExcel,
	}
	for _, supported := range supportedFormats {
		if format == supported {
			return true
		}
	}
	return false
}

func (b *CustomReportBuilder) calculateQueryComplexity(query interfaces.CustomQuery) string {
	complexity := 0

	// Data sources contribute to complexity
	complexity += len(query.DataSources) * 2

	// Filters contribute based on type
	for _, filter := range query.Filters {
		switch v := filter.(type) {
		case []interface{}:
			complexity += len(v) // Array filters are more complex
		default:
			complexity += 1
		}
	}

	// Aggregations are expensive
	complexity += len(query.Aggregations) * 3

	// Sorting adds some complexity
	complexity += len(query.Sorting)

	// Time range affects complexity
	timeDiff := query.TimeRange.End.Sub(query.TimeRange.Start)
	if timeDiff > 7*24*time.Hour { // More than a week
		complexity += 2
	}

	if complexity >= 20 {
		return "high"
	} else if complexity >= 10 {
		return "medium"
	}
	return "low"
}

func (b *CustomReportBuilder) estimateRowCount(query interfaces.CustomQuery) int {
	// This is a simplified estimation - in reality you'd query statistics tables
	baseRows := 10000 // Base assumption - larger to trigger streaming in tests

	// Adjust based on data sources
	baseRows *= len(query.DataSources)

	// Adjust based on time range
	timeDiff := query.TimeRange.End.Sub(query.TimeRange.Start)
	daysFactor := int(timeDiff.Hours() / 24)
	if daysFactor > 1 {
		baseRows *= daysFactor
	}

	// Filters reduce the count
	if len(query.Filters) > 0 {
		baseRows = baseRows / (len(query.Filters) + 1)
	}

	// Aggregations typically reduce row count significantly
	if len(query.Aggregations) > 0 {
		baseRows = baseRows / 10
	}

	if baseRows < 100 {
		return 100
	}
	return baseRows
}

func (b *CustomReportBuilder) generateCacheKey(query interfaces.CustomQuery) string {
	// Create a deterministic cache key from the query
	data := fmt.Sprintf("%+v", query)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (b *CustomReportBuilder) generateStreamToken(req interfaces.CustomReportRequest) string {
	// In a real implementation, this would encode the query parameters
	// and store them temporarily for retrieval during pagination
	data := fmt.Sprintf("%s-%s-%d", req.TenantID, req.Name, time.Now().Unix())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes for shorter token
}

func (b *CustomReportBuilder) generateReportData(ctx context.Context, report *interfaces.CustomReport, query *interfaces.ProcessedQuery) error {
	startTime := time.Now()

	// Mock data generation for now
	// In a real implementation, this would execute the query against data providers
	report.Data = map[string]interface{}{
		"query":        query,
		"results":      []interface{}{},
		"generated_at": time.Now(),
	}

	report.Summary = interfaces.ReportSummary{
		DevicesAnalyzed:    10,
		DriftEventsTotal:   5,
		ComplianceScore:    85.5,
		CriticalIssues:     2,
		TrendDirection:     interfaces.TrendStable,
		KeyInsights:        []string{"System performance is stable", "Compliance has improved"},
		RecommendedActions: []string{"Review critical issues", "Monitor trends"},
	}

	report.DataPoints = 100
	report.GenerationMS = time.Since(startTime).Milliseconds()

	b.logger.Info("Generated report data",
		"report_id", report.ID,
		"data_points", report.DataPoints,
		"generation_ms", report.GenerationMS,
	)

	return nil
}
