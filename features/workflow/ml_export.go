package workflow

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// MLDataExporter provides data export capabilities for ML analysis tools
type MLDataExporter struct {
	loggingProvider interfaces.LoggingProvider
}

// NewMLDataExporter creates a new ML data exporter
func NewMLDataExporter(provider interfaces.LoggingProvider) *MLDataExporter {
	return &MLDataExporter{
		loggingProvider: provider,
	}
}

// ExportFormat defines supported export formats
type ExportFormat string

const (
	ExportFormatJSON    ExportFormat = "json"
	ExportFormatCSV     ExportFormat = "csv"
	ExportFormatJSONL   ExportFormat = "jsonl"   // JSON Lines format
	ExportFormatParquet ExportFormat = "parquet" // Future: Parquet for large datasets
)

// ExportRequest defines parameters for data export
type ExportRequest struct {
	// Time range
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	// Filters
	WorkflowNames []string `json:"workflow_names,omitempty"`
	ExecutionIDs  []string `json:"execution_ids,omitempty"`
	EventTypes    []string `json:"event_types,omitempty"`
	StepNames     []string `json:"step_names,omitempty"`

	// Export configuration
	Format         ExportFormat `json:"format"`
	IncludeHeaders bool         `json:"include_headers"`
	MaxRecords     int          `json:"max_records,omitempty"` // 0 = no limit

	// Data selection
	IncludeVariableStates  bool `json:"include_variable_states"`
	IncludeAPIData         bool `json:"include_api_data"`
	IncludePerformanceData bool `json:"include_performance_data"`
	IncludeErrorPatterns   bool `json:"include_error_patterns"`

	// ML-specific options
	FlattenNestedData   bool     `json:"flatten_nested_data"`
	IncludeOnlyMLEvents bool     `json:"include_only_ml_events"`
	ExcludeFields       []string `json:"exclude_fields,omitempty"`
	CustomFields        []string `json:"custom_fields,omitempty"`
}

// ExportResult contains the result of an export operation
type ExportResult struct {
	RecordCount    int           `json:"record_count"`
	BytesExported  int64         `json:"bytes_exported"`
	ProcessingTime time.Duration `json:"processing_time"`
	Format         ExportFormat  `json:"format"`
	Filters        ExportRequest `json:"filters"`
	ExportedAt     time.Time     `json:"exported_at"`
}

// ExportMLData exports ML logging data in the specified format
func (exporter *MLDataExporter) ExportMLData(ctx context.Context, request ExportRequest, writer io.Writer) (*ExportResult, error) {
	startTime := time.Now()

	// Query data from logging provider
	query := interfaces.TimeRangeQuery{
		StartTime: request.StartTime,
		EndTime:   request.EndTime,
		Filters:   buildFilters(request),
		Limit:     request.MaxRecords,
		OrderBy:   "timestamp",
		SortDesc:  false,
	}

	entries, err := exporter.loggingProvider.QueryTimeRange(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query ML data: %w", err)
	}

	// Filter and convert entries
	mlEntries, err := exporter.extractMLEntries(entries, request)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ML entries: %w", err)
	}

	// Export in requested format
	bytesWritten := int64(0)
	switch request.Format {
	case ExportFormatJSON:
		bytesWritten, err = exporter.exportJSON(mlEntries, writer, request)
	case ExportFormatCSV:
		bytesWritten, err = exporter.exportCSV(mlEntries, writer, request)
	case ExportFormatJSONL:
		bytesWritten, err = exporter.exportJSONLines(mlEntries, writer, request)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", request.Format)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to export data: %w", err)
	}

	result := &ExportResult{
		RecordCount:    len(mlEntries),
		BytesExported:  bytesWritten,
		ProcessingTime: time.Since(startTime),
		Format:         request.Format,
		Filters:        request,
		ExportedAt:     time.Now(),
	}

	return result, nil
}

// extractMLEntries extracts and filters ML log entries from standard log entries
func (exporter *MLDataExporter) extractMLEntries(entries []interfaces.LogEntry, request ExportRequest) ([]MLLogEntry, error) {
	var mlEntries []MLLogEntry

	for _, entry := range entries {
		// Check if this is an ML log entry
		if entry.Component != "ml_logger" {
			continue
		}

		// Extract ML data from the fields
		mlDataStr, exists := entry.Fields["ml_data"].(string)
		if !exists {
			continue
		}

		var mlEntry MLLogEntry
		if err := json.Unmarshal([]byte(mlDataStr), &mlEntry); err != nil {
			// Log error but continue processing
			continue
		}

		// Apply filters
		if !exporter.matchesFilters(mlEntry, request) {
			continue
		}

		// Apply data selection filters
		mlEntry = exporter.applyDataSelection(mlEntry, request)

		mlEntries = append(mlEntries, mlEntry)
	}

	return mlEntries, nil
}

// matchesFilters checks if an ML entry matches the export filters
func (exporter *MLDataExporter) matchesFilters(entry MLLogEntry, request ExportRequest) bool {
	// Filter by workflow names
	if len(request.WorkflowNames) > 0 {
		found := false
		for _, name := range request.WorkflowNames {
			if entry.WorkflowName == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by execution IDs
	if len(request.ExecutionIDs) > 0 {
		found := false
		for _, id := range request.ExecutionIDs {
			if entry.ExecutionID == id {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by event types
	if len(request.EventTypes) > 0 {
		found := false
		for _, eventType := range request.EventTypes {
			if entry.EventType == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by step names
	if len(request.StepNames) > 0 && entry.StepName != "" {
		found := false
		for _, stepName := range request.StepNames {
			if entry.StepName == stepName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter ML-only events
	if request.IncludeOnlyMLEvents {
		mlEventTypes := []string{"execution_start", "execution_end", "step_start", "step_end",
			"variable_change", "api_request", "api_response", "performance_snapshot", "error_pattern"}
		found := false
		for _, mlType := range mlEventTypes {
			if entry.EventType == mlType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// applyDataSelection applies data selection filters to ML entries
func (exporter *MLDataExporter) applyDataSelection(entry MLLogEntry, request ExportRequest) MLLogEntry {
	// Remove data based on inclusion flags
	if !request.IncludeVariableStates {
		entry.VariableStates = nil
		entry.VariableChanges = nil
	}

	if !request.IncludeAPIData {
		entry.APIRequestData = nil
		entry.APIResponseData = nil
	}

	if !request.IncludePerformanceData {
		entry.PerformanceMetrics = nil
	}

	if !request.IncludeErrorPatterns {
		entry.ErrorPattern = nil
	}

	return entry
}

// exportJSON exports ML entries as JSON
func (exporter *MLDataExporter) exportJSON(entries []MLLogEntry, writer io.Writer, request ExportRequest) (int64, error) {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")

	data := map[string]interface{}{
		"export_metadata": map[string]interface{}{
			"exported_at":  time.Now(),
			"record_count": len(entries),
			"format":       request.Format,
			"time_range":   map[string]time.Time{"start": request.StartTime, "end": request.EndTime},
		},
		"ml_log_entries": entries,
	}

	if err := encoder.Encode(data); err != nil {
		return 0, err
	}

	// Calculate approximate bytes written
	jsonBytes, _ := json.Marshal(data)
	return int64(len(jsonBytes)), nil
}

// exportJSONLines exports ML entries as JSON Lines format (one JSON object per line)
func (exporter *MLDataExporter) exportJSONLines(entries []MLLogEntry, writer io.Writer, request ExportRequest) (int64, error) {
	encoder := json.NewEncoder(writer)
	bytesWritten := int64(0)

	// Write metadata as first line
	metadata := map[string]interface{}{
		"_metadata": map[string]interface{}{
			"exported_at":  time.Now(),
			"record_count": len(entries),
			"format":       request.Format,
			"time_range":   map[string]time.Time{"start": request.StartTime, "end": request.EndTime},
		},
	}

	if err := encoder.Encode(metadata); err != nil {
		return 0, err
	}

	// Write each entry as a separate line
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			return bytesWritten, err
		}
	}

	// Estimate bytes written
	for _, entry := range entries {
		entryBytes, _ := json.Marshal(entry)
		bytesWritten += int64(len(entryBytes))
	}

	return bytesWritten, nil
}

// exportCSV exports ML entries as CSV format (flattened)
func (exporter *MLDataExporter) exportCSV(entries []MLLogEntry, writer io.Writer, request ExportRequest) (int64, error) {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	if len(entries) == 0 {
		return 0, nil
	}

	// Determine columns based on first entry and request
	columns := exporter.determineCSVColumns(entries[0], request)

	bytesWritten := int64(0)

	// Write headers if requested
	if request.IncludeHeaders {
		if err := csvWriter.Write(columns); err != nil {
			return 0, err
		}
		bytesWritten += int64(len(strings.Join(columns, ",")))
	}

	// Write data rows
	for _, entry := range entries {
		row := exporter.flattenEntryToCSVRow(entry, columns, request)
		if err := csvWriter.Write(row); err != nil {
			return bytesWritten, err
		}
		bytesWritten += int64(len(strings.Join(row, ",")))
	}

	return bytesWritten, nil
}

// determineCSVColumns determines CSV column headers based on ML entry structure
func (exporter *MLDataExporter) determineCSVColumns(entry MLLogEntry, request ExportRequest) []string {
	columns := []string{
		"timestamp", "execution_id", "workflow_name", "step_name", "event_type",
		"start_time", "end_time", "duration_ms",
	}

	// Add columns based on inclusion flags
	if request.IncludeVariableStates {
		columns = append(columns, "variable_states_json")
	}

	if request.IncludeAPIData {
		columns = append(columns, "api_request_url", "api_request_method", "api_response_status", "api_response_time_ms")
	}

	if request.IncludePerformanceData {
		columns = append(columns, "cpu_usage_percent", "memory_usage_bytes", "goroutine_count", "gc_count")
	}

	if request.IncludeErrorPatterns {
		columns = append(columns, "error_code", "error_message", "error_category", "is_recoverable")
	}

	// Add custom fields
	if len(request.CustomFields) > 0 {
		columns = append(columns, request.CustomFields...)
	}

	// Remove excluded fields
	if len(request.ExcludeFields) > 0 {
		filteredColumns := make([]string, 0, len(columns))
		for _, col := range columns {
			excluded := false
			for _, excludeField := range request.ExcludeFields {
				if col == excludeField {
					excluded = true
					break
				}
			}
			if !excluded {
				filteredColumns = append(filteredColumns, col)
			}
		}
		columns = filteredColumns
	}

	return columns
}

// flattenEntryToCSVRow converts an ML entry to CSV row values
func (exporter *MLDataExporter) flattenEntryToCSVRow(entry MLLogEntry, columns []string, request ExportRequest) []string {
	row := make([]string, len(columns))

	for i, column := range columns {
		switch column {
		case "timestamp":
			row[i] = entry.Timestamp.Format(time.RFC3339)
		case "execution_id":
			row[i] = entry.ExecutionID
		case "workflow_name":
			row[i] = entry.WorkflowName
		case "step_name":
			row[i] = entry.StepName
		case "event_type":
			row[i] = entry.EventType
		case "start_time":
			if !entry.StartTime.IsZero() {
				row[i] = entry.StartTime.Format(time.RFC3339)
			}
		case "end_time":
			if !entry.EndTime.IsZero() {
				row[i] = entry.EndTime.Format(time.RFC3339)
			}
		case "duration_ms":
			if entry.Duration > 0 {
				row[i] = strconv.FormatInt(entry.Duration.Milliseconds(), 10)
			}
		case "variable_states_json":
			if entry.VariableStates != nil {
				if jsonBytes, err := json.Marshal(entry.VariableStates); err == nil {
					row[i] = string(jsonBytes)
				}
			}
		case "api_request_url":
			if entry.APIRequestData != nil {
				row[i] = entry.APIRequestData.URL
			}
		case "api_request_method":
			if entry.APIRequestData != nil {
				row[i] = entry.APIRequestData.Method
			}
		case "api_response_status":
			if entry.APIResponseData != nil {
				row[i] = strconv.Itoa(entry.APIResponseData.StatusCode)
			}
		case "api_response_time_ms":
			if entry.APIResponseData != nil {
				row[i] = strconv.FormatInt(entry.APIResponseData.ResponseTime.Milliseconds(), 10)
			}
		case "cpu_usage_percent":
			if entry.PerformanceMetrics != nil {
				row[i] = strconv.FormatFloat(entry.PerformanceMetrics.CPUUsagePercent, 'f', 2, 64)
			}
		case "memory_usage_bytes":
			if entry.PerformanceMetrics != nil {
				row[i] = strconv.FormatUint(entry.PerformanceMetrics.MemoryUsageBytes, 10)
			}
		case "goroutine_count":
			if entry.PerformanceMetrics != nil {
				row[i] = strconv.Itoa(entry.PerformanceMetrics.GoRoutineCount)
			}
		case "gc_count":
			if entry.PerformanceMetrics != nil {
				row[i] = strconv.FormatUint(uint64(entry.PerformanceMetrics.GCCount), 10)
			}
		case "error_code":
			if entry.ErrorPattern != nil {
				row[i] = entry.ErrorPattern.ErrorCode
			}
		case "error_message":
			if entry.ErrorPattern != nil {
				row[i] = entry.ErrorPattern.ErrorMessage
			}
		case "error_category":
			if entry.ErrorPattern != nil {
				row[i] = entry.ErrorPattern.FailureCategory
			}
		case "is_recoverable":
			if entry.ErrorPattern != nil {
				row[i] = strconv.FormatBool(entry.ErrorPattern.IsRecoverable)
			}
		default:
			// Handle custom fields from ML metadata
			if entry.MLMetadata != nil {
				if value, exists := entry.MLMetadata[column]; exists {
					if valueStr, ok := value.(string); ok {
						row[i] = valueStr
					} else {
						row[i] = fmt.Sprintf("%v", value)
					}
				}
			}
		}
	}

	return row
}

// buildFilters builds query filters from export request
func buildFilters(request ExportRequest) map[string]interface{} {
	filters := make(map[string]interface{})

	// Add component filter to get only ML logging entries
	filters["component"] = "ml_logger"

	// Note: Workflow name filtering is handled in extractMLEntries
	// as the query interface may not support OR conditions directly

	return filters
}

// GetAvailableDataSummary returns a summary of available ML data for a time range
func (exporter *MLDataExporter) GetAvailableDataSummary(ctx context.Context, startTime, endTime time.Time) (*DataSummary, error) {
	query := interfaces.CountQuery{
		StartTime: startTime,
		EndTime:   endTime,
		Filters:   map[string]interface{}{"component": "ml_logger"},
		GroupBy:   []string{"workflow_name", "event_type"},
	}

	count, err := exporter.loggingProvider.QueryCount(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get data summary: %w", err)
	}

	// Get sample entries to analyze structure
	sampleQuery := interfaces.TimeRangeQuery{
		StartTime: startTime,
		EndTime:   endTime,
		Filters:   query.Filters,
		Limit:     100,
		OrderBy:   "timestamp",
	}

	sampleEntries, err := exporter.loggingProvider.QueryTimeRange(ctx, sampleQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get sample entries: %w", err)
	}

	summary := &DataSummary{
		TotalRecords:    count,
		TimeRange:       TimeRange{Start: startTime, End: endTime},
		WorkflowNames:   make(map[string]int64),
		EventTypes:      make(map[string]int64),
		AvailableFields: make([]string, 0),
	}

	// Analyze sample entries
	for _, entry := range sampleEntries {
		// Extract workflow names and event types from sample
		if workflowName, exists := entry.Fields["workflow_name"].(string); exists {
			summary.WorkflowNames[workflowName]++
		}
		if eventType, exists := entry.Fields["ml_event_type"].(string); exists {
			summary.EventTypes[eventType]++
		}
	}

	// Add common available fields
	summary.AvailableFields = []string{
		"timestamp", "execution_id", "workflow_name", "step_name", "event_type",
		"variable_states", "api_request_data", "api_response_data",
		"performance_metrics", "error_pattern", "execution_path",
	}

	return summary, nil
}

// DataSummary provides information about available ML data
type DataSummary struct {
	TotalRecords    int64            `json:"total_records"`
	TimeRange       TimeRange        `json:"time_range"`
	WorkflowNames   map[string]int64 `json:"workflow_names"`
	EventTypes      map[string]int64 `json:"event_types"`
	AvailableFields []string         `json:"available_fields"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
