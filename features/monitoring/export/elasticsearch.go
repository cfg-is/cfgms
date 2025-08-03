package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ElasticsearchExporter exports logs and events to Elasticsearch.
// This enables integration with the ELK stack (Elasticsearch, Logstash, Kibana).
type ElasticsearchExporter struct {
	logger     logging.Logger
	httpClient *http.Client
	config     ElasticsearchConfig
	
	// State tracking
	lastExport   time.Time
	exportCount  int64
	errorCount   int64
	connected    bool
}

// ElasticsearchConfig contains configuration for Elasticsearch export.
type ElasticsearchConfig struct {
	Endpoint     string            `json:"endpoint" yaml:"endpoint"`
	Index        string            `json:"index" yaml:"index"`
	IndexPattern string            `json:"index_pattern" yaml:"index_pattern"` // e.g., "cfgms-logs-%{+yyyy.MM.dd}"
	DocType      string            `json:"doc_type" yaml:"doc_type"`
	Username     string            `json:"username" yaml:"username"`
	Password     string            `json:"password" yaml:"password"`
	APIKey       string            `json:"api_key" yaml:"api_key"`
	Timeout      time.Duration     `json:"timeout" yaml:"timeout"`
	
	// Bulk indexing settings
	BulkSize     int           `json:"bulk_size" yaml:"bulk_size"`
	FlushTimeout time.Duration `json:"flush_timeout" yaml:"flush_timeout"`
	
	// Data settings
	IncludeEvents bool `json:"include_events" yaml:"include_events"`
	IncludeLogs   bool `json:"include_logs" yaml:"include_logs"`
	IncludeHealth bool `json:"include_health" yaml:"include_health"`
	
	// Field mapping
	TimestampField string            `json:"timestamp_field" yaml:"timestamp_field"`
	MessageField   string            `json:"message_field" yaml:"message_field"`
	ExtraFields    map[string]string `json:"extra_fields" yaml:"extra_fields"`
}

// NewElasticsearchExporter creates a new Elasticsearch log exporter.
func NewElasticsearchExporter(logger logging.Logger) *ElasticsearchExporter {
	return &ElasticsearchExporter{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		config: ElasticsearchConfig{
			Endpoint:       "http://localhost:9200",
			Index:          "cfgms-logs",
			IndexPattern:   "cfgms-logs-%{+2006.01.02}", // Go time format
			DocType:        "_doc",
			Timeout:        30 * time.Second,
			BulkSize:       100,
			FlushTimeout:   5 * time.Second,
			IncludeEvents:  true,
			IncludeLogs:    true,
			IncludeHealth:  false,
			TimestampField: "@timestamp",
			MessageField:   "message",
			ExtraFields:    make(map[string]string),
		},
	}
}

// Name returns the name of this exporter.
func (ee *ElasticsearchExporter) Name() string {
	return "elasticsearch"
}

// Configure initializes the Elasticsearch exporter with configuration.
func (ee *ElasticsearchExporter) Configure(config ExporterConfig) error {
	// Use endpoint from general config
	if config.Endpoint != "" {
		ee.config.Endpoint = config.Endpoint
	}
	
	// Use timeout from general config
	if config.Timeout > 0 {
		ee.config.Timeout = config.Timeout
		ee.httpClient.Timeout = config.Timeout
	}
	
	// Use authentication from general config
	if config.Username != "" {
		ee.config.Username = config.Username
	}
	if config.Password != "" {
		ee.config.Password = config.Password
	}
	if config.APIKey != "" {
		ee.config.APIKey = config.APIKey
	}
	
	// Extract Elasticsearch-specific configuration
	if config.Config != nil {
		if index, ok := config.Config["index"].(string); ok {
			ee.config.Index = index
		}
		if indexPattern, ok := config.Config["index_pattern"].(string); ok {
			ee.config.IndexPattern = indexPattern
		}
		if docType, ok := config.Config["doc_type"].(string); ok {
			ee.config.DocType = docType
		}
		if bulkSize, ok := config.Config["bulk_size"].(float64); ok {
			ee.config.BulkSize = int(bulkSize)
		}
		if flushTimeout, ok := config.Config["flush_timeout"].(string); ok {
			if duration, err := time.ParseDuration(flushTimeout); err == nil {
				ee.config.FlushTimeout = duration
			}
		}
		if includeEvents, ok := config.Config["include_events"].(bool); ok {
			ee.config.IncludeEvents = includeEvents
		}
		if includeLogs, ok := config.Config["include_logs"].(bool); ok {
			ee.config.IncludeLogs = includeLogs
		}
		if includeHealth, ok := config.Config["include_health"].(bool); ok {
			ee.config.IncludeHealth = includeHealth
		}
		if timestampField, ok := config.Config["timestamp_field"].(string); ok {
			ee.config.TimestampField = timestampField
		}
		if messageField, ok := config.Config["message_field"].(string); ok {
			ee.config.MessageField = messageField
		}
	}
	
	ee.logger.InfoCtx(context.Background(), "Configured Elasticsearch exporter",
		"endpoint", ee.config.Endpoint,
		"index", ee.config.Index,
		"bulk_size", ee.config.BulkSize,
		"include_events", ee.config.IncludeEvents,
		"include_logs", ee.config.IncludeLogs)
	
	return nil
}

// Start initializes the Elasticsearch exporter.
func (ee *ElasticsearchExporter) Start(ctx context.Context) error {
	ee.logger.InfoCtx(ctx, "Starting Elasticsearch exporter",
		"endpoint", ee.config.Endpoint)
	
	// Test connectivity
	health := ee.HealthCheck(ctx)
	if health.Status != "healthy" {
		ee.logger.WarnCtx(ctx, "Elasticsearch health check failed",
			"status", health.Status,
			"message", health.Message)
		// Don't fail startup - allow degraded operation
	}
	
	return nil
}

// Stop shuts down the Elasticsearch exporter.
func (ee *ElasticsearchExporter) Stop(ctx context.Context) error {
	ee.logger.InfoCtx(ctx, "Stopping Elasticsearch exporter")
	ee.connected = false
	return nil
}

// Export sends monitoring data to Elasticsearch.
func (ee *ElasticsearchExporter) Export(ctx context.Context, data ExportData) error {
	startTime := time.Now()
	
	// Create export context with timeout
	exportCtx, cancel := context.WithTimeout(ctx, ee.config.Timeout)
	defer cancel()
	
	var documents []ElasticsearchDocument
	
	// Process logs if enabled
	if ee.config.IncludeLogs && len(data.Logs) > 0 {
		for _, log := range data.Logs {
			doc := ee.convertLogToDocument(log, data)
			documents = append(documents, doc)
		}
	}
	
	// Process events if enabled
	if ee.config.IncludeEvents && len(data.Events) > 0 {
		for _, event := range data.Events {
			doc := ee.convertEventToDocument(event, data)
			documents = append(documents, doc)
		}
	}
	
	// Process health status if enabled
	if ee.config.IncludeHealth && len(data.HealthStatus) > 0 {
		for component, health := range data.HealthStatus {
			doc := ee.convertHealthToDocument(component, health, data)
			documents = append(documents, doc)
		}
	}
	
	if len(documents) == 0 {
		return nil // Nothing to export
	}
	
	// Send documents to Elasticsearch
	if err := ee.bulkIndex(exportCtx, documents); err != nil {
		ee.errorCount++
		ee.connected = false
		return fmt.Errorf("failed to bulk index documents: %w", err)
	}
	
	// Update state
	ee.lastExport = time.Now()
	ee.exportCount++
	ee.connected = true
	
	ee.logger.DebugCtx(ctx, "Elasticsearch export completed",
		"export_time_ms", time.Since(startTime).Milliseconds(),
		"documents_count", len(documents))
	
	return nil
}

// HealthCheck verifies connectivity to Elasticsearch.
func (ee *ElasticsearchExporter) HealthCheck(ctx context.Context) ExporterHealth {
	health := ExporterHealth{
		Name:            ee.Name(),
		LastHealthCheck: time.Now(),
		ExportCount:     ee.exportCount,
		ErrorCount:      ee.errorCount,
		LastExport:      ee.lastExport,
	}
	
	// Check Elasticsearch cluster health
	healthURL := ee.config.Endpoint + "/_cluster/health"
	
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		health.Status = "unhealthy"
		health.Message = fmt.Sprintf("Failed to create health request: %v", err)
		return health
	}
	
	// Add authentication
	ee.addAuthentication(req)
	
	startTime := time.Now()
	resp, err := ee.httpClient.Do(req)
	responseTime := time.Since(startTime)
	health.ResponseTime = responseTime
	
	if err != nil {
		health.Status = "unhealthy"
		health.Message = fmt.Sprintf("Health check request failed: %v", err)
		return health
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
		}
	}()
	
	if resp.StatusCode != http.StatusOK {
		health.Status = "unhealthy"
		health.Message = fmt.Sprintf("Health check returned status %d", resp.StatusCode)
		return health
	}
	
	// Parse cluster health response
	var clusterHealth map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&clusterHealth); err != nil {
		health.Status = "degraded"
		health.Message = "Could not parse cluster health response"
		return health
	}
	
	// Check cluster status
	if status, ok := clusterHealth["status"].(string); ok {
		switch status {
		case "green":
			health.Status = "healthy"
			health.Message = "Elasticsearch cluster is healthy"
		case "yellow":
			health.Status = "degraded"
			health.Message = "Elasticsearch cluster is degraded (yellow)"
		case "red":
			health.Status = "unhealthy"
			health.Message = "Elasticsearch cluster is unhealthy (red)"
		default:
			health.Status = "unknown"
			health.Message = fmt.Sprintf("Unknown cluster status: %s", status)
		}
	} else {
		health.Status = "degraded"
		health.Message = "Could not determine cluster status"
	}
	
	return health
}

// ElasticsearchDocument represents a document to be indexed in Elasticsearch.
type ElasticsearchDocument struct {
	Index string                 `json:"_index"`
	Type  string                 `json:"_type,omitempty"`
	ID    string                 `json:"_id,omitempty"`
	Source map[string]interface{} `json:"_source"`
}

// convertLogToDocument converts a log entry to an Elasticsearch document.
func (ee *ElasticsearchExporter) convertLogToDocument(log LogEntry, data ExportData) ElasticsearchDocument {
	doc := ElasticsearchDocument{
		Index: ee.getIndexName(log.Timestamp),
		Type:  ee.config.DocType,
		Source: map[string]interface{}{
			ee.config.TimestampField: log.Timestamp.Format(time.RFC3339Nano),
			ee.config.MessageField:   log.Message,
			"level":                  log.Level,
			"component":              log.Component,
			"source":                 log.Source,
			"correlation_id":         log.CorrelationID,
			"trace_id":               log.TraceID,
			"export_type":            data.ExportType,
			"export_source":          data.Source,
			"document_type":          "log",
		},
	}
	
	// Add log fields
	if log.Fields != nil {
		for key, value := range log.Fields {
			doc.Source[key] = value
		}
	}
	
	// Add extra configured fields
	for key, value := range ee.config.ExtraFields {
		doc.Source[key] = value
	}
	
	return doc
}

// convertEventToDocument converts a system event to an Elasticsearch document.
func (ee *ElasticsearchExporter) convertEventToDocument(event SystemEvent, data ExportData) ElasticsearchDocument {
	doc := ElasticsearchDocument{
		Index: ee.getIndexName(event.Timestamp),
		Type:  ee.config.DocType,
		ID:    event.ID,
		Source: map[string]interface{}{
			ee.config.TimestampField: event.Timestamp.Format(time.RFC3339Nano),
			ee.config.MessageField:   event.Message,
			"event_type":             event.Type,
			"event_source":           event.Source,
			"component":              event.Component,
			"severity":               event.Severity,
			"correlation_id":         event.CorrelationID,
			"trace_id":               event.TraceID,
			"export_type":            data.ExportType,
			"export_source":          data.Source,
			"document_type":          "event",
		},
	}
	
	// Add event data
	if event.Data != nil {
		for key, value := range event.Data {
			doc.Source["event_"+key] = value
		}
	}
	
	// Add extra configured fields
	for key, value := range ee.config.ExtraFields {
		doc.Source[key] = value
	}
	
	return doc
}

// convertHealthToDocument converts health status to an Elasticsearch document.
func (ee *ElasticsearchExporter) convertHealthToDocument(component string, health HealthStatus, data ExportData) ElasticsearchDocument {
	doc := ElasticsearchDocument{
		Index: ee.getIndexName(health.LastChecked),
		Type:  ee.config.DocType,
		Source: map[string]interface{}{
			ee.config.TimestampField: health.LastChecked.Format(time.RFC3339Nano),
			ee.config.MessageField:   health.Message,
			"component":              component,
			"health_status":          health.Status,
			"export_type":            data.ExportType,
			"export_source":          data.Source,
			"document_type":          "health",
		},
	}
	
	// Add health details
	if health.Details != nil {
		for key, value := range health.Details {
			doc.Source["health_"+key] = value
		}
	}
	
	// Add extra configured fields
	for key, value := range ee.config.ExtraFields {
		doc.Source[key] = value
	}
	
	return doc
}

// bulkIndex sends documents to Elasticsearch using bulk API.
func (ee *ElasticsearchExporter) bulkIndex(ctx context.Context, documents []ElasticsearchDocument) error {
	if len(documents) == 0 {
		return nil
	}
	
	// Build bulk request body
	var bulkBody bytes.Buffer
	for _, doc := range documents {
		// Index action line
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": doc.Index,
				"_type":  doc.Type,
			},
		}
		if doc.ID != "" {
			action["index"].(map[string]interface{})["_id"] = doc.ID
		}
		
		actionJSON, _ := json.Marshal(action)
		bulkBody.Write(actionJSON)
		bulkBody.WriteString("\n")
		
		// Document source line
		sourceJSON, _ := json.Marshal(doc.Source)
		bulkBody.Write(sourceJSON)
		bulkBody.WriteString("\n")
	}
	
	// Send bulk request
	bulkURL := ee.config.Endpoint + "/_bulk"
	req, err := http.NewRequestWithContext(ctx, "POST", bulkURL, &bulkBody)
	if err != nil {
		return fmt.Errorf("failed to create bulk request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/x-ndjson")
	ee.addAuthentication(req)
	
	resp, err := ee.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("bulk request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
		}
	}()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bulk request returned status %d", resp.StatusCode)
	}
	
	// Check for individual document errors
	var bulkResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&bulkResponse); err != nil {
		// Log warning but don't fail - data was likely indexed
		ee.logger.WarnCtx(ctx, "Could not parse bulk response", "error", err)
	} else if hasErrors, ok := bulkResponse["errors"].(bool); ok && hasErrors {
		ee.logger.WarnCtx(ctx, "Some documents failed to index",
			"total_documents", len(documents))
		// Don't return error - partial success is acceptable
	}
	
	return nil
}

// addAuthentication adds authentication headers to the request.
func (ee *ElasticsearchExporter) addAuthentication(req *http.Request) {
	if ee.config.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+ee.config.APIKey)
	} else if ee.config.Username != "" && ee.config.Password != "" {
		req.SetBasicAuth(ee.config.Username, ee.config.Password)
	}
}

// getIndexName generates the index name based on timestamp and pattern.
func (ee *ElasticsearchExporter) getIndexName(timestamp time.Time) string {
	if ee.config.IndexPattern != "" {
		// Format timestamp according to pattern
		return timestamp.Format(ee.config.IndexPattern)
	}
	return ee.config.Index
}