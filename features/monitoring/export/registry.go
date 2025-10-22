package export

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// ExporterRegistry provides a centralized way to register and manage monitoring exporters.
// It includes built-in exporters and allows for custom exporter registration.
type ExporterRegistry struct {
	logger    logging.Logger
	tracer    *telemetry.Tracer
	exporters map[string]ExporterFactory
}

// ExporterFactory is a function that creates a new exporter instance.
type ExporterFactory func(logger logging.Logger) MonitoringExporter

// NewExporterRegistry creates a new exporter registry with built-in exporters.
func NewExporterRegistry(logger logging.Logger, tracer *telemetry.Tracer) *ExporterRegistry {
	registry := &ExporterRegistry{
		logger:    logger,
		tracer:    tracer,
		exporters: make(map[string]ExporterFactory),
	}

	// Register built-in exporters
	registry.RegisterBuiltinExporters()

	return registry
}

// RegisterBuiltinExporters registers all built-in monitoring exporters.
func (er *ExporterRegistry) RegisterBuiltinExporters() {
	// Register Prometheus exporter
	er.RegisterExporter("prometheus", func(logger logging.Logger) MonitoringExporter {
		return NewPrometheusExporter(logger)
	})

	// Register OTLP exporter
	er.RegisterExporter("otlp", func(logger logging.Logger) MonitoringExporter {
		return NewOTLPExporter(logger)
	})

	// Register Elasticsearch exporter
	er.RegisterExporter("elasticsearch", func(logger logging.Logger) MonitoringExporter {
		return NewElasticsearchExporter(logger)
	})

	er.logger.InfoCtx(context.Background(), "Registered built-in monitoring exporters",
		"exporters", []string{"prometheus", "otlp", "elasticsearch"})
}

// RegisterExporter registers a custom exporter factory.
func (er *ExporterRegistry) RegisterExporter(name string, factory ExporterFactory) {
	er.exporters[name] = factory
	er.logger.InfoCtx(context.Background(), "Registered monitoring exporter",
		"exporter_name", name)
}

// CreateExporter creates a new exporter instance by name.
func (er *ExporterRegistry) CreateExporter(name string) (MonitoringExporter, error) {
	factory, exists := er.exporters[name]
	if !exists {
		return nil, fmt.Errorf("unknown exporter: %s", name)
	}

	exporter := factory(er.logger)
	er.logger.InfoCtx(context.Background(), "Created monitoring exporter instance",
		"exporter_name", name,
		"exporter_type", exporter.Name())

	return exporter, nil
}

// GetAvailableExporters returns a list of available exporter names.
func (er *ExporterRegistry) GetAvailableExporters() []string {
	exporters := make([]string, 0, len(er.exporters))
	for name := range er.exporters {
		exporters = append(exporters, name)
	}
	return exporters
}

// CreateExportManagerWithExporters creates a pre-configured export manager with specified exporters.
func (er *ExporterRegistry) CreateExportManagerWithExporters(config *ExportConfig, exporterNames []string) (*ExportManager, error) {
	if config == nil {
		config = DefaultExportConfig()
	}

	// Create export manager
	manager := NewExportManager(er.logger, er.tracer, config)

	// Register specified exporters
	for _, name := range exporterNames {
		exporter, err := er.CreateExporter(name)
		if err != nil {
			return nil, fmt.Errorf("failed to create exporter %s: %w", name, err)
		}

		if err := manager.RegisterExporter(name, exporter); err != nil {
			return nil, fmt.Errorf("failed to register exporter %s: %w", name, err)
		}
	}

	er.logger.InfoCtx(context.Background(), "Created export manager with exporters",
		"exporters", exporterNames)

	return manager, nil
}

// CreateExportManagerFromConfig creates an export manager based on configuration.
func (er *ExporterRegistry) CreateExportManagerFromConfig(config *ExportConfig) (*ExportManager, error) {
	if config == nil {
		config = DefaultExportConfig()
	}

	// Create export manager
	manager := NewExportManager(er.logger, er.tracer, config)

	// Register all enabled exporters from configuration
	for exporterName, exporterConfig := range config.Exporters {
		if !exporterConfig.Enabled {
			continue
		}

		exporter, err := er.CreateExporter(exporterName)
		if err != nil {
			er.logger.WarnCtx(context.Background(), "Failed to create configured exporter",
				"exporter_name", exporterName,
				"error", err)
			continue
		}

		if err := manager.RegisterExporter(exporterName, exporter); err != nil {
			er.logger.WarnCtx(context.Background(), "Failed to register configured exporter",
				"exporter_name", exporterName,
				"error", err)
			continue
		}

		er.logger.InfoCtx(context.Background(), "Registered exporter from configuration",
			"exporter_name", exporterName)
	}

	return manager, nil
}

// ExampleConfigurations provides example configurations for different monitoring setups.
type ExampleConfigurations struct{}

// GetPrometheusConfig returns an example configuration for Prometheus monitoring.
func (ExampleConfigurations) GetPrometheusConfig() *ExportConfig {
	config := DefaultExportConfig()
	config.Enabled = true
	config.ExportInterval = 30 * time.Second

	config.Exporters["prometheus"] = ExporterConfig{
		Enabled:  true,
		Endpoint: "0.0.0.0:2112",
		Config: map[string]interface{}{
			"metrics_path":      "/metrics",
			"enable_go_metrics": true,
			"metric_prefix":     "cfgms",
		},
		DataTypes: []string{"metrics", "health"},
	}

	return config
}

// GetELKStackConfig returns an example configuration for ELK stack integration.
func (ExampleConfigurations) GetELKStackConfig() *ExportConfig {
	config := DefaultExportConfig()
	config.Enabled = true
	config.ExportInterval = 10 * time.Second

	config.Exporters["elasticsearch"] = ExporterConfig{
		Enabled:  true,
		Endpoint: "https://elasticsearch:9200",
		Config: map[string]interface{}{
			"index_pattern":  "cfgms-logs-%{+2006.01.02}",
			"bulk_size":      100,
			"include_events": true,
			"include_logs":   true,
			"include_health": false,
		},
		DataTypes: []string{"logs", "events"},
	}

	return config
}

// GetOTLPConfig returns an example configuration for OpenTelemetry integration.
func (ExampleConfigurations) GetOTLPConfig() *ExportConfig {
	config := DefaultExportConfig()
	config.Enabled = true
	config.ExportInterval = 15 * time.Second

	config.Exporters["otlp"] = ExporterConfig{
		Enabled:  true,
		Endpoint: "http://jaeger:4318",
		Config: map[string]interface{}{
			"export_traces":         true,
			"export_metrics":        true,
			"export_logs":           true,
			"trace_sampling_rate":   0.1,
			"metrics_sampling_rate": 1.0,
			"compression":           "gzip",
		},
		DataTypes: []string{"traces", "metrics", "logs"},
	}

	return config
}

// GetFullMonitoringConfig returns a comprehensive configuration with all exporters.
func (ExampleConfigurations) GetFullMonitoringConfig() *ExportConfig {
	config := DefaultExportConfig()
	config.Enabled = true
	config.ExportInterval = 30 * time.Second
	config.SamplingRate = 0.8 // Sample 80% of data

	// Prometheus for metrics
	config.Exporters["prometheus"] = ExporterConfig{
		Enabled:  true,
		Endpoint: "0.0.0.0:2112",
		Config: map[string]interface{}{
			"metrics_path":  "/metrics",
			"metric_prefix": "cfgms",
		},
		DataTypes:   []string{"metrics", "health"},
		ExportTypes: []ExportType{ExportTypeScheduled},
	}

	// Elasticsearch for logs and events
	config.Exporters["elasticsearch"] = ExporterConfig{
		Enabled:  true,
		Endpoint: "https://elasticsearch:9200",
		Config: map[string]interface{}{
			"index_pattern":  "cfgms-logs-%{+2006.01.02}",
			"bulk_size":      50,
			"include_events": true,
			"include_logs":   true,
		},
		DataTypes:   []string{"logs", "events"},
		ExportTypes: []ExportType{ExportTypeScheduled, ExportTypeTriggered},
	}

	// OTLP for distributed tracing
	config.Exporters["otlp"] = ExporterConfig{
		Enabled:  true,
		Endpoint: "http://jaeger:4318",
		Config: map[string]interface{}{
			"export_traces":       true,
			"export_metrics":      false, // Use Prometheus for metrics
			"export_logs":         false, // Use Elasticsearch for logs
			"trace_sampling_rate": 0.1,
			"compression":         "gzip",
		},
		DataTypes:   []string{"traces"},
		ExportTypes: []ExportType{ExportTypeScheduled, ExportTypeTriggered},
	}

	return config
}

// GetExampleConfig returns an example configuration based on the monitoring stack type.
func GetExampleConfig(stackType string) *ExportConfig {
	examples := ExampleConfigurations{}

	switch stackType {
	case "prometheus":
		return examples.GetPrometheusConfig()
	case "elk", "elasticsearch":
		return examples.GetELKStackConfig()
	case "otlp", "jaeger", "opentelemetry":
		return examples.GetOTLPConfig()
	case "full", "complete":
		return examples.GetFullMonitoringConfig()
	default:
		return DefaultExportConfig()
	}
}
