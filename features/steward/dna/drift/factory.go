// Package drift provides factory functions for creating drift detection components.

package drift

import (
	"fmt"

	"github.com/cfgis/cfgms/pkg/logging"
)

// NewFilterFromConfig creates a new drift event filter with the specified configuration.
func NewFilterFromConfig(config *FilterConfig, logger logging.Logger) (Filter, error) {
	return &filter{
		logger:    logger,
		config:    config,
		whitelist: make([]*WhitelistPattern, 0),
		stats:     &FilterStats{},
	}, nil
}

// NewRuleEngineFromConfig creates a new rule engine with the specified configuration.
func NewRuleEngineFromConfig(config *RuleEngineConfig, logger logging.Logger) (RuleEngine, error) {
	return &ruleEngine{
		logger: logger,
		config: config,
		rules:  make(map[string]*DriftRule),
		stats: &RuleEngineStats{
			RulePerformance: make(map[string]*RulePerf),
		},
	}, nil
}

// NewDriftService creates a complete drift detection service with all components.
func NewDriftService(
	detectorConfig *DetectorConfig,
	filterConfig *FilterConfig,
	ruleEngineConfig *RuleEngineConfig,
	monitorConfig *MonitorConfig,
	logger logging.Logger,
) (*DriftService, error) {

	// Create detector
	detector, err := NewDetector(detectorConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create detector: %w", err)
	}

	// Create filter (if needed by detector implementation)
	if filterConfig != nil {
		_, err = NewFilterFromConfig(filterConfig, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create filter: %w", err)
		}
	}

	// Create rule engine (if needed by detector implementation)
	if ruleEngineConfig != nil {
		_, err = NewRuleEngineFromConfig(ruleEngineConfig, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create rule engine: %w", err)
		}
	}

	service := &DriftService{
		detector: detector,
		logger:   logger,
	}

	return service, nil
}

// DriftService provides a high-level interface for drift detection operations.
type DriftService struct {
	detector Detector
	monitor  Monitor
	logger   logging.Logger
}

// GetDetector returns the drift detector.
func (ds *DriftService) GetDetector() Detector {
	return ds.detector
}

// GetMonitor returns the drift monitor (if available).
func (ds *DriftService) GetMonitor() Monitor {
	return ds.monitor
}

// Close releases all service resources.
func (ds *DriftService) Close() error {
	var errs []error

	if ds.detector != nil {
		if err := ds.detector.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close detector: %w", err))
		}
	}

	if ds.monitor != nil {
		if err := ds.monitor.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop monitor: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing drift service: %v", errs)
	}

	return nil
}
