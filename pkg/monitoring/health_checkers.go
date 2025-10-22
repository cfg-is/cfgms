package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// BasicHealthChecker provides basic health checking functionality.
type BasicHealthChecker struct {
	componentName string
	logger        logging.Logger
	endpoints     []HealthEndpoint
}

// NewBasicHealthChecker creates a new basic health checker.
func NewBasicHealthChecker(componentName string, logger logging.Logger) *BasicHealthChecker {
	return &BasicHealthChecker{
		componentName: componentName,
		logger:        logger,
		endpoints:     make([]HealthEndpoint, 0),
	}
}

// AddEndpoint adds a health check endpoint.
func (bhc *BasicHealthChecker) AddEndpoint(endpoint HealthEndpoint) {
	bhc.endpoints = append(bhc.endpoints, endpoint)
}

// CheckHealth performs a health check on the component.
func (bhc *BasicHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealth, error) {
	health := &ComponentHealth{
		ComponentName: bhc.componentName,
		Status:        HealthStatusHealthy,
		Timestamp:     time.Now(),
		Details:       make(map[string]interface{}),
		Dependencies:  make([]DependencyHealth, 0),
		LastCheck:     time.Now(),
	}

	// Check all endpoints
	for _, endpoint := range bhc.endpoints {
		depHealth := bhc.checkEndpoint(ctx, endpoint)
		health.Dependencies = append(health.Dependencies, depHealth)

		// If any endpoint is unhealthy, mark component as degraded
		if depHealth.Status != HealthStatusHealthy {
			health.Status = HealthStatusDegraded
		}
	}

	// Add basic runtime metrics
	health.Details["goroutines"] = runtime.NumGoroutine()
	health.Details["cgo_calls"] = runtime.NumCgoCall()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	health.Details["memory_alloc"] = memStats.Alloc
	health.Details["memory_sys"] = memStats.Sys
	health.Details["gc_count"] = memStats.NumGC

	return health, nil
}

// GetHealthEndpoints returns the configured health endpoints.
func (bhc *BasicHealthChecker) GetHealthEndpoints(ctx context.Context) ([]HealthEndpoint, error) {
	return bhc.endpoints, nil
}

// checkEndpoint checks a specific health endpoint.
func (bhc *BasicHealthChecker) checkEndpoint(ctx context.Context, endpoint HealthEndpoint) DependencyHealth {
	depHealth := DependencyHealth{
		Name:      endpoint.Name,
		Status:    HealthStatusHealthy,
		Timestamp: time.Now(),
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: endpoint.Timeout,
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.URL, nil)
	if err != nil {
		depHealth.Status = HealthStatusUnhealthy
		depHealth.Message = fmt.Sprintf("Failed to create request: %v", err)
		return depHealth
	}

	// Add headers
	for key, value := range endpoint.Headers {
		req.Header.Set(key, value)
	}

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		depHealth.Status = HealthStatusUnhealthy
		depHealth.Message = fmt.Sprintf("Request failed: %v", err)
		return depHealth
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			bhc.logger.Warn("Failed to close response body", "error", closeErr)
		}
	}()

	// Check status code
	if resp.StatusCode != endpoint.ExpectedStatus {
		depHealth.Status = HealthStatusDegraded
		depHealth.Message = fmt.Sprintf("Unexpected status code: %d (expected %d)",
			resp.StatusCode, endpoint.ExpectedStatus)
	} else {
		depHealth.Message = "Endpoint healthy"
	}

	return depHealth
}

// ControllerHealthChecker provides health checking for controller components.
type ControllerHealthChecker struct {
	*BasicHealthChecker
	services map[string]interface{} // Service dependencies
}

// NewControllerHealthChecker creates a health checker for controller components.
func NewControllerHealthChecker(logger logging.Logger) *ControllerHealthChecker {
	return &ControllerHealthChecker{
		BasicHealthChecker: NewBasicHealthChecker("controller", logger),
		services:           make(map[string]interface{}),
	}
}

// AddService adds a service dependency to monitor.
func (chc *ControllerHealthChecker) AddService(name string, service interface{}) {
	chc.services[name] = service
}

// CheckHealth performs comprehensive health check for controller.
func (chc *ControllerHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealth, error) {
	// Get basic health
	health, err := chc.BasicHealthChecker.CheckHealth(ctx)
	if err != nil {
		return nil, err
	}

	// Check service dependencies
	for serviceName, service := range chc.services {
		depHealth := DependencyHealth{
			Name:      serviceName,
			Status:    HealthStatusHealthy,
			Timestamp: time.Now(),
		}

		// Check if service is nil (indicating it's not initialized)
		if service == nil {
			depHealth.Status = HealthStatusUnhealthy
			depHealth.Message = "Service not initialized"
			health.Status = HealthStatusDegraded
		} else {
			depHealth.Message = "Service available"
		}

		health.Dependencies = append(health.Dependencies, depHealth)
	}

	return health, nil
}

// StewardHealthChecker provides health checking for steward components.
type StewardHealthChecker struct {
	*BasicHealthChecker
	connectionStatus string
	lastHeartbeat    time.Time
}

// NewStewardHealthChecker creates a health checker for steward components.
func NewStewardHealthChecker(logger logging.Logger) *StewardHealthChecker {
	return &StewardHealthChecker{
		BasicHealthChecker: NewBasicHealthChecker("steward", logger),
		connectionStatus:   "disconnected",
	}
}

// UpdateConnectionStatus updates the connection status.
func (shc *StewardHealthChecker) UpdateConnectionStatus(status string) {
	shc.connectionStatus = status
	if status == "connected" {
		shc.lastHeartbeat = time.Now()
	}
}

// CheckHealth performs comprehensive health check for steward.
func (shc *StewardHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealth, error) {
	// Get basic health
	health, err := shc.BasicHealthChecker.CheckHealth(ctx)
	if err != nil {
		return nil, err
	}

	// Check connection status
	connHealth := DependencyHealth{
		Name:      "controller_connection",
		Status:    HealthStatusHealthy,
		Timestamp: time.Now(),
	}

	if shc.connectionStatus != "connected" {
		connHealth.Status = HealthStatusUnhealthy
		connHealth.Message = fmt.Sprintf("Connection status: %s", shc.connectionStatus)
		health.Status = HealthStatusUnhealthy
	} else {
		// Check heartbeat freshness
		timeSinceHeartbeat := time.Since(shc.lastHeartbeat)
		if timeSinceHeartbeat > 2*time.Minute {
			connHealth.Status = HealthStatusDegraded
			connHealth.Message = fmt.Sprintf("Heartbeat stale: %v ago", timeSinceHeartbeat)
			health.Status = HealthStatusDegraded
		} else {
			connHealth.Message = fmt.Sprintf("Connected, last heartbeat: %v ago", timeSinceHeartbeat)
		}
	}

	health.Dependencies = append(health.Dependencies, connHealth)

	// Add connection details
	health.Details["connection_status"] = shc.connectionStatus
	health.Details["last_heartbeat"] = shc.lastHeartbeat
	health.Details["heartbeat_age_seconds"] = time.Since(shc.lastHeartbeat).Seconds()

	return health, nil
}

// DatabaseHealthChecker provides health checking for database connections.
type DatabaseHealthChecker struct {
	*BasicHealthChecker
	db interface{} // Database connection (generic interface)
}

// NewDatabaseHealthChecker creates a health checker for database connections.
func NewDatabaseHealthChecker(logger logging.Logger, db interface{}) *DatabaseHealthChecker {
	return &DatabaseHealthChecker{
		BasicHealthChecker: NewBasicHealthChecker("database", logger),
		db:                 db,
	}
}

// CheckHealth performs health check on database connection.
func (dhc *DatabaseHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealth, error) {
	health, err := dhc.BasicHealthChecker.CheckHealth(ctx)
	if err != nil {
		return nil, err
	}

	// Check database connection
	dbHealth := DependencyHealth{
		Name:      "database_connection",
		Status:    HealthStatusHealthy,
		Timestamp: time.Now(),
	}

	if dhc.db == nil {
		dbHealth.Status = HealthStatusUnhealthy
		dbHealth.Message = "Database connection not initialized"
		health.Status = HealthStatusUnhealthy
	} else {
		// TODO: Add actual database ping when we have concrete DB interface
		dbHealth.Message = "Database connection available"
	}

	health.Dependencies = append(health.Dependencies, dbHealth)
	return health, nil
}

// StorageHealthChecker provides health checking for storage systems.
type StorageHealthChecker struct {
	*BasicHealthChecker
	storageProvider interface{} // Storage provider interface
}

// NewStorageHealthChecker creates a health checker for storage systems.
func NewStorageHealthChecker(logger logging.Logger, provider interface{}) *StorageHealthChecker {
	return &StorageHealthChecker{
		BasicHealthChecker: NewBasicHealthChecker("storage", logger),
		storageProvider:    provider,
	}
}

// CheckHealth performs health check on storage system.
func (shc *StorageHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealth, error) {
	health, err := shc.BasicHealthChecker.CheckHealth(ctx)
	if err != nil {
		return nil, err
	}

	// Check storage provider
	storageHealth := DependencyHealth{
		Name:      "storage_provider",
		Status:    HealthStatusHealthy,
		Timestamp: time.Now(),
	}

	if shc.storageProvider == nil {
		storageHealth.Status = HealthStatusUnhealthy
		storageHealth.Message = "Storage provider not initialized"
		health.Status = HealthStatusUnhealthy
	} else {
		// TODO: Add storage-specific health checks when we have concrete interfaces
		storageHealth.Message = "Storage provider available"
	}

	health.Dependencies = append(health.Dependencies, storageHealth)
	return health, nil
}
