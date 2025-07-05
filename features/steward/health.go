package steward

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// HealthStatus represents the current health status of the steward
type HealthStatus string

const (
	// StatusHealthy indicates the steward is operating normally
	StatusHealthy HealthStatus = "healthy"

	// StatusDegraded indicates the steward is operational but with issues
	StatusDegraded HealthStatus = "degraded"

	// StatusUnhealthy indicates the steward is not functioning properly
	StatusUnhealthy HealthStatus = "unhealthy"
)

// HealthMetrics contains health-related metrics for the steward
type HealthMetrics struct {
	// TaskLatency records the time taken for tasks
	TaskLatency time.Duration

	// ConfigErrors records the number of configuration application errors
	ConfigErrors int

	// RecoveryAttempts counts self-recovery attempts
	RecoveryAttempts int

	// LastStatusChange records when the status last changed
	LastStatusChange time.Time

	// Status is the current health status
	Status HealthStatus

	// TaskCount records the number of tasks executed
	TaskCount int

	// AverageTaskLatency records the average time taken for tasks
	AverageTaskLatency time.Duration

	// TotalTaskLatency is used to calculate the average
	TotalTaskLatency time.Duration

	// Controller connectivity metrics (only for controller mode)
	ControllerConnected bool
	LastHeartbeat       time.Time
	HeartbeatErrors     int
}

// HealthMonitor implements health monitoring and automatic recovery
type HealthMonitor struct {
	logger               logging.Logger
	checkInterval        time.Duration
	stop                 chan struct{}
	stopped              chan struct{}
	running              atomic.Bool
	metrics              *HealthMetrics
	mu                   sync.RWMutex
	configErrorThreshold int
	latencyThreshold     time.Duration
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(logger logging.Logger) *HealthMonitor {
	metrics := &HealthMetrics{
		Status:           StatusHealthy,
		LastStatusChange: time.Now(),
	}
	return &HealthMonitor{
		logger:               logger,
		checkInterval:        30 * time.Second,
		stop:                 make(chan struct{}),
		stopped:              make(chan struct{}),
		metrics:              metrics,
		configErrorThreshold: 3,                      // Default threshold
		latencyThreshold:     100 * time.Millisecond, // Default threshold
	}
}

// SetConfigErrorThreshold sets the threshold for config errors that triggers status change
func (h *HealthMonitor) SetConfigErrorThreshold(threshold int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.configErrorThreshold = threshold
}

// SetLatencyThreshold sets the threshold for task latency that triggers status change
func (h *HealthMonitor) SetLatencyThreshold(threshold time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.latencyThreshold = threshold
}

// ResetMetrics resets all metrics to their initial values
func (h *HealthMonitor) ResetMetrics() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.metrics = &HealthMetrics{
		Status:           StatusHealthy,
		LastStatusChange: time.Now(),
	}
}

// Start begins the health monitoring process
func (h *HealthMonitor) Start(ctx context.Context) {
	if !h.running.CompareAndSwap(false, true) {
		h.logger.Warn("Health monitor already running")
		return
	}

	ticker := time.NewTicker(h.checkInterval)
	defer ticker.Stop()
	defer func() {
		h.running.Store(false)
		close(h.stopped)
	}()

	h.logger.Info("Health monitor started")

	for {
		select {
		case <-ticker.C:
			h.performHealthCheck()
		case <-ctx.Done():
			h.logger.Info("Health monitor stopping due to context cancellation")
			return
		case <-h.stop:
			h.logger.Info("Health monitor stopping")
			return
		}
	}
}

// Stop ends the health monitoring process
func (h *HealthMonitor) Stop() {
	if h.running.Load() {
		close(h.stop)
		<-h.stopped
	}
}

// GetStatus returns the current health status
func (h *HealthMonitor) GetStatus() HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.metrics.Status
}

// GetMetrics returns a copy of the current health metrics
func (h *HealthMonitor) GetMetrics() HealthMetrics {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return *h.metrics
}

// RecordTaskLatency records the latency of a task
func (h *HealthMonitor) RecordTaskLatency(latency time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.metrics.TaskCount++
	h.metrics.TotalTaskLatency += latency
	h.metrics.AverageTaskLatency = h.metrics.TotalTaskLatency / time.Duration(h.metrics.TaskCount)

	// Check if latency exceeds threshold
	if h.metrics.AverageTaskLatency > h.latencyThreshold {
		if h.metrics.Status == StatusHealthy {
			h.metrics.Status = StatusDegraded
			h.metrics.LastStatusChange = time.Now()
			h.logger.Warn("Health status degraded due to high latency",
				"latency", h.metrics.AverageTaskLatency,
				"threshold", h.latencyThreshold)
		}
	}
}

// RecordConfigError increments the configuration error count
func (h *HealthMonitor) RecordConfigError() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.metrics.ConfigErrors++

	// Check if errors exceed threshold
	if h.metrics.ConfigErrors >= h.configErrorThreshold {
		if h.metrics.Status == StatusHealthy {
			h.metrics.Status = StatusDegraded
			h.metrics.LastStatusChange = time.Now()
			h.logger.Warn("Health status degraded due to config errors",
				"errors", h.metrics.ConfigErrors,
				"threshold", h.configErrorThreshold)
		} else if h.metrics.ConfigErrors >= h.configErrorThreshold*2 {
			h.metrics.Status = StatusUnhealthy
			h.metrics.LastStatusChange = time.Now()
			h.logger.Error("Health status unhealthy due to excessive config errors",
				"errors", h.metrics.ConfigErrors,
				"threshold", h.configErrorThreshold)
		}
	}
}

// performHealthCheck checks the steward's health and attempts recovery if needed
func (h *HealthMonitor) performHealthCheck() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Update metrics based on thresholds
	if h.metrics.ConfigErrors >= h.configErrorThreshold {
		h.metrics.Status = StatusUnhealthy
		h.metrics.LastStatusChange = time.Now()
	} else if h.metrics.AverageTaskLatency > h.latencyThreshold {
		h.metrics.Status = StatusDegraded
		h.metrics.LastStatusChange = time.Now()
	} else {
		h.metrics.Status = StatusHealthy
		h.metrics.LastStatusChange = time.Now()
	}
}

// attemptRecovery tries to restore the steward to a healthy state
func (h *HealthMonitor) attemptRecovery() {
	h.mu.Lock()
	h.metrics.RecoveryAttempts++
	recoveryAttempt := h.metrics.RecoveryAttempts
	h.mu.Unlock()

	h.logger.Warn("Attempting steward recovery", "attempt", recoveryAttempt)

	// TODO: Implement recovery strategies
	// - Restart failed components
	// - Re-establish controller connection
	// - Reset state if necessary

	h.logger.Info("Recovery attempt completed", "attempt", recoveryAttempt)
}

// SetStatus manually sets the health status
func (h *HealthMonitor) SetStatus(status HealthStatus) {
	h.mu.Lock()
	defer h.mu.Unlock()

	oldStatus := h.metrics.Status
	h.metrics.Status = status

	if oldStatus != status {
		h.metrics.LastStatusChange = time.Now()
		h.logger.Info("Health status manually changed",
			"old_status", oldStatus,
			"new_status", status)
	}
}

// UpdateControllerConnectivity updates controller connectivity metrics
func (h *HealthMonitor) UpdateControllerConnectivity(connected bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	oldConnected := h.metrics.ControllerConnected
	h.metrics.ControllerConnected = connected

	if connected != oldConnected {
		if connected {
			h.logger.Info("Controller connectivity restored")
			// Reset heartbeat errors on reconnection
			h.metrics.HeartbeatErrors = 0
		} else {
			h.logger.Warn("Controller connectivity lost")
		}
	}

	// Update health status based on connectivity
	if !connected && h.metrics.Status == StatusHealthy {
		h.metrics.Status = StatusDegraded
		h.metrics.LastStatusChange = time.Now()
		h.logger.Warn("Health status degraded due to controller disconnection")
	}
}

// RecordHeartbeatSuccess records a successful heartbeat
func (h *HealthMonitor) RecordHeartbeatSuccess() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.metrics.LastHeartbeat = time.Now()
	h.metrics.HeartbeatErrors = 0
	h.metrics.ControllerConnected = true
}

// RecordHeartbeatError records a heartbeat error
func (h *HealthMonitor) RecordHeartbeatError() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.metrics.HeartbeatErrors++

	// Check if errors exceed threshold
	if h.metrics.HeartbeatErrors >= 3 {
		h.metrics.ControllerConnected = false
		if h.metrics.Status == StatusHealthy {
			h.metrics.Status = StatusDegraded
			h.metrics.LastStatusChange = time.Now()
			h.logger.Warn("Health status degraded due to heartbeat failures",
				"errors", h.metrics.HeartbeatErrors)
		}
	}
}

// IsRunning returns whether the health monitor is running
func (h *HealthMonitor) IsRunning() bool {
	return h.running.Load()
}
