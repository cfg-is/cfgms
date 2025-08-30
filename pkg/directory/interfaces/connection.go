// Package interfaces - Connection Pool Management and Health Monitoring
//
// This file implements connection pool management with health monitoring for directory providers.
// It provides connection pooling, health checks, automatic failover, and performance monitoring
// following CFGMS's reliability and observability patterns.

package interfaces

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// DirectoryConnectionPool manages a pool of directory connections with health monitoring
type DirectoryConnectionPool interface {
	// Connection lifecycle
	Get(ctx context.Context) (DirectoryConnection, error)
	Put(conn DirectoryConnection) error
	Close() error
	
	// Pool management
	GetStatistics() *PoolStatistics
	GetHealthStatus() *PoolHealth
	SetHealthCheck(checker HealthChecker)
	
	// Configuration
	SetMaxConnections(max int)
	SetIdleTimeout(timeout time.Duration)
	SetHealthCheckInterval(interval time.Duration)
}

// DefaultDirectoryConnectionPool is the default implementation of connection pooling
type DefaultDirectoryConnectionPool struct {
	// Configuration
	config PoolConfig
	
	// Connection management
	connections    chan DirectoryConnection
	activeConns    map[DirectoryConnection]bool
	connectionFunc ConnectionFunc
	mutex          sync.RWMutex
	
	// Health monitoring
	healthChecker     HealthChecker
	healthCheckTicker *time.Ticker
	healthStatus      atomic.Value // stores *PoolHealth
	
	// Statistics
	stats     atomic.Value // stores *PoolStatistics
	statsLock sync.Mutex
	
	// Control
	closed    int32
	closeOnce sync.Once
	closeChan chan struct{}
}

// PoolConfig contains configuration for the connection pool
type PoolConfig struct {
	// Pool sizing
	MaxConnections    int           `json:"max_connections"`     // Maximum number of connections
	MinConnections    int           `json:"min_connections"`     // Minimum number of connections
	InitialSize       int           `json:"initial_size"`        // Initial pool size
	
	// Timeouts
	ConnectionTimeout time.Duration `json:"connection_timeout"`  // Timeout for creating connections
	IdleTimeout       time.Duration `json:"idle_timeout"`        // Timeout for idle connections
	MaxLifetime       time.Duration `json:"max_lifetime"`        // Maximum connection lifetime
	
	// Health monitoring
	HealthCheckInterval time.Duration `json:"health_check_interval"` // Health check frequency
	HealthCheckTimeout  time.Duration `json:"health_check_timeout"`  // Health check timeout
	MaxRetries          int           `json:"max_retries"`            // Max connection retry attempts
	RetryDelay          time.Duration `json:"retry_delay"`            // Delay between retries
	
	// Failover
	FailoverThreshold   int           `json:"failover_threshold"`     // Failed connections before failover
	RecoveryInterval    time.Duration `json:"recovery_interval"`      // Recovery check interval
}

// ConnectionFunc creates a new directory connection
type ConnectionFunc func(ctx context.Context) (DirectoryConnection, error)

// HealthChecker performs health checks on connections
type HealthChecker interface {
	CheckHealth(ctx context.Context, conn DirectoryConnection) error
}

// DefaultHealthChecker is the default health checker implementation
type DefaultHealthChecker struct {
	timeout time.Duration
}

// NewDefaultHealthChecker creates a new default health checker
func NewDefaultHealthChecker(timeout time.Duration) *DefaultHealthChecker {
	return &DefaultHealthChecker{timeout: timeout}
}

// CheckHealth performs a health check on a connection
func (h *DefaultHealthChecker) CheckHealth(ctx context.Context, conn DirectoryConnection) error {
	if conn == nil {
		return fmt.Errorf("connection is nil")
	}
	
	// Use timeout context for health check
	checkCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	
	if !conn.IsHealthy(checkCtx) {
		return fmt.Errorf("connection health check failed")
	}
	return nil
}

// PoolHealth represents the health status of the connection pool
type PoolHealth struct {
	IsHealthy           bool                       `json:"is_healthy"`
	LastCheck           time.Time                  `json:"last_check"`
	ActiveConnections   int                        `json:"active_connections"`
	IdleConnections     int                        `json:"idle_connections"`
	FailedConnections   int                        `json:"failed_connections"`
	HealthyConnections  int                        `json:"healthy_connections"`
	UnhealthyConnections int                       `json:"unhealthy_connections"`
	Details             map[string]interface{}     `json:"details,omitempty"`
	Issues              []string                   `json:"issues,omitempty"`
}

// NewDirectoryConnectionPool creates a new directory connection pool
func NewDirectoryConnectionPool(config PoolConfig, connectionFunc ConnectionFunc) (*DefaultDirectoryConnectionPool, error) {
	if config.MaxConnections <= 0 {
		return nil, fmt.Errorf("max_connections must be positive")
	}
	
	if connectionFunc == nil {
		return nil, fmt.Errorf("connection function cannot be nil")
	}
	
	// Set defaults
	if config.MinConnections <= 0 {
		config.MinConnections = 1
	}
	if config.InitialSize <= 0 {
		config.InitialSize = config.MinConnections
	}
	if config.ConnectionTimeout <= 0 {
		config.ConnectionTimeout = 30 * time.Second
	}
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = 5 * time.Minute
	}
	if config.MaxLifetime <= 0 {
		config.MaxLifetime = 30 * time.Minute
	}
	if config.HealthCheckInterval <= 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.HealthCheckTimeout <= 0 {
		config.HealthCheckTimeout = 5 * time.Second
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = time.Second
	}
	
	pool := &DefaultDirectoryConnectionPool{
		config:         config,
		connections:    make(chan DirectoryConnection, config.MaxConnections),
		activeConns:    make(map[DirectoryConnection]bool),
		connectionFunc: connectionFunc,
		healthChecker:  NewDefaultHealthChecker(config.HealthCheckTimeout),
		closeChan:      make(chan struct{}),
	}
	
	// Initialize statistics
	pool.stats.Store(&PoolStatistics{
		MaxConnections:    config.MaxConnections,
		ActiveConnections: 0,
		IdleConnections:   0,
		RequestCount:      0,
		ErrorCount:        0,
		AverageLatency:    0,
		LastRequestTime:   time.Now(),
	})
	
	// Initialize health status
	pool.healthStatus.Store(&PoolHealth{
		IsHealthy: true,
		LastCheck: time.Now(),
	})
	
	// Create initial connections
	if err := pool.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize connection pool: %w", err)
	}
	
	// Start health monitoring
	pool.startHealthMonitoring()
	
	return pool, nil
}

// initialize creates initial connections for the pool
func (p *DefaultDirectoryConnectionPool) initialize() error {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.ConnectionTimeout*time.Duration(p.config.InitialSize))
	defer cancel()
	
	for i := 0; i < p.config.InitialSize; i++ {
		conn, err := p.createConnection(ctx)
		if err != nil {
			// Log warning but continue with other connections
			continue
		}
		
		select {
		case p.connections <- conn:
			// Connection added to pool
		default:
			// Pool is full, close extra connection
			_ = conn.Close(ctx) // Ignore error during cleanup
		}
	}
	
	return nil
}

// createConnection creates a new directory connection with retry logic
func (p *DefaultDirectoryConnectionPool) createConnection(ctx context.Context) (DirectoryConnection, error) {
	var lastErr error
	
	for attempt := 0; attempt < p.config.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(p.config.RetryDelay * time.Duration(attempt)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		
		conn, err := p.connectionFunc(ctx)
		if err != nil {
			lastErr = err
			continue
		}
		
		// Test the connection
		if err := p.healthChecker.CheckHealth(ctx, conn); err != nil {
			_ = conn.Close(ctx) // Ignore error during cleanup // Close unhealthy connection
			lastErr = err
			continue
		}
		
		return conn, nil
	}
	
	return nil, fmt.Errorf("failed to create connection after %d attempts: %w", p.config.MaxRetries, lastErr)
}

// Get retrieves a connection from the pool
func (p *DefaultDirectoryConnectionPool) Get(ctx context.Context) (DirectoryConnection, error) {
	if atomic.LoadInt32(&p.closed) != 0 {
		return nil, fmt.Errorf("connection pool is closed")
	}
	
	select {
	case conn := <-p.connections:
		// Got connection from pool
		if conn != nil {
			// Verify connection health
			if err := p.healthChecker.CheckHealth(ctx, conn); err != nil {
				// Connection is unhealthy, close it and create new one
				_ = conn.Close(ctx) // Ignore error during cleanup
				return p.createNewConnection(ctx)
			}
			
			// Mark as active
			p.mutex.Lock()
			p.activeConns[conn] = true
			p.mutex.Unlock()
			
			p.updateStatistics(func(stats *PoolStatistics) {
				stats.ActiveConnections++
				stats.IdleConnections--
				stats.RequestCount++
			})
			
			return conn, nil
		}
		
		// nil connection, create new one
		return p.createNewConnection(ctx)
		
	case <-ctx.Done():
		return nil, ctx.Err()
		
	default:
		// No idle connections available, try to create new one if under limit
		return p.createNewConnection(ctx)
	}
}

// createNewConnection creates a new connection when pool is empty or connections are unhealthy
func (p *DefaultDirectoryConnectionPool) createNewConnection(ctx context.Context) (DirectoryConnection, error) {
	p.mutex.RLock()
	currentActive := len(p.activeConns)
	p.mutex.RUnlock()
	
	if currentActive >= p.config.MaxConnections {
		return nil, fmt.Errorf("connection pool exhausted (max: %d)", p.config.MaxConnections)
	}
	
	conn, err := p.createConnection(ctx)
	if err != nil {
		p.updateStatistics(func(stats *PoolStatistics) {
			stats.ErrorCount++
		})
		return nil, err
	}
	
	// Mark as active
	p.mutex.Lock()
	p.activeConns[conn] = true
	p.mutex.Unlock()
	
	p.updateStatistics(func(stats *PoolStatistics) {
		stats.ActiveConnections++
		stats.RequestCount++
	})
	
	return conn, nil
}

// Put returns a connection to the pool
func (p *DefaultDirectoryConnectionPool) Put(conn DirectoryConnection) error {
	if atomic.LoadInt32(&p.closed) != 0 {
		if conn != nil {
			conn.Close(context.Background())
		}
		return fmt.Errorf("connection pool is closed")
	}
	
	if conn == nil {
		return fmt.Errorf("cannot put nil connection")
	}
	
	// Remove from active connections
	p.mutex.Lock()
	delete(p.activeConns, conn)
	p.mutex.Unlock()
	
	// Check connection health before returning to pool
	ctx, cancel := context.WithTimeout(context.Background(), p.config.HealthCheckTimeout)
	defer cancel()
	
	if err := p.healthChecker.CheckHealth(ctx, conn); err != nil {
		// Connection is unhealthy, close it
		conn.Close(ctx)
		
		p.updateStatistics(func(stats *PoolStatistics) {
			stats.ActiveConnections--
			stats.ErrorCount++
		})
		
		return nil // Don't return error, just close unhealthy connection
	}
	
	// Try to return to pool
	select {
	case p.connections <- conn:
		// Returned to pool
		p.updateStatistics(func(stats *PoolStatistics) {
			stats.ActiveConnections--
			stats.IdleConnections++
		})
		return nil
		
	default:
		// Pool is full, close connection
		conn.Close(ctx)
		
		p.updateStatistics(func(stats *PoolStatistics) {
			stats.ActiveConnections--
		})
		
		return nil
	}
}

// Close closes the connection pool and all connections
func (p *DefaultDirectoryConnectionPool) Close() error {
	var err error
	
	p.closeOnce.Do(func() {
		atomic.StoreInt32(&p.closed, 1)
		close(p.closeChan)
		
		// Stop health monitoring
		if p.healthCheckTicker != nil {
			p.healthCheckTicker.Stop()
		}
		
		// Close all idle connections
		close(p.connections)
		for conn := range p.connections {
			if conn != nil {
				conn.Close(context.Background())
			}
		}
		
		// Close all active connections
		p.mutex.Lock()
		for conn := range p.activeConns {
			if conn != nil {
				conn.Close(context.Background())
			}
		}
		p.activeConns = make(map[DirectoryConnection]bool)
		p.mutex.Unlock()
		
		// Update final statistics
		p.updateStatistics(func(stats *PoolStatistics) {
			stats.ActiveConnections = 0
			stats.IdleConnections = 0
		})
	})
	
	return err
}

// GetStatistics returns current pool statistics
func (p *DefaultDirectoryConnectionPool) GetStatistics() *PoolStatistics {
	stats := p.stats.Load().(*PoolStatistics)
	
	// Create a copy to prevent race conditions
	return &PoolStatistics{
		ActiveConnections: stats.ActiveConnections,
		IdleConnections:   stats.IdleConnections,
		MaxConnections:    stats.MaxConnections,
		RequestCount:      stats.RequestCount,
		ErrorCount:        stats.ErrorCount,
		AverageLatency:    stats.AverageLatency,
		LastRequestTime:   stats.LastRequestTime,
	}
}

// GetHealthStatus returns the current health status of the pool
func (p *DefaultDirectoryConnectionPool) GetHealthStatus() *PoolHealth {
	health := p.healthStatus.Load().(*PoolHealth)
	
	// Create a copy to prevent race conditions
	return &PoolHealth{
		IsHealthy:            health.IsHealthy,
		LastCheck:            health.LastCheck,
		ActiveConnections:    health.ActiveConnections,
		IdleConnections:      health.IdleConnections,
		FailedConnections:    health.FailedConnections,
		HealthyConnections:   health.HealthyConnections,
		UnhealthyConnections: health.UnhealthyConnections,
		Details:              health.Details,
		Issues:               append([]string(nil), health.Issues...),
	}
}

// SetHealthCheck sets the health checker for the pool
func (p *DefaultDirectoryConnectionPool) SetHealthCheck(checker HealthChecker) {
	if checker != nil {
		p.healthChecker = checker
	}
}

// SetMaxConnections updates the maximum number of connections
func (p *DefaultDirectoryConnectionPool) SetMaxConnections(max int) {
	if max > 0 {
		p.config.MaxConnections = max
		
		p.updateStatistics(func(stats *PoolStatistics) {
			stats.MaxConnections = max
		})
	}
}

// SetIdleTimeout updates the idle timeout for connections
func (p *DefaultDirectoryConnectionPool) SetIdleTimeout(timeout time.Duration) {
	if timeout > 0 {
		p.config.IdleTimeout = timeout
	}
}

// SetHealthCheckInterval updates the health check interval
func (p *DefaultDirectoryConnectionPool) SetHealthCheckInterval(interval time.Duration) {
	if interval > 0 {
		p.config.HealthCheckInterval = interval
		
		// Restart health monitoring with new interval
		if p.healthCheckTicker != nil {
			p.healthCheckTicker.Stop()
		}
		p.startHealthMonitoring()
	}
}

// updateStatistics updates pool statistics atomically
func (p *DefaultDirectoryConnectionPool) updateStatistics(updater func(*PoolStatistics)) {
	p.statsLock.Lock()
	defer p.statsLock.Unlock()
	
	current := p.stats.Load().(*PoolStatistics)
	
	// Create a copy
	updated := &PoolStatistics{
		ActiveConnections: current.ActiveConnections,
		IdleConnections:   current.IdleConnections,
		MaxConnections:    current.MaxConnections,
		RequestCount:      current.RequestCount,
		ErrorCount:        current.ErrorCount,
		AverageLatency:    current.AverageLatency,
		LastRequestTime:   time.Now(),
	}
	
	// Apply updates
	updater(updated)
	
	// Store the updated statistics
	p.stats.Store(updated)
}

// startHealthMonitoring starts the background health monitoring
func (p *DefaultDirectoryConnectionPool) startHealthMonitoring() {
	p.healthCheckTicker = time.NewTicker(p.config.HealthCheckInterval)
	
	go func() {
		for {
			select {
			case <-p.healthCheckTicker.C:
				p.performHealthCheck()
			case <-p.closeChan:
				return
			}
		}
	}()
}

// performHealthCheck performs a comprehensive health check of the pool
func (p *DefaultDirectoryConnectionPool) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.HealthCheckTimeout*2)
	defer cancel()
	
	p.mutex.RLock()
	activeCount := len(p.activeConns)
	p.mutex.RUnlock()
	
	idleCount := len(p.connections)
	
	health := &PoolHealth{
		IsHealthy:         true,
		LastCheck:         time.Now(),
		ActiveConnections: activeCount,
		IdleConnections:   idleCount,
		Details:           make(map[string]interface{}),
		Issues:            []string{},
	}
	
	// Check if pool is within healthy limits
	totalConnections := activeCount + idleCount
	if totalConnections < p.config.MinConnections {
		health.Issues = append(health.Issues, fmt.Sprintf("Below minimum connections: %d < %d", totalConnections, p.config.MinConnections))
	}
	
	if activeCount > int(float64(p.config.MaxConnections)*0.9) {
		health.Issues = append(health.Issues, fmt.Sprintf("High connection utilization: %d/%d", activeCount, p.config.MaxConnections))
	}
	
	// Test a sample of idle connections
	healthyConns := 0
	unhealthyConns := 0
	
	// Sample up to 5 idle connections for health testing
	sampleSize := idleCount
	if sampleSize > 5 {
		sampleSize = 5
	}
	
connectionSample:
	for i := 0; i < sampleSize; i++ {
		select {
		case conn := <-p.connections:
			if conn != nil {
				if err := p.healthChecker.CheckHealth(ctx, conn); err != nil {
					// Connection is unhealthy, close it
					_ = conn.Close(ctx) // Ignore error during cleanup
					unhealthyConns++
					health.Issues = append(health.Issues, fmt.Sprintf("Unhealthy connection: %v", err))
				} else {
					// Connection is healthy, return to pool
					healthyConns++
					select {
					case p.connections <- conn:
					default:
						// Pool is full, close connection
						_ = conn.Close(ctx) // Ignore error during cleanup
					}
				}
			}
		default:
			break connectionSample // No more connections to test
		}
	}
	
	health.HealthyConnections = healthyConns
	health.UnhealthyConnections = unhealthyConns
	
	// Determine overall health
	if len(health.Issues) > 0 {
		health.IsHealthy = false
	}
	
	// Add pool utilization details
	health.Details["utilization_percent"] = float64(activeCount) / float64(p.config.MaxConnections) * 100
	health.Details["total_connections"] = totalConnections
	health.Details["min_connections"] = p.config.MinConnections
	health.Details["max_connections"] = p.config.MaxConnections
	
	// Store updated health status
	p.healthStatus.Store(health)
}

// DirectoryConnectionMonitor provides monitoring capabilities for directory connections
type DirectoryConnectionMonitor struct {
	pools   map[string]DirectoryConnectionPool
	metrics *ConnectionMetrics
	mutex   sync.RWMutex
}

// ConnectionMetrics holds aggregated metrics across all connection pools
type ConnectionMetrics struct {
	TotalPools           int                        `json:"total_pools"`
	TotalConnections     int                        `json:"total_connections"`
	TotalActiveConnections int                      `json:"total_active_connections"`
	TotalIdleConnections int                        `json:"total_idle_connections"`
	TotalRequests        int64                      `json:"total_requests"`
	TotalErrors          int64                      `json:"total_errors"`
	PoolMetrics          map[string]*PoolStatistics `json:"pool_metrics"`
	PoolHealth           map[string]*PoolHealth      `json:"pool_health"`
	LastUpdated          time.Time                  `json:"last_updated"`
}

// NewDirectoryConnectionMonitor creates a new connection monitor
func NewDirectoryConnectionMonitor() *DirectoryConnectionMonitor {
	return &DirectoryConnectionMonitor{
		pools: make(map[string]DirectoryConnectionPool),
		metrics: &ConnectionMetrics{
			PoolMetrics: make(map[string]*PoolStatistics),
			PoolHealth:  make(map[string]*PoolHealth),
			LastUpdated: time.Now(),
		},
	}
}

// RegisterPool registers a connection pool for monitoring
func (m *DirectoryConnectionMonitor) RegisterPool(name string, pool DirectoryConnectionPool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	m.pools[name] = pool
}

// UnregisterPool removes a pool from monitoring
func (m *DirectoryConnectionMonitor) UnregisterPool(name string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	delete(m.pools, name)
	delete(m.metrics.PoolMetrics, name)
	delete(m.metrics.PoolHealth, name)
}

// GetMetrics returns current aggregated metrics
func (m *DirectoryConnectionMonitor) GetMetrics() *ConnectionMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	metrics := &ConnectionMetrics{
		TotalPools:      len(m.pools),
		PoolMetrics:     make(map[string]*PoolStatistics),
		PoolHealth:      make(map[string]*PoolHealth),
		LastUpdated:     time.Now(),
	}
	
	for name, pool := range m.pools {
		stats := pool.GetStatistics()
		health := pool.GetHealthStatus()
		
		metrics.PoolMetrics[name] = stats
		metrics.PoolHealth[name] = health
		
		metrics.TotalConnections += stats.ActiveConnections + stats.IdleConnections
		metrics.TotalActiveConnections += stats.ActiveConnections
		metrics.TotalIdleConnections += stats.IdleConnections
		metrics.TotalRequests += stats.RequestCount
		metrics.TotalErrors += stats.ErrorCount
	}
	
	// Update cached metrics
	m.metrics = metrics
	
	return metrics
}

// GetPoolHealth returns health status for a specific pool
func (m *DirectoryConnectionMonitor) GetPoolHealth(name string) (*PoolHealth, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	pool, exists := m.pools[name]
	if !exists {
		return nil, fmt.Errorf("pool '%s' not found", name)
	}
	
	return pool.GetHealthStatus(), nil
}

// IsHealthy returns true if all pools are healthy
func (m *DirectoryConnectionMonitor) IsHealthy() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	for _, pool := range m.pools {
		if health := pool.GetHealthStatus(); !health.IsHealthy {
			return false
		}
	}
	
	return true
}