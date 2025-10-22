package performance

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// DefaultProcessCollector implements ProcessCollector using gopsutil
type DefaultProcessCollector struct{}

// NewProcessCollector creates a new process metrics collector
func NewProcessCollector() ProcessCollector {
	return &DefaultProcessCollector{}
}

// GetTopProcesses returns the top N processes by CPU/memory usage
func (c *DefaultProcessCollector) GetTopProcesses(ctx context.Context, count int) ([]ProcessMetrics, error) {
	// Get all processes
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get processes: %w", err)
	}

	// Collect metrics for all processes
	procMetrics := make([]ProcessMetrics, 0, len(procs))
	for _, p := range procs {
		metrics, err := c.getProcessMetrics(ctx, p)
		if err != nil {
			// Skip processes we can't read (permission denied, etc.)
			continue
		}
		procMetrics = append(procMetrics, *metrics)
	}

	// Sort by CPU usage (descending)
	sort.Slice(procMetrics, func(i, j int) bool {
		return procMetrics[i].CPUPercent > procMetrics[j].CPUPercent
	})

	// Return top N
	if len(procMetrics) > count {
		procMetrics = procMetrics[:count]
	}

	return procMetrics, nil
}

// GetWatchlistProcesses returns metrics for processes in the watchlist
func (c *DefaultProcessCollector) GetWatchlistProcesses(ctx context.Context, watchlist []string) ([]ProcessMetrics, error) {
	// Get all processes
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get processes: %w", err)
	}

	// Create watchlist map for fast lookup
	watchlistMap := make(map[string]bool)
	for _, name := range watchlist {
		watchlistMap[name] = true
	}

	// Collect metrics for watchlisted processes
	watchlistMetrics := make([]ProcessMetrics, 0)
	for _, p := range procs {
		name, err := p.NameWithContext(ctx)
		if err != nil {
			continue
		}

		// Check if this process is in the watchlist
		if watchlistMap[name] {
			metrics, err := c.getProcessMetrics(ctx, p)
			if err != nil {
				continue
			}
			metrics.IsWatchlisted = true
			watchlistMetrics = append(watchlistMetrics, *metrics)
		}
	}

	return watchlistMetrics, nil
}

// GetServiceStatus returns status for services in the watchlist
// Note: Service status checking is platform-specific and requires additional implementation
func (c *DefaultProcessCollector) GetServiceStatus(ctx context.Context, services []string) ([]ProcessMetrics, error) {
	// For now, return empty - service status is more complex and platform-specific
	// This will be implemented in a later phase
	return []ProcessMetrics{}, nil
}

// GetProcessByPID returns metrics for a specific process
func (c *DefaultProcessCollector) GetProcessByPID(ctx context.Context, pid int32) (*ProcessMetrics, error) {
	// Get process by PID
	p, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get process %d: %w", pid, err)
	}

	return c.getProcessMetrics(ctx, p)
}

// getProcessMetrics collects metrics for a single process
func (c *DefaultProcessCollector) getProcessMetrics(ctx context.Context, p *process.Process) (*ProcessMetrics, error) {
	pid := p.Pid

	// Get process name
	name, err := p.NameWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get process name: %w", err)
	}

	// Get CPU percent (this requires a measurement interval)
	cpuPercent, err := p.CPUPercentWithContext(ctx)
	if err != nil {
		cpuPercent = 0.0 // Default to 0 if we can't measure
	}

	// Get memory info
	memInfo, err := p.MemoryInfoWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}

	// Get memory percent
	memPercent, err := p.MemoryPercentWithContext(ctx)
	if err != nil {
		memPercent = 0.0
	}

	// Get command line (may fail on some systems)
	cmdline, _ := p.CmdlineWithContext(ctx)

	// Get username (may fail on some systems)
	username, _ := p.UsernameWithContext(ctx)

	// Get thread count (may fail on some systems)
	threadCount, _ := p.NumThreadsWithContext(ctx)

	// Get process status (may fail on some systems)
	statusCodes, _ := p.StatusWithContext(ctx)
	status := ""
	if len(statusCodes) > 0 {
		status = statusCodes[0]
	}

	// Get create time (may fail on some systems)
	createTimeUnix, _ := p.CreateTimeWithContext(ctx)
	createTime := time.Unix(createTimeUnix/1000, 0)

	return &ProcessMetrics{
		PID:           pid,
		Name:          name,
		Cmdline:       cmdline,
		Username:      username,
		CPUPercent:    cpuPercent,
		MemoryBytes:   int64(memInfo.RSS),
		MemoryPercent: float64(memPercent),
		ThreadCount:   threadCount,
		CreateTime:    createTime,
		Status:        status,
	}, nil
}
