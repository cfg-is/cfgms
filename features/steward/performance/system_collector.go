package performance

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// DefaultSystemCollector implements SystemCollector using gopsutil
type DefaultSystemCollector struct {
	platform string

	// For calculating throughput metrics
	lastDiskIO  *disk.IOCountersStat
	lastNetIO   net.IOCountersStat
	lastCollect time.Time
}

// NewSystemCollector creates a platform-appropriate system collector
func NewSystemCollector() SystemCollector {
	return &DefaultSystemCollector{
		platform:    runtime.GOOS,
		lastCollect: time.Now(),
	}
}

// CollectMetrics gathers system metrics
func (c *DefaultSystemCollector) CollectMetrics(ctx context.Context) (*SystemMetrics, error) {
	timestamp := time.Now()

	// CPU metrics
	cpuPercent, err := cpu.PercentWithContext(ctx, 0, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU metrics: %w", err)
	}

	// Per-core CPU metrics
	cpuPercentPerCore, _ := cpu.PercentWithContext(ctx, 0, true)

	// Memory metrics
	vmem, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get memory metrics: %w", err)
	}

	// Swap metrics
	swap, err := mem.SwapMemoryWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get swap metrics: %w", err)
	}

	// Disk I/O metrics
	diskReadRate, diskWriteRate, diskReadOps, diskWriteOps := c.collectDiskMetrics(ctx, timestamp)

	// Network I/O metrics
	netRecvRate, netSentRate, netRecvPkts, netSentPkts := c.collectNetworkMetrics(ctx, timestamp)

	// Build metrics
	cpuPercentValue := 0.0
	if len(cpuPercent) > 0 {
		cpuPercentValue = cpuPercent[0]
	}

	metrics := &SystemMetrics{
		CPUPercent:           cpuPercentValue,
		CPUPercentPerCore:    cpuPercentPerCore,
		MemoryUsedBytes:      int64(vmem.Used),
		MemoryTotalBytes:     int64(vmem.Total),
		MemoryPercent:        vmem.UsedPercent,
		SwapUsedBytes:        int64(swap.Used),
		SwapTotalBytes:       int64(swap.Total),
		DiskReadBytesPerSec:  diskReadRate,
		DiskWriteBytesPerSec: diskWriteRate,
		DiskReadOpsPerSec:    diskReadOps,
		DiskWriteOpsPerSec:   diskWriteOps,
		NetRecvBytesPerSec:   netRecvRate,
		NetSentBytesPerSec:   netSentRate,
		NetRecvPktsPerSec:    netRecvPkts,
		NetSentPktsPerSec:    netSentPkts,
		CollectedAt:          timestamp,
	}

	return metrics, nil
}

// collectDiskMetrics collects disk I/O metrics and calculates rates
func (c *DefaultSystemCollector) collectDiskMetrics(ctx context.Context, timestamp time.Time) (int64, int64, int64, int64) {
	// Get current disk I/O counters (aggregate all disks)
	ioCounters, err := disk.IOCountersWithContext(ctx)
	if err != nil {
		return 0, 0, 0, 0
	}

	// Aggregate all disks
	var totalReadBytes, totalWriteBytes, totalReadCount, totalWriteCount uint64
	for _, io := range ioCounters {
		totalReadBytes += io.ReadBytes
		totalWriteBytes += io.WriteBytes
		totalReadCount += io.ReadCount
		totalWriteCount += io.WriteCount
	}

	currentIO := &disk.IOCountersStat{
		ReadBytes:  totalReadBytes,
		WriteBytes: totalWriteBytes,
		ReadCount:  totalReadCount,
		WriteCount: totalWriteCount,
	}

	// Calculate rates if we have a previous measurement
	var readRate, writeRate, readOps, writeOps int64
	if c.lastDiskIO != nil && !c.lastCollect.IsZero() {
		timeDelta := timestamp.Sub(c.lastCollect).Seconds()
		if timeDelta > 0 {
			readRate = int64(float64(currentIO.ReadBytes-c.lastDiskIO.ReadBytes) / timeDelta)
			writeRate = int64(float64(currentIO.WriteBytes-c.lastDiskIO.WriteBytes) / timeDelta)
			readOps = int64(float64(currentIO.ReadCount-c.lastDiskIO.ReadCount) / timeDelta)
			writeOps = int64(float64(currentIO.WriteCount-c.lastDiskIO.WriteCount) / timeDelta)
		}
	}

	// Store current values for next calculation
	c.lastDiskIO = currentIO
	c.lastCollect = timestamp

	return readRate, writeRate, readOps, writeOps
}

// collectNetworkMetrics collects network I/O metrics and calculates rates
func (c *DefaultSystemCollector) collectNetworkMetrics(ctx context.Context, timestamp time.Time) (int64, int64, int64, int64) {
	// Get current network I/O counters
	ioCounters, err := net.IOCountersWithContext(ctx, false) // false = aggregate all interfaces
	if err != nil || len(ioCounters) == 0 {
		return 0, 0, 0, 0
	}

	currentIO := ioCounters[0] // Aggregated stats

	// Calculate rates if we have a previous measurement
	var recvRate, sentRate, recvPkts, sentPkts int64
	if c.lastNetIO.BytesRecv > 0 && !c.lastCollect.IsZero() {
		timeDelta := timestamp.Sub(c.lastCollect).Seconds()
		if timeDelta > 0 {
			recvRate = int64(float64(currentIO.BytesRecv-c.lastNetIO.BytesRecv) / timeDelta)
			sentRate = int64(float64(currentIO.BytesSent-c.lastNetIO.BytesSent) / timeDelta)
			recvPkts = int64(float64(currentIO.PacketsRecv-c.lastNetIO.PacketsRecv) / timeDelta)
			sentPkts = int64(float64(currentIO.PacketsSent-c.lastNetIO.PacketsSent) / timeDelta)
		}
	}

	// Store current values for next calculation
	c.lastNetIO = currentIO

	return recvRate, sentRate, recvPkts, sentPkts
}

// GetPlatform returns the platform name
func (c *DefaultSystemCollector) GetPlatform() string {
	return c.platform
}
