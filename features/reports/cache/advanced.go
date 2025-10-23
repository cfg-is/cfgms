// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package cache

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// AdvancedCache wraps a basic cache with report-type-specific TTL management
type AdvancedCache struct {
	cache  interfaces.ReportCache
	config interfaces.AdvancedCacheConfig
	logger logging.Logger
}

// NewAdvancedCache creates a new advanced cache wrapper
func NewAdvancedCache(baseCache interfaces.ReportCache, config interfaces.AdvancedCacheConfig, logger logging.Logger) *AdvancedCache {
	return &AdvancedCache{
		cache:  baseCache,
		config: config,
		logger: logger,
	}
}

// Get retrieves a report from the cache with advanced logic
func (ac *AdvancedCache) Get(ctx context.Context, key string) (*interfaces.Report, error) {
	if !ac.config.EnableAdvancedCaching {
		return nil, ErrCacheMiss
	}

	report, err := ac.cache.Get(ctx, key)
	if err != nil {
		ac.logger.Debug("cache miss", "key", key)
		return nil, err
	}

	ac.logger.Debug("cache hit", "key", key, "report_type", report.Type)
	return report, nil
}

// Set implements the ReportCache interface with standard TTL
func (ac *AdvancedCache) Set(ctx context.Context, key string, report *interfaces.Report, ttl time.Duration) error {
	if !ac.config.EnableAdvancedCaching {
		return nil // Silently skip if caching disabled
	}

	err := ac.cache.Set(ctx, key, report, ttl)
	if err != nil {
		ac.logger.Warn("failed to cache report", "key", key, "error", err)
		return err
	}

	ac.logger.Debug("cached report", "key", key, "ttl", ttl)
	return nil
}

// SetWithType stores a report in the cache with type-specific TTL
func (ac *AdvancedCache) SetWithType(ctx context.Context, key string, report *interfaces.Report, reportType interfaces.ReportType) error {
	if !ac.config.EnableAdvancedCaching {
		return nil // Silently skip if caching disabled
	}

	// Determine TTL based on report type
	ttl := ac.getTTLForReportType(reportType)

	err := ac.cache.Set(ctx, key, report, ttl)
	if err != nil {
		ac.logger.Warn("failed to cache report", "key", key, "error", err)
		return err
	}

	ac.logger.Debug("cached report",
		"key", key,
		"report_type", reportType,
		"ttl", ttl,
		"size_estimate", ac.estimateReportSize(report))

	return nil
}

// Delete removes a report from the cache
func (ac *AdvancedCache) Delete(ctx context.Context, key string) error {
	return ac.cache.Delete(ctx, key)
}

// Clear removes all reports from the cache
func (ac *AdvancedCache) Clear(ctx context.Context) error {
	ac.logger.Info("clearing advanced cache")
	return ac.cache.Clear(ctx)
}

// GenerateKey creates a cache key from request parameters using secure SHA-256 hashing
func (ac *AdvancedCache) GenerateKey(reportType interfaces.ReportType, params map[string]interface{}) string {
	// Create deterministic key from report type and parameters
	keyData := fmt.Sprintf("%s:%v", reportType, params)
	hash := sha256.Sum256([]byte(keyData))
	key := fmt.Sprintf("advanced:%s:%x", reportType, hash)

	ac.logger.Debug("generated cache key", "report_type", reportType, "key", key)
	return key
}

// GetCacheMetrics returns advanced cache metrics
func (ac *AdvancedCache) GetCacheMetrics(ctx context.Context) map[string]interface{} {
	if !ac.config.CacheMetricsEnabled {
		return map[string]interface{}{}
	}

	baseMetrics := map[string]interface{}{
		"enabled":                 ac.config.EnableAdvancedCaching,
		"compliance_report_ttl":   ac.config.ComplianceReportTTL.String(),
		"security_report_ttl":     ac.config.SecurityReportTTL.String(),
		"executive_report_ttl":    ac.config.ExecutiveReportTTL.String(),
		"multi_tenant_report_ttl": ac.config.MultiTenantReportTTL.String(),
		"max_cache_size":          ac.config.MaxCacheSize,
	}

	// Try to get additional metrics from underlying cache if supported
	if metricProvider, ok := ac.cache.(interface {
		GetMetrics(context.Context) map[string]interface{}
	}); ok {
		underlyingMetrics := metricProvider.GetMetrics(ctx)
		for k, v := range underlyingMetrics {
			baseMetrics[k] = v
		}
	}

	return baseMetrics
}

// getTTLForReportType returns the appropriate TTL for a given report type
func (ac *AdvancedCache) getTTLForReportType(reportType interfaces.ReportType) time.Duration {
	switch reportType {
	case interfaces.ReportTypeCompliance:
		return ac.config.ComplianceReportTTL
	case interfaces.ReportTypeSecurity:
		return ac.config.SecurityReportTTL
	case interfaces.ReportTypeExecutive:
		return ac.config.ExecutiveReportTTL
	case interfaces.ReportTypeMultiTenant:
		return ac.config.MultiTenantReportTTL
	case interfaces.ReportTypeDrift:
		return ac.config.SecurityReportTTL // Use security TTL for drift (also dynamic)
	case interfaces.ReportTypeOperational:
		return ac.config.ExecutiveReportTTL // Use executive TTL for operational
	case interfaces.ReportTypeAudit:
		return ac.config.SecurityReportTTL // Use security TTL for audit (also dynamic)
	default:
		return 1 * time.Hour // Default TTL for unknown types
	}
}

// estimateReportSize provides a rough estimate of report size for metrics
func (ac *AdvancedCache) estimateReportSize(report *interfaces.Report) int {
	size := len(report.Title) + len(report.Subtitle)

	for _, section := range report.Sections {
		size += len(section.Title) + 100 // Rough estimate for section content
	}

	for _, chart := range report.Charts {
		size += len(chart.Title) + 200 // Rough estimate for chart data
	}

	return size
}

// InvalidateByPattern removes cache entries matching a pattern (for tenant isolation)
func (ac *AdvancedCache) InvalidateByPattern(ctx context.Context, pattern string) error {
	ac.logger.Info("invalidating cache entries by pattern", "pattern", pattern)

	// For basic implementation, we'll clear all cache
	// A more sophisticated implementation would maintain a pattern index
	return ac.Clear(ctx)
}

// PrewarmCache pre-populates cache with commonly requested reports
func (ac *AdvancedCache) PrewarmCache(ctx context.Context, reportRequests []interfaces.ReportRequest) error {
	if !ac.config.EnableAdvancedCaching {
		return nil
	}

	ac.logger.Info("prewarming cache", "request_count", len(reportRequests))

	// This would typically be implemented to generate and cache common reports
	// For now, just log the intent
	for _, req := range reportRequests {
		ac.logger.Debug("cache prewarm request", "template", req.Template, "type", req.Type)
	}

	return nil
}
