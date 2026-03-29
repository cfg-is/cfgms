// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package dna provides system DNA (system attributes) collection for stewards.
//
// DNA represents the digital fingerprint of a system, containing hardware,
// software, and configuration attributes that uniquely identify and describe
// the system. This information is used by the controller for configuration
// targeting and system management.
//
// Basic usage:
//
//	collector := dna.NewCollector(logger)
//	dna, err := collector.Collect(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Printf("System ID: %s\n", dna.Id)
//	fmt.Printf("OS: %s\n", dna.Attributes["os"])
package dna

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Collector collects system DNA (attributes) for identification and targeting.
//
// The collector gathers hardware, software, and network information to create
// a comprehensive system profile. This information is used by the controller
// for configuration targeting and system management.
//
// Static hardware data (CPU, memory, motherboard, BIOS) is cached after the
// first collection and reused on subsequent calls. Software inventory
// (packages, services, processes) is collected asynchronously in a background
// goroutine after the first Collect() call, so startup is never blocked.
type Collector struct {
	logger logging.Logger

	// Hardware cache — static hardware data collected once and reused.
	hwCacheOnce sync.Once
	hwCacheMu   sync.RWMutex
	hwCache     map[string]string

	// Background collection — slow software/security data collected asynchronously.
	bgOnce    sync.Once
	bgDone    chan struct{} // closed when background collection completes
	slowMu    sync.RWMutex
	slowAttrs map[string]string
}

// NewCollector creates a new DNA collector.
//
// The collector will gather system information using platform-specific methods
// and create a comprehensive DNA profile for the system.
func NewCollector(logger logging.Logger) *Collector {
	return &Collector{
		logger: logger,
		bgDone: make(chan struct{}),
	}
}

// Collect gathers the current system DNA (attributes).
//
// On the first call, this method synchronously collects fast data (basic system
// info, cached hardware, network, environment) and immediately returns. Slow
// data (installed packages, services, processes, security) is collected
// asynchronously in a background goroutine.
//
// On subsequent calls, if the background collection has completed, the returned
// DNA includes the full merged dataset. If background collection is still
// running, only fast data is returned.
//
// The context controls per-command timeouts for platform-specific WMI and
// shell commands. A 30-second per-command timeout is applied automatically.
//
// Returns a DNA structure with a unique system ID and all collected attributes.
func (c *Collector) Collect(ctx context.Context) (*commonpb.DNA, error) {
	startTime := time.Now()
	c.logger.Debug("Collecting system DNA")

	attributes := make(map[string]string)

	// Collect basic system information (always fast)
	basicStart := time.Now()
	c.collectBasicInfo(attributes)
	c.logger.Debug("Basic info collected", "duration", time.Since(basicStart))

	// Collect hardware information (cached after first call)
	hwStart := time.Now()
	c.collectHardwareInfo(ctx, attributes)
	c.logger.Debug("Hardware info collected", "duration", time.Since(hwStart))

	// Collect network information (fast on all platforms)
	netStart := time.Now()
	c.collectNetworkInfo(ctx, attributes)
	c.logger.Debug("Network info collected", "duration", time.Since(netStart))

	// Collect environment information (always fast)
	envStart := time.Now()
	c.collectEnvironmentInfo(attributes)
	c.logger.Debug("Environment info collected", "duration", time.Since(envStart))

	// Start background goroutine for slow data on first call.
	// Uses context.Background() with a generous timeout so the goroutine
	// runs to completion even if the caller's context is short-lived.
	c.bgOnce.Do(func() {
		bgCtx, bgCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		go func() {
			defer bgCancel()
			c.runBackgroundCollection(bgCtx)
		}()
	})

	// Merge background data if it has already completed.
	select {
	case <-c.bgDone:
		c.slowMu.RLock()
		for k, v := range c.slowAttrs {
			attributes[k] = v
		}
		c.slowMu.RUnlock()
	default:
		// Background not yet complete; return fast data only.
	}

	// Generate stable system ID from hardware characteristics
	systemID := c.generateSystemID(attributes)

	now := time.Now()
	totalDuration := now.Sub(startTime)

	dna := &commonpb.DNA{
		Id:          systemID,
		Attributes:  attributes,
		LastUpdated: timestamppb.New(now),

		// Sync metadata (will be updated by steward with config info)
		ConfigHash:      "", // Will be set when steward loads configuration
		LastSyncTime:    timestamppb.New(now),
		AttributeCount:  c.safeInt32(len(attributes)), // Safe conversion with bounds validation
		SyncFingerprint: c.generateSyncFingerprint(systemID, attributes, ""),
	}

	c.logger.Info("System DNA collected",
		"id", systemID,
		"attributes", len(attributes),
		"total_duration", totalDuration)

	return dna, nil
}

// runBackgroundCollection collects slow software and security data asynchronously.
// It merges results into slowAttrs and closes bgDone when finished.
func (c *Collector) runBackgroundCollection(ctx context.Context) {
	c.logger.Debug("Starting background DNA collection (software + security)")
	start := time.Now()

	slowAttrs := make(map[string]string)
	c.collectSoftwareInfo(ctx, slowAttrs)
	c.collectSecurityInfo(ctx, slowAttrs)

	c.slowMu.Lock()
	c.slowAttrs = slowAttrs
	c.slowMu.Unlock()

	close(c.bgDone)
	c.logger.Info("Background DNA collection completed",
		"attributes", len(slowAttrs),
		"duration", time.Since(start))
}

// collectBasicInfo collects basic system information.
func (c *Collector) collectBasicInfo(attributes map[string]string) {
	attributes["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	attributes["runtime_version"] = runtime.Version()
	attributes["runtime_os"] = runtime.GOOS
	attributes["runtime_arch"] = runtime.GOARCH
	attributes["num_cpu"] = fmt.Sprintf("%d", runtime.NumCPU())

	if hostname, err := os.Hostname(); err == nil {
		attributes["hostname"] = hostname
	}

	if wd, err := os.Getwd(); err == nil {
		attributes["working_directory"] = wd
	}
}

// collectHardwareInfo collects hardware-specific information using platform-specific collectors.
// Static hardware data (CPU, memory, disk model, motherboard) is cached after the first call.
func (c *Collector) collectHardwareInfo(ctx context.Context, attributes map[string]string) {
	// Populate the hardware cache exactly once. Use a background context with a
	// generous timeout so the cache is always filled even when the caller's
	// context has a short deadline.
	c.hwCacheOnce.Do(func() {
		cacheCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		cache := make(map[string]string)
		hwCollector := NewHardwareCollector(cacheCtx)

		if err := hwCollector.CollectCPU(cacheCtx, cache); err != nil {
			c.logger.Error("Failed to collect CPU information", "error", err)
		}

		if err := hwCollector.CollectMemory(cacheCtx, cache); err != nil {
			c.logger.Error("Failed to collect memory information", "error", err)
		}

		if err := hwCollector.CollectDisk(cacheCtx, cache); err != nil {
			c.logger.Error("Failed to collect disk information", "error", err)
		}

		if err := hwCollector.CollectMotherboard(cacheCtx, cache); err != nil {
			c.logger.Error("Failed to collect motherboard information", "error", err)
		}

		c.hwCacheMu.Lock()
		c.hwCache = cache
		c.hwCacheMu.Unlock()
	})

	// Copy cached hardware data into the caller's attribute map.
	c.hwCacheMu.RLock()
	for k, v := range c.hwCache {
		attributes[k] = v
	}
	c.hwCacheMu.RUnlock()

	// Runtime fallback — always present, fast.
	attributes["runtime_arch"] = runtime.GOARCH
	attributes["runtime_os"] = runtime.GOOS
}

// collectSoftwareInfo collects software and OS information using platform-specific collectors.
func (c *Collector) collectSoftwareInfo(ctx context.Context, attributes map[string]string) {
	swCollector := NewSoftwareCollector(ctx)

	// Collect OS information
	if err := swCollector.CollectOS(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect OS information", "error", err)
	}

	// Collect installed packages/applications
	if err := swCollector.CollectPackages(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect package information", "error", err)
	}

	// Collect service information
	if err := swCollector.CollectServices(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect service information", "error", err)
	}

	// Collect process information
	if err := swCollector.CollectProcesses(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect process information", "error", err)
	}

	// Environment-based OS info as backup
	if osName := os.Getenv("OS"); osName != "" {
		attributes["env_os_name"] = osName
	}
}

// collectNetworkInfo collects network configuration information using platform-specific collectors.
func (c *Collector) collectNetworkInfo(ctx context.Context, attributes map[string]string) {
	netCollector := NewNetworkCollector()

	// Collect network interface information
	if err := netCollector.CollectInterfaces(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect network interface information", "error", err)
	}

	// Collect routing information
	if err := netCollector.CollectRouting(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect routing information", "error", err)
	}

	// Collect DNS configuration
	if err := netCollector.CollectDNS(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect DNS information", "error", err)
	}

	// Collect firewall configuration
	if err := netCollector.CollectFirewall(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect firewall information", "error", err)
	}
}

// collectSecurityInfo collects security attributes using platform-specific collectors.
func (c *Collector) collectSecurityInfo(ctx context.Context, attributes map[string]string) {
	secCollector := NewSecurityCollector()

	// Collect user information
	if err := secCollector.CollectUsers(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect user information", "error", err)
	}

	// Collect group information
	if err := secCollector.CollectGroups(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect group information", "error", err)
	}

	// Collect permission information
	if err := secCollector.CollectPermissions(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect permission information", "error", err)
	}

	// Collect certificate information
	if err := secCollector.CollectCertificates(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect certificate information", "error", err)
	}
}

// collectEnvironmentInfo collects environment and user information.
func (c *Collector) collectEnvironmentInfo(attributes map[string]string) {
	// User information
	if user := os.Getenv("USER"); user != "" {
		attributes["user"] = user
	}
	if home := os.Getenv("HOME"); home != "" {
		attributes["home_directory"] = home
	}

	// Path information
	if path := os.Getenv("PATH"); path != "" {
		// Store only the count to avoid exposing sensitive paths
		attributes["path_elements"] = fmt.Sprintf("%d", len(strings.Split(path, string(os.PathListSeparator))))
	}

	// Shell information
	if shell := os.Getenv("SHELL"); shell != "" {
		attributes["shell"] = shell
	}

	// Terminal information
	if term := os.Getenv("TERM"); term != "" {
		attributes["terminal"] = term
	}

	// Timezone
	if tz := os.Getenv("TZ"); tz != "" {
		attributes["timezone"] = tz
	} else {
		// Get timezone from system
		if zone, offset := time.Now().Zone(); zone != "" {
			attributes["timezone"] = zone
			attributes["timezone_offset"] = fmt.Sprintf("%d", offset)
		}
	}
}

// generateSystemID creates a stable system identifier from hardware characteristics.
//
// The system ID is generated from stable hardware identifiers like MAC addresses
// and hostname to ensure the same system gets the same ID across restarts.
func (c *Collector) generateSystemID(attributes map[string]string) string {
	// Use stable identifiers to generate system ID
	var identifiers []string

	// Primary MAC address (most stable)
	if mac := attributes["primary_mac"]; mac != "" {
		identifiers = append(identifiers, mac)
	}

	// Hostname (usually stable)
	if hostname := attributes["hostname"]; hostname != "" {
		identifiers = append(identifiers, hostname)
	}

	// CPU count and architecture (hardware characteristics)
	if cpuCount := attributes["cpu_count"]; cpuCount != "" {
		identifiers = append(identifiers, cpuCount)
	}
	if arch := attributes["arch"]; arch != "" {
		identifiers = append(identifiers, arch)
	}

	// If we have no stable identifiers, use runtime characteristics
	if len(identifiers) == 0 {
		identifiers = append(identifiers,
			attributes["runtime_os"],
			attributes["runtime_arch"],
			fmt.Sprintf("%d", time.Now().Unix()/3600), // Change hourly as fallback
		)
	}

	// Generate SHA256 hash of identifiers
	data := strings.Join(identifiers, "|")
	hash := sha256.Sum256([]byte(data))

	// Return first 16 characters of hex encoding
	return fmt.Sprintf("%x", hash[:8])
}

// RefreshDNA collects fresh DNA information.
//
// This is a convenience method that calls Collect() to get fresh system information.
// It's useful for periodic DNA updates where some attributes may have changed.
func (c *Collector) RefreshDNA(ctx context.Context) (*commonpb.DNA, error) {
	return c.Collect(ctx)
}

// CompareDNA compares two DNA structures and returns true if they represent the same system.
//
// This method compares the system IDs and key hardware characteristics to determine
// if two DNA structures represent the same physical system.
func CompareDNA(dna1, dna2 *commonpb.DNA) bool {
	if dna1 == nil || dna2 == nil {
		return false
	}

	// Primary comparison: system ID
	if dna1.Id != dna2.Id {
		return false
	}

	// Secondary comparison: key hardware characteristics
	keyAttributes := []string{"primary_mac", "hostname", "cpu_count", "arch"}

	for _, attr := range keyAttributes {
		if dna1.Attributes[attr] != dna2.Attributes[attr] {
			return false
		}
	}

	return true
}

// generateSyncFingerprint creates a fingerprint for sync verification.
//
// This combines the system ID, number of attributes, and config hash into a single
// fingerprint that can be used to quickly verify if DNA and configuration are in sync.
func (c *Collector) generateSyncFingerprint(systemID string, attributes map[string]string, configHash string) string {
	// Combine stable elements for sync verification
	elements := []string{
		systemID,
		fmt.Sprintf("%d", len(attributes)),
		configHash,
	}

	// Generate SHA256 hash
	data := strings.Join(elements, "|")
	hash := sha256.Sum256([]byte(data))

	// Return first 12 characters for compact representation
	return fmt.Sprintf("%x", hash[:6])
}

// UpdateSyncMetadata updates the sync-related fields in DNA.
//
// This should be called by the steward when configuration changes or when
// sync verification needs to be updated.
func (c *Collector) UpdateSyncMetadata(dna *commonpb.DNA, configHash string) {
	if dna == nil {
		return
	}

	dna.ConfigHash = configHash
	dna.LastSyncTime = timestamppb.New(time.Now())
	dna.AttributeCount = c.safeInt32(len(dna.Attributes)) // Safe conversion with bounds validation
	dna.SyncFingerprint = c.generateSyncFingerprint(dna.Id, dna.Attributes, configHash)
}

// ComputeHash computes a deterministic SHA-256 hash of the given DNA attributes.
//
// The hash is stable across Go map iteration order: keys are sorted before
// hashing so the same attribute set always produces the same hash regardless
// of insertion order. Returns an empty string when attributes is nil or empty.
//
// Both the steward and the controller call this function with the same attribute
// set so that matching hashes confirm synchronisation without full retransmission.
func ComputeHash(attributes map[string]string) string {
	if len(attributes) == 0 {
		return ""
	}

	keys := make([]string, 0, len(attributes))
	for k := range attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		// Write errors on hash.Hash are documented as always nil; ignore per io.Writer contract.
		_, _ = fmt.Fprintf(h, "%s=%s\n", k, attributes[k])
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// safeInt32 safely converts an int to int32 with bounds validation
func (c *Collector) safeInt32(value int) int32 {
	// Clamp to int32 max to prevent overflow
	if value > 2147483647 {
		return 2147483647
	}
	if value < -2147483648 {
		return -2147483648
	}
	return int32(value) // Safe: bounds validated above
}
