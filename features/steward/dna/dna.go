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
// Static hardware data (CPU, memory, motherboard) is cached after the first
// collection and reused on subsequent calls. Slow software data (packages,
// services, processes) is collected in the background so that Collect()
// returns fast data synchronously on every call.
type Collector struct {
	logger logging.Logger

	// Static hardware cache: CPU, memory, motherboard do not change at runtime.
	cachedHardware map[string]string
	hardwareMu     sync.RWMutex
	hardwareCached bool

	// Background slow-software data: packages, services, processes.
	bgData      map[string]string
	bgMu        sync.RWMutex
	bgRunning   bool
	bgRunningMu sync.Mutex
}

// NewCollector creates a new DNA collector.
//
// The collector will gather system information using platform-specific methods
// and create a comprehensive DNA profile for the system.
func NewCollector(logger logging.Logger) *Collector {
	return &Collector{
		logger: logger,
	}
}

// Collect gathers the current system DNA (attributes).
//
// Fast data (basic info, cached hardware, OS info, network, environment,
// security) is collected synchronously. Slow data (packages, services,
// processes) is collected in the background; the results from the previous
// background run are merged into this call's result.
//
// Static hardware (CPU, memory, motherboard) is cached after the first call
// and reused on all subsequent calls. Disk free space is always re-collected.
//
// Returns a DNA structure with a unique system ID and all collected attributes.
func (c *Collector) Collect(ctx context.Context) (*commonpb.DNA, error) {
	startTime := time.Now()
	c.logger.Debug("Collecting system DNA")

	attributes := make(map[string]string)

	// Basic system information (fastest first)
	basicStart := time.Now()
	c.collectBasicInfo(attributes)
	c.logger.Debug("Basic info collected", "duration", time.Since(basicStart))

	// Hardware information: static fields from cache, disk always fresh
	hwStart := time.Now()
	c.collectHardwareInfoCached(ctx, attributes)
	c.logger.Debug("Hardware info collected", "duration", time.Since(hwStart))

	// OS info only (fast part of software collection)
	osStart := time.Now()
	c.collectOSInfo(ctx, attributes)
	c.logger.Debug("OS info collected", "duration", time.Since(osStart))

	// Network information
	netStart := time.Now()
	c.collectNetworkInfo(ctx, attributes)
	c.logger.Debug("Network info collected", "duration", time.Since(netStart))

	// Environment information (fast)
	envStart := time.Now()
	c.collectEnvironmentInfo(attributes)
	c.logger.Debug("Environment info collected", "duration", time.Since(envStart))

	// Security information
	secStart := time.Now()
	c.collectSecurityInfo(ctx, attributes)
	c.logger.Debug("Security info collected", "duration", time.Since(secStart))

	// Merge any available background software data from the previous run
	c.bgMu.RLock()
	for k, v := range c.bgData {
		attributes[k] = v
	}
	c.bgMu.RUnlock()

	// Launch background goroutine for slow software if not already running
	c.bgRunningMu.Lock()
	if !c.bgRunning {
		c.bgRunning = true
		// Use a detached context so the background goroutine is not cancelled
		// when the caller's context is cancelled. Each command has its own
		// 30-second timeout enforced inside the platform collectors.
		go c.collectSlowSoftwareBackground(context.Background())
	}
	c.bgRunningMu.Unlock()

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

// collectHardwareInfoCached collects hardware information with caching.
//
// CPU, memory, and motherboard data are static and cached after first
// collection. Disk data (which includes free space) is always re-collected.
func (c *Collector) collectHardwareInfoCached(ctx context.Context, attributes map[string]string) {
	hwCollector := NewHardwareCollector()

	// Always collect disk — free space changes at runtime.
	if err := hwCollector.CollectDisk(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect disk information", "error", err)
	}

	// Return cached static hardware if available.
	c.hardwareMu.RLock()
	if c.hardwareCached {
		for k, v := range c.cachedHardware {
			attributes[k] = v
		}
		c.hardwareMu.RUnlock()
		attributes["runtime_arch"] = runtime.GOARCH
		attributes["runtime_os"] = runtime.GOOS
		return
	}
	c.hardwareMu.RUnlock()

	// First call: collect and cache static hardware.
	staticAttrs := make(map[string]string)

	if err := hwCollector.CollectCPU(ctx, staticAttrs); err != nil {
		c.logger.Error("Failed to collect CPU information", "error", err)
	}
	if err := hwCollector.CollectMemory(ctx, staticAttrs); err != nil {
		c.logger.Error("Failed to collect memory information", "error", err)
	}
	if err := hwCollector.CollectMotherboard(ctx, staticAttrs); err != nil {
		c.logger.Error("Failed to collect motherboard information", "error", err)
	}

	c.hardwareMu.Lock()
	c.cachedHardware = staticAttrs
	c.hardwareCached = true
	c.hardwareMu.Unlock()

	for k, v := range staticAttrs {
		attributes[k] = v
	}

	attributes["runtime_arch"] = runtime.GOARCH
	attributes["runtime_os"] = runtime.GOOS
}

// collectHardwareInfo collects all hardware information (CPU, memory, disk,
// motherboard) without caching. Used for direct testing.
func (c *Collector) collectHardwareInfo(ctx context.Context, attributes map[string]string) {
	hwCollector := NewHardwareCollector()

	if err := hwCollector.CollectCPU(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect CPU information", "error", err)
	}
	if err := hwCollector.CollectMemory(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect memory information", "error", err)
	}
	if err := hwCollector.CollectDisk(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect disk information", "error", err)
	}
	if err := hwCollector.CollectMotherboard(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect motherboard information", "error", err)
	}

	attributes["runtime_arch"] = runtime.GOARCH
	attributes["runtime_os"] = runtime.GOOS
}

// collectOSInfo collects only the OS portion of software information (fast).
func (c *Collector) collectOSInfo(ctx context.Context, attributes map[string]string) {
	swCollector := NewSoftwareCollector()

	if err := swCollector.CollectOS(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect OS information", "error", err)
	}

	if osName := os.Getenv("OS"); osName != "" {
		attributes["env_os_name"] = osName
	}
}

// collectSoftwareInfo collects all software information synchronously.
// Used for direct testing; Collect() uses collectOSInfo + background goroutine instead.
func (c *Collector) collectSoftwareInfo(ctx context.Context, attributes map[string]string) {
	swCollector := NewSoftwareCollector()

	if err := swCollector.CollectOS(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect OS information", "error", err)
	}
	if err := swCollector.CollectPackages(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect package information", "error", err)
	}
	if err := swCollector.CollectServices(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect service information", "error", err)
	}
	if err := swCollector.CollectProcesses(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect process information", "error", err)
	}

	if osName := os.Getenv("OS"); osName != "" {
		attributes["env_os_name"] = osName
	}
}

// collectSlowSoftwareBackground collects packages, services, and processes in
// the background and stores the result for the next Collect() call to merge.
func (c *Collector) collectSlowSoftwareBackground(ctx context.Context) {
	defer func() {
		c.bgRunningMu.Lock()
		c.bgRunning = false
		c.bgRunningMu.Unlock()
	}()

	swCollector := NewSoftwareCollector()
	bgAttrs := make(map[string]string)

	if err := swCollector.CollectPackages(ctx, bgAttrs); err != nil {
		c.logger.Error("Background: failed to collect package information", "error", err)
	}
	if err := swCollector.CollectServices(ctx, bgAttrs); err != nil {
		c.logger.Error("Background: failed to collect service information", "error", err)
	}
	if err := swCollector.CollectProcesses(ctx, bgAttrs); err != nil {
		c.logger.Error("Background: failed to collect process information", "error", err)
	}

	c.bgMu.Lock()
	c.bgData = bgAttrs
	c.bgMu.Unlock()

	c.logger.Debug("Background software collection complete", "attributes", len(bgAttrs))
}

// collectNetworkInfo collects network configuration information using platform-specific collectors.
func (c *Collector) collectNetworkInfo(ctx context.Context, attributes map[string]string) {
	netCollector := NewNetworkCollector()

	if err := netCollector.CollectInterfaces(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect network interface information", "error", err)
	}
	if err := netCollector.CollectRouting(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect routing information", "error", err)
	}
	if err := netCollector.CollectDNS(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect DNS information", "error", err)
	}
	if err := netCollector.CollectFirewall(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect firewall information", "error", err)
	}
}

// collectSecurityInfo collects security attributes using platform-specific collectors.
func (c *Collector) collectSecurityInfo(ctx context.Context, attributes map[string]string) {
	secCollector := NewSecurityCollector()

	if err := secCollector.CollectUsers(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect user information", "error", err)
	}
	if err := secCollector.CollectGroups(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect group information", "error", err)
	}
	if err := secCollector.CollectPermissions(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect permission information", "error", err)
	}
	if err := secCollector.CollectCertificates(ctx, attributes); err != nil {
		c.logger.Error("Failed to collect certificate information", "error", err)
	}
}

// collectEnvironmentInfo collects environment and user information.
func (c *Collector) collectEnvironmentInfo(attributes map[string]string) {
	if user := os.Getenv("USER"); user != "" {
		attributes["user"] = user
	}
	if home := os.Getenv("HOME"); home != "" {
		attributes["home_directory"] = home
	}

	if path := os.Getenv("PATH"); path != "" {
		attributes["path_elements"] = fmt.Sprintf("%d", len(strings.Split(path, string(os.PathListSeparator))))
	}

	if shell := os.Getenv("SHELL"); shell != "" {
		attributes["shell"] = shell
	}
	if term := os.Getenv("TERM"); term != "" {
		attributes["terminal"] = term
	}

	if tz := os.Getenv("TZ"); tz != "" {
		attributes["timezone"] = tz
	} else {
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
	var identifiers []string

	if mac := attributes["primary_mac"]; mac != "" {
		identifiers = append(identifiers, mac)
	}
	if hostname := attributes["hostname"]; hostname != "" {
		identifiers = append(identifiers, hostname)
	}
	if cpuCount := attributes["cpu_count"]; cpuCount != "" {
		identifiers = append(identifiers, cpuCount)
	}
	if arch := attributes["arch"]; arch != "" {
		identifiers = append(identifiers, arch)
	}

	if len(identifiers) == 0 {
		identifiers = append(identifiers,
			attributes["runtime_os"],
			attributes["runtime_arch"],
			fmt.Sprintf("%d", time.Now().Unix()/3600),
		)
	}

	data := strings.Join(identifiers, "|")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

// RefreshDNA collects fresh DNA information.
//
// This is a convenience method that calls Collect() to get fresh system
// information. It's useful for periodic DNA updates where some attributes
// may have changed.
func (c *Collector) RefreshDNA(ctx context.Context) (*commonpb.DNA, error) {
	return c.Collect(ctx)
}

// CompareDNA compares two DNA structures and returns true if they represent the same system.
func CompareDNA(dna1, dna2 *commonpb.DNA) bool {
	if dna1 == nil || dna2 == nil {
		return false
	}
	if dna1.Id != dna2.Id {
		return false
	}

	keyAttributes := []string{"primary_mac", "hostname", "cpu_count", "arch"}
	for _, attr := range keyAttributes {
		if dna1.Attributes[attr] != dna2.Attributes[attr] {
			return false
		}
	}

	return true
}

// generateSyncFingerprint creates a fingerprint for sync verification.
func (c *Collector) generateSyncFingerprint(systemID string, attributes map[string]string, configHash string) string {
	elements := []string{
		systemID,
		fmt.Sprintf("%d", len(attributes)),
		configHash,
	}

	data := strings.Join(elements, "|")
	hash := sha256.Sum256([]byte(data))
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
	dna.AttributeCount = c.safeInt32(len(dna.Attributes))
	dna.SyncFingerprint = c.generateSyncFingerprint(dna.Id, dna.Attributes, configHash)
}

// ComputeHash computes a deterministic SHA-256 hash of the given DNA attributes.
//
// The hash is stable across Go map iteration order: keys are sorted before
// hashing so the same attribute set always produces the same hash regardless
// of insertion order. Returns an empty string when attributes is nil or empty.
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
		_, _ = fmt.Fprintf(h, "%s=%s\n", k, attributes[k])
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// safeInt32 safely converts an int to int32 with bounds validation
func (c *Collector) safeInt32(value int) int32 {
	if value > 2147483647 {
		return 2147483647
	}
	if value < -2147483648 {
		return -2147483648
	}
	return int32(value)
}
