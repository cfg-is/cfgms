//go:build !windows
// +build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package syslog implements a syslog subscriber for CFGMS logging system.
// This subscriber forwards log entries to syslog servers using RFC5424 format.
package syslog

import (
	"context"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// SyslogSubscriber implements LoggingSubscriber for syslog forwarding
type SyslogSubscriber struct {
	config      *SyslogConfig
	writer      *syslog.Writer
	initialized bool
	mutex       sync.RWMutex
	closeOnce   sync.Once

	// Level filtering
	enabledLevels map[string]bool

	// System information for RFC5424 fields
	hostname string
	procID   string
}

// SyslogConfig holds configuration for the syslog subscriber
type SyslogConfig struct {
	// Network configuration
	Network   string `json:"network"`    // "tcp", "udp", "unixgram", "unix"
	Address   string `json:"address"`    // "localhost:514", "/dev/log", etc.
	EnableTLS bool   `json:"enable_tls"` // Enable TLS for TCP connections

	// Syslog configuration
	Facility string `json:"facility"` // "daemon", "local0", etc.
	Tag      string `json:"tag"`      // Application tag for syslog

	// Filtering
	Levels []string `json:"levels"` // ["ERROR", "WARN", "INFO"] - empty means all

	// Performance settings
	WriteTimeout string `json:"write_timeout"` // "5s" - timeout for network writes
	BufferSize   int    `json:"buffer_size"`   // Buffer size for batching

	// Advanced settings
	StructuredData bool `json:"structured_data"` // Include CFGMS fields as structured data
	IncludePID     bool `json:"include_pid"`     // Include process ID
}

// DefaultSyslogConfig returns sensible defaults for syslog configuration
func DefaultSyslogConfig() *SyslogConfig {
	return &SyslogConfig{
		Network:        "udp",
		Address:        "localhost:514",
		EnableTLS:      false,
		Facility:       "daemon",
		Tag:            "cfgms",
		Levels:         []string{}, // All levels
		WriteTimeout:   "5s",
		BufferSize:     100,
		StructuredData: true,
		IncludePID:     true,
	}
}

// NewSyslogSubscriber creates a new syslog subscriber
func NewSyslogSubscriber() *SyslogSubscriber {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	return &SyslogSubscriber{
		config:        DefaultSyslogConfig(),
		enabledLevels: make(map[string]bool),
		hostname:      hostname,
		procID:        strconv.Itoa(os.Getpid()),
	}
}

// Name returns the subscriber name
func (s *SyslogSubscriber) Name() string {
	return "syslog"
}

// Description returns a human-readable description
func (s *SyslogSubscriber) Description() string {
	return "RFC5424 syslog subscriber for enterprise log aggregation"
}

// Initialize configures the syslog subscriber
func (s *SyslogSubscriber) Initialize(config map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.initialized {
		return fmt.Errorf("syslog subscriber already initialized")
	}

	// Parse configuration
	s.config = DefaultSyslogConfig()
	if err := s.parseConfig(config); err != nil {
		return fmt.Errorf("invalid syslog configuration: %w", err)
	}

	// Set up level filtering
	s.setupLevelFiltering()

	// Create syslog writer
	if err := s.createSyslogWriter(); err != nil {
		return fmt.Errorf("failed to create syslog writer: %w", err)
	}

	s.initialized = true
	return nil
}

// Close shuts down the syslog subscriber
func (s *SyslogSubscriber) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.mutex.Lock()
		defer s.mutex.Unlock()

		if !s.initialized {
			return
		}

		s.initialized = false

		if s.writer != nil {
			err = s.writer.Close()
			s.writer = nil
		}
	})

	return err
}

// Available checks if the syslog service is reachable
func (s *SyslogSubscriber) Available() (bool, error) {
	s.mutex.RLock()
	config := s.config
	s.mutex.RUnlock()

	if config == nil {
		return false, fmt.Errorf("subscriber not configured")
	}

	// Test connection for network protocols
	if config.Network == "tcp" || config.Network == "udp" {
		timeout := 5 * time.Second
		if config.WriteTimeout != "" {
			if duration, err := time.ParseDuration(config.WriteTimeout); err == nil {
				timeout = duration
			}
		}

		conn, err := net.DialTimeout(config.Network, config.Address, timeout)
		if err != nil {
			return false, fmt.Errorf("cannot connect to syslog server: %w", err)
		}
		_ = conn.Close()
	}

	return true, nil
}

// HandleLogEntry processes a log entry and sends it to syslog
func (s *SyslogSubscriber) HandleLogEntry(ctx context.Context, entry interfaces.LogEntry) error {
	s.mutex.RLock()
	writer := s.writer
	initialized := s.initialized
	config := s.config
	s.mutex.RUnlock()

	if !initialized || writer == nil {
		return fmt.Errorf("syslog subscriber not initialized")
	}

	// Check if we should handle this entry
	if !s.ShouldHandle(entry) {
		return nil // Silently skip filtered entries
	}

	// Populate RFC5424 fields
	facility := s.parseFacility(config.Facility)
	interfaces.PopulateRFC5424Fields(&entry, s.hostname, config.Tag, s.procID, facility)

	// Convert to syslog format
	syslogMessage := entry.ToSyslogFormat()

	// Send to syslog with context timeout
	writeCtx := ctx
	if config.WriteTimeout != "" {
		if timeout, err := time.ParseDuration(config.WriteTimeout); err == nil {
			var cancel context.CancelFunc
			writeCtx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
	}

	// Write with context cancellation support
	done := make(chan error, 1)
	go func() {
		// Write to syslog
		_, err := writer.Write([]byte(syslogMessage))
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-writeCtx.Done():
		return fmt.Errorf("syslog write timeout: %w", writeCtx.Err())
	}
}

// ShouldHandle determines if this subscriber should process the log entry
func (s *SyslogSubscriber) ShouldHandle(entry interfaces.LogEntry) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Check level filtering
	if len(s.enabledLevels) > 0 {
		return s.enabledLevels[entry.Level]
	}

	// No filtering - handle all entries
	return true
}

// parseConfig parses the configuration map into SyslogConfig
func (s *SyslogSubscriber) parseConfig(config map[string]interface{}) error {
	if network, ok := config["network"].(string); ok {
		s.config.Network = network
	}

	if address, ok := config["address"].(string); ok {
		s.config.Address = address
	}

	if enableTLS, ok := config["enable_tls"].(bool); ok {
		s.config.EnableTLS = enableTLS
	}

	if facility, ok := config["facility"].(string); ok {
		s.config.Facility = facility
	}

	if tag, ok := config["tag"].(string); ok {
		s.config.Tag = tag
	}

	if writeTimeout, ok := config["write_timeout"].(string); ok {
		s.config.WriteTimeout = writeTimeout
	}

	if structuredData, ok := config["structured_data"].(bool); ok {
		s.config.StructuredData = structuredData
	}

	if includePID, ok := config["include_pid"].(bool); ok {
		s.config.IncludePID = includePID
	}

	// Parse levels array
	if levels, ok := config["levels"].([]interface{}); ok {
		s.config.Levels = nil
		for _, level := range levels {
			if levelStr, ok := level.(string); ok {
				s.config.Levels = append(s.config.Levels, levelStr)
			}
		}
	} else if levels, ok := config["levels"].([]string); ok {
		s.config.Levels = levels
	}

	// Parse buffer size
	if bufferSize, ok := config["buffer_size"].(float64); ok {
		s.config.BufferSize = int(bufferSize)
	} else if bufferSize, ok := config["buffer_size"].(int); ok {
		s.config.BufferSize = bufferSize
	}

	return nil
}

// setupLevelFiltering configures level filtering based on config
func (s *SyslogSubscriber) setupLevelFiltering() {
	s.enabledLevels = make(map[string]bool)

	// If no levels specified, enable all
	if len(s.config.Levels) == 0 {
		return
	}

	// Enable only specified levels
	for _, level := range s.config.Levels {
		s.enabledLevels[strings.ToUpper(level)] = true
	}
}

// createSyslogWriter creates the underlying syslog.Writer
func (s *SyslogSubscriber) createSyslogWriter() error {
	facility := s.parseFacility(s.config.Facility)
	priority := syslog.Priority(int(facility) * 8) // Base priority for INFO level

	// Create writer based on network type
	var writer *syslog.Writer
	var err error

	switch s.config.Network {
	case "":
		// Default: local syslog
		writer, err = syslog.New(priority, s.config.Tag)
	default:
		// Network syslog
		writer, err = syslog.Dial(s.config.Network, s.config.Address, priority, s.config.Tag)
	}

	if err != nil {
		return fmt.Errorf("failed to create syslog writer: %w", err)
	}

	s.writer = writer
	return nil
}

// parseFacility converts facility string to SyslogFacility
func (s *SyslogSubscriber) parseFacility(facilityStr string) interfaces.SyslogFacility {
	switch strings.ToLower(facilityStr) {
	case "kern", "kernel":
		return interfaces.FacilityKernel
	case "user":
		return interfaces.FacilityUser
	case "mail":
		return interfaces.FacilityMail
	case "daemon":
		return interfaces.FacilityDaemon
	case "syslog":
		return interfaces.FacilitySyslog
	case "lpr":
		return interfaces.FacilityLPR
	case "news":
		return interfaces.FacilityNews
	case "uucp":
		return interfaces.FacilityUUCP
	case "cron":
		return interfaces.FacilityCron
	case "authpriv":
		return interfaces.FacilityAuthpriv
	case "ftp":
		return interfaces.FacilityFTP
	case "local0":
		return interfaces.FacilityLocal0
	case "local1":
		return interfaces.FacilityLocal1
	case "local2":
		return interfaces.FacilityLocal2
	case "local3":
		return interfaces.FacilityLocal3
	case "local4":
		return interfaces.FacilityLocal4
	case "local5":
		return interfaces.FacilityLocal5
	case "local6":
		return interfaces.FacilityLocal6
	case "local7":
		return interfaces.FacilityLocal7
	default:
		return interfaces.FacilityDaemon // Default to daemon
	}
}
