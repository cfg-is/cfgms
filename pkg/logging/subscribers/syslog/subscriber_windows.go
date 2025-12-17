//go:build windows
// +build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package syslog provides stubs for Windows where native syslog is not available.
// On Windows, syslog functionality is not supported as there is no native syslog daemon.
// Consider using Windows Event Log instead for Windows-native logging.
package syslog

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// ErrNotSupported indicates syslog is not available on Windows
var ErrNotSupported = errors.New("syslog is not supported on Windows; use Windows Event Log instead")

// SyslogSubscriber stub for Windows - syslog is not natively supported
type SyslogSubscriber struct {
	config        *SyslogConfig
	initialized   bool
	mutex         sync.RWMutex
	enabledLevels map[string]bool
	hostname      string
	procID        string
}

// SyslogConfig holds configuration for the syslog subscriber
type SyslogConfig struct {
	Network   string   `json:"network"`
	Address   string   `json:"address"`
	EnableTLS bool     `json:"enable_tls"`
	Facility  string   `json:"facility"`
	Tag       string   `json:"tag"`
	Levels    []string `json:"levels"`
}

// DefaultSyslogConfig returns default syslog configuration (stub for Windows)
func DefaultSyslogConfig() *SyslogConfig {
	return &SyslogConfig{
		Network:  "udp",
		Address:  "localhost:514",
		Facility: "daemon",
		Tag:      "cfgms",
		Levels:   []string{},
	}
}

// NewSyslogSubscriber returns a stub subscriber on Windows (syslog is not supported)
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

// Name returns the subscriber name (implements LoggingSubscriber interface)
func (s *SyslogSubscriber) Name() string {
	return "syslog"
}

// Description returns the subscriber description (implements LoggingSubscriber interface)
func (s *SyslogSubscriber) Description() string {
	return "Syslog subscriber (not available on Windows)"
}

// Initialize initializes the subscriber (implements LoggingSubscriber interface)
// Returns an error since syslog is not supported on Windows
func (s *SyslogSubscriber) Initialize(config map[string]interface{}) error {
	return ErrNotSupported
}

// Close closes the subscriber (implements LoggingSubscriber interface)
func (s *SyslogSubscriber) Close() error {
	return nil
}

// HandleLogEntry is a no-op on Windows - logs are silently dropped
// (implements LoggingSubscriber interface)
func (s *SyslogSubscriber) HandleLogEntry(ctx context.Context, entry interfaces.LogEntry) error {
	// Silently drop - syslog not available on Windows
	return nil
}

// ShouldHandle always returns false on Windows since syslog is not available
// (implements LoggingSubscriber interface)
func (s *SyslogSubscriber) ShouldHandle(entry interfaces.LogEntry) bool {
	return false
}

// Available returns availability status (implements LoggingSubscriber interface)
// Always returns false on Windows since syslog is not available
func (s *SyslogSubscriber) Available() (bool, error) {
	return false, ErrNotSupported
}
