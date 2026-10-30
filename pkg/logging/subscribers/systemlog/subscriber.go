// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package systemlog implements a local system log subscriber for the CFGMS
// logging system. It writes to the Windows Event Log on Windows and to the
// local syslog socket on Linux and macOS (on macOS the syslog socket feeds the
// unified log). It exists so a steward with no usable identity, which cannot
// reach the controller, can still leave its reason where a local admin looks.
package systemlog

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// Level is the severity of a system log message.
type Level int

const (
	// LevelInfo is an informational message.
	LevelInfo Level = iota
	// LevelWarning is a warning.
	LevelWarning
	// LevelError is an error.
	LevelError
)

const (
	// DefaultTag is the syslog tag and the default Event Log source name.
	DefaultTag = "cfgms-steward"
	// DefaultCollapseWindow is how long identical consecutive messages are suppressed.
	DefaultCollapseWindow = time.Hour
	// maxMessageLength bounds what is written to the system log.
	maxMessageLength = 1024
	// redacted replaces any value that looks like a secret.
	redacted = "[REDACTED]"
)

// Config holds the systemlog subscriber configuration.
type Config struct {
	// Tag is the syslog tag (Unix) and Event Log source name (Windows).
	Tag string
	// CollapseWindow suppresses identical consecutive messages inside the window.
	CollapseWindow time.Duration
	// Network and Address select a non-default syslog socket (Unix only).
	// Both empty means the local system syslog socket.
	Network string
	Address string
	// Levels are the log entry levels HandleLogEntry forwards.
	Levels []string
}

func defaultConfig() Config {
	return Config{
		Tag:            DefaultTag,
		CollapseWindow: DefaultCollapseWindow,
		Levels:         []string{"WARN", "ERROR", "FATAL"},
	}
}

// backend is the platform-specific writer (Event Log or syslog).
type backend interface {
	write(level Level, message string) error
	close() error
}

// Subscriber implements interfaces.LoggingSubscriber for the local system log.
type Subscriber struct {
	mu      sync.Mutex
	cfg     Config
	be      backend
	openErr error
	levels  map[string]bool
	now     func() time.Time

	lastKey     string
	lastMessage string
	lastWritten time.Time
	haveLast    bool
}

var _ interfaces.LoggingSubscriber = (*Subscriber)(nil)

// NewSubscriber creates an uninitialized systemlog subscriber.
func NewSubscriber() *Subscriber {
	return &Subscriber{cfg: defaultConfig(), now: time.Now, openErr: errors.New("systemlog: not initialized")}
}

// Name returns the subscriber name.
func (s *Subscriber) Name() string { return "systemlog" }

// Description returns a human-readable description.
func (s *Subscriber) Description() string {
	return "Local system log sink (Windows Event Log, syslog, macOS unified log via syslog)"
}

// Initialize parses configuration and opens the platform backend. It returns
// an error, never panics, when the backend cannot be opened so callers can
// fall back to stderr.
func (s *Subscriber) Initialize(config map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.be != nil {
		return errors.New("systemlog subscriber already initialized")
	}
	cfg := defaultConfig()
	if err := parseConfig(&cfg, config); err != nil {
		s.openErr = err
		return fmt.Errorf("invalid systemlog configuration: %w", err)
	}
	be, err := openBackend(cfg)
	if err != nil {
		s.openErr = err
		return fmt.Errorf("systemlog backend unavailable: %w", err)
	}
	s.cfg = cfg
	s.be = be
	s.openErr = nil
	s.levels = make(map[string]bool, len(cfg.Levels))
	for _, l := range cfg.Levels {
		s.levels[strings.ToUpper(l)] = true
	}
	return nil
}

func parseConfig(cfg *Config, config map[string]interface{}) error {
	if v, ok := config["tag"].(string); ok && v != "" {
		cfg.Tag = v
	}
	if v, ok := config["network"].(string); ok {
		cfg.Network = v
	}
	if v, ok := config["address"].(string); ok {
		cfg.Address = v
	}
	switch v := config["collapse_window"].(type) {
	case nil:
	case string:
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return fmt.Errorf("collapse_window %q is not a valid duration", v)
		}
		cfg.CollapseWindow = d
	case time.Duration:
		if v < 0 {
			return errors.New("collapse_window must not be negative")
		}
		cfg.CollapseWindow = v
	default:
		return errors.New("collapse_window must be a duration string")
	}
	switch v := config["levels"].(type) {
	case nil:
	case []string:
		cfg.Levels = v
	case []interface{}:
		cfg.Levels = nil
		for _, e := range v {
			str, ok := e.(string)
			if !ok {
				return errors.New("levels must be strings")
			}
			cfg.Levels = append(cfg.Levels, str)
		}
	default:
		return errors.New("levels must be a list of strings")
	}
	return nil
}

// Close releases the backend.
func (s *Subscriber) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.be == nil {
		return nil
	}
	err := s.be.close()
	s.be = nil
	s.openErr = errors.New("systemlog: closed")
	return err
}

// Available reports whether the backend is open; when false the error says why.
func (s *Subscriber) Available() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.be == nil {
		return false, s.openErr
	}
	return true, nil
}

// ShouldHandle reports whether the entry's level is configured for forwarding.
func (s *Subscriber) ShouldHandle(entry interfaces.LogEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.be != nil && s.levels[strings.ToUpper(entry.Level)]
}

// HandleLogEntry writes the entry through the collapse window.
func (s *Subscriber) HandleLogEntry(_ context.Context, entry interfaces.LogEntry) error {
	level := LevelInfo
	switch strings.ToUpper(entry.Level) {
	case "WARN", "WARNING":
		level = LevelWarning
	case "ERROR", "FATAL":
		level = LevelError
	}
	return s.WriteOnce(level, entry.Component, entry.Message)
}

// WriteOnce writes message at level unless the same key and message were
// written most recently inside the collapse window. The message is sanitized
// and secret-looking values are redacted before it leaves the process.
func (s *Subscriber) WriteOnce(level Level, key, message string) error {
	message = Sanitize(message)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.be == nil {
		return fmt.Errorf("systemlog unavailable: %w", s.openErr)
	}
	now := s.now()
	if s.haveLast && key == s.lastKey && message == s.lastMessage &&
		now.Sub(s.lastWritten) < s.cfg.CollapseWindow {
		return nil
	}
	if err := s.be.write(level, message); err != nil {
		return fmt.Errorf("systemlog write failed: %w", err)
	}
	s.lastKey, s.lastMessage, s.lastWritten, s.haveLast = key, message, now, true
	return nil
}

var (
	// key=value / key: value pairs whose key names a credential.
	secretPairRE = regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|credential|private[_-]?key|bearer)[a-z0-9_.-]*)\s*[=:]\s*\S+`)
	// Authorization-style "Bearer xyz".
	bearerRE = regexp.MustCompile(`(?i)\bbearer\s+\S+`)
	// PEM blocks.
	pemRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+-----.*?(?:-----END [A-Z ]+-----|$)`)
	// Long opaque runs (base64/hex/JWT) that look like key material.
	opaqueRE = regexp.MustCompile(`[A-Za-z0-9+/_=.-]{32,}`)
)

// Sanitize strips control characters, redacts secret-looking values and
// bounds the length of a system log message.
func Sanitize(msg string) string {
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '_'
		}
		return r
	}, msg)
	msg = pemRE.ReplaceAllString(msg, redacted)
	msg = secretPairRE.ReplaceAllString(msg, "${1}="+redacted)
	msg = bearerRE.ReplaceAllString(msg, "Bearer "+redacted)
	msg = opaqueRE.ReplaceAllString(msg, redacted)
	if len(msg) > maxMessageLength {
		msg = strings.ToValidUTF8(msg[:maxMessageLength], "") + "..."
	}
	return msg
}
