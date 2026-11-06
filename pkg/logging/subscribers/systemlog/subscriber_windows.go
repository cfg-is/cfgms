//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package systemlog

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/eventlog"
)

const eventLogKeyPrefix = `SYSTEM\CurrentControlSet\Services\EventLog\Application\`

type eventLogBackend struct {
	l *eventlog.Log
}

// openBackend registers the event source on first use (the steward runs as
// SYSTEM) and opens it. Failure is returned so callers can fall back to stderr.
func openBackend(cfg Config) (backend, error) {
	justInstalled := false
	if !sourceInstalled(cfg.Tag) {
		if err := eventlog.InstallAsEventCreate(cfg.Tag, eventlog.Info|eventlog.Warning|eventlog.Error); err != nil {
			return nil, fmt.Errorf("install event source: %w", err)
		}
		justInstalled = true
	}
	// An already-installed source is known to the Event Log service, so
	// access denied there is a real failure and is not retried.
	l, err := openSourceWithRetry(eventlog.Open, cfg.Tag, retryDeadline(justInstalled), sourceOpenInterval)
	if err != nil {
		return nil, fmt.Errorf("open event source: %w", err)
	}
	return &eventLogBackend{l: l}, nil
}

const (
	sourceOpenDeadline = 5 * time.Second
	sourceOpenInterval = 50 * time.Millisecond
)

func retryDeadline(justInstalled bool) time.Duration {
	if justInstalled {
		return sourceOpenDeadline
	}
	return 0
}

// openSourceWithRetry opens an event source, polling while the open fails with
// ERROR_ACCESS_DENIED until deadline. The registry key written by the install
// step is learned asynchronously by the Event Log service, so RegisterEventSource
// can be denied briefly for a freshly installed source. Any other error, or a
// zero deadline, returns after the first attempt.
func openSourceWithRetry(open func(string) (*eventlog.Log, error), source string, deadline, interval time.Duration) (*eventlog.Log, error) {
	stop := time.Now().Add(deadline)
	for {
		l, err := open(source)
		if err == nil {
			return l, nil
		}
		remaining := time.Until(stop)
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || remaining <= 0 {
			return nil, err
		}
		time.Sleep(min(interval, remaining))
	}
}

func sourceInstalled(source string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, eventLogKeyPrefix+source, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

const eventID = 1

func (b *eventLogBackend) write(level Level, message string) error {
	switch level {
	case LevelError:
		return b.l.Error(eventID, message)
	case LevelWarning:
		return b.l.Warning(eventID, message)
	default:
		return b.l.Info(eventID, message)
	}
}

func (b *eventLogBackend) close() error { return b.l.Close() }
