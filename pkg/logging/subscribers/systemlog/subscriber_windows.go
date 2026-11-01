//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package systemlog

import (
	"fmt"

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
	if !sourceInstalled(cfg.Tag) {
		if err := eventlog.InstallAsEventCreate(cfg.Tag, eventlog.Info|eventlog.Warning|eventlog.Error); err != nil {
			return nil, fmt.Errorf("install event source: %w", err)
		}
	}
	l, err := eventlog.Open(cfg.Tag)
	if err != nil {
		return nil, fmt.Errorf("open event source: %w", err)
	}
	return &eventLogBackend{l: l}, nil
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
