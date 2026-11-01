//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package systemlog

import (
	"log/syslog"
)

type syslogBackend struct {
	w *syslog.Writer
}

// openBackend connects to the local syslog socket. With no Network/Address
// configured this is the system socket (on macOS it feeds the unified log).
func openBackend(cfg Config) (backend, error) {
	priority := syslog.LOG_DAEMON | syslog.LOG_INFO
	var (
		w   *syslog.Writer
		err error
	)
	if cfg.Network == "" && cfg.Address == "" {
		w, err = syslog.New(priority, cfg.Tag)
	} else {
		w, err = syslog.Dial(cfg.Network, cfg.Address, priority, cfg.Tag)
	}
	if err != nil {
		return nil, err
	}
	return &syslogBackend{w: w}, nil
}

func (b *syslogBackend) write(level Level, message string) error {
	switch level {
	case LevelError:
		return b.w.Err(message)
	case LevelWarning:
		return b.w.Warning(message)
	default:
		return b.w.Info(message)
	}
}

func (b *syslogBackend) close() error { return b.w.Close() }
