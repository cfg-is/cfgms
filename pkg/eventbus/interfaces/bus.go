// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package interfaces defines the EventBus contract for CFGMS log-entry fan-out.
//
// EventBus decouples LoggingManager's write path from its subscribers. The
// default in-process channel provider (providers/channel) preserves the
// existing best-effort, drop-on-full semantics. A NATS JetStream provider
// lands later under #2051 and satisfies this interface without touching any
// WriteEntry call site.
package interfaces

import (
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// EventBus fans log entries out to zero or more subscribers asynchronously.
// Implementations must be safe for concurrent use.
type EventBus interface {
	// Publish enqueues entry for delivery to all registered subscribers.
	// Returns immediately (non-blocking). If the bus buffer is full the entry
	// is dropped and an internal counter is incremented — primary persistence
	// (LoggingManager.WriteEntry) is unaffected.
	Publish(entry interfaces.LogEntry)

	// Subscribe registers a subscriber to receive future entries. It is safe
	// to call after the bus has started; the subscriber receives entries
	// published after this call returns.
	Subscribe(sub interfaces.LoggingSubscriber)

	// Close drains in-flight entries and releases resources. All registered
	// subscribers are closed. Subsequent Publish calls are silently dropped.
	Close() error
}
