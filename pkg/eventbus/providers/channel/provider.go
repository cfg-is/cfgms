// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package channel provides an in-process Go-channel implementation of
// pkg/eventbus/interfaces.EventBus.
//
// Semantics: best-effort, drop-on-full, parallel subscriber dispatch with a
// per-handler timeout. These match the semantics that existed in
// LoggingManager before this package was extracted. The NATS JetStream
// provider (#2051) will satisfy the same EventBus interface without requiring
// any changes to call sites.
package channel

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

const (
	// defaultHandlerTimeout is the per-subscriber dispatch deadline.
	defaultHandlerTimeout = 5 * time.Second
)

// Bus is the in-process channel EventBus implementation.
type Bus struct {
	ch      chan interfaces.LogEntry
	stopCh  chan struct{}
	once    sync.Once
	dropped atomic.Int64

	mu          sync.RWMutex
	subscribers []interfaces.LoggingSubscriber
}

// New creates a Bus with the given channel buffer size and starts its event
// loop. bufSize must be > 0; use a value matching the LoggingConfig.BufferSize.
func New(bufSize int) *Bus {
	if bufSize <= 0 {
		bufSize = 1
	}
	b := &Bus{
		ch:     make(chan interfaces.LogEntry, bufSize),
		stopCh: make(chan struct{}),
	}
	go b.loop()
	return b
}

// Subscribe registers a subscriber for subsequent entries. It is safe to call
// concurrently and after the bus has started.
func (b *Bus) Subscribe(sub interfaces.LoggingSubscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers = append(b.subscribers, sub)
}

// Publish enqueues entry for delivery. If the channel is full the entry is
// dropped and DroppedCount is incremented.
func (b *Bus) Publish(entry interfaces.LogEntry) {
	select {
	case b.ch <- entry:
	default:
		b.dropped.Add(1)
	}
}

// DroppedCount returns the total number of entries dropped due to a full
// channel buffer since the bus was created.
func (b *Bus) DroppedCount() int64 {
	return b.dropped.Load()
}

// Close drains the event loop, closes all subscribers, and releases
// resources. Safe to call multiple times.
func (b *Bus) Close() error {
	b.once.Do(func() {
		close(b.stopCh)
	})

	// Close all registered subscribers.
	b.mu.RLock()
	subs := make([]interfaces.LoggingSubscriber, len(b.subscribers))
	copy(subs, b.subscribers)
	b.mu.RUnlock()

	for _, s := range subs {
		if err := s.Close(); err != nil {
			fmt.Printf("Warning: failed to close event bus subscriber %s: %v\n", s.Name(), err)
		}
	}
	return nil
}

// loop is the background goroutine that fans out entries to subscribers.
func (b *Bus) loop() {
	for {
		select {
		case entry := <-b.ch:
			b.dispatch(entry)
		case <-b.stopCh:
			return
		}
	}
}

// dispatch sends entry to all subscribers whose ShouldHandle returns true.
// Each subscriber is called in its own goroutine with a per-handler timeout.
func (b *Bus) dispatch(entry interfaces.LogEntry) {
	b.mu.RLock()
	subs := make([]interfaces.LoggingSubscriber, len(b.subscribers))
	copy(subs, b.subscribers)
	b.mu.RUnlock()

	for _, sub := range subs {
		if !sub.ShouldHandle(entry) {
			continue
		}
		go func(s interfaces.LoggingSubscriber) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultHandlerTimeout)
			defer cancel()
			if err := s.HandleLogEntry(ctx, entry); err != nil {
				fmt.Printf("Warning: event bus subscriber %s failed: %v\n", s.Name(), err)
			}
		}(sub)
	}
}
