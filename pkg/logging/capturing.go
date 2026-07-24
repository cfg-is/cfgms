// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

import (
	"context"
	"sync"
)

// WarnEntry records the key-value pairs emitted by a single Warn or WarnCtx call.
type WarnEntry map[string]interface{}

// CapturingLogger is a Logger that records Warn/WarnCtx calls for inspection in
// tests. Other log levels are silently discarded.
// Thread-safe; safe to share across goroutines in parallel tests.
type CapturingLogger struct {
	mu           sync.Mutex
	WarnEntries  []WarnEntry // KV fields per Warn call
	WarnMessages []string    // message text per Warn call (parallel slice to WarnEntries)
}

// NewCapturingLogger returns a Logger that records Warn and WarnCtx calls.
func NewCapturingLogger() *CapturingLogger {
	return &CapturingLogger{}
}

func (l *CapturingLogger) record(msg string, kv []interface{}) {
	entry := make(WarnEntry, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if key, ok := kv[i].(string); ok {
			entry[key] = kv[i+1]
		}
	}
	l.mu.Lock()
	l.WarnEntries = append(l.WarnEntries, entry)
	l.WarnMessages = append(l.WarnMessages, msg)
	l.mu.Unlock()
}

func (l *CapturingLogger) Debug(_ string, _ ...interface{})                       {}
func (l *CapturingLogger) Info(_ string, _ ...interface{})                        {}
func (l *CapturingLogger) Warn(msg string, kv ...interface{})                     { l.record(msg, kv) }
func (l *CapturingLogger) Error(_ string, _ ...interface{})                       {}
func (l *CapturingLogger) Fatal(_ string, _ ...interface{})                       {}
func (l *CapturingLogger) DebugCtx(_ context.Context, _ string, _ ...interface{}) {}
func (l *CapturingLogger) InfoCtx(_ context.Context, _ string, _ ...interface{})  {}
func (l *CapturingLogger) WarnCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv)
}
func (l *CapturingLogger) ErrorCtx(_ context.Context, _ string, _ ...interface{}) {}
func (l *CapturingLogger) FatalCtx(_ context.Context, _ string, _ ...interface{}) {}
