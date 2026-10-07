// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

import (
	"context"
	"sync"
)

// LogEntry records the key-value pairs emitted by a single captured log call.
type LogEntry map[string]interface{}

// WarnEntry is the key-value record of a single Warn or WarnCtx call.
type WarnEntry = LogEntry

// InfoEntry is the key-value record of a single Info or InfoCtx call.
type InfoEntry = LogEntry

// CapturingLogger is a Logger that records Warn/WarnCtx and Info/InfoCtx calls
// for inspection in tests. Other log levels are silently discarded.
// Thread-safe; safe to share across goroutines in parallel tests.
type CapturingLogger struct {
	mu           sync.Mutex
	WarnEntries  []WarnEntry // KV fields per Warn call
	WarnMessages []string    // message text per Warn call (parallel slice to WarnEntries)
	InfoEntries  []InfoEntry // KV fields per Info call
	InfoMessages []string    // message text per Info call (parallel slice to InfoEntries)
}

// NewCapturingLogger returns a Logger that records Warn/WarnCtx and Info/InfoCtx calls.
func NewCapturingLogger() *CapturingLogger {
	return &CapturingLogger{}
}

// toEntry converts a variadic key-value list into a LogEntry, dropping any pair
// whose key is not a string.
func toEntry(kv []interface{}) LogEntry {
	entry := make(LogEntry, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if key, ok := kv[i].(string); ok {
			entry[key] = kv[i+1]
		}
	}
	return entry
}

func (l *CapturingLogger) record(msg string, kv []interface{}) {
	entry := toEntry(kv)
	l.mu.Lock()
	l.WarnEntries = append(l.WarnEntries, entry)
	l.WarnMessages = append(l.WarnMessages, msg)
	l.mu.Unlock()
}

func (l *CapturingLogger) recordInfo(msg string, kv []interface{}) {
	entry := toEntry(kv)
	l.mu.Lock()
	l.InfoEntries = append(l.InfoEntries, entry)
	l.InfoMessages = append(l.InfoMessages, msg)
	l.mu.Unlock()
}

// FindWarn returns the fields of the first Warn/WarnCtx call whose message
// equals msg (case-sensitive), and whether such a call was recorded.
func (l *CapturingLogger) FindWarn(msg string) (LogEntry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return findEntry(l.WarnMessages, l.WarnEntries, msg)
}

// FindInfo returns the fields of the first Info/InfoCtx call whose message
// equals msg (case-sensitive), and whether such a call was recorded.
func (l *CapturingLogger) FindInfo(msg string) (LogEntry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return findEntry(l.InfoMessages, l.InfoEntries, msg)
}

// InfoCount returns the number of Info/InfoCtx calls recorded so far.
func (l *CapturingLogger) InfoCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.InfoMessages)
}

// WarnCount returns the number of Warn/WarnCtx calls recorded so far.
func (l *CapturingLogger) WarnCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.WarnMessages)
}

// findEntry locates msg in parallel message/entry slices. Callers hold the lock.
func findEntry(messages []string, entries []LogEntry, msg string) (LogEntry, bool) {
	for i, m := range messages {
		if m == msg {
			return entries[i], true
		}
	}
	return nil, false
}

func (l *CapturingLogger) Debug(_ string, _ ...interface{})                       {}
func (l *CapturingLogger) Info(msg string, kv ...interface{})                     { l.recordInfo(msg, kv) }
func (l *CapturingLogger) Warn(msg string, kv ...interface{})                     { l.record(msg, kv) }
func (l *CapturingLogger) Error(_ string, _ ...interface{})                       {}
func (l *CapturingLogger) Fatal(_ string, _ ...interface{})                       {}
func (l *CapturingLogger) DebugCtx(_ context.Context, _ string, _ ...interface{}) {}
func (l *CapturingLogger) InfoCtx(_ context.Context, msg string, kv ...interface{}) {
	l.recordInfo(msg, kv)
}
func (l *CapturingLogger) WarnCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv)
}
func (l *CapturingLogger) ErrorCtx(_ context.Context, _ string, _ ...interface{}) {}
func (l *CapturingLogger) FatalCtx(_ context.Context, _ string, _ ...interface{}) {}
