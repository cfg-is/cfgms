// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines the SessionStore interface for durable session persistence
package interfaces

import (
	"context"
	"errors"
	"time"
)

// ErrNotSupported is returned when a provider does not implement a particular store type.
var ErrNotSupported = errors.New("operation not supported by this provider")

// ErrImmutable is returned when an attempt is made to modify or delete an immutable record.
var ErrImmutable = errors.New("record is immutable and cannot be modified or deleted")

// SessionStore defines storage interface for durable session data.
// Only sessions with Persistent=true should be written here.
// Ephemeral sessions (Persistent=false) belong in pkg/cache and are out of scope.
//
// Methods from RuntimeStore that manage ephemeral runtime state
// (SetRuntimeState, GetRuntimeState, DeleteRuntimeState, ListRuntimeKeys)
// are intentionally absent — those belong in pkg/cache.
type SessionStore interface {
	// Session CRUD
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	UpdateSession(ctx context.Context, sessionID string, session *Session) error
	DeleteSession(ctx context.Context, sessionID string) error
	ListSessions(ctx context.Context, filters *SessionFilter) ([]*Session, error)

	// Session lifecycle
	SetSessionTTL(ctx context.Context, sessionID string, ttl time.Duration) error
	CleanupExpiredSessions(ctx context.Context) (int, error)

	// Session queries
	GetSessionsByUser(ctx context.Context, userID string) ([]*Session, error)
	GetSessionsByTenant(ctx context.Context, tenantID string) ([]*Session, error)
	GetSessionsByType(ctx context.Context, sessionType SessionType) ([]*Session, error)
	GetActiveSessionsCount(ctx context.Context) (int64, error)

	// Health and diagnostics
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (*RuntimeStoreStats, error)

	// Lifecycle
	Initialize(ctx context.Context) error
	Close() error
}

// SessionStoreProvider is an optional extension interface that providers implement
// when they support durable session storage.
type SessionStoreProvider interface {
	CreateSessionStore(config map[string]interface{}) (SessionStore, error)
}
