// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package terminal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMinimalAuthManager builds an AuthenticatedTerminalManager with only the
// fields touched by rotateTokensIfNeeded so the test has no dependency on
// RBAC, cert, or audit infrastructure.
func newMinimalAuthManager(rotationInterval time.Duration) *AuthenticatedTerminalManager {
	return &AuthenticatedTerminalManager{
		sessionTokens:  make(map[string]*SessionToken),
		notifyChannels: make(map[string]chan<- *TerminalMessage),
		config: &AuthConfig{
			TokenRotationInterval: rotationInterval,
			SessionTimeout:        4 * time.Hour,
		},
	}
}

func TestRotateTokensIfNeeded_SendsTokenRefreshMessage(t *testing.T) {
	atm := newMinimalAuthManager(1 * time.Millisecond)

	sessionID := "test-session-001"
	oldTokenStr := "old-token-value"

	atm.sessionTokens[oldTokenStr] = &SessionToken{
		Token:       oldTokenStr,
		SessionID:   sessionID,
		UserID:      "test-user",
		IssuedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(2 * time.Hour),
		LastRotated: time.Now().Add(-2 * time.Hour), // well past the 1 ms rotation interval
		Active:      true,
		Metadata:    make(map[string]string),
	}

	ch := make(chan *TerminalMessage, 1)
	atm.RegisterTokenRefreshChannel(sessionID, ch)

	atm.rotateTokensIfNeeded()

	require.Len(t, ch, 1, "expected exactly one token-refresh message on the channel")
	msg := <-ch

	assert.Equal(t, MessageTypeTokenRefresh, msg.Type)
	assert.Equal(t, sessionID, msg.SessionID)
	assert.NotEmpty(t, msg.Token, "new token must not be empty")
	assert.NotEqual(t, oldTokenStr, msg.Token, "rotated token must differ from the old one")
	require.NotNil(t, msg.ExpiresAt, "expires_at must be set")
	assert.True(t, msg.ExpiresAt.After(time.Now()), "expires_at must be in the future")

	// Old token must be gone; new token must be in the map.
	atm.tokenMutex.RLock()
	_, oldExists := atm.sessionTokens[oldTokenStr]
	_, newExists := atm.sessionTokens[msg.Token]
	atm.tokenMutex.RUnlock()

	assert.False(t, oldExists, "old token must be removed from the map after rotation")
	assert.True(t, newExists, "rotated token must be present in the map")
}

func TestRotateTokensIfNeeded_SlowClientDoesNotBlock(t *testing.T) {
	atm := newMinimalAuthManager(1 * time.Millisecond)

	sessionID := "test-session-slow"
	oldTokenStr := "old-token-slow"

	atm.sessionTokens[oldTokenStr] = &SessionToken{
		Token:       oldTokenStr,
		SessionID:   sessionID,
		UserID:      "test-user",
		IssuedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(2 * time.Hour),
		LastRotated: time.Now().Add(-2 * time.Hour),
		Active:      true,
		Metadata:    make(map[string]string),
	}

	// Unbuffered channel with no reader — simulates a slow or disconnected client.
	ch := make(chan *TerminalMessage)
	atm.RegisterTokenRefreshChannel(sessionID, ch)

	start := time.Now()
	atm.rotateTokensIfNeeded()
	elapsed := time.Since(start)

	// Rotation must not block longer than the notify timeout + a small margin.
	assert.Less(t, elapsed, tokenRefreshNotifyTimeout+200*time.Millisecond,
		"rotation must not block on a slow/disconnected client (elapsed: %v)", elapsed)

	// Token must still be rotated even when the client is slow.
	atm.tokenMutex.RLock()
	_, oldExists := atm.sessionTokens[oldTokenStr]
	count := len(atm.sessionTokens)
	atm.tokenMutex.RUnlock()

	assert.False(t, oldExists, "old token must be removed even when the notify channel is full")
	assert.Equal(t, 1, count, "exactly one token (the rotated replacement) must remain in the map")
}

func TestRotateTokensIfNeeded_NoNotifyWhenNoChannelRegistered(t *testing.T) {
	atm := newMinimalAuthManager(1 * time.Millisecond)

	atm.sessionTokens["tok"] = &SessionToken{
		Token:       "tok",
		SessionID:   "no-channel-session",
		UserID:      "test-user",
		IssuedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(2 * time.Hour),
		LastRotated: time.Now().Add(-2 * time.Hour),
		Active:      true,
		Metadata:    make(map[string]string),
	}

	// No channel registered — rotation must succeed without panicking.
	require.NotPanics(t, func() { atm.rotateTokensIfNeeded() })

	// Old token must be rotated out regardless.
	atm.tokenMutex.RLock()
	_, oldExists := atm.sessionTokens["tok"]
	atm.tokenMutex.RUnlock()
	assert.False(t, oldExists, "old token must be removed even without a registered notify channel")
}

func TestRotateTokensIfNeeded_TokenNotYetDue(t *testing.T) {
	atm := newMinimalAuthManager(1 * time.Hour) // long rotation interval

	sessionID := "test-session-not-due"
	tokenStr := "fresh-token"

	atm.sessionTokens[tokenStr] = &SessionToken{
		Token:       tokenStr,
		SessionID:   sessionID,
		UserID:      "test-user",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(4 * time.Hour),
		LastRotated: time.Now(), // just rotated — not due again
		Active:      true,
		Metadata:    make(map[string]string),
	}

	ch := make(chan *TerminalMessage, 1)
	atm.RegisterTokenRefreshChannel(sessionID, ch)

	atm.rotateTokensIfNeeded()

	assert.Len(t, ch, 0, "no refresh message expected when rotation interval has not elapsed")

	// Token must remain unchanged.
	atm.tokenMutex.RLock()
	_, exists := atm.sessionTokens[tokenStr]
	atm.tokenMutex.RUnlock()
	assert.True(t, exists, "token must remain in the map when rotation is not yet due")
}

func TestRegisterUnregisterTokenRefreshChannel(t *testing.T) {
	atm := newMinimalAuthManager(time.Hour)
	sessionID := "reg-test-session"
	ch := make(chan *TerminalMessage, 1)

	atm.RegisterTokenRefreshChannel(sessionID, ch)
	atm.tokenMutex.RLock()
	_, registered := atm.notifyChannels[sessionID]
	atm.tokenMutex.RUnlock()
	assert.True(t, registered, "channel must be present after RegisterTokenRefreshChannel")

	atm.UnregisterTokenRefreshChannel(sessionID)
	atm.tokenMutex.RLock()
	_, registered = atm.notifyChannels[sessionID]
	atm.tokenMutex.RUnlock()
	assert.False(t, registered, "channel must be absent after UnregisterTokenRefreshChannel")
}
