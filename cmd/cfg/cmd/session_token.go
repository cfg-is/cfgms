// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/oskeychain" // register OS-keychain provider
)

// sessionTokenKey is the key used to store the active session record in the OS keychain.
const sessionTokenKey = "cfgms/active-session" // #nosec G101 — keychain storage key, not a credential

// sessionRecord holds the active session state stored in the OS-native secret store.
// No token material is ever written to a file on disk.
type sessionRecord struct {
	Token          string    `json:"token"`
	SessionID      string    `json:"session_id"`
	ControllerURL  string    `json:"controller_url"`
	ConnectionName string    `json:"connection_name"`
	AbsoluteExpiry time.Time `json:"absolute_expiry"`
	CACertPEM      string    `json:"ca_cert_pem,omitempty"` // CA used to verify the controller; empty → system pool
}

// sessionStoreFn opens the OS-native secret store for session token management.
// Overridable in tests to inject an in-memory SecretStore.
var sessionStoreFn = openSessionStore

// openSessionStore opens the oskeychain SecretStore.
// Returns (nil, nil) when the provider is unavailable on this platform.
func openSessionStore() (interfaces.SecretStore, error) {
	p, err := interfaces.GetSecretProvider("oskeychain")
	if err != nil {
		return nil, nil // provider not registered; treat as unavailable
	}
	avail, err := p.Available()
	if err != nil || !avail {
		return nil, nil // keychain service not reachable on this system
	}
	store, err := p.CreateSecretStore(map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("session store: create: %w", err)
	}
	return store, nil
}

// storeSessionToken serialises rec as JSON and writes it to the OS keychain.
// Returns an error if the store is unavailable or the write fails.
func storeSessionToken(rec *sessionRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("session token: marshal: %w", err)
	}
	store, err := sessionStoreFn()
	if err != nil {
		return fmt.Errorf("session token: open store: %w", err)
	}
	if store == nil {
		return fmt.Errorf("session token: OS secret store unavailable")
	}
	return store.StoreSecret(context.Background(), &interfaces.SecretRequest{
		Key:   sessionTokenKey,
		Value: string(data),
	})
}

// loadSessionToken reads and deserialises the active session record from the OS keychain.
// Returns (nil, nil) when no session is stored or the store is unavailable.
func loadSessionToken() (*sessionRecord, error) {
	store, err := sessionStoreFn()
	if err != nil || store == nil {
		return nil, nil // treat unavailability as "no session"
	}
	secret, err := store.GetSecret(context.Background(), sessionTokenKey)
	if err != nil {
		if errors.Is(err, interfaces.ErrSecretNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("session token: get: %w", err)
	}
	var rec sessionRecord
	if err := json.Unmarshal([]byte(secret.Value), &rec); err != nil {
		return nil, fmt.Errorf("session token: decode: %w", err)
	}
	return &rec, nil
}

// updateSessionToken replaces only the token field in the stored session record.
// Called by the OnTokenRenewed callback after each rolling-renewal response.
func updateSessionToken(newToken string) error {
	store, err := sessionStoreFn()
	if err != nil || store == nil {
		return nil // best-effort; don't fail commands on keychain hiccups
	}
	secret, err := store.GetSecret(context.Background(), sessionTokenKey)
	if err != nil {
		return fmt.Errorf("session token: load for update: %w", err)
	}
	var rec sessionRecord
	if err := json.Unmarshal([]byte(secret.Value), &rec); err != nil {
		return fmt.Errorf("session token: decode for update: %w", err)
	}
	rec.Token = newToken
	data, err := json.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("session token: marshal for update: %w", err)
	}
	return store.StoreSecret(context.Background(), &interfaces.SecretRequest{
		Key:   sessionTokenKey,
		Value: string(data),
	})
}

// deleteSessionToken removes the active session record from the OS keychain.
// Returns nil when the key is not present (idempotent).
func deleteSessionToken() error {
	store, err := sessionStoreFn()
	if err != nil || store == nil {
		return nil // nothing to delete
	}
	if err := store.DeleteSecret(context.Background(), sessionTokenKey); err != nil {
		if errors.Is(err, interfaces.ErrSecretNotFound) {
			return nil
		}
		return fmt.Errorf("session token: delete: %w", err)
	}
	return nil
}
