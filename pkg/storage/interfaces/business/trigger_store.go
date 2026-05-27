// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
package business

import (
	"context"
	"errors"
	"time"
)

// ErrTriggerNotFound is returned when a requested trigger ID does not exist.
var ErrTriggerNotFound = errors.New("trigger not found")

// TriggerRecord is the durable storage representation of a workflow trigger.
//
// All credential material is stored by reference only — the *Ref fields hold
// pkg/secrets keys, not raw credential values. An empty string means no
// credential of that type is configured. The struct design makes it
// structurally impossible to store a cleartext credential: no field has a
// name or type that could hold a raw secret value.
//
// Storage key convention (enforced in Story J): triggers/<tenantID>/<triggerID>
type TriggerRecord struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Status        string    `json:"status"` // maps to/from trigger.TriggerStatus in manager layer (Story J)
	WorkflowName  string    `json:"workflow_name"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	WebhookPath   string    `json:"webhook_path"`
	WebhookMethod []string  `json:"webhook_method"`

	// Secret reference IDs — empty string means no credential of this type configured.
	// These hold pkg/secrets keys, never credential values.
	BearerTokenRef   string `json:"bearer_token_ref"`
	HMACSecretRef    string `json:"hmac_secret_ref"`
	APIKeyRef        string `json:"apikey_ref"`
	BasicUsernameRef string `json:"basic_username_ref"`
	BasicPasswordRef string `json:"basic_password_ref"`

	// ConfigPayload holds the non-sensitive serialized trigger config.
	// Authentication fields must be zeroed before marshaling into this field.
	ConfigPayload []byte `json:"config_payload,omitempty"`
}

// TriggerStoreFilter constrains ListTriggers queries.
type TriggerStoreFilter struct {
	TenantID string
	Type     string
	Status   string
	Limit    int
	Offset   int
}

// TriggerStore defines the storage interface for workflow trigger persistence.
// Implementations must be safe for concurrent use.
//
// This interface intentionally has zero imports from features/ — the manager
// layer (Story J) owns the mapping between this package's plain string Status
// field and trigger.TriggerStatus.
type TriggerStore interface {
	// StoreTrigger creates or updates a trigger record. The record must have
	// non-empty ID and TenantID fields.
	StoreTrigger(ctx context.Context, record *TriggerRecord) error

	// GetTrigger retrieves a trigger by ID. Returns ErrTriggerNotFound when
	// no record with the given ID exists.
	GetTrigger(ctx context.Context, id string) (*TriggerRecord, error)

	// DeleteTrigger removes a trigger by ID. Returns ErrTriggerNotFound when
	// no record with the given ID exists.
	DeleteTrigger(ctx context.Context, id string) error

	// ListTriggers returns triggers matching the filter. An empty filter
	// returns all triggers. Results are ordered by created_at descending.
	ListTriggers(ctx context.Context, filter TriggerStoreFilter) ([]*TriggerRecord, error)

	// Close releases any resources held by the store.
	Close() error
}
