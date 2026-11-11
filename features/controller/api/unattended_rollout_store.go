// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// Config-store location owned by UnattendedRolloutStore. The setting is one value
// for the whole cell, so it lives under a fixed system tenant (config stores
// reject an empty tenant). UnattendedRolloutStore is the only writer: no route and
// no sync path may store into the namespace (see
// TestUnattendedRolloutNamespaceOnlyStoreWrites).
const (
	unattendedRolloutNamespace = "rollout-unattended"
	unattendedRolloutTenant    = "system"
	unattendedRolloutName      = "setting"
)

// UnattendedRolloutSetting is the cell's unattended (machine-initiated) rollout
// setting. A cell with no stored record has Enabled false and no ChangedBy or
// ChangedAt.
type UnattendedRolloutSetting struct {
	Enabled   bool       `json:"enabled"`
	ChangedBy string     `json:"changed_by"`
	ChangedAt *time.Time `json:"changed_at"`
}

// unattendedRolloutRecord is the stored form of the setting.
type unattendedRolloutRecord struct {
	Enabled   bool      `json:"enabled"`
	ChangedBy string    `json:"changed_by"`
	ChangedAt time.Time `json:"changed_at"`
}

// UnattendedRolloutStore persists the cell's unattended rollout setting over a
// durable config store. Enforcement of the setting belongs to the rollout
// automation that reads it; this store only holds the value.
type UnattendedRolloutStore struct {
	store cfgconfig.ConfigStore
	now   func() time.Time
}

// NewUnattendedRolloutStore builds a store over cs, which must be a durable
// provider.
func NewUnattendedRolloutStore(cs cfgconfig.ConfigStore) (*UnattendedRolloutStore, error) {
	if cs == nil {
		return nil, errors.New("unattended rollout store: config store is required")
	}
	return &UnattendedRolloutStore{store: cs, now: func() time.Time { return time.Now().UTC() }}, nil
}

func unattendedRolloutKey() *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: unattendedRolloutTenant, Namespace: unattendedRolloutNamespace, Name: unattendedRolloutName}
}

// Get returns the setting. With no stored record it is off. A store read error or
// an undecodable record is returned as an error and never as the default, so a
// failing store cannot read as either value.
func (s *UnattendedRolloutStore) Get(ctx context.Context) (UnattendedRolloutSetting, error) {
	entry, err := s.store.GetConfig(ctx, unattendedRolloutKey())
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return UnattendedRolloutSetting{}, nil
		}
		return UnattendedRolloutSetting{}, fmt.Errorf("unattended rollout store: read setting: %w", err)
	}
	var rec unattendedRolloutRecord
	if err := json.Unmarshal(entry.Data, &rec); err != nil {
		return UnattendedRolloutSetting{}, fmt.Errorf("unattended rollout store: decode setting: %w", err)
	}
	at := rec.ChangedAt
	return UnattendedRolloutSetting{Enabled: rec.Enabled, ChangedBy: rec.ChangedBy, ChangedAt: &at}, nil
}

// Set stores the setting and returns the stored value. It is the only writer of
// the namespace.
func (s *UnattendedRolloutStore) Set(ctx context.Context, enabled bool, actor string) (UnattendedRolloutSetting, error) {
	if actor == "" {
		return UnattendedRolloutSetting{}, errors.New("unattended rollout store: actor is required")
	}
	rec := unattendedRolloutRecord{Enabled: enabled, ChangedBy: actor, ChangedAt: s.now()}
	data, err := json.Marshal(rec)
	if err != nil {
		return UnattendedRolloutSetting{}, fmt.Errorf("unattended rollout store: encode setting: %w", err)
	}
	err = s.store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:       unattendedRolloutKey(),
		Data:      data,
		Format:    cfgconfig.ConfigFormatJSON,
		Checksum:  fmt.Sprintf("%x", sha256.Sum256(data)),
		UpdatedAt: rec.ChangedAt,
		UpdatedBy: actor,
		Source:    "rollout-settings",
	})
	if err != nil {
		return UnattendedRolloutSetting{}, fmt.Errorf("unattended rollout store: write setting: %w", err)
	}
	at := rec.ChangedAt
	return UnattendedRolloutSetting{Enabled: enabled, ChangedBy: actor, ChangedAt: &at}, nil
}
