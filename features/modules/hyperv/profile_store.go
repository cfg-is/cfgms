// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// profileNamespace is the stored-config namespace that holds unattended-install
// profiles. Combined with the profile name it forms the documented key path
// hyperv/profiles/<name> (ADR-003 stored-config conventions). The slash-joined
// "hyperv/profiles" maps onto the ConfigKey namespace; the profile name is the
// ConfigKey name.
const profileNamespace = "hyperv/profiles"

// ConfigBackedProfileStore implements ProfileStore by reading YAML-serialised
// UnattendProfile values from the controller's stored-config backend. It depends
// only on the pkg/storage/interfaces config contract (never a concrete provider
// implementation, per the CLAUDE.md anti-pattern rule) so any config-store
// backend (flatfile, database, test double) works unchanged.
type ConfigBackedProfileStore struct {
	store cfgconfig.ConfigStore
	// tenantID scopes profile lookups to a tenant. Empty is permitted for
	// single-tenant/root deployments; the config backend treats it as the root
	// scope.
	tenantID string
}

// NewConfigBackedProfileStore constructs a ConfigBackedProfileStore over the
// given config store and tenant. It is used by Configure() wiring and by tests.
func NewConfigBackedProfileStore(store cfgconfig.ConfigStore, tenantID string) *ConfigBackedProfileStore {
	return &ConfigBackedProfileStore{store: store, tenantID: tenantID}
}

// profileConfigKey builds the ConfigKey for a profile name under the documented
// hyperv/profiles namespace.
func (s *ConfigBackedProfileStore) profileConfigKey(name string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{
		TenantID:  s.tenantID,
		Namespace: profileNamespace,
		Name:      name,
	}
}

// GetProfile reads the named profile from the config-store backend at key path
// hyperv/profiles/<name>, YAML-decodes it, and validates structural invariants.
// The name is validated against the profile name pattern before any lookup so
// an unsafe name never reaches the backend. Returns ErrProfileNotFound when the
// profile is absent.
func (s *ConfigBackedProfileStore) GetProfile(ctx context.Context, name string) (*UnattendProfile, error) {
	if s.store == nil {
		return nil, errors.New("hyperv: ConfigBackedProfileStore has no config store")
	}
	if !profileNamePattern.MatchString(name) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidProfileName, name)
	}

	entry, err := s.store.GetConfig(ctx, s.profileConfigKey(name))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return nil, fmt.Errorf("%w: %q", ErrProfileNotFound, name)
		}
		return nil, fmt.Errorf("hyperv: loading profile %q: %w", name, err)
	}
	if entry == nil {
		return nil, fmt.Errorf("%w: %q", ErrProfileNotFound, name)
	}

	var profile UnattendProfile
	if err := yaml.Unmarshal(entry.Data, &profile); err != nil {
		return nil, fmt.Errorf("hyperv: decoding profile %q: %w", name, err)
	}
	// The stored Name may be omitted; the key name is authoritative.
	if profile.Name == "" {
		profile.Name = name
	}
	if err := profile.validate(); err != nil {
		return nil, err
	}
	return &profile, nil
}

// ListProfiles returns the names of all profiles stored under the hyperv/profiles
// namespace for the store's tenant. It is used by operator tooling to enumerate
// available profiles. Returns an empty slice (not an error) when none exist.
func (s *ConfigBackedProfileStore) ListProfiles(ctx context.Context) ([]string, error) {
	if s.store == nil {
		return nil, errors.New("hyperv: ConfigBackedProfileStore has no config store")
	}
	entries, err := s.store.ListConfigs(ctx, &cfgconfig.ConfigFilter{
		TenantID:  s.tenantID,
		Namespace: profileNamespace,
	})
	if err != nil {
		return nil, fmt.Errorf("hyperv: listing profiles: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e == nil || e.Key == nil {
			continue
		}
		names = append(names, e.Key.Name)
	}
	return names, nil
}

// Verify ConfigBackedProfileStore satisfies the ProfileStore contract.
var _ ProfileStore = (*ConfigBackedProfileStore)(nil)
