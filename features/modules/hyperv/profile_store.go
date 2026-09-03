// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"fmt"
	"text/template"

	"gopkg.in/yaml.v3"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// profileNamespace is the stored-config namespace that holds unattended-install
// profiles. Combined with the profile name it forms the documented key path
// hyperv-profiles/<name> (ADR-003 stored-config conventions). Must not contain
// "/": ConfigKey.Namespace is a leaf path segment on the default flatfile/git
// backend (keysafe.ValidateLeafField rejects path separators to prevent a
// namespace value from escaping its directory), so a slash-joined value here
// would 500 on every write against the real backend (Issue #3785).
const profileNamespace = "hyperv-profiles"

// profileMaxSizeBytes bounds a YAML-encoded profile's stored size. A hand-
// authored provisioning profile is short text (a preseed/autounattend
// template plus a few metadata fields); the generic stored-config namespace
// cap is 10MB, but that ceiling exists for bulk config payloads, not this
// resource. A tight cap keeps a runaway or malicious template out of the
// store before it can ever reach VM provisioning (Issue #3785).
const profileMaxSizeBytes = 256 * 1024

// ErrProfileTooLarge is returned by StoreProfile when the YAML-encoded profile
// exceeds profileMaxSizeBytes.
var ErrProfileTooLarge = errors.New("hyperv: profile exceeds maximum size")

// ErrInvalidProfileTemplate is returned by StoreProfile when the profile's
// Template fails text/template.Parse. Wrapping the stdlib parse error in this
// sentinel lets callers (the REST write handler) distinguish an author-time
// input error from a backend failure without depending on stdlib error shape.
var ErrInvalidProfileTemplate = errors.New("hyperv: invalid profile template")

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
// hyperv-profiles namespace.
func (s *ConfigBackedProfileStore) profileConfigKey(name string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{
		TenantID:  s.tenantID,
		Namespace: profileNamespace,
		Name:      name,
	}
}

// GetProfile reads the named profile from the config-store backend at key path
// hyperv-profiles/<name>, YAML-decodes it, and validates structural invariants.
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

// ListProfiles returns the names of all profiles stored under the hyperv-profiles
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

// StoreProfile validates profile (name pattern and structural invariants via
// validate(), template parses, and the size cap) and persists it as YAML to the
// config-store backend at hyperv-profiles/<name>. This is the sole write path
// (Issue #3785): every profile that can be referenced by a VM source (and
// rendered/executed as root at guest first boot) is validated here at author
// time, before it ever reaches VM provisioning.
func (s *ConfigBackedProfileStore) StoreProfile(ctx context.Context, profile *UnattendProfile) error {
	if s.store == nil {
		return errors.New("hyperv: ConfigBackedProfileStore has no config store")
	}
	if profile == nil {
		return errors.New("hyperv: nil profile")
	}
	if err := profile.validate(); err != nil {
		return err
	}
	if _, err := template.New(profile.Name).Parse(profile.Template); err != nil {
		return fmt.Errorf("%w: profile %q: %v", ErrInvalidProfileTemplate, profile.Name, err)
	}

	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("hyperv: encoding profile %q: %w", profile.Name, err)
	}
	if len(data) > profileMaxSizeBytes {
		return fmt.Errorf("%w: %q is %d bytes (max %d)", ErrProfileTooLarge, profile.Name, len(data), profileMaxSizeBytes)
	}

	entry := &cfgconfig.ConfigEntry{
		Key:    s.profileConfigKey(profile.Name),
		Data:   data,
		Format: cfgconfig.ConfigFormatYAML,
	}
	if err := s.store.StoreConfig(ctx, entry); err != nil {
		return fmt.Errorf("hyperv: storing profile %q: %w", profile.Name, err)
	}
	return nil
}

// DeleteProfile removes the named profile from the config-store backend. The
// name is validated against the profile name pattern before any lookup so an
// unsafe name never reaches the backend, mirroring GetProfile. Returns
// ErrProfileNotFound when no profile exists under name.
func (s *ConfigBackedProfileStore) DeleteProfile(ctx context.Context, name string) error {
	if s.store == nil {
		return errors.New("hyperv: ConfigBackedProfileStore has no config store")
	}
	if !profileNamePattern.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidProfileName, name)
	}
	if err := s.store.DeleteConfig(ctx, s.profileConfigKey(name)); err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return fmt.Errorf("%w: %q", ErrProfileNotFound, name)
		}
		return fmt.Errorf("hyperv: deleting profile %q: %w", name, err)
	}
	return nil
}

// Verify ConfigBackedProfileStore satisfies the ProfileStore contract.
var _ ProfileStore = (*ConfigBackedProfileStore)(nil)
