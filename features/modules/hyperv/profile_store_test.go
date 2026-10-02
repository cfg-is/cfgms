// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// MockConfigStore is an in-memory ConfigStore test double. It is a real
// implementation of the cfgconfig.ConfigStore contract (it actually stores and
// returns entries keyed by ConfigKey.String()), not a mock framework — so it can
// round-trip a profile through ConfigBackedProfileStore as the AC requires. The
// stateless struct{} double in pkg/storage/interfaces/provider_test.go cannot
// round-trip and lives in an un-importable _test.go, so the round-trip double is
// defined here in-package.
type MockConfigStore struct {
	mu      sync.Mutex
	entries map[string]*cfgconfig.ConfigEntry
}

func newMockConfigStore() *MockConfigStore {
	return &MockConfigStore{entries: make(map[string]*cfgconfig.ConfigEntry)}
}

func (m *MockConfigStore) StoreConfig(_ context.Context, entry *cfgconfig.ConfigEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[entry.Key.String()] = entry
	return nil
}

func (m *MockConfigStore) GetConfig(_ context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key.String()]
	if !ok {
		return nil, cfgconfig.ErrConfigNotFound
	}
	return e, nil
}

func (m *MockConfigStore) DeleteConfig(_ context.Context, key *cfgconfig.ConfigKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[key.String()]; !ok {
		// Mirrors the real backend (pkg/storage/providers/flatfile): deleting a
		// missing key returns ErrConfigNotFound rather than succeeding silently.
		return cfgconfig.ErrConfigNotFound
	}
	delete(m.entries, key.String())
	return nil
}

func (m *MockConfigStore) ListConfigs(_ context.Context, filter *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*cfgconfig.ConfigEntry
	for _, e := range m.entries {
		if filter != nil {
			if filter.TenantID != "" && e.Key.TenantID != filter.TenantID {
				continue
			}
			if filter.Namespace != "" && e.Key.Namespace != filter.Namespace {
				continue
			}
		}
		out = append(out, e)
	}
	return out, nil
}

func (m *MockConfigStore) GetConfigHistory(_ context.Context, _ *cfgconfig.ConfigKey, _ int) ([]*cfgconfig.ConfigEntry, error) {
	return nil, nil
}
func (m *MockConfigStore) GetConfigVersion(_ context.Context, _ *cfgconfig.ConfigKey, _ int64) (*cfgconfig.ConfigEntry, error) {
	return nil, cfgconfig.ErrConfigNotFound
}
func (m *MockConfigStore) StoreConfigBatch(_ context.Context, _ []*cfgconfig.ConfigEntry) error {
	return nil
}
func (m *MockConfigStore) DeleteConfigBatch(_ context.Context, _ []*cfgconfig.ConfigKey) error {
	return nil
}
func (m *MockConfigStore) ResolveConfigWithInheritance(_ context.Context, _ *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return nil, cfgconfig.ErrConfigNotFound
}
func (m *MockConfigStore) ValidateConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error {
	return nil
}
func (m *MockConfigStore) GetConfigStats(_ context.Context) (*cfgconfig.ConfigStats, error) {
	return &cfgconfig.ConfigStats{}, nil
}

var _ cfgconfig.ConfigStore = (*MockConfigStore)(nil)

// seedProfile stores a profile in the config store under hyperv-profiles/<name>
// for the given tenant, mirroring how an operator would author it.
func seedProfile(t *testing.T, store *MockConfigStore, tenantID string, p *UnattendProfile) {
	t.Helper()
	data, err := yaml.Marshal(p)
	require.NoError(t, err)
	require.NoError(t, store.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: profileNamespace, Name: p.Name},
		Data:   data,
		Format: cfgconfig.ConfigFormatYAML,
	}))
}

// TestConfigBackedProfileStore_GetProfile is the REQUIRED TEST from the AC: it
// round-trips a profile through ConfigBackedProfileStore using a real config
// store double.
func TestConfigBackedProfileStore_GetProfile(t *testing.T) {
	store := newMockConfigStore()
	want := &UnattendProfile{
		Name:         "debian-12-base",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     "hostname={{ .VMName }}\nregtoken={{ secret \"hyperv/enroll/regtoken\" }}",
		Enroll: EnrollConfig{
			RegistrationTokenSecretKey: "hyperv/enroll/regtoken",
			BundleURL:                  "https://controller.example/bundle",
			CorrelationLabel:           "fleet-a",
		},
	}
	seedProfile(t, store, "root", want)

	ps := NewConfigBackedProfileStore(store, "root")
	got, err := ps.GetProfile(context.Background(), "debian-12-base")
	require.NoError(t, err)

	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.OSFamily, got.OSFamily)
	assert.Equal(t, want.AnswerFormat, got.AnswerFormat)
	assert.Equal(t, want.Template, got.Template)
	assert.Equal(t, want.Enroll, got.Enroll)
}

// TestConfigBackedProfileStore_GetProfile_NotFound asserts the not-found path
// returns ErrProfileNotFound (mapped from cfgconfig.ErrConfigNotFound).
func TestConfigBackedProfileStore_GetProfile_NotFound(t *testing.T) {
	store := newMockConfigStore()
	ps := NewConfigBackedProfileStore(store, "root")

	_, err := ps.GetProfile(context.Background(), "no-such-profile")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

// TestConfigBackedProfileStore_GetProfile_RejectsInvalidName asserts an unsafe
// name is rejected before any store lookup.
func TestConfigBackedProfileStore_GetProfile_RejectsInvalidName(t *testing.T) {
	store := newMockConfigStore()
	ps := NewConfigBackedProfileStore(store, "root")

	_, err := ps.GetProfile(context.Background(), "../etc/passwd")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidProfileName)
}

// TestConfigBackedProfileStore_GetProfile_RejectsBadAnswerFormat asserts a
// stored profile with an invalid answer_format fails validation on load.
func TestConfigBackedProfileStore_GetProfile_RejectsBadAnswerFormat(t *testing.T) {
	store := newMockConfigStore()
	seedProfile(t, store, "root", &UnattendProfile{
		Name:         "bad",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormat("nope"),
		Template:     "x",
	})

	ps := NewConfigBackedProfileStore(store, "root")
	_, err := ps.GetProfile(context.Background(), "bad")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAnswerFormat)
}

// TestConfigBackedProfileStore_ListProfiles round-trips multiple profiles and
// asserts ListProfiles enumerates them by name within the tenant scope.
func TestConfigBackedProfileStore_ListProfiles(t *testing.T) {
	store := newMockConfigStore()
	seedProfile(t, store, "root", &UnattendProfile{Name: "p1", OSFamily: "linux", AnswerFormat: AnswerFormatPreseed, Template: "x"})
	seedProfile(t, store, "root", &UnattendProfile{Name: "p2", OSFamily: "windows", AnswerFormat: AnswerFormatAutounattend, Template: "y"})
	// A different tenant's profile must not leak into root's listing.
	seedProfile(t, store, "other", &UnattendProfile{Name: "p3", OSFamily: "linux", AnswerFormat: AnswerFormatPreseed, Template: "z"})

	ps := NewConfigBackedProfileStore(store, "root")
	names, err := ps.ListProfiles(context.Background())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"p1", "p2"}, names)
}

// TestConfigBackedProfileStore_StoreProfile_RoundTrip asserts a profile stored
// via StoreProfile is loadable via GetProfile and enumerable via ListProfiles.
func TestConfigBackedProfileStore_StoreProfile_RoundTrip(t *testing.T) {
	store := newMockConfigStore()
	ps := NewConfigBackedProfileStore(store, "root")

	profile := &UnattendProfile{
		Name:         "debian-12-custom",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     "hostname={{ .VMName }}",
		Enroll: EnrollConfig{
			RegistrationTokenSecretKey: "hyperv/enroll/regtoken",
			BundleURL:                  "https://controller.example/bundle",
		},
	}
	require.NoError(t, ps.StoreProfile(context.Background(), profile))

	got, err := ps.GetProfile(context.Background(), "debian-12-custom")
	require.NoError(t, err)
	assert.Equal(t, profile.OSFamily, got.OSFamily)
	assert.Equal(t, profile.AnswerFormat, got.AnswerFormat)
	assert.Equal(t, profile.Template, got.Template)
	assert.Equal(t, profile.Enroll, got.Enroll)

	names, err := ps.ListProfiles(context.Background())
	require.NoError(t, err)
	assert.Contains(t, names, "debian-12-custom")
}

// TestConfigBackedProfileStore_StoreProfile_RejectsInvalidName asserts an unsafe
// name is rejected before any store write.
func TestConfigBackedProfileStore_StoreProfile_RejectsInvalidName(t *testing.T) {
	store := newMockConfigStore()
	ps := NewConfigBackedProfileStore(store, "root")

	err := ps.StoreProfile(context.Background(), &UnattendProfile{
		Name:         "../etc/passwd",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     "x",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidProfileName)
}

// TestConfigBackedProfileStore_StoreProfile_RejectsBadAnswerFormat asserts an
// invalid answer_format is rejected before any store write.
func TestConfigBackedProfileStore_StoreProfile_RejectsBadAnswerFormat(t *testing.T) {
	store := newMockConfigStore()
	ps := NewConfigBackedProfileStore(store, "root")

	err := ps.StoreProfile(context.Background(), &UnattendProfile{
		Name:         "bad-format",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormat("nope"),
		Template:     "x",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAnswerFormat)
}

// TestConfigBackedProfileStore_StoreProfile_RejectsUnparseableTemplate asserts a
// template that fails text/template.Parse is rejected at author time, not at
// VM-provision time.
func TestConfigBackedProfileStore_StoreProfile_RejectsUnparseableTemplate(t *testing.T) {
	store := newMockConfigStore()
	ps := NewConfigBackedProfileStore(store, "root")

	err := ps.StoreProfile(context.Background(), &UnattendProfile{
		Name:         "bad-template",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     "hostname={{ .VMName",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidProfileTemplate)
}

// TestConfigBackedProfileStore_StoreProfile_RejectsOversizedProfile asserts a
// profile whose YAML-encoded size exceeds profileMaxSizeBytes is rejected.
func TestConfigBackedProfileStore_StoreProfile_RejectsOversizedProfile(t *testing.T) {
	store := newMockConfigStore()
	ps := NewConfigBackedProfileStore(store, "root")

	err := ps.StoreProfile(context.Background(), &UnattendProfile{
		Name:         "oversized",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     strings.Repeat("x", profileMaxSizeBytes+1),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileTooLarge)
}

// TestConfigBackedProfileStore_DeleteProfile_RemovesProfile asserts a stored
// profile is removed and a subsequent GetProfile returns ErrProfileNotFound.
func TestConfigBackedProfileStore_DeleteProfile_RemovesProfile(t *testing.T) {
	store := newMockConfigStore()
	ps := NewConfigBackedProfileStore(store, "root")

	require.NoError(t, ps.StoreProfile(context.Background(), &UnattendProfile{
		Name:         "to-delete",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     "x",
	}))

	require.NoError(t, ps.DeleteProfile(context.Background(), "to-delete"))

	_, err := ps.GetProfile(context.Background(), "to-delete")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

// TestConfigBackedProfileStore_DeleteProfile_NotFound asserts deleting a
// non-existent profile returns ErrProfileNotFound.
func TestConfigBackedProfileStore_DeleteProfile_NotFound(t *testing.T) {
	store := newMockConfigStore()
	ps := NewConfigBackedProfileStore(store, "root")

	err := ps.DeleteProfile(context.Background(), "no-such-profile")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

// TestConfigure_WiresConfigBackedProfileStore asserts that passing a config
// store under the "config_store" key at Configure time wires a
// ConfigBackedProfileStore onto the module (same injection pattern as
// audit_manager). The profile is then loadable end-to-end through the module's
// wired store.
func TestConfigure_WiresConfigBackedProfileStore(t *testing.T) {
	store := newMockConfigStore()
	seedProfile(t, store, "tenant-x", &UnattendProfile{
		Name:         "win-2025-base",
		OSFamily:     "windows",
		AnswerFormat: AnswerFormatAutounattend,
		Template:     "<ComputerName>{{ .VMName }}</ComputerName>",
	})

	secrets := newInlineStore()
	m := newModuleWithDetector(secrets, &fakeDetector{result: true})

	require.NoError(t, m.Configure(mapConfigState{
		"tenant_id":         "tenant-x",
		"config_store":      cfgconfig.ConfigStore(store),
		"winrm_host":        "host.example",
		"winrm_user_secret": "user-key",
		"winrm_pass_secret": "pass-key",
		"transport":         "winrm",
	}))

	require.NotNil(t, m.profileStore, "config_store should wire a ProfileStore")

	got, err := m.profileStore.GetProfile(context.Background(), "win-2025-base")
	require.NoError(t, err)
	assert.Equal(t, "win-2025-base", got.Name)
	assert.Equal(t, AnswerFormatAutounattend, got.AnswerFormat)
}

// TestConfigure_NoConfigStoreLeavesProfileStoreNil asserts that without a
// config_store key, the profile store remains whatever WithProfileStore set
// (nil here), so the absence of a backend is handled gracefully.
func TestConfigure_NoConfigStoreLeavesProfileStoreNil(t *testing.T) {
	secrets := newInlineStore()
	m := newModuleWithDetector(secrets, &fakeDetector{result: true})

	require.NoError(t, m.Configure(mapConfigState{
		"winrm_host":        "host.example",
		"winrm_user_secret": "user-key",
		"winrm_pass_secret": "pass-key",
		"transport":         "winrm",
	}))

	assert.Nil(t, m.profileStore)
}

// TestWithProfileStore_Overrides asserts the option setter injects a store
// usable without any config backend.
func TestWithProfileStore_Overrides(t *testing.T) {
	ms := newMemProfileStore()
	ms.put(&UnattendProfile{Name: "p1", OSFamily: "linux", AnswerFormat: AnswerFormatPreseed, Template: "x"})

	var m *hypervModule
	mod := New(&fakeDetector{result: true}, WithProfileStore(ms))
	m = mod.(*hypervModule)
	require.NotNil(t, m.profileStore)

	got, err := m.profileStore.GetProfile(context.Background(), "p1")
	require.NoError(t, err)
	assert.Equal(t, "p1", got.Name)
}

// ensure the modules import is used (mapConfigState satisfies modules.ConfigState).
var _ modules.ConfigState = mapConfigState(nil)
