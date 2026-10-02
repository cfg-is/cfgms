// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// White-box tests for the compiled-in additional-publisher registry.
//
// These tests live in package trust (not trust_test) because the registry's
// only legitimate source of key material is the unexported, ldflags-injected
// additionalPublisherKeyMaterial variable (ADR-006: publisher key material is
// baked in at build time, never supplied at runtime). An external test package
// cannot set it, so without these tests defaultResolveKnownPublisher — the
// resolver wired into NewStewardTrustEnforcer and
// NewStewardTrustEnforcerWithIdentity, and therefore the one that runs in a
// real release binary — would only ever be exercised through its
// empty-registry short-circuit.
package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	featuremodules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
)

// setKeyMaterial replaces the ldflags-injected registry for the duration of one
// test, restoring the build-time value afterwards. These tests must not call
// t.Parallel(): they share this package-level variable.
func setKeyMaterial(t *testing.T, value string) {
	t.Helper()
	previous := additionalPublisherKeyMaterial
	additionalPublisherKeyMaterial = value
	t.Cleanup(func() { additionalPublisherKeyMaterial = previous })
}

// newRegistryKey returns an Ed25519 keypair plus the base64 encoding of the
// public key exactly as the release pipeline would emit it into the registry
// string. A 32-byte key always encodes to 44 base64 characters ending in "=",
// so every entry built here also covers the padding case: the parser must split
// name from key on the FIRST "=" only.
func newRegistryKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(pub)
	require.Contains(t, encoded, "=", "a 32-byte Ed25519 key must base64-encode with padding")
	return pub, priv, encoded
}

// registryTestEnforcer returns an enforcer wired to the production resolver
// (defaultResolveKnownPublisher) with an injected CFGMS identity, so strict-mode
// verification can be driven end to end without a build-time CFGMS key.
func registryTestEnforcer(cfgmsPub ed25519.PublicKey) *StewardTrustEnforcer {
	return NewStewardTrustEnforcerWithIdentity(func() pkgtrust.PublisherIdentity {
		return pkgtrust.PublisherIdentity{Name: "cfgms", PublicKey: []byte(cfgmsPub), Algorithm: "ed25519"}
	})
}

func newRegistryTestBundle() *bundle.Bundle {
	return &bundle.Bundle{
		Manifest: &featuremodules.ModuleMetadata{
			Name:      "registry-test-module",
			Version:   "1.0.0",
			Executors: []string{"steward"},
			Kind:      "steward",
			Publisher: "vendor-a",
		},
		ContentHash: "sha256-registry-test-content-hash",
	}
}

func signRegistryTestBundle(b *bundle.Bundle, publisher string, priv ed25519.PrivateKey) {
	b.Signatures = append(b.Signatures, bundle.BundleSignature{
		Publisher: publisher,
		Algorithm: "ed25519",
		Signature: ed25519.Sign(priv, []byte(b.ContentHash)),
	})
}

// TestDefaultResolveKnownPublisher_SingleEntryResolves: a well-formed
// single-entry registry resolves the named publisher to its exact key material.
func TestDefaultResolveKnownPublisher_SingleEntryResolves(t *testing.T) {
	pub, _, encoded := newRegistryKey(t)
	setKeyMaterial(t, "vendor-a="+encoded)

	id, ok := defaultResolveKnownPublisher("vendor-a")
	require.True(t, ok, "a well-formed registry entry must resolve")
	assert.Equal(t, "vendor-a", id.Name)
	assert.Equal(t, "ed25519", id.Algorithm)
	assert.Equal(t, []byte(pub), id.PublicKey, "resolved key must be the decoded registry key")
}

// TestDefaultResolveKnownPublisher_MultiEntryListResolvesEachName: a comma
// separated multi-entry registry resolves every name to its own key, including
// entries after the first — the loop must not stop at entry one.
func TestDefaultResolveKnownPublisher_MultiEntryListResolvesEachName(t *testing.T) {
	pubA, _, encodedA := newRegistryKey(t)
	pubB, _, encodedB := newRegistryKey(t)
	pubC, _, encodedC := newRegistryKey(t)
	require.NotEqual(t, []byte(pubA), []byte(pubB))
	setKeyMaterial(t, "vendor-a="+encodedA+",vendor-b="+encodedB+",vendor-c="+encodedC)

	for name, want := range map[string]ed25519.PublicKey{
		"vendor-a": pubA,
		"vendor-b": pubB,
		"vendor-c": pubC,
	} {
		id, ok := defaultResolveKnownPublisher(name)
		require.True(t, ok, "entry %q must resolve", name)
		assert.Equal(t, name, id.Name)
		assert.Equal(t, []byte(want), id.PublicKey, "entry %q resolved to the wrong key", name)
	}
}

// TestDefaultResolveKnownPublisher_UnknownNameIsUnresolved: a name absent from a
// populated registry does not resolve, and must not borrow another entry's key.
func TestDefaultResolveKnownPublisher_UnknownNameIsUnresolved(t *testing.T) {
	_, _, encoded := newRegistryKey(t)
	setKeyMaterial(t, "vendor-a="+encoded)

	id, ok := defaultResolveKnownPublisher("vendor-z")
	assert.False(t, ok)
	assert.Equal(t, pkgtrust.PublisherIdentity{}, id)
}

// TestDefaultResolveKnownPublisher_EmptyRegistryIsUnresolved: an unconfigured
// build (no ldflags injection) resolves nothing.
func TestDefaultResolveKnownPublisher_EmptyRegistryIsUnresolved(t *testing.T) {
	setKeyMaterial(t, "")

	id, ok := defaultResolveKnownPublisher("vendor-a")
	assert.False(t, ok)
	assert.Equal(t, pkgtrust.PublisherIdentity{}, id)
}

// TestDefaultResolveKnownPublisher_EntryWithoutSeparatorIsSkipped: a malformed
// entry carrying no "=" is skipped rather than aborting the scan, so a
// well-formed entry alongside it still resolves; the malformed entry's own text
// never resolves.
func TestDefaultResolveKnownPublisher_EntryWithoutSeparatorIsSkipped(t *testing.T) {
	pub, _, encoded := newRegistryKey(t)
	setKeyMaterial(t, "garbage-without-separator,vendor-a="+encoded)

	id, ok := defaultResolveKnownPublisher("vendor-a")
	require.True(t, ok, "a malformed entry must not prevent a later well-formed entry from resolving")
	assert.Equal(t, []byte(pub), id.PublicKey)

	_, ok = defaultResolveKnownPublisher("garbage-without-separator")
	assert.False(t, ok, "an entry with no key half must never resolve")
}

// TestDefaultResolveKnownPublisher_InvalidBase64IsUnresolved: a matching name
// whose key half is not valid base64 fails resolution (fail closed) rather than
// resolving to truncated or empty key material.
func TestDefaultResolveKnownPublisher_InvalidBase64IsUnresolved(t *testing.T) {
	setKeyMaterial(t, "vendor-a=not-valid-base64!!!")

	id, ok := defaultResolveKnownPublisher("vendor-a")
	assert.False(t, ok, "an entry with an undecodable key must not resolve")
	assert.Nil(t, id.PublicKey)
}

// TestDefaultResolveKnownPublisher_WrongKeySizeIsUnresolved: base64 that decodes
// cleanly but is not an Ed25519 public key length fails resolution — a short or
// long key must never reach the trust store.
func TestDefaultResolveKnownPublisher_WrongKeySizeIsUnresolved(t *testing.T) {
	for name, size := range map[string]int{
		"too short": ed25519PublicKeySize - 1,
		"too long":  ed25519PublicKeySize + 1,
		"empty":     0,
	} {
		t.Run(name, func(t *testing.T) {
			raw := make([]byte, size)
			_, err := rand.Read(raw)
			require.NoError(t, err)
			setKeyMaterial(t, "vendor-a="+base64.StdEncoding.EncodeToString(raw))

			id, ok := defaultResolveKnownPublisher("vendor-a")
			assert.False(t, ok, "a %d-byte key must not resolve", size)
			assert.Nil(t, id.PublicKey)
		})
	}
}

// TestDefaultResolveKnownPublisher_EmptyNameIsUnresolved: an empty
// additional_publishers entry must not match a malformed registry entry whose
// name half is empty — that would grant trust to key material the operator
// never named.
func TestDefaultResolveKnownPublisher_EmptyNameIsUnresolved(t *testing.T) {
	_, _, encoded := newRegistryKey(t)
	setKeyMaterial(t, "="+encoded)

	id, ok := defaultResolveKnownPublisher("")
	assert.False(t, ok, "an empty publisher name must never resolve to key material")
	assert.Nil(t, id.PublicKey)
}

// TestDefaultResolveKnownPublisher_NameMatchIsExact: name comparison is exact,
// so neither a prefix nor an extension of a registered name resolves.
func TestDefaultResolveKnownPublisher_NameMatchIsExact(t *testing.T) {
	_, _, encoded := newRegistryKey(t)
	setKeyMaterial(t, "vendor-alpha="+encoded)

	for _, name := range []string{"vendor", "vendor-alph", "vendor-alphax", "VENDOR-ALPHA"} {
		_, ok := defaultResolveKnownPublisher(name)
		assert.False(t, ok, "%q must not match registry entry %q", name, "vendor-alpha")
	}
	_, ok := defaultResolveKnownPublisher("vendor-alpha")
	assert.True(t, ok)
}

// TestCompiledInRegistry_ResolvedPublisherLoadsUnderStrict exercises the path a
// real release binary takes: key material compiled in via ldflags, resolved
// through the production resolver, then used to accept a bundle that publisher
// signed under module_trust.mode: strict.
func TestCompiledInRegistry_ResolvedPublisherLoadsUnderStrict(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, vendorPriv, encoded := newRegistryKey(t)
	setKeyMaterial(t, "vendor-a="+encoded)

	enforcer := registryTestEnforcer(cfgmsPub)
	resolved, err := enforcer.ResolveAdditionalPublishers([]string{"vendor-a"})
	require.NoError(t, err)
	require.Len(t, resolved, 1)

	b := newRegistryTestBundle()
	signRegistryTestBundle(b, "vendor-a", vendorPriv)
	assert.NoError(t, enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustModeStrict, resolved),
		"a bundle signed by a compiled-in additional publisher must load under strict mode")
}

// TestCompiledInRegistry_ResolvedPublisherDoesNotTrustOtherKeys: resolution
// grants trust to exactly the compiled-in key, not to any bundle claiming that
// publisher's name.
func TestCompiledInRegistry_ResolvedPublisherDoesNotTrustOtherKeys(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, _, encoded := newRegistryKey(t)
	setKeyMaterial(t, "vendor-a="+encoded)

	_, impostorPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	enforcer := registryTestEnforcer(cfgmsPub)
	resolved, err := enforcer.ResolveAdditionalPublishers([]string{"vendor-a"})
	require.NoError(t, err)

	forged := newRegistryTestBundle()
	signRegistryTestBundle(forged, "vendor-a", impostorPriv)
	err = enforcer.VerifyForLoad(forged, stewardtypes.ModuleTrustModeStrict, resolved)
	require.Error(t, err, "a bundle signed by a key other than the compiled-in one must not load")
	assert.ErrorIs(t, err, pkgtrust.ErrInvalidSignature)
}

// TestCompiledInRegistry_MalformedEntryNamesEntryInError: when the compiled-in
// entry for a configured name cannot be decoded, resolution refuses and names
// the entry — it must not be dropped silently or fall through to the baked-in
// CFGMS publisher only (Issue #4398).
func TestCompiledInRegistry_MalformedEntryNamesEntryInError(t *testing.T) {
	_, _, encoded := newRegistryKey(t)
	setKeyMaterial(t, "vendor-a=***not-base64***,vendor-b="+encoded)

	enforcer := NewStewardTrustEnforcer()

	resolved, err := enforcer.ResolveAdditionalPublishers([]string{"vendor-b", "vendor-a"})
	require.Error(t, err)
	assert.Nil(t, resolved, "no publishers may be returned when any entry fails to resolve")
	assert.ErrorIs(t, err, ErrAdditionalPublisherUnresolvable)
	assert.Contains(t, err.Error(), "vendor-a")
}

// TestCompiledInRegistry_ProductionConstructorUsesRegistry: the production
// constructor (no test injection) resolves against the compiled-in registry,
// confirming defaultResolveKnownPublisher is the resolver actually wired in.
func TestCompiledInRegistry_ProductionConstructorUsesRegistry(t *testing.T) {
	pub, _, encoded := newRegistryKey(t)
	setKeyMaterial(t, "vendor-a="+encoded)

	resolved, err := NewStewardTrustEnforcer().ResolveAdditionalPublishers([]string{"vendor-a"})
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Equal(t, "vendor-a", resolved[0].Name)
	assert.Equal(t, []byte(pub), resolved[0].PublicKey)
}
