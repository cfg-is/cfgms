// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package cert_trust

import (
	"testing"
)

// TestLinuxExecutor_RoundTrip verifies that a cert installed via install() is
// subsequently visible via list() and disappears after remove(). The executor is
// pointed at t.TempDir() so the real system trust store is never touched.
func TestLinuxExecutor_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	exec := newLinuxExecutorWithRoot(tmpDir)

	certPEM, certDER := generateTestCAPEM(t)
	_ = certPEM

	fp := certFingerprint(certDER)

	// Precondition: cert is not yet in the store.
	entries, err := exec.list()
	if err != nil {
		t.Fatalf("list() before install returned error: %v", err)
	}
	for _, e := range entries {
		if e.Fingerprint == fp {
			t.Fatal("cert already present in empty trust store before install")
		}
	}

	// Install the cert.
	if err := exec.install(certDER); err != nil {
		t.Fatalf("install() returned error: %v", err)
	}

	// Verify the cert is present after install.
	entries, err = exec.list()
	if err != nil {
		t.Fatalf("list() after install returned error: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Fingerprint == fp {
			found = true
			if e.Subject == "" {
				t.Error("certEntry.Subject must not be empty for an installed cert")
			}
			if e.Issuer == "" {
				t.Error("certEntry.Issuer must not be empty for an installed cert")
			}
			if e.NotAfter == "" {
				t.Error("certEntry.NotAfter must not be empty for an installed cert")
			}
		}
	}
	if !found {
		t.Errorf("installed cert with fingerprint %s not found via list()", fp)
	}

	// Remove the cert.
	if err := exec.remove(fp); err != nil {
		t.Fatalf("remove() returned error: %v", err)
	}

	// Verify the cert is gone after remove.
	entries, err = exec.list()
	if err != nil {
		t.Fatalf("list() after remove returned error: %v", err)
	}
	for _, e := range entries {
		if e.Fingerprint == fp {
			t.Errorf("cert with fingerprint %s still present after remove()", fp)
		}
	}
}

// TestLinuxExecutor_Remove_Idempotent verifies that removing a cert that is not
// present in the trust store is a no-op and does not return an error.
func TestLinuxExecutor_Remove_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	exec := newLinuxExecutorWithRoot(tmpDir)

	const ghostFingerprint = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if err := exec.remove(ghostFingerprint); err != nil {
		t.Errorf("remove() of absent cert must be a no-op, got error: %v", err)
	}
}

// TestLinuxExecutor_Install_Idempotent verifies that installing a cert that is
// already present does not produce an error (overwrite with same content).
func TestLinuxExecutor_Install_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	exec := newLinuxExecutorWithRoot(tmpDir)

	_, certDER := generateTestCAPEM(t)

	if err := exec.install(certDER); err != nil {
		t.Fatalf("first install() returned error: %v", err)
	}
	if err := exec.install(certDER); err != nil {
		t.Errorf("second install() of same cert returned error: %v", err)
	}
}

// TestLinuxExecutor_List_EmptyDir verifies list() returns empty (not an error)
// when the trust store directory is empty.
func TestLinuxExecutor_List_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	exec := newLinuxExecutorWithRoot(tmpDir)

	entries, err := exec.list()
	if err != nil {
		t.Fatalf("list() on empty dir returned error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("list() on empty dir returned %d entries, want 0", len(entries))
	}
}

// TestLinuxExecutor_List_NonExistentDir verifies list() returns empty (not an
// error) when the trust store directory does not exist.
func TestLinuxExecutor_List_NonExistentDir(t *testing.T) {
	exec := newLinuxExecutorWithRoot("/tmp/cfgms-cert-trust-nonexistent-dir-xyzzy")

	entries, err := exec.list()
	if err != nil {
		t.Fatalf("list() on non-existent dir returned error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("list() on non-existent dir returned %d entries, want 0", len(entries))
	}
}

// TestLinuxModule_RoundTrip verifies the full module Get/Set round-trip using
// the Linux executor pointed at a temp directory.
func TestLinuxModule_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	mod := &certTrustModule{
		executor: newLinuxExecutorWithRoot(tmpDir),
	}

	certPEM, certDER := generateTestCAPEM(t)
	fp := certFingerprint(certDER)

	// Precondition: Get returns "absent".
	state, err := mod.Get(t.Context(), fp)
	if err != nil {
		t.Fatalf("Get() before Set returned error: %v", err)
	}
	m := state.AsMap()
	if s := m["state"].(string); s != "absent" {
		t.Errorf("Get() before Set: state = %q, want 'absent'", s)
	}

	// Install via Set.
	installConfig := &CertTrustConfig{
		State:   "present",
		CertPEM: certPEM,
	}
	if err := mod.Set(t.Context(), fp, installConfig); err != nil {
		t.Fatalf("Set(present) returned error: %v", err)
	}

	// Get must now return "present".
	state, err = mod.Get(t.Context(), fp)
	if err != nil {
		t.Fatalf("Get() after Set(present) returned error: %v", err)
	}
	m = state.AsMap()
	if s := m["state"].(string); s != "present" {
		t.Errorf("Get() after Set(present): state = %q, want 'present'", s)
	}
	if gotFP := m["fingerprint"].(string); gotFP != fp {
		t.Errorf("Get() fingerprint = %q, want %q", gotFP, fp)
	}

	// Remove via Set.
	removeConfig := &CertTrustConfig{State: "absent"}
	if err := mod.Set(t.Context(), fp, removeConfig); err != nil {
		t.Fatalf("Set(absent) returned error: %v", err)
	}

	// Get must return "absent" again.
	state, err = mod.Get(t.Context(), fp)
	if err != nil {
		t.Fatalf("Get() after Set(absent) returned error: %v", err)
	}
	m = state.AsMap()
	if s := m["state"].(string); s != "absent" {
		t.Errorf("Get() after Set(absent): state = %q, want 'absent'", s)
	}
}
