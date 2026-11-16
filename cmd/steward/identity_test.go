// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/client"
)

func TestSaveAndLoadIdentity_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	id := StewardIdentity{
		StewardID:        "steward-abc123",
		TenantID:         "tenant-xyz",
		TransportAddress: "controller:4433",
		CACertPEM:        "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----",
		ServerCertPEM:    "-----BEGIN CERTIFICATE-----\nfake-server\n-----END CERTIFICATE-----",
		SigningCertPEM:   "-----BEGIN CERTIFICATE-----\nfake-signing\n-----END CERTIFICATE-----",
	}

	require.NoError(t, saveIdentity(dir, id))

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, id.StewardID, got.StewardID)
	assert.Equal(t, id.TenantID, got.TenantID)
	assert.Equal(t, id.TransportAddress, got.TransportAddress)
	assert.Equal(t, id.CACertPEM, got.CACertPEM)
	assert.Equal(t, id.ServerCertPEM, got.ServerCertPEM)
	assert.Equal(t, id.SigningCertPEM, got.SigningCertPEM)
}

// TestSaveAndLoadIdentity_PersistsServerCert proves the controller's server
// certificate survives a save/load cycle. Without it the reconnect path cannot
// verify signed sync_config commands and the steward silently stops applying
// configuration after a restart.
func TestSaveAndLoadIdentity_PersistsServerCert(t *testing.T) {
	dir := t.TempDir()
	id := StewardIdentity{
		StewardID:        "steward-server-cert",
		TransportAddress: "controller:4433",
		ServerCertPEM:    "-----BEGIN CERTIFICATE-----\nserver-only\n-----END CERTIFICATE-----",
	}

	require.NoError(t, saveIdentity(dir, id))

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, id.ServerCertPEM, got.ServerCertPEM)
	assert.Empty(t, got.SigningCertPEM, "signing cert is optional and was not set")
}

func TestLoadIdentity_MissingFile_ReturnsNilNoError(t *testing.T) {
	dir := t.TempDir()
	got, err := loadIdentity(dir)
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestLoadIdentity_CorruptJSON_ReturnsNilError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, identityFileName)
	require.NoError(t, os.WriteFile(path, []byte("{not valid json"), 0600))

	got, err := loadIdentity(dir)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "corrupt")
}

func TestLoadIdentity_MissingStewardID_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, identityFileName)
	require.NoError(t, os.WriteFile(path, []byte(`{"tenant_id":"t1","transport_address":"ctrl:4433"}`), 0600))

	got, err := loadIdentity(dir)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "missing required fields")
}

func TestLoadIdentity_MissingTransportAddress_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, identityFileName)
	require.NoError(t, os.WriteFile(path, []byte(`{"steward_id":"s1","tenant_id":"t1"}`), 0600))

	got, err := loadIdentity(dir)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "missing required fields")
}

func TestSaveIdentity_FileMode_IsOwnerReadWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission check not applicable on Windows")
	}
	dir := t.TempDir()
	id := StewardIdentity{
		StewardID:        "steward-abc123",
		TransportAddress: "controller:4433",
	}
	require.NoError(t, saveIdentity(dir, id))

	info, err := os.Stat(filepath.Join(dir, identityFileName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestSaveIdentity_CreatesDirectoryIfAbsent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "subdir")
	id := StewardIdentity{
		StewardID:        "steward-abc123",
		TransportAddress: "controller:4433",
	}
	require.NoError(t, saveIdentity(dir, id))

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "steward-abc123", got.StewardID)
}

func TestSaveIdentity_OverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	first := StewardIdentity{StewardID: "first", TransportAddress: "ctrl:4433"}
	second := StewardIdentity{StewardID: "second", TransportAddress: "ctrl:4433"}

	require.NoError(t, saveIdentity(dir, first))
	require.NoError(t, saveIdentity(dir, second))

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "second", got.StewardID)
}

func TestSaveAndLoadPendingState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	state := PendingState{PendingID: "pending-abc123"}

	require.NoError(t, savePendingState(dir, state))

	got, err := loadPendingState(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "pending-abc123", got.PendingID)
}

func TestSaveAndLoadPendingState_ClientKeyPEM_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	state := PendingState{PendingID: "pending-abc123", ClientKeyPEM: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----"}

	require.NoError(t, savePendingState(dir, state))

	got, err := loadPendingState(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "pending-abc123", got.PendingID)
	assert.Equal(t, state.ClientKeyPEM, got.ClientKeyPEM, "persisted steward private key must survive the round trip")
}

func TestLoadPendingState_MissingFile_ReturnsNilNoError(t *testing.T) {
	dir := t.TempDir()
	got, err := loadPendingState(dir)
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestLoadPendingState_CorruptJSON_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pendingStateFileName)
	require.NoError(t, os.WriteFile(path, []byte("{not valid json"), 0600))

	got, err := loadPendingState(dir)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "corrupt")
}

func TestLoadPendingState_MissingPendingID_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pendingStateFileName)
	require.NoError(t, os.WriteFile(path, []byte(`{}`), 0600))

	got, err := loadPendingState(dir)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "missing pending_id")
}

func TestClearPendingState_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, savePendingState(dir, PendingState{PendingID: "test-id"}))

	require.NoError(t, clearPendingState(dir))

	got, err := loadPendingState(dir)
	assert.NoError(t, err)
	assert.Nil(t, got, "pending state must be absent after clear")
}

func TestClearPendingState_NoOp_WhenFileAbsent(t *testing.T) {
	dir := t.TempDir()
	assert.NoError(t, clearPendingState(dir))
}

func TestSavePendingState_FileMode_IsOwnerReadWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission check not applicable on Windows")
	}
	dir := t.TempDir()
	require.NoError(t, savePendingState(dir, PendingState{PendingID: "p1"}))

	info, err := os.Stat(filepath.Join(dir, pendingStateFileName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestSavePendingState_CreatesDirectoryIfAbsent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "subdir")
	require.NoError(t, savePendingState(dir, PendingState{PendingID: "p1"}))

	got, err := loadPendingState(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "p1", got.PendingID)
}

// TestSaveIdentity_ConcurrentReadersNeverBlockOrSeePartialFile proves a save
// is atomic and never blocked by a reader that is loading the same file.
func TestSaveIdentity_ConcurrentReadersNeverBlockOrSeePartialFile(t *testing.T) {
	dir := t.TempDir()
	a := StewardIdentity{StewardID: "identity-a", TransportAddress: "ctrl-a:4433"}
	b := StewardIdentity{StewardID: "identity-b", TransportAddress: "ctrl-b:4433"}
	require.NoError(t, saveIdentity(dir, a))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var loads int
	var loadErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			got, err := loadIdentity(dir)
			if err != nil {
				loadErr = err
				return
			}
			if got == nil || (got.StewardID != a.StewardID && got.StewardID != b.StewardID) ||
				(got.StewardID == a.StewardID && got.TransportAddress != a.TransportAddress) ||
				(got.StewardID == b.StewardID && got.TransportAddress != b.TransportAddress) {
				loadErr = errors.New("loadIdentity returned nil or a partial identity")
				return
			}
			loads++
		}
	}()

	for i := 0; i < 300; i++ {
		id := a
		if i%2 == 1 {
			id = b
		}
		require.NoError(t, saveIdentity(dir, id), "save %d", i)
	}
	close(stop)
	wg.Wait()
	require.NoError(t, loadErr)
	assert.Positive(t, loads)
}

// TestSaveIdentity_ConcurrentWritersNeverCorrupt runs many concurrent saves of
// differently sized identities. A shared temp path let the shorter payload land
// over a longer one (trailing bytes after the JSON object) and made one writer's
// rename fail after another had consumed the temp file.
func TestSaveIdentity_ConcurrentWritersNeverCorrupt(t *testing.T) {
	const (
		writers    = 16
		iterations = 40
	)
	dir := t.TempDir()

	written := make([]StewardIdentity, writers)
	for w := range written {
		pems := make([]string, w+1)
		for i := range pems {
			pems[i] = strings.Repeat("x", 64*(w+1)) + fmt.Sprintf("-w%d-c%d", w, i)
		}
		written[w] = StewardIdentity{
			StewardID:        fmt.Sprintf("steward-%d", w),
			TransportAddress: "controller:4433",
			SigningCertPEMs:  pems,
		}
	}
	require.NoError(t, saveIdentity(dir, written[0]))

	start := make(chan struct{})
	errs := make(chan error, writers*iterations)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				if err := saveIdentity(dir, written[w]); err != nil {
					errs <- fmt.Errorf("writer %d iteration %d: %w", w, i, err)
				}
			}
		}(w)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	got, err := loadIdentity(dir)
	require.NoError(t, err, "identity file must load after concurrent saves")
	require.NotNil(t, got)
	matched := false
	for _, want := range written {
		if reflect.DeepEqual(*got, want) {
			matched = true
			break
		}
	}
	assert.True(t, matched, "loaded identity %q must equal exactly one written value", got.StewardID)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.Equal(t, identityFileName, e.Name(), "no temp file may be left behind")
	}
}

// TestSaveIdentity_FailureLeavesNoTempFile verifies a failed commit removes its
// per-call temp file and leaves the existing identity intact.
func TestSaveIdentity_FailureLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	orig := StewardIdentity{StewardID: "orig", TransportAddress: "ctrl:4433"}
	require.NoError(t, saveIdentity(dir, orig))

	// A directory at the destination path makes the final replace fail.
	blocked := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(blocked, identityFileName), 0700))
	require.Error(t, saveIdentity(blocked, orig))

	entries, err := os.ReadDir(blocked)
	require.NoError(t, err)
	require.Len(t, entries, 1, "failed save must remove its temp file")

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	assert.Equal(t, "orig", got.StewardID)
}

func advertiseTestIdentity(addr string) StewardIdentity {
	return StewardIdentity{
		StewardID:        "steward-advertise",
		TenantID:         "tenant-advertise",
		TransportAddress: addr,
		CACertPEM:        "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----",
		ServerCertPEM:    "-----BEGIN CERTIFICATE-----\nfake-server\n-----END CERTIFICATE-----",
		SigningCertPEMs:  []string{"signing-a", "signing-b"},
		DeviceID:         "device-1",
		TrustMode:        "install-pinned",
		CAPinFingerprint: "abcd",
	}
}

// TestPersistAdvertisedTransportAddress_KeepsPrevious: the replaced address is kept
// as the previous one, nothing else changes, and re-persisting is a no-op.
func TestPersistAdvertisedTransportAddress_KeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	orig := advertiseTestIdentity("a:4433")
	require.NoError(t, saveIdentity(dir, orig))

	require.NoError(t, persistAdvertisedTransportAddress(dir, "b:4433"))

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	want := orig
	want.TransportAddress = "b:4433"
	want.PreviousTransportAddress = "a:4433"
	assert.Equal(t, want, *got)
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(filepath.Join(dir, identityFileName))
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}

	before, err := os.ReadFile(filepath.Join(dir, identityFileName))
	require.NoError(t, err)
	require.NoError(t, persistAdvertisedTransportAddress(dir, "b:4433"))
	after, err := os.ReadFile(filepath.Join(dir, identityFileName))
	require.NoError(t, err)
	assert.Equal(t, before, after, "the same address again leaves the file byte-identical")
}

func TestPersistAdvertisedTransportAddress_NoIdentity(t *testing.T) {
	err := persistAdvertisedTransportAddress(t.TempDir(), "b:4433")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity not found")
}

func TestPersistAdvertisedTransportAddress_CorruptIdentity(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, identityFileName), []byte("{not json"), 0600))
	require.Error(t, persistAdvertisedTransportAddress(dir, "b:4433"))
}

// TestLoadIdentity_WithoutPreviousTransportAddress_StillLoads: identity files
// written before the field existed remain valid.
func TestLoadIdentity_WithoutPreviousTransportAddress_StillLoads(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"steward_id":"steward-old","tenant_id":"t","transport_address":"old:4433","ca_cert_pem":"ca"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, identityFileName), []byte(legacy), 0600))

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "old:4433", got.TransportAddress)
	assert.Empty(t, got.PreviousTransportAddress)

	require.NoError(t, saveIdentity(dir, *got))
	data, err := os.ReadFile(filepath.Join(dir, identityFileName))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "previous_transport_address", "an empty previous address is omitted")
}

// TestAdvertiseTransportAddress_InvalidValueLeavesIdentityUnchanged applies the
// handler's gate (client.ValidateTransportAddress) in front of the shared persist
// function, exactly as the handler does: a refused value never reaches the
// identity file, whose bytes stay unchanged.
func TestAdvertiseTransportAddress_InvalidValueLeavesIdentityUnchanged(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, saveIdentity(dir, advertiseTestIdentity("a:4433")))
	before, err := os.ReadFile(filepath.Join(dir, identityFileName))
	require.NoError(t, err)

	for _, bad := range []string{"", "no-port", "host:", ":4433", "host:0", "host:70000", "host:abc", "https://host:4433", "host name:4433"} {
		require.Error(t, client.ValidateTransportAddress(bad), "value %q must be refused", bad)
		after, readErr := os.ReadFile(filepath.Join(dir, identityFileName))
		require.NoError(t, readErr)
		assert.Equal(t, before, after, "identity file changed after refused value %q", bad)
	}

	// A valid value passes the gate and is persisted.
	require.NoError(t, client.ValidateTransportAddress("b:4433"))
	require.NoError(t, persistAdvertisedTransportAddress(dir, "b:4433"))
	got, err := loadIdentity(dir)
	require.NoError(t, err)
	assert.Equal(t, "b:4433", got.TransportAddress)
}

// TestIdentityPersist_SigningTrustAndAddressDoNotLoseEachOther: the controller
// sends a signing-certificate push and a transport-address advertisement on every
// connect, and the steward runs both persist callbacks concurrently. Each one
// rewrites the whole identity file, so without a shared lock one loads the file
// before the other saves and writes the other's field back stale. After a restart
// the steward would then trust the old signing set, or dial the old address. Both
// results must survive in every ordering (Issue #6255).
func TestIdentityPersist_SigningTrustAndAddressDoNotLoseEachOther(t *testing.T) {
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	for round := 0; round < 200; round++ {
		dir := t.TempDir()
		orig := advertiseTestIdentity("a:4433")
		orig.SigningCertPEMs = []string{"old-cert"}
		require.NoError(t, saveIdentity(dir, orig))

		var wg sync.WaitGroup
		errs := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs <- persistSigningTrust(dir, []string{"new-cert"}, &expiry)
		}()
		go func() {
			defer wg.Done()
			errs <- persistAdvertisedTransportAddress(dir, "b:4433")
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}

		got, err := loadIdentity(dir)
		require.NoError(t, err)
		require.Equal(t, []string{"new-cert"}, got.SigningCertPEMs, "round %d: signing set lost to the address persist", round)
		require.NotNil(t, got.OverlapExpiresAt, "round %d", round)
		require.True(t, expiry.Equal(*got.OverlapExpiresAt), "round %d", round)
		require.Equal(t, "b:4433", got.TransportAddress, "round %d: address lost to the signing persist", round)
		require.Equal(t, "a:4433", got.PreviousTransportAddress, "round %d", round)
	}
}

func TestPersistSigningTrust_NoIdentity(t *testing.T) {
	err := persistSigningTrust(t.TempDir(), []string{"c"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity not found")
}
