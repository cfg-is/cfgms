// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRotateSigningCertificateSuccess verifies that a rotation from an expired overlap
// window creates a new cert, promotes it to CurrentSerial, and moves the old serial
// to RotatingSerial.
func TestRotateSigningCertificateSuccess(t *testing.T) {
	m := newTestManager(t)

	initialCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		ValidityDays: 30,
		KeySize:      2048,
	})
	require.NoError(t, err)

	// Establish cursor with an already-expired overlap window so next rotation is allowed.
	require.NoError(t, transitionSigningCursor(m.store, m.store.basePath, initialCert.SerialNumber, 1))
	cursor, err := loadSigningCursor(m.store.basePath)
	require.NoError(t, err)
	cursor.RotatedAt = time.Now().UTC().Add(-2 * 24 * time.Hour)
	require.NoError(t, saveSigningCursor(m.store.basePath, cursor))

	newCert, err := m.RotateSigningCertificate(7)
	require.NoError(t, err)
	require.NotNil(t, newCert)
	assert.NotEqual(t, initialCert.SerialNumber, newCert.SerialNumber)
	assert.Equal(t, CertificateTypeConfigSigning, newCert.Type)

	loaded, err := loadSigningCursor(m.store.basePath)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, newCert.SerialNumber, loaded.CurrentSerial)
	assert.Equal(t, initialCert.SerialNumber, loaded.RotatingSerial)
	assert.Equal(t, 7, loaded.OverlapWindowDays)
}

// TestRotateSigningCertificateInProgressError verifies that RotateSigningCertificate
// returns "rotation already in progress" when RotatingSerial is still within the
// overlap window.
func TestRotateSigningCertificateInProgressError(t *testing.T) {
	m := newTestManager(t)

	oldCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer-old",
		ValidityDays: 30,
		KeySize:      2048,
	})
	require.NoError(t, err)

	newCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer-current",
		ValidityDays: 30,
		KeySize:      2048,
	})
	require.NoError(t, err)

	// Active rotation: RotatedAt is now, window is 30 days — far from expired.
	cursor := &SigningCertCursor{
		CurrentSerial:     newCert.SerialNumber,
		RotatingSerial:    oldCert.SerialNumber,
		OverlapWindowDays: 30,
		RotatedAt:         time.Now().UTC(),
	}
	require.NoError(t, saveSigningCursor(m.store.basePath, cursor))

	_, err = m.RotateSigningCertificate(7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation already in progress")

	// Cursor must be unchanged.
	unchanged, err := loadSigningCursor(m.store.basePath)
	require.NoError(t, err)
	assert.Equal(t, newCert.SerialNumber, unchanged.CurrentSerial)
	assert.Equal(t, oldCert.SerialNumber, unchanged.RotatingSerial)
}

// TestRotateSigningCertificateCrashRecovery verifies that a leftover .tmp file from
// a crash mid-write does not prevent a subsequent successful rotation.
func TestRotateSigningCertificateCrashRecovery(t *testing.T) {
	m := newTestManager(t)

	initialCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		ValidityDays: 30,
		KeySize:      2048,
	})
	require.NoError(t, err)

	// Cursor with an expired overlap window so rotation is allowed.
	cursor := &SigningCertCursor{
		CurrentSerial:     initialCert.SerialNumber,
		OverlapWindowDays: 1,
		RotatedAt:         time.Now().UTC().Add(-2 * 24 * time.Hour),
	}
	require.NoError(t, saveSigningCursor(m.store.basePath, cursor))

	// Simulate a crash: write an orphaned .tmp file that saveSigningCursor would
	// leave behind if the process died between WriteFile and Rename.
	tmpPath := filepath.Join(m.store.basePath, "signing-cursor.json.tmp")
	require.NoError(t, os.WriteFile(tmpPath, []byte(`{"partial": true}`), 0600))

	// Rotation must succeed despite the orphaned tmp file.
	newCert, err := m.RotateSigningCertificate(7)
	require.NoError(t, err)
	require.NotNil(t, newCert)
	assert.NotEqual(t, initialCert.SerialNumber, newCert.SerialNumber)

	loaded, err := loadSigningCursor(m.store.basePath)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, newCert.SerialNumber, loaded.CurrentSerial)
	assert.Equal(t, initialCert.SerialNumber, loaded.RotatingSerial)
	assert.Equal(t, 7, loaded.OverlapWindowDays)
}

// TestRotateSigningCertificateConcurrency verifies that concurrent calls to
// RotateSigningCertificate are serialised: exactly one call succeeds and the
// rest return "rotation already in progress".
// Run with: go test -race ./pkg/cert/...
func TestRotateSigningCertificateConcurrency(t *testing.T) {
	m := newTestManager(t)

	// Generate initial cert so a cursor can be established.
	initialCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		ValidityDays: 30,
		KeySize:      2048,
	})
	require.NoError(t, err)

	// Establish cursor with an expired overlap window so the first rotation is allowed.
	require.NoError(t, transitionSigningCursor(m.store, m.store.basePath, initialCert.SerialNumber, 1))
	cursor, err := loadSigningCursor(m.store.basePath)
	require.NoError(t, err)
	cursor.RotatedAt = time.Now().UTC().Add(-2 * 24 * time.Hour)
	require.NoError(t, saveSigningCursor(m.store.basePath, cursor))

	const goroutines = 5
	errs := make(chan error, goroutines)

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, rotErr := m.RotateSigningCertificate(30)
			errs <- rotErr
		}()
	}

	wg.Wait()
	close(errs)

	var successes, inProgressErrors int
	for rotErr := range errs {
		if rotErr == nil {
			successes++
		} else if strings.Contains(rotErr.Error(), "rotation already in progress") {
			inProgressErrors++
		}
	}

	assert.Equal(t, 1, successes, "exactly one concurrent rotation must succeed")
	assert.Equal(t, goroutines-1, inProgressErrors, "all other goroutines must report rotation in progress")
}
