// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package identity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// recLogger records Info messages and their key/value pairs.
type recLogger struct {
	logging.NoopLogger
	mu   sync.Mutex
	logs []string
}

func (l *recLogger) Info(msg string, kv ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	b.WriteString(msg)
	for _, v := range kv {
		b.WriteString(" ")
		if s, ok := v.(string); ok {
			b.WriteString(s)
		}
	}
	l.logs = append(l.logs, b.String())
}

func (l *recLogger) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.logs, "\n")
}

// useTPMOpener points the registered TPM backend at open for one test and gives
// Open a file backend that does not depend on /etc/machine-id.
func useTPMOpener(t *testing.T, open tpmOpener) {
	t.Helper()
	savedOpener, savedFactory := defaultTPMOpener, newFileStore
	defaultTPMOpener = open
	newFileStore = func(dir string) (*FileKeyStore, error) { return NewFileKeyStoreForTesting(dir) }
	t.Cleanup(func() { defaultTPMOpener, newFileStore = savedOpener, savedFactory })
}

func requireFileFallback(t *testing.T, dir string, ks KeyStore, log *recLogger) {
	t.Helper()
	assert.Equal(t, ProtectionFile, ks.ProtectionLevel())
	assert.Equal(t, AlgorithmEd25519, ks.Algorithm())
	assert.Len(t, ks.DeviceID(), 64)
	_, err := os.Stat(filepath.Join(dir, keyFileName))
	assert.NoError(t, err, "fallback creates the file key")
	assert.Contains(t, log.joined(), "Hardware device key backend unavailable")
}

func TestOpen_TPMOpenerErrorFallsBackToFile(t *testing.T) {
	useTPMOpener(t, func() (transport.TPMCloser, error) { return nil, errors.New("permission denied") })
	dir := t.TempDir()
	log := &recLogger{}
	ks, err := Open(context.Background(), dir, log)
	require.NoError(t, err, "enrollment must not see a TPM error")
	requireFileFallback(t, dir, ks, log)
	assert.Contains(t, log.joined(), "permission denied")
	_, statErr := os.Stat(filepath.Join(dir, tpmBlobFileName))
	assert.True(t, os.IsNotExist(statErr))
}

func TestOpen_NoTPMDeviceFallsBackToFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "tpmrm0")
	useTPMOpener(t, func() (transport.TPMCloser, error) { return linuxtpm.Open(missing) })
	dir := t.TempDir()
	log := &recLogger{}
	ks, err := Open(context.Background(), dir, log)
	require.NoError(t, err)
	requireFileFallback(t, dir, ks, log)
}

func TestOpen_ProductionOpenerWithoutDevice(t *testing.T) {
	if _, err := os.Stat(tpmDevicePath); err == nil {
		t.Skipf("%s present on this host; the no-device path is exercised by the other tests", tpmDevicePath)
	}
	savedFactory := newFileStore
	newFileStore = func(dir string) (*FileKeyStore, error) { return NewFileKeyStoreForTesting(dir) }
	t.Cleanup(func() { newFileStore = savedFactory })
	dir := t.TempDir()
	log := &recLogger{}
	ks, err := Open(context.Background(), dir, log)
	require.NoError(t, err)
	requireFileFallback(t, dir, ks, log)
}

func TestTPMBlobFile_CorruptIsRejected(t *testing.T) {
	_, _, err := decodeBlobFile([]byte{0, 0})
	assert.Error(t, err)
	_, _, err = decodeBlobFile([]byte{0xff, 0xff, 0xff, 0xff, 1})
	assert.Error(t, err)
	p, q, err := decodeBlobFile(encodeBlobFile([]byte("pub"), []byte("priv")))
	require.NoError(t, err)
	assert.Equal(t, "pub", string(p))
	assert.Equal(t, "priv", string(q))
}
