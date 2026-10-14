// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ErrHardwareKeyUnavailable is returned by Open when the stored identity records a
// hardware-backed key but that backend cannot load it. The caller retries with
// backoff; it must not create a file key, which would mint a new DeviceID.
var ErrHardwareKeyUnavailable = errors.New("hardware-backed device key unavailable")

// storedIdentityFileName is the steward's persisted registration record in the
// identity directory (cmd/steward defines the writer). Open reads only the
// key_protection_level field from it.
const storedIdentityFileName = "steward-identity.json"

// newFileStore constructs the file backend. Tests replace it to use a fixed-machine-ID encryptor.
var newFileStore = NewFileKeyStore

// backend is a hardware key store registered for one protection level.
type backend struct {
	level ProtectionLevel
	// open returns a store for dir. It fails when the hardware is absent or unusable.
	open func(ctx context.Context, dir string, logger logging.Logger) (KeyStore, error)
	// remove deletes any key this backend holds for dir.
	remove func(dir string) error
}

var (
	backendsMu sync.Mutex
	backends   []backend
)

// registerBackend adds a hardware backend; backends are probed in registration
// order. Per-platform files call it from init. No backend registers yet.
func registerBackend(b backend) {
	backendsMu.Lock()
	defer backendsMu.Unlock()
	backends = append(backends, b)
}

func registeredBackends() []backend {
	backendsMu.Lock()
	defer backendsMu.Unlock()
	return append([]backend(nil), backends...)
}

// recordedProtectionLevel returns the key_protection_level in the persisted
// steward identity, or "" when there is none.
func recordedProtectionLevel(dir string) ProtectionLevel {
	data, err := os.ReadFile(filepath.Join(dir, storedIdentityFileName)) //#nosec G304 -- fixed name under the identity directory
	if err != nil {
		return ""
	}
	var rec struct {
		Level string `json:"key_protection_level"`
	}
	if json.Unmarshal(data, &rec) != nil {
		return ""
	}
	return ProtectionLevel(rec.Level)
}

// Open returns the device KeyStore for identityDir, already loaded or generated.
//
// The backend is decided once, at first enrollment (ADR-011 Amendment 3):
//   - an existing device_identity.enc means the file backend, and no hardware
//     backend is probed;
//   - a persisted identity recording a hardware level means that backend only; if
//     it cannot load, Open returns ErrHardwareKeyUnavailable and creates no file key;
//   - otherwise registered hardware backends are tried in order and any failure
//     falls back to the file backend, with the reason logged.
func Open(ctx context.Context, identityDir string, logger logging.Logger) (KeyStore, error) {
	keyPath := filepath.Join(identityDir, keyFileName)
	if _, err := os.Stat(keyPath); err == nil {
		return openFile(ctx, identityDir)
	}

	if level := recordedProtectionLevel(identityDir); level != "" && level != ProtectionFile {
		for _, b := range registeredBackends() {
			if b.level != level {
				continue
			}
			ks, err := openBackend(ctx, b, identityDir, logger)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrHardwareKeyUnavailable, level, err)
			}
			return ks, nil
		}
		return nil, fmt.Errorf("%w: no %s backend in this build", ErrHardwareKeyUnavailable, level)
	}

	for _, b := range registeredBackends() {
		ks, err := openBackend(ctx, b, identityDir, logger)
		if err != nil {
			logger.Info("Hardware device key backend unavailable; trying next",
				"backend", string(b.level), "error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		return ks, nil
	}
	return openFile(ctx, identityDir)
}

func openBackend(ctx context.Context, b backend, dir string, logger logging.Logger) (KeyStore, error) {
	ks, err := b.open(ctx, dir, logger)
	if err != nil {
		return nil, err
	}
	if _, _, err := ks.GenerateOrLoad(ctx); err != nil {
		return nil, err
	}
	return ks, nil
}

func openFile(ctx context.Context, dir string) (KeyStore, error) {
	ks, err := newFileStore(dir)
	if err != nil {
		return nil, err
	}
	if _, _, err := ks.GenerateOrLoad(ctx); err != nil {
		return nil, err
	}
	return ks, nil
}

// RemoveAllStoredKeys deletes the device key from the file backend and from every
// registered hardware backend, so prepare-image leaves no key behind whichever
// backend held it. Absent keys are not an error.
func RemoveAllStoredKeys(dir string) error {
	errs := []error{RemoveStoredKey(dir)}
	for _, b := range registeredBackends() {
		if b.remove != nil {
			errs = append(errs, b.remove(dir))
		}
	}
	return errors.Join(errs...)
}
