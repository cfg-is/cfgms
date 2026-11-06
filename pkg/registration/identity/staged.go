// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package identity

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// stagedKeyFileName holds a replacement device key while the controller has not
// yet accepted it. It sits beside the current key so the same encryptor (and its
// per-directory salt) protects it.
const stagedKeyFileName = keyFileName + ".next"

// StagedRotator is implemented by key stores that can hold a replacement key next
// to the current one. A repair uses it to rotate the device identity key: the old
// key keeps signing until the controller has accepted the new one, and only then
// does the new key take over. A store that cannot stage a key does not implement
// it, and the repair is refused rather than discarding the only accepted key.
type StagedRotator interface {
	KeyStore
	// StageNext returns the staged key, generating it on first call. A second call
	// returns the same key, so a retried request carries the same new key.
	StageNext(ctx context.Context) (crypto.PublicKey, Algorithm, error)
	// StagedPublicKey returns the staged public key, or nil when none is staged.
	StagedPublicKey() crypto.PublicKey
	// SignStaged signs message with the staged key.
	SignStaged(message []byte) ([]byte, error)
	// PromoteStaged makes the staged key current and drops the old one.
	PromoteStaged() error
	// DiscardStaged drops the staged key; the current key is untouched.
	DiscardStaged() error
}

var _ StagedRotator = (*FileKeyStore)(nil)

// StageNext implements StagedRotator.
func (ks *FileKeyStore) StageNext(_ context.Context) (crypto.PublicKey, Algorithm, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if err := ks.loadStagedLocked(); err != nil {
		return nil, "", err
	}
	if ks.stagedPriv != nil {
		return ks.stagedPriv.Public(), AlgorithmEd25519, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate staged device identity key: %w", err)
	}
	ciphertext, err := ks.encryptor.Encrypt([]byte(priv))
	if err != nil {
		return nil, "", fmt.Errorf("encrypt staged device identity key: %w", err)
	}
	if err := os.MkdirAll(ks.identityDir, 0700); err != nil {
		return nil, "", fmt.Errorf("create identity dir: %w", err)
	}
	path := filepath.Join(ks.identityDir, stagedKeyFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, ciphertext, 0600); err != nil {
		_ = os.Remove(tmp)
		return nil, "", fmt.Errorf("write staged device identity key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, "", fmt.Errorf("commit staged device identity key: %w", err)
	}
	ks.stagedPriv = priv
	return pub, AlgorithmEd25519, nil
}

// loadStagedLocked loads a staged key left by an earlier process. ks.mu is held.
func (ks *FileKeyStore) loadStagedLocked() error {
	if ks.stagedPriv != nil {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(ks.identityDir, stagedKeyFileName)) //#nosec G304 -- fixed name under the identity directory
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read staged device identity key: %w", err)
	}
	plaintext, err := ks.encryptor.Decrypt(data)
	if err != nil {
		return fmt.Errorf("decrypt staged device identity key: %w", err)
	}
	if len(plaintext) != ed25519.PrivateKeySize {
		return fmt.Errorf("staged device identity key corrupt: expected %d bytes, got %d", ed25519.PrivateKeySize, len(plaintext))
	}
	ks.stagedPriv = ed25519.PrivateKey(plaintext)
	return nil
}

// StagedPublicKey implements StagedRotator.
func (ks *FileKeyStore) StagedPublicKey() crypto.PublicKey {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.loadStagedLocked() != nil || ks.stagedPriv == nil {
		return nil
	}
	return ks.stagedPriv.Public()
}

// SignStaged implements StagedRotator.
func (ks *FileKeyStore) SignStaged(message []byte) ([]byte, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if err := ks.loadStagedLocked(); err != nil {
		return nil, err
	}
	if ks.stagedPriv == nil {
		return nil, errors.New("no staged device identity key")
	}
	return ed25519.Sign(ks.stagedPriv, message), nil
}

// PromoteStaged implements StagedRotator. The staged file is renamed over the
// current key, so a crash leaves one of the two keys in place, never neither.
func (ks *FileKeyStore) PromoteStaged() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if err := ks.loadStagedLocked(); err != nil {
		return err
	}
	if ks.stagedPriv == nil {
		return errors.New("no staged device identity key to promote")
	}
	staged := filepath.Join(ks.identityDir, stagedKeyFileName)
	if err := os.Rename(staged, filepath.Join(ks.identityDir, keyFileName)); err != nil {
		return fmt.Errorf("promote staged device identity key: %w", err)
	}
	pub := ks.stagedPriv.Public().(ed25519.PublicKey)
	ks.privateKey, ks.publicKey, ks.deviceID = ks.stagedPriv, pub, ed25519DeviceID(pub)
	ks.stagedPriv = nil
	return nil
}

// DiscardStaged implements StagedRotator.
func (ks *FileKeyStore) DiscardStaged() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.stagedPriv = nil
	if err := os.Remove(filepath.Join(ks.identityDir, stagedKeyFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("discard staged device identity key: %w", err)
	}
	return nil
}
