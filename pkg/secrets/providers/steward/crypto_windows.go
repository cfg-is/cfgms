// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package steward

import (
	"crypto/sha256"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// DPAPI flags
const (
	cryptprotectUIForbidden  = 0x1
	cryptprotectLocalMachine = 0x4
)

var (
	modcrypt32             = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData   = modcrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = modcrypt32.NewProc("CryptUnprotectData")
)

// dataBlob matches the Windows DATA_BLOB structure.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// userEntropyInfo is the HKDF context string for the entropy of the CLI
// credential store's user-scope DPAPI blobs.
const userEntropyInfo = "cfgms-cli-credentials-v1"

// dpapiEncryptor implements platformEncryptor using Windows DPAPI.
type dpapiEncryptor struct {
	entropy []byte // Application-specific entropy for additional binding
	// protectFlags are the CryptProtectData flags. With
	// cryptprotectLocalMachine any account on the machine can decrypt;
	// without it only the Windows user who encrypted can.
	protectFlags uintptr
}

// newPlatformEncryptor creates the steward's machine-scope DPAPI encryptor.
func newPlatformEncryptor(_ string) (platformEncryptor, error) {
	// Compute application-specific entropy as SHA-256 of our info string
	entropyHash := sha256.Sum256([]byte(hkdfInfo))
	return &dpapiEncryptor{
		entropy:      entropyHash[:],
		protectFlags: cryptprotectUIForbidden | cryptprotectLocalMachine,
	}, nil
}

// newUserEncryptor creates the CLI credential store's user-scope DPAPI
// encryptor, bound to this machine through its MachineGuid and to the store
// through the salt in dir.
func newUserEncryptor(dir string) (platformEncryptor, error) {
	machineID, err := MachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to read machine ID: %w", err)
	}
	return newUserDPAPIEncryptor(machineID, dir)
}

// newUserDPAPIEncryptor creates a user-scope DPAPI encryptor whose entropy is
// HKDF-SHA256 over machineID with the per-store salt kept in dir. A blob
// copied to another machine (a roaming profile, say) meets a different
// MachineGuid there and does not decrypt.
func newUserDPAPIEncryptor(machineID []byte, dir string) (*dpapiEncryptor, error) {
	if len(machineID) == 0 {
		return nil, fmt.Errorf("machine ID cannot be empty")
	}
	salt, err := loadOrGenerateSalt(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to load or generate salt: %w", err)
	}
	entropy := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, machineID, salt, []byte(userEntropyInfo)), entropy); err != nil {
		return nil, fmt.Errorf("failed to derive DPAPI entropy: %w", err)
	}
	return &dpapiEncryptor{
		entropy:      entropy,
		protectFlags: cryptprotectUIForbidden,
	}, nil
}

// MachineID returns the host's stable machine identifier (the registry
// MachineGuid under HKLM\SOFTWARE\Microsoft\Cryptography).
func MachineID() ([]byte, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, fmt.Errorf("open cryptography registry key: %w", err)
	}
	defer func() { _ = k.Close() }()
	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return nil, fmt.Errorf("read MachineGuid: %w", err)
	}
	if guid == "" {
		return nil, fmt.Errorf("MachineGuid is empty")
	}
	return []byte(guid), nil
}

// Encrypt encrypts plaintext using DPAPI CryptProtectData.
func (e *dpapiEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	input := newDataBlob(plaintext)
	entropy := newDataBlob(e.entropy)
	var output dataBlob

	ret, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0, // no description
		uintptr(unsafe.Pointer(&entropy)),
		0, // reserved
		0, // no prompt struct
		e.protectFlags,
		uintptr(unsafe.Pointer(&output)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptProtectData failed: %w", err)
	}
	defer func() { _, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(output.pbData))) }()

	return blobToBytes(output), nil
}

// Decrypt decrypts ciphertext using DPAPI CryptUnprotectData.
func (e *dpapiEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	input := newDataBlob(ciphertext)
	entropy := newDataBlob(e.entropy)
	var output dataBlob

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0, // no description
		uintptr(unsafe.Pointer(&entropy)),
		0, // reserved
		0, // no prompt struct
		uintptr(cryptprotectUIForbidden),
		uintptr(unsafe.Pointer(&output)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	defer func() { _, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(output.pbData))) }()

	return blobToBytes(output), nil
}

// Algorithm returns the encryption algorithm name.
func (e *dpapiEncryptor) Algorithm() string {
	return "DPAPI"
}

// newDataBlob creates a DATA_BLOB from a byte slice.
func newDataBlob(data []byte) dataBlob {
	if len(data) == 0 {
		return dataBlob{}
	}
	return dataBlob{
		cbData: uint32(len(data)),
		pbData: &data[0],
	}
}

// blobToBytes copies data from a DATA_BLOB to a Go byte slice.
func blobToBytes(blob dataBlob) []byte {
	if blob.cbData == 0 {
		return nil
	}
	result := make([]byte, blob.cbData)
	copy(result, unsafe.Slice(blob.pbData, blob.cbData))
	return result
}
