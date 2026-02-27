// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build windows

package steward

import (
	"crypto/sha256"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPI flags
const (
	cryptprotectUIForbidden = 0x1
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

// dpapiEncryptor implements platformEncryptor using Windows DPAPI.
type dpapiEncryptor struct {
	entropy []byte // Application-specific entropy for additional binding
}

// newPlatformEncryptor creates a DPAPI-based encryptor for Windows.
func newPlatformEncryptor(_ string) (platformEncryptor, error) {
	// Compute application-specific entropy as SHA-256 of our info string
	entropyHash := sha256.Sum256([]byte(hkdfInfo))
	return &dpapiEncryptor{
		entropy: entropyHash[:],
	}, nil
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
		uintptr(cryptprotectUIForbidden|cryptprotectLocalMachine),
		uintptr(unsafe.Pointer(&output)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptProtectData failed: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.pbData)))

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
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.pbData)))

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
