// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package oskeychain

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Credential Manager constants.
const (
	credTypeGeneric = 1 // CRED_TYPE_GENERIC

	// credPersistSession scopes the credential to the current logon session: it
	// lives in memory for the session and is never persisted to disk, matching
	// the short-lived session-token model and the Linux session-keyring fallback.
	credPersistSession = 1 // CRED_PERSIST_SESSION

	// errorNotFound is returned by CredReadW/CredDeleteW when the target is absent.
	errorNotFound = 1168 // ERROR_NOT_FOUND
)

var (
	modadvapi32      = windows.NewLazySystemDLL("advapi32.dll")
	procCredWriteW   = modadvapi32.NewProc("CredWriteW")
	procCredReadW    = modadvapi32.NewProc("CredReadW")
	procCredDeleteW  = modadvapi32.NewProc("CredDeleteW")
	procCredFreeProc = modadvapi32.NewProc("CredFree")
)

// credentialW mirrors the Windows CREDENTIALW structure. Field order and
// padding must match the C ABI exactly (see wincred.h).
type credentialW struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// credManBackend implements backend using the Windows Credential Manager.
type credManBackend struct{}

// platformNewBackend returns the Credential Manager backend. It is always
// available on Windows.
func platformNewBackend() (backend, error) {
	return &credManBackend{}, nil
}

func (b *credManBackend) name() string { return "windows-credential-manager" }

func (b *credManBackend) available() bool { return true }

func (b *credManBackend) set(key string, value []byte) error {
	target, err := windows.UTF16PtrFromString(key)
	if err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

	cred := credentialW{
		Type:               credTypeGeneric,
		TargetName:         target,
		CredentialBlobSize: uint32(len(value)),
		Persist:            credPersistSession,
	}
	if len(value) > 0 {
		cred.CredentialBlob = &value[0]
	}

	ret, _, callErr := procCredWriteW.Call(
		uintptr(unsafe.Pointer(&cred)),
		0, // flags
	)
	if ret == 0 {
		return fmt.Errorf("CredWriteW failed: %w", callErr)
	}
	return nil
}

func (b *credManBackend) get(key string) ([]byte, error) {
	target, err := windows.UTF16PtrFromString(key)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}

	var pcred *credentialW
	ret, _, callErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(target)),
		uintptr(credTypeGeneric),
		0, // flags
		uintptr(unsafe.Pointer(&pcred)),
	)
	if ret == 0 {
		if errno, ok := callErr.(windows.Errno); ok && uintptr(errno) == errorNotFound {
			return nil, errSecretNotFound
		}
		return nil, fmt.Errorf("CredReadW failed: %w", callErr)
	}
	defer func() { _, _, _ = procCredFreeProc.Call(uintptr(unsafe.Pointer(pcred))) }()

	// Copy the blob out of the Credential Manager-allocated buffer before freeing.
	if pcred.CredentialBlobSize == 0 || pcred.CredentialBlob == nil {
		return []byte{}, nil
	}
	out := make([]byte, pcred.CredentialBlobSize)
	copy(out, unsafe.Slice(pcred.CredentialBlob, pcred.CredentialBlobSize))
	return out, nil
}

func (b *credManBackend) del(key string) error {
	target, err := windows.UTF16PtrFromString(key)
	if err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

	ret, _, callErr := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(target)),
		uintptr(credTypeGeneric),
		0, // flags
	)
	if ret == 0 {
		if errno, ok := callErr.(windows.Errno); ok && uintptr(errno) == errorNotFound {
			// Deleting an absent key is not an error.
			return nil
		}
		return fmt.Errorf("CredDeleteW failed: %w", callErr)
	}
	return nil
}
