// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maxTokenFileSize bounds the read of a token file.
const maxTokenFileSize = 4096

// tokenFileSDDL is the security descriptor a token file is created with: owner
// BUILTIN\Administrators and a protected DACL (no ACEs inherited from the
// directory) granting full control to SYSTEM and BUILTIN\Administrators only.
const tokenFileSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" // #nosec G101 -- security descriptor string, not a credential

// Well-known SIDs a token file may name.
const (
	sidLocalSystem    = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

// writeTokenFile writes the registration token to path. The content goes into
// a new temp file in the same directory, created with CREATE_NEW and the
// admin-only descriptor tokenFileSDDL, so the descriptor is in force before any
// content is written. The temp file is flushed and then moved over the target
// with MoveFileEx(MOVEFILE_REPLACE_EXISTING), which also replaces the
// descriptor of a token file that already exists.
func writeTokenFile(path, token string) error {
	if err := validateToken(token); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //#nosec G301 -- shared config dir also holds the CA cert
		return fmt.Errorf("create token directory: %w", err)
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("create temporary token file name: %w", err)
	}
	tmp := filepath.Join(dir, "."+tokenFileName+"."+hex.EncodeToString(suffix)+".tmp")

	sd, err := windows.SecurityDescriptorFromString(tokenFileSDDL)
	if err != nil {
		return fmt.Errorf("build token file security descriptor: %w", err)
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	tmpPtr, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return fmt.Errorf("create temporary token file: %w", err)
	}
	h, err := windows.CreateFile(tmpPtr, windows.GENERIC_WRITE, 0, &sa,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("create temporary token file: %w", err)
	}
	f := os.NewFile(uintptr(h), tmp)
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.WriteString(token + "\n"); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("write token file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("sync token file: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close token file: %w", err)
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		cleanup()
		return fmt.Errorf("install token file: %w", err)
	}
	if err := windows.MoveFileEx(tmpPtr, pathPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		cleanup()
		return fmt.Errorf("install token file: %w", err)
	}
	return nil
}

// ReadTokenFile reads the registration token from path. The file is opened
// without following links, and it is refused unless it is a regular file owned
// by SYSTEM or BUILTIN\Administrators whose DACL has access-allowed ACEs for
// those two principals only. Errors never contain the token.
func ReadTokenFile(path string) (string, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("open registration token file %s: %w", path, err)
	}
	h, err := windows.CreateFile(pathPtr, windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return "", fmt.Errorf("registration token file %s does not exist", path)
		}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return "", explainAccessDenied(path, err)
		}
		return "", fmt.Errorf("open registration token file %s: %w", path, err)
	}
	f := os.NewFile(uintptr(h), path)
	defer func() { _ = f.Close() }()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", fmt.Errorf("inspect registration token file %s: %w", path, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return "", fmt.Errorf("registration token file %s is not a regular file", path)
	}
	if err := checkTokenFileSecurity(h, path); err != nil {
		return "", err
	}

	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read registration token file %s: %w", path, err)
	}
	if len(data) > maxTokenFileSize {
		return "", fmt.Errorf("registration token file %s is too large", path)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("registration token file %s is empty", path)
	}
	if err := validateToken(token); err != nil {
		return "", fmt.Errorf("registration token file %s: %w", path, err)
	}
	return token, nil
}

// explainAccessDenied reports why the token file could not be opened for
// reading. A deny ACE, or any ACE that withholds read from the caller, makes
// the open fail before the DACL can be checked, and every CreateFile handle
// needs SYNCHRONIZE, which a deny-all ACE also withholds. The owner is always
// granted READ_CONTROL, so the descriptor is read by path instead and the
// same checks run, returning the refusal they give. This path only ever
// produces an error and never reads the file, so reading the descriptor
// through a link here cannot admit a token. When the checks pass, the open
// error is returned.
func explainAccessDenied(path string, openErr error) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		if err := checkTokenFileDescriptor(sd, path); err != nil {
			return err
		}
	}
	return fmt.Errorf("open registration token file %s: %w", path, openErr)
}

// checkTokenFileSecurity refuses the open token file h unless its security
// descriptor passes checkTokenFileDescriptor.
func checkTokenFileSecurity(h windows.Handle, path string) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security descriptor of registration token file %s: %w", path, err)
	}
	return checkTokenFileDescriptor(sd, path)
}

// checkTokenFileDescriptor refuses sd unless its owner is SYSTEM or
// BUILTIN\Administrators and every ACE of its DACL is an access-allowed ACE
// for one of those two principals. A missing (NULL) DACL, which grants
// everyone full access, is refused.
func checkTokenFileDescriptor(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("cannot determine owner of registration token file %s", path)
	}
	if !isTokenFilePrincipal(owner) {
		return fmt.Errorf("registration token file %s must be owned by SYSTEM or BUILTIN\\Administrators", path)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return fmt.Errorf("registration token file %s has no access control list: grant access to SYSTEM and BUILTIN\\Administrators only", path)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return fmt.Errorf("read access control list of registration token file %s: %w", path, err)
		}
		// Only an access-allowed ACE has its SID at SidStart; any other type is
		// refused before the SID is read.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			!isTokenFilePrincipal((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return fmt.Errorf("registration token file %s must grant access to SYSTEM and BUILTIN\\Administrators only", path)
		}
	}
	return nil
}

// isTokenFilePrincipal reports whether sid is SYSTEM or BUILTIN\Administrators.
func isTokenFilePrincipal(sid *windows.SID) bool {
	s := sid.String()
	return s == sidLocalSystem || s == sidAdministrators
}

// installRegistrationToken writes token to the platform token file and returns
// its path. The file is created admin-only by writeTokenFile.
func installRegistrationToken(token string) (string, error) {
	path := platformTokenFilePath()
	fmt.Printf("Writing registration token to %s...\n", path)
	if err := writeTokenFile(path, token); err != nil {
		return "", fmt.Errorf("failed to write registration token file: %w", err)
	}
	return path, nil
}

// tokenFileConfigured reports whether path is a non-empty regular file. A
// missing path reports false, not an error. It never returns the content.
func tokenFileConfigured(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect registration token file %s: %w", path, err)
	}
	return info.Mode().IsRegular() && info.Size() > 0, nil
}
