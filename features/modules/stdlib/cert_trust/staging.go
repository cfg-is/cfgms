// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package cert_trust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// stagedFileName is the name of the staged file inside its private directory.
// It is fixed because the directory, not the name, is what is unpredictable.
const stagedFileName = "cert.pem"

// stageForTrustCommand writes pemData to a freshly created file inside a freshly
// created private subdirectory of baseDir, for a trust-store command to read.
//
// The base directory is created with mode 0700 when missing and, on Unix, must
// be a real directory (not a symlink) owned by the current effective user and
// not group- or other-writable. The subdirectory comes from os.MkdirTemp (mode
// 0700) and the file is created with O_CREATE|O_EXCL, so a pre-planted file or
// symlink can never be opened or followed. The returned cleanup function removes
// the subdirectory and the file; it is safe to call more than once.
func stageForTrustCommand(baseDir string, pemData []byte) (string, func(), error) {
	if baseDir == "" {
		return "", nil, errors.New("staging base directory is empty")
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return "", nil, fmt.Errorf("create staging base directory: %w", err)
	}
	if err := checkStagingBase(baseDir); err != nil {
		return "", nil, err
	}

	dir, err := os.MkdirTemp(baseDir, "stage-")
	if err != nil {
		return "", nil, fmt.Errorf("create staging directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	path := filepath.Join(dir, stagedFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 - path is inside a directory this call just created
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("create staged file: %w", err)
	}
	if _, err := f.Write(pemData); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, fmt.Errorf("write staged file: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("close staged file: %w", err)
	}
	return path, cleanup, nil
}
