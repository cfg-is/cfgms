// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package config

import "os"

// isRetryableLockError reports whether an O_EXCL create failed only because
// another holder owns the lock.
func isRetryableLockError(err error) bool { return os.IsExist(err) }
