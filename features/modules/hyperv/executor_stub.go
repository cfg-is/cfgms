// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package hyperv

// stubHypervExecutor is used on platforms where Hyper-V is not available.
// All executor methods added in Stories 2–4 will return ErrUnsupportedPlatform.
type stubHypervExecutor struct{}

func newExecutor() hypervExecutor {
	return &stubHypervExecutor{}
}
