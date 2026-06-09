// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package hyperv

import (
	"context"
	"errors"
)

// errPSHostUnsupported is returned when newPSHostTransport is invoked on a
// non-Windows platform. The hyperv module itself is only operationally
// useful on Windows hosts (Hyper-V is Windows-only), but the package must
// build cross-platform so tests and dependents compile.
var errPSHostUnsupported = errors.New("hyperv: PS host transport requires Windows")

// psHostTransport on non-Windows is an unreachable type kept only so the
// hypervModule struct's transport field can hold one across builds. ExecutePS
// always returns an error.
type psHostTransport struct{}

// newPSHostTransport on non-Windows returns nil + the unsupported sentinel.
// hypervModule.Configure on Linux/macOS therefore falls through to the
// winrmClient path (still buildable, even if the lab deployment shape it
// targets — local steward on Hyper-V host — only exists on Windows).
//
// can reference newPSHostTransport unconditionally.
//
//nolint:unused // The signature must match the Windows version so module.go
func newPSHostTransport(_ context.Context) (*psHostTransport, error) {
	return nil, errPSHostUnsupported
}

// ExecutePS on non-Windows is unreachable in practice — Configure on non-
// Windows never assigns a psHostTransport to m.transport — but is defined
// so the type satisfies winrmTransport for cross-platform compilation.
func (t *psHostTransport) ExecutePS(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", errPSHostUnsupported
}

// Close on non-Windows is a no-op.
func (t *psHostTransport) Close() error { return nil }
