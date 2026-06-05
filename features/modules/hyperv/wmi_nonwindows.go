// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package hyperv

import (
	"context"
	"errors"
)

// ErrUseWinRMFallback is the cross-platform symbol matching the one defined
// in wmi_windows.go so module.go can reference it from cross-platform code.
// On non-Windows it is unreachable in practice — wmiTransport.ExecutePS is
// never invoked because newWMITransport returns nil.
var ErrUseWinRMFallback = errors.New("hyperv: wmi transport unavailable on this platform")

// wmiTransport on non-Windows is an unreachable stub kept only so module.go
// type-references compile cross-platform. ExecutePS is never called because
// newWMITransport returns nil and the module's transport-selection logic
// treats nil as "WMI unavailable".
type wmiTransport struct{}

// newWMITransport on non-Windows returns nil. hypervModule treats a nil WMI
// transport as "use winrmClient only" — the Linux/macOS steward cannot manage
// Hyper-V (Hyper-V is a Windows-only feature) so this is the correct outcome.
//
//nolint:unused // The signature must match the Windows version so module.go
// can reference newWMITransport unconditionally.
func newWMITransport(_ string) *wmiTransport { return nil }

// ExecutePS on non-Windows is unreachable but defined so the type satisfies
// the winrmTransport interface for cross-platform test compilation.
func (t *wmiTransport) ExecutePS(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", ErrUseWinRMFallback
}
