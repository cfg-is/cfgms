// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
)

// ErrHostNotHyperV is returned by Get and Set when the local host is not a
// Hyper-V host. Inject a fakeDetector in tests to control this gate.
var ErrHostNotHyperV = errors.New("hyperv: host is not a Hyper-V host")

// HypervDetector detects whether the local host has Hyper-V enabled.
type HypervDetector interface {
	IsHypervHost(ctx context.Context) (bool, error)
}
