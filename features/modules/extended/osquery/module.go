// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package osquery scaffolds an ADR-006-compliant extended module bundle for
// read-only host fact observation via the osquery binary. The four curated fact
// domains served are host:cpu, host:memory, host:os, and host:bios — matching
// the allowlist in features/steward/dna/fragments.go hostFactFragmentSpecs.
//
// Set() is permanently unimplemented. Get() fact-mapping logic is implemented
// in get.go (S4 of epic #2855).
//
// # Which binary this module executes
//
// The only binary this module will ever execute is the one carried by the
// installed, publisher-signed osquery bundle (ADR-006), resolved through
// PreExecVerifier.VerifyBeforeExec on every Get(). There is no host-install
// fallback path: the module never runs whatever osquery happens to be present
// at a well-known system location such as /usr/bin/osqueryi or
// /usr/local/bin/osqueryi. Those locations are outside CFGMS's control (unknown
// provenance and version, defeating pinnedVersion) and on some platforms are
// writable by non-root local users, which under the CFGMS threat model — where
// a steward runs privileged on a host that may be compromised — is a local
// privilege escalation into the steward's context.
//
// A module constructed without an Installation therefore fails closed: Get()
// returns ErrNoVerifiedInstallation rather than falling back to any path.
package osquery

import (
	"context"
	"errors"

	"github.com/cfgis/cfgms/features/modules"
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// pinnedVersion is the osquery release this bundle ships. S9 of epic #2855
// wires this constant into the refresh-pins mechanism; until then it is a
// named constant so a version bump is a single-line, auditable change.
//
// The pin is only meaningful because the executed binary comes from the signed
// bundle: a host-install path would run whatever version is installed there.
const pinnedVersion = "5.23.1"

// ErrNoVerifiedInstallation is returned by Get() when the module was built
// without an installed osquery bundle to verify against. It is a fail-closed
// error, never a signal to fall back to a host-installed osquery binary.
var ErrNoVerifiedInstallation = errors.New(
	"osquery: no verified bundle installation configured; refusing to execute any binary")

// Installation identifies the installed osquery bundle whose binary this module
// executes, together with the trust policy to enforce against it.
//
// Root is the directory the bundle was installed into; Bundle is the ADR-006
// bundle record (manifest, os-arch keyed binary paths, publisher signatures,
// signed content hash) describing what should be there. TrustMode is the
// steward.cfg module_trust.mode in force, and AdditionalPublishers are any
// operator-configured publishers beyond the baked-in CFGMS identity.
//
// The zero value carries no bundle, so a module built from it fails closed.
type Installation struct {
	Bundle               *bundle.Bundle
	Root                 string
	TrustMode            stewardtrust.TrustMode
	AdditionalPublishers []stewardtrust.PublisherIdentity
}

// osqueryModule implements modules.Module for read-only host fact observation.
// osquery is never a managed authority — it observes the four curated host:*
// fact domains (host:cpu, host:memory, host:os, host:bios) and never converges
// resource state.
type osqueryModule struct {
	// verifier re-verifies the installed bundle before every invocation.
	verifier *PreExecVerifier
	// install names the signed bundle whose binary Get() runs.
	install Installation
}

// New returns an osquery module that executes the binary carried by the
// installed, publisher-signed bundle described by install. The bundle is
// re-verified (trust gate plus on-disk content hash) before every invocation.
func New(install Installation) modules.Module {
	return &osqueryModule{
		verifier: NewPreExecVerifier(),
		install:  install,
	}
}

// newForTesting returns an osqueryModule wired to the given verifier and
// installation. Tests use it with NewPreExecVerifierWithEnforcer to inject a
// known publisher key pair over a real signed bundle installed in a temp dir —
// the production verification path still runs in full.
func newForTesting(verifier *PreExecVerifier, install Installation) *osqueryModule {
	return &osqueryModule{verifier: verifier, install: install}
}

// verifiedBinPath returns the on-disk path of the osquery binary after
// re-verifying the installed bundle: the steward trust gate (honouring
// module_trust.mode and the publisher trust store) followed by an on-disk
// content-hash re-check against the signed ContentHash.
//
// It is called once per Get(), so a binary swapped on disk between two
// convergence cycles is refused on the next one rather than executed. When no
// installation was configured it fails closed with ErrNoVerifiedInstallation;
// there is deliberately no unverified fallback path.
func (m *osqueryModule) verifiedBinPath() (string, error) {
	if m.verifier == nil || m.install.Bundle == nil || m.install.Root == "" {
		return "", ErrNoVerifiedInstallation
	}
	return m.verifier.VerifyBeforeExec(
		m.install.Bundle,
		m.install.Root,
		m.install.TrustMode,
		m.install.AdditionalPublishers,
	)
}

// IsActiveAndHealthy returns true if the installed bundle passes the complete
// trust gate (VerifyBeforeExec) without spawning any process. Used by the DNA
// collector's per-cycle source-selection gate (Issue #3565, ADR-017 Amendment 3).
//
// Returns false when no installation is configured (ErrNoVerifiedInstallation)
// or when the binary fails the on-disk content-hash re-check. No process is
// started — only the trust gate and hash re-check run.
func (m *osqueryModule) IsActiveAndHealthy() bool {
	_, err := m.verifiedBinPath()
	return err == nil
}

// Get returns the current host facts for the requested kind from osquery.
// Supported kinds: "host:cpu", "host:memory", "host:os", "host:bios".
// Returns an error for unknown kinds. Fails closed on zero osquery rows.
//
// The binary is resolved through verifiedBinPath on every call, so no osquery
// process is ever started from an unverified path.
func (m *osqueryModule) Get(ctx context.Context, kind string) (modules.ConfigState, error) {
	return getHostFact(ctx, m.verifiedBinPath, kind)
}

// Set permanently returns ErrNotImplemented — osquery is a read-only observer
// and is never a managed authority that converges resource state. This is an
// architectural invariant of the osquery epic, not a temporary stub.
func (m *osqueryModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return modules.ErrNotImplemented
}
