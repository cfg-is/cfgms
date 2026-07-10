// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package github_runner provides idempotent Get/Set/Test management of a GitHub
// Actions self-hosted runner agent on a steward host.
//
// The module manages three token-free dimensions of desired state:
//
//  1. Agent binary installed at a pinned version under a work directory. The
//     agent archive is downloaded (net/http), its SHA-256 verified against the
//     operator-pinned agent_sha256 (no network hash lookup), and unpacked with
//     the Go standard library (archive/tar+compress/gzip on Linux, archive/zip
//     on Windows) — never by shelling out to tar/Expand-Archive.
//  2. The desired runner label set, tracked in the module's own on-disk state
//     marker so drift is detectable offline.
//  3. The runner service kept enabled and running, via the native service
//     manager (systemd on Linux, SCM on Windows).
//
// The module deliberately does NOT mint or consume registration tokens and never
// registers/deregisters the runner with GitHub. Registration — and therefore the
// initial creation of the runner service and application of label changes to the
// GitHub side — is performed by the publisher-signed register script driven by
// the CI-runner provisioning workflow, which holds the single-use token. This
// module owns only the idempotent steady state that needs no secret.
package github_runner

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// svcStatus is the observed state of the runner's OS service.
type svcStatus struct {
	Installed bool // the service is registered with the OS service manager
	Running   bool
	Enabled   bool // starts automatically on boot
}

// runnerServiceExecutor is the platform-specific backend for runner-service
// state. Linux uses systemd, Windows uses the SCM; unsupported platforms return
// modules.ErrUnsupportedPlatform. It never creates or registers the service
// (that needs a registration token, which this module does not handle) — it only
// reports and converges the running/enabled state of an already-registered
// service.
type runnerServiceExecutor interface {
	// status reports whether the named runner service is registered, running,
	// and enabled. A service that is not registered yet returns
	// svcStatus{Installed:false} with a nil error.
	status(ctx context.Context, serviceName string) (svcStatus, error)
	// ensure converges an already-registered service to the desired running and
	// enabled state. It is idempotent and is a no-op when the service is already
	// in the desired state. If the service is not registered it returns an error
	// (registration is the provisioning workflow's responsibility).
	ensure(ctx context.Context, serviceName string, running, enabled bool) error
}

// agentInstaller downloads, verifies, and unpacks the runner agent archive into
// the work directory. The production implementation is httpInstaller (install.go);
// tests exercise it directly against a local httptest server (no external
// network, no mocks).
type agentInstaller interface {
	install(ctx context.Context, src installSource) error
}

// runnerModule implements modules.Module, modules.Configurable, and a Test method
// (the manifest's Test interface). Service state is delegated to a
// platform-specific executor; agent installation to an agentInstaller. Both are
// injected so the convergence logic is unit-testable without an init system or
// outbound network.
type runnerModule struct {
	modules.DefaultLoggingSupport
	modules.DefaultSecretStoreSupport

	executor  runnerServiceExecutor
	installer agentInstaller
}

// New creates a github_runner module wired with the platform service executor
// and the real HTTP agent installer.
func New() modules.Module {
	return newModule(newServiceExecutor(), newHTTPInstaller())
}

// newModule is the test seam: it injects the service executor and installer so
// tests can supply a test executor (the OS init system is unavailable in CI) and
// drive the real installer against a local server.
func newModule(exec runnerServiceExecutor, inst agentInstaller) *runnerModule {
	return &runnerModule{executor: exec, installer: inst}
}

// Configure implements modules.Configurable. It validates the desired runner
// configuration before any Get/Set so a malformed config is rejected without
// touching the host. No secrets are read — the module is token-free.
func (m *runnerModule) Configure(config modules.ConfigState) error {
	if config == nil {
		return fmt.Errorf("%w: config must not be nil", modules.ErrInvalidInput)
	}
	rc, err := asRunnerConfig(config)
	if err != nil {
		return err
	}
	return rc.Validate()
}

// Get returns the current observed state of the runner identified by resourceID
// (the resourceID is the runner's work directory, the stable host-side identity).
// It is network-free: version and labels come from the module's on-disk state
// marker, service state from the OS service manager.
func (m *runnerModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, modules.ErrInvalidResourceID
	}
	logger := m.GetEffectiveLogger(logging.ForModule("github_runner"))

	st, err := readState(resourceID)
	if err != nil {
		return nil, fmt.Errorf("read runner state: %w", err)
	}

	cur := &RunnerConfig{
		Version:   st.Version,
		Labels:    st.Labels,
		WorkDir:   resourceID,
		Installed: st.Version != "",
	}

	// Service state is keyed by the service name recorded in the state marker.
	// Before the first converge there is no recorded service name, so service
	// state is simply reported as not-yet-registered.
	if st.ServiceName != "" {
		status, serr := m.executor.status(ctx, st.ServiceName)
		if serr != nil {
			return nil, fmt.Errorf("query runner service %q: %w", logging.SanitizeLogValue(st.ServiceName), serr)
		}
		cur.ServiceName = st.ServiceName
		cur.ServiceRunning = status.Running
		cur.ServiceEnabled = status.Enabled
	}

	logger.InfoCtx(ctx, "github_runner state retrieved",
		"operation", "github_runner_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"installed", cur.Installed,
		"service_running", cur.ServiceRunning,
		"status", "completed")

	return cur, nil
}

// Test reports whether the current state matches the desired configuration.
// It returns true when there is NO drift and false when the installed version,
// the tracked label set, or the service run-state differs from desired —
// satisfying the manifest Test interface (drift => false).
func (m *runnerModule) Test(ctx context.Context, resourceID string, config modules.ConfigState) (bool, error) {
	desired, err := asRunnerConfig(config)
	if err != nil {
		return false, err
	}
	if err := desired.Validate(); err != nil {
		return false, err
	}
	currentState, err := m.Get(ctx, resourceID)
	if err != nil {
		return false, err
	}
	cur := currentState.(*RunnerConfig)

	if cur.Version != desired.Version {
		return false, nil
	}
	if !equalLabels(cur.Labels, desired.Labels) {
		return false, nil
	}
	// The module's goal is a service that is enabled and running.
	if !cur.ServiceRunning || !cur.ServiceEnabled {
		return false, nil
	}
	return true, nil
}

// Set converges the runner to the desired configuration. It is idempotent: a
// second Set against an already-converged host performs no observable change.
//
// Order: (1) install/replace the agent binary when the pinned version differs;
// (2) record the desired version + label set in the state marker; (3) ensure the
// service is enabled and running. Applying label changes to the GitHub side
// requires re-running the publisher-signed register script (provisioning
// workflow) because it needs a registration token; this module records the
// desired labels so drift is resolved locally and leaves token-bearing
// re-registration to that workflow.
func (m *runnerModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if resourceID == "" {
		return modules.ErrInvalidResourceID
	}
	if config == nil {
		return modules.ErrInvalidInput
	}
	desired, err := asRunnerConfig(config)
	if err != nil {
		return err
	}
	if err := desired.Validate(); err != nil {
		return err
	}
	logger := m.GetEffectiveLogger(logging.ForModule("github_runner"))

	st, err := readState(resourceID)
	if err != nil {
		return fmt.Errorf("read runner state: %w", err)
	}

	if st.Version != desired.Version {
		logger.InfoCtx(ctx, "installing runner agent",
			"operation", "github_runner_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"from_version", logging.SanitizeLogValue(st.Version),
			"to_version", logging.SanitizeLogValue(desired.Version))
		if ierr := m.installer.install(ctx, installSource{
			URL:     desired.AgentURL,
			SHA256:  desired.AgentSHA256,
			Version: desired.Version,
			WorkDir: resourceID,
			Format:  archiveFormatForOS(),
		}); ierr != nil {
			return fmt.Errorf("install runner agent: %w", ierr)
		}
		st.Version = desired.Version
	}

	// Record desired labels + service name so drift is resolved locally.
	st.Labels = append([]string(nil), desired.Labels...)
	sort.Strings(st.Labels)
	st.ServiceName = desired.ServiceName
	if werr := writeState(resourceID, st); werr != nil {
		return fmt.Errorf("write runner state: %w", werr)
	}

	// Ensure the service is enabled + running. Skipped when the service is not
	// yet registered (the provisioning workflow registers it on first standup);
	// in that case Get/Test report drift until registration completes.
	status, serr := m.executor.status(ctx, desired.ServiceName)
	if serr != nil {
		return fmt.Errorf("query runner service %q: %w", logging.SanitizeLogValue(desired.ServiceName), serr)
	}
	if status.Installed {
		if eerr := m.executor.ensure(ctx, desired.ServiceName, true, true); eerr != nil {
			return fmt.Errorf("ensure runner service %q: %w", logging.SanitizeLogValue(desired.ServiceName), eerr)
		}
	} else {
		logger.WarnCtx(ctx, "runner service not yet registered; agent staged, awaiting provisioning registration",
			"operation", "github_runner_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"service_name", logging.SanitizeLogValue(desired.ServiceName))
	}

	logger.InfoCtx(ctx, "github_runner converged",
		"operation", "github_runner_set",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"version", logging.SanitizeLogValue(desired.Version),
		"service_registered", status.Installed,
		"status", "completed")
	return nil
}

// asRunnerConfig coerces a modules.ConfigState into a *RunnerConfig, accepting
// either the concrete type or any ConfigState whose AsMap carries the fields.
func asRunnerConfig(config modules.ConfigState) (*RunnerConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: nil config", modules.ErrInvalidInput)
	}
	if rc, ok := config.(*RunnerConfig); ok {
		return rc, nil
	}
	rc := &RunnerConfig{}
	if err := rc.fromMap(config.AsMap()); err != nil {
		return nil, err
	}
	return rc, nil
}

// equalLabels compares two label sets order-insensitively.
func equalLabels(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// ErrServiceNotRegistered is returned by an executor's ensure when asked to
// converge a service the OS does not know about.
var ErrServiceNotRegistered = errors.New("runner service not registered")
