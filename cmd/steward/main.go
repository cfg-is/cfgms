// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/version"
	"github.com/spf13/cobra"

	// Import logging providers to register them
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"

	// Import secrets providers to register them
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

// ControllerURL is the controller address baked in at build time via ldflags.
// Set during build: go build -ldflags "-X main.ControllerURL=https://ctrl.example.com"
// For deployments where the binary is not rebuilt per controller, pass
// --controller-url at install time (ADR-013 §3, Issue #1517).
var ControllerURL string

// SecurityProfile is stamped by release builds. Canonical public-beta builds
// set this to "public-beta"; direct `go build` remains an explicitly
// non-public development build.
var SecurityProfile = "development"

const (
	securityProfileDevelopment = "development"
	securityProfileTest        = "test"
	securityProfilePublicBeta  = "public-beta"
)

func publicBetaSecurityEnabled() (bool, error) {
	compiled := strings.TrimSpace(SecurityProfile)
	if compiled == "" {
		compiled = securityProfileDevelopment
	}
	envProfile := strings.TrimSpace(os.Getenv("CFGMS_SECURITY_PROFILE"))

	valid := func(profile string) bool {
		switch profile {
		case securityProfileDevelopment, securityProfileTest, securityProfilePublicBeta:
			return true
		default:
			return false
		}
	}
	if !valid(compiled) {
		return false, fmt.Errorf("invalid compiled security profile %q", compiled)
	}
	if envProfile != "" && !valid(envProfile) {
		return false, fmt.Errorf("invalid CFGMS_SECURITY_PROFILE %q", envProfile)
	}
	if compiled == securityProfilePublicBeta &&
		envProfile != "" && envProfile != securityProfilePublicBeta {
		return false, fmt.Errorf("CFGMS_SECURITY_PROFILE cannot downgrade compiled public-beta security profile to %q", envProfile)
	}
	return compiled == securityProfilePublicBeta || envProfile == securityProfilePublicBeta, nil
}

// TrustSource identifies the enrollment channel that established the trust anchor.
// Higher values denote stronger assurance. A steward never silently accepts a
// weaker source than it was built or enrolled for (ADR-013 §3, Issue #1517).
type TrustSource int

const (
	trustSourceTOFU          TrustSource = 1 // first-registration CA pin
	trustSourceInstallPinned TrustSource = 2 // --controller-ca at install time
	trustSourceCompileBaked  TrustSource = 3 // URL baked via ldflags
)

// connectFuncT is the signature of the controller connect function, injectable
// for testing so tests can simulate a controller-unreachable condition without
// touching the network. Production code always uses registerAndConnect. (Issue #2034)
type connectFuncT func(
	ctx context.Context,
	token, controllerURL string,
	trustSrc TrustSource,
	installCAPEM string,
	ks *identity.FileKeyStore,
	publicBeta bool,
	logger logging.Logger,
) (*client.TransportClient, error)

// subsystemState tracks which named subsystems are ready. The heartbeat loop
// reads this to report "degraded" while subsystems are still pending and
// "healthy" once they all attach. Thread-safe. (Issue #2034)
type subsystemState struct {
	mu       sync.Mutex
	degraded map[string]struct{}
}

func newSubsystemState() *subsystemState {
	return &subsystemState{degraded: make(map[string]struct{})}
}

func (s *subsystemState) markDegraded(subsystem string) {
	s.mu.Lock()
	s.degraded[subsystem] = struct{}{}
	s.mu.Unlock()
}

func (s *subsystemState) markHealthy(subsystem string) {
	s.mu.Lock()
	delete(s.degraded, subsystem)
	s.mu.Unlock()
}

// isTrustDowngrade returns true when err is a trust-source downgrade rejection
// from checkTrustDowngrade or tryReconnectWithStoredIdentity. These are
// integrity decisions that must not be silently retried. (Issue #2034)
func isTrustDowngrade(err error) bool {
	return err != nil && strings.Contains(err.Error(), "trust downgrade rejected")
}

// status returns "degraded" when any tracked subsystem is not yet ready,
// "healthy" when all subsystems have attached. Called by the heartbeat loop.
func (s *subsystemState) status() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.degraded) > 0 {
		return string(steward.StatusDegraded)
	}
	return string(steward.StatusHealthy)
}

func trustModeString(ts TrustSource) string {
	switch ts {
	case trustSourceCompileBaked:
		return "compile-baked"
	case trustSourceInstallPinned:
		return "install-pinned"
	case trustSourceTOFU:
		return "tofu"
	default:
		return "unknown"
	}
}

func trustSourceFromMode(mode string) TrustSource {
	switch mode {
	case "compile-baked":
		return trustSourceCompileBaked
	case "install-pinned":
		return trustSourceInstallPinned
	case "tofu":
		return trustSourceTOFU
	default:
		return 0
	}
}

// computeCAPEMFingerprint returns the SHA-256 hex fingerprint of the DER bytes
// of the first certificate block in caPEM.
func computeCAPEMFingerprint(caPEM string) (string, error) {
	block, _ := pem.Decode([]byte(caPEM))
	if block == nil {
		return "", fmt.Errorf("no PEM block found in CA PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("invalid CA certificate: %w", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// resolveTrustSource determines the effective trust level and controller URL.
//
// Rules (ADR-013 §3):
//   - compile-baked: no installURL supplied — use compiledURL
//   - install-pinned: installURL and installCA both non-empty
//   - tofu: installURL non-empty, installCA empty
func resolveTrustSource(compiledURL, installURL, installCA string) (TrustSource, string, error) {
	if installURL == "" {
		if compiledURL == "" {
			return 0, "", fmt.Errorf("controller URL not set: binary must be built with " +
				"-ldflags \"-X main.ControllerURL=https://your-controller.example.com\". " +
				"See docs/deployment/ for build instructions")
		}
		return trustSourceCompileBaked, compiledURL, nil
	}
	if installCA != "" {
		return trustSourceInstallPinned, installURL, nil
	}
	return trustSourceTOFU, installURL, nil
}

// checkTrustDowngrade rejects an enroll attempt that would weaken the trust
// anchor recorded in id. Also rejects a same-level re-enroll with a different CA.
func checkTrustDowngrade(current TrustSource, currentCAPEM string, id *StewardIdentity) error {
	stored := trustSourceFromMode(id.TrustMode)
	if stored == 0 {
		return nil
	}
	if current < stored {
		return fmt.Errorf("trust downgrade rejected: enrolled with %s (level %d); "+
			"cannot re-enroll with %s (level %d) — wipe identity to change trust anchor",
			id.TrustMode, stored, trustModeString(current), current)
	}
	if current >= trustSourceInstallPinned && id.CAPinFingerprint != "" && currentCAPEM != "" {
		fp, err := computeCAPEMFingerprint(currentCAPEM)
		if err != nil {
			return fmt.Errorf("compute CA fingerprint for downgrade check: %w", err)
		}
		if fp != id.CAPinFingerprint {
			return fmt.Errorf("already enrolled; re-pin requires wipe + re-enroll")
		}
	}
	return nil
}

// pinTOFUCA pins the controller CA on first TOFU enrollment. On first call it
// records the fingerprint in id and writes the CA to caPath at 0444 (public,
// immutable). On subsequent calls it verifies the CA matches the pinned value.
func pinTOFUCA(caPath, caPEM string, id *StewardIdentity) error {
	fp, err := computeCAPEMFingerprint(caPEM)
	if err != nil {
		return fmt.Errorf("compute TOFU CA fingerprint: %w", err)
	}
	if id.CAPinFingerprint != "" {
		if fp != id.CAPinFingerprint {
			return fmt.Errorf("already enrolled; re-pin requires wipe + re-enroll")
		}
		return nil
	}
	id.CAPinFingerprint = fp
	if caPath != "" {
		// #nosec G301 -- the steward service must traverse this directory to
		// read the public TOFU-pinned CA certificate; it contains no private key.
		if err := os.MkdirAll(filepath.Dir(caPath), 0755); err != nil {
			return fmt.Errorf("create TOFU CA cert directory: %w", err)
		}
		// #nosec G306 -- a CA certificate is public verification material; 0444
		// makes the TOFU pin service-readable and immutable by the service user.
		if err := os.WriteFile(caPath, []byte(caPEM), 0444); err != nil {
			return fmt.Errorf("write TOFU CA cert: %w", err)
		}
	}
	return nil
}

func main() {
	// On Windows: detect if launched by the Service Control Manager and run as
	// a Windows service. This must happen before any cobra / flag parsing.
	if checkAndRunAsWindowsService() {
		return
	}

	rootCmd := buildRootCommand()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// buildRootCommand constructs the cobra command tree for cfgms-steward.
func buildRootCommand() *cobra.Command {
	var (
		configPath    string
		regToken      string
		controllerURL string
	)

	root := &cobra.Command{
		Use:     "cfgms-steward",
		Version: version.Short(),
		Short:   "CFGMS Steward — endpoint configuration management agent",
		Long: fmt.Sprintf(`CFGMS Steward %s

Manages the local endpoint configuration on behalf of a CFGMS controller.

Entry paths:
  cfgms-steward --regtoken TOKEN     Run in foreground (controller-connected)
  cfgms-steward --config path.cfg    Run in standalone mode
  cfgms-steward install --regtoken TOKEN  Install as OS service
  cfgms-steward                      Interactive mode (prompts for token)`, version.Short()),
		// SilenceUsage prevents cobra printing usage on every error.
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRootCommand(cmd, regToken, controllerURL, configPath)
		},
	}

	// Flags used by the root command (foreground run mode).
	root.Flags().StringVar(&configPath, "config", "", "Path to configuration file (enables standalone mode)")
	root.Flags().StringVar(&regToken, "regtoken", "", "Registration token for controller registration")
	root.Flags().StringVar(&controllerURL, "controller-url", "", "Controller URL (overrides compile-time URL; set at install time via service definition)")

	// Subcommands.
	root.AddCommand(
		buildInstallCommand(),
		buildUninstallCommand(),
		buildStatusCommand(),
		buildDexSpikeCommand(),
	)

	return root
}

// runRootCommand implements the default (foreground) run behaviour.
// When no meaningful flags are provided it enters interactive mode.
func runRootCommand(cmd *cobra.Command, regToken, controllerURL, configPath string) error {
	// Interactive mode: no flags set and no subcommand selected.
	noFlags := regToken == "" && configPath == ""
	if noFlags {
		return runInteractive()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	return runSteward(ctx, regToken, controllerURL, configPath)
}

// runSteward starts the steward with the given configuration and blocks until
// ctx is cancelled. It is called from both the root cobra command and the
// Windows service handler.
func runSteward(ctx context.Context, regToken, controllerURL, configPath string) error {
	return runStewardInternal(ctx, regToken, controllerURL, configPath, nil)
}

// runStewardInternal is the testable core of runSteward. cf is the connect
// function; when nil, registerAndConnect is used. Tests inject a failing stub
// to simulate controller-unreachable conditions without network I/O. (Issue #2034)
func runStewardInternal(ctx context.Context, regToken, controllerURL, configPath string, cf connectFuncT) error {
	if cf == nil {
		cf = registerAndConnect
	}

	// ── Early stderr logger ───────────────────────────────────────────────────
	// Active BEFORE the file logging provider is initialised so that boot-time
	// failures are never silent (no more 0-byte log files on fast-exit). (Issue #2034)
	earlyLog := log.New(os.Stderr, "[cfgms-steward] ", log.Ltime|log.Lmsgprefix)
	earlyLog.Printf("starting (pid %d)", os.Getpid())

	// ── File logging provider ─────────────────────────────────────────────────
	// Best-effort: if the file provider fails, fall back to a stdout logger so
	// the process continues instead of dying with a 0-byte log file. (Issue #2034)
	logDir := os.Getenv("CFGMS_LOG_DIR")
	if logDir == "" {
		logDir = "/tmp/cfgms"
		earlyLog.Printf("WARNING: CFGMS_LOG_DIR not set; using /tmp/cfgms — set for production deployments")
	}
	loggingConfig := &logging.LoggingConfig{
		Provider:          "file",
		Level:             logLevelFromEnv(),
		ServiceName:       "steward",
		Component:         "main",
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
		AsyncWrites:       true,
		BatchSize:         100,
		FlushInterval:     5 * time.Second,
		RetentionDays:     30,
		Config: map[string]interface{}{
			"directory": logDir,
		},
	}

	var logger logging.Logger
	if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
		// File provider unavailable (e.g. /tmp not writable at early boot).
		// Log to stderr and continue with a stdout fallback — process liveness
		// must not depend on the log subsystem being ready. (Issue #2034)
		earlyLog.Printf("WARNING: file logging unavailable (%v); using stdout fallback", err)
		logger = logging.NewLogger(logLevelFromEnv())
	} else {
		// Flush and close the logger when runStewardInternal returns so that
		// buffered entries (AsyncWrites=true) reach disk before os.Exit fires.
		defer func() {
			if mgr := logging.GetGlobalLoggingManager(); mgr != nil {
				_ = mgr.Close()
			}
		}()
		(&logging.TelemetryBridge{}).Initialize()
		logging.InitializeGlobalLoggerFactory("steward", "main")
		logger = logging.ForComponent("steward")
	}

	// ── gRPC transport registration flow ─────────────────────────────────────
	if regToken != "" {
		publicBeta, profileErr := publicBetaSecurityEnabled()
		if profileErr != nil {
			return profileErr
		}
		logger.Info("Using registration token for auto-registration (gRPC transport mode)",
			"operation", "registration_init",
			"token_prefix", logging.RedactedID(regToken))

		// Derive a cancellable context so a pushed binary upgrade can request a
		// graceful self-exit (the launcher then re-execs the staged binary).
		// Cancelling runCtx flows into <-runCtx.Done() below, driving the clean
		// Disconnect+return path — no hard os.Exit. The parent ctx (signal/SCM
		// stop) still cancels runCtx too. (Issue #2001)
		runCtx, runCancel := context.WithCancel(ctx)
		defer runCancel()

		// ── Subsystem state tracker ───────────────────────────────────────────
		// Tracks which subsystems are ready so the heartbeat can report the real
		// health state instead of a hardcoded "healthy". (Issue #2034)
		subsysState := newSubsystemState()
		subsysState.markDegraded("controller") // degraded until first connect succeeds
		subsysState.markDegraded("dna")        // degraded until initial DNA collection succeeds

		// Initialise device identity key store before registration so the refresh
		// handshake path (Issue #2094) has a stable key available. Failure here is
		// non-fatal: initial registration still works; only the refresh path is disabled.
		ks, ksErr := identity.NewFileKeyStore(defaultCertStoreDir())
		if ksErr != nil {
			logger.Warn("Failed to create device identity key store; registration-refresh disabled", "error", ksErr)
		} else if _, _, loadErr := ks.GenerateOrLoad(runCtx); loadErr != nil {
			logger.Warn("Failed to load/generate device identity key; registration-refresh disabled", "error", loadErr)
			ks = nil
		}

		// Resolve trust source using the compile-baked URL, install-time URL,
		// and the CA cert on disk (written by the installer for install-pinned mode).
		installCACertPath := resolveRegistrationCACertPath(logger)
		var installCAPEM string
		if installCACertPath != "" {
			// #nosec G304 -- path is returned by resolveRegistrationCACertPath
			// from the explicit installer CA option or fixed service CA path.
			if caData, caErr := os.ReadFile(installCACertPath); caErr == nil {
				installCAPEM = string(caData)
			}
		}
		trustSrc, resolvedURL, trustErr := resolveTrustSource(ControllerURL, controllerURL, installCAPEM)
		if trustErr != nil {
			return trustErr
		}

		// ── Non-fatal controller connect with exponential backoff ─────────────
		// A connect failure at boot (network not up, controller not reachable) is
		// a not-ready condition. The steward marks itself degraded and retries in
		// the background instead of exiting. Process liveness is never gated on
		// controller availability. (Issue #2034)
		connectedCh := make(chan *client.TransportClient, 1)
		go func() {
			backoff := 5 * time.Second
			const maxBackoff = 5 * time.Minute
			for {
				if runCtx.Err() != nil {
					return
				}
				tc, connErr := cf(runCtx, regToken, resolvedURL, trustSrc, installCAPEM, ks, publicBeta, logger)
				if connErr == nil {
					subsysState.markHealthy("controller")
					connectedCh <- tc
					return
				}
				if runCtx.Err() != nil {
					return
				}
				// Terminal security decisions must not be silently retried —
				// they are integrity failures, not transient not-ready conditions.
				// Log loudly and stop the retry loop; the operator must take action.
				if errors.Is(connErr, registration.ErrRefreshRejected) {
					logger.Error("Registration refresh rejected by controller; steward must be manually re-admitted",
						"operation", "connect_terminal",
						"error", connErr)
					return
				}
				if isTrustDowngrade(connErr) {
					logger.Error("Trust-anchor downgrade rejected; wipe identity to change trust source",
						"operation", "connect_terminal",
						"error", connErr)
					return
				}
				logger.Warn("Controller connection failed; running in degraded mode, will retry",
					"operation", "connect_retry",
					"error", connErr,
					"backoff", backoff)
				select {
				case <-runCtx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < maxBackoff {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}
			}
		}()

		// Block until connected or shutdown signal — the launcher startup window
		// (#2033) handles known-good gating; this just ensures we stay alive.
		var transportCl *client.TransportClient
		select {
		case transportCl = <-connectedCh:
		case <-runCtx.Done():
			logger.Info("Shutdown before controller connection established",
				"operation", "steward_shutdown")
			return nil
		}

		// Wire real health state into the periodic heartbeat so the controller
		// can distinguish "started but subsystems pending" from "fully healthy".
		// Must be called before loops start so the first periodic heartbeat uses
		// the correct status. (Issue #2034)
		transportCl.SetStatusFunc(subsysState.status)

		// Wire the graceful-shutdown trigger used after a successful
		// push_steward_binary swap. Pass runCtx so the upgrade grace-delay timer
		// watches the process lifecycle (cancelled only on SCM stop / signal /
		// runCancel) for early-exit, NOT a per-command context. (Issue #2001, #2003)
		transportCl.SetShutdownFunc(runCtx, runCancel)

		logger.Info("Steward registered and connected successfully via gRPC transport",
			"operation", "registration_complete",
			"steward_id", transportCl.GetStewardID(),
			"tenant_id", transportCl.GetTenantID())

		logger.Info("Running in gRPC controller-connected mode",
			"operation", "steward_mode",
			"mode", "grpc_transport")

		// Collect and publish DNA so the controller's steward record carries
		// `os`, `hostname`, `arch`, etc. — selectors like `os:windows` and
		// `cfg steward run-command --target …` depend on the controller
		// having received a non-empty DNA snapshot. Without this one-shot
		// publish, the controller's steward record stays at its registration-
		// time defaults (empty DNA) and every selector matches zero stewards.
		// Failures are non-fatal — the steward stays usable for config
		// convergence even if DNA publication is briefly unavailable; the
		// controller will pick up DNA on the next convergence-driven publish
		// in publishConfigStatus. On success the DNA subsystem is marked healthy
		// so the heartbeat transitions from degraded to healthy. (Issue #2034)
		// Publish the FULL composite DNA (hardware + module). Using the composite
		// collector — not a raw host-only dna.Collector — is essential: a host-only
		// publish here runs after config apply and would delta-clobber the module
		// DNA (cluster:*, vm:*) the config-apply publish just sent (#2520).
		if pubErr := transportCl.PublishCurrentDNA(runCtx); pubErr != nil {
			// DNA subsystem stays degraded; the refresh loop retries on each tick.
			logger.Warn("Initial DNA publish failed; controller selectors may match no stewards until the next convergence-driven publish",
				"error", pubErr)
		} else {
			subsysState.markHealthy("dna")
			logger.Info("Initial DNA snapshot published")
		}

		// Check for launcher-written upgrade flag files and emit lifecycle events.
		// Must run before the heartbeat loop so the controller learns commit/rollback
		// status on the first heartbeat after a restart. (Issue #1943)
		checkUpgradeFlagFiles(runCtx, defaultCertStoreDir(), transportCl, logger)

		// Start scheduled convergence loop. The initial interval defaults to
		// 30 minutes. When the controller delivers a cfg, the loop reads
		// converge_interval from it and resets the ticker accordingly.
		// sync_config commands from the controller also trigger immediate
		// convergence as an out-of-band optimization on top of the schedule.
		transportCl.StartConvergenceLoop(runCtx)

		// Start periodic DNA refresh loop. Re-collects system attributes on
		// the configured interval and publishes delta updates so the controller
		// fleet view stays current without requiring a full reconnect. (Issue #1915)
		transportCl.StartDNARefreshLoop(runCtx)

		// Wait for context cancellation (signal, SCM stop, or a pushed-upgrade
		// graceful self-exit request via SetShutdownFunc → runCancel).
		<-runCtx.Done()
		logger.Info("Shutdown signal received, disconnecting...",
			"operation", "steward_shutdown")

		disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer disconnectCancel()
		if err := transportCl.Disconnect(disconnectCtx); err != nil {
			logger.Error("Error during transport disconnect",
				"operation", "transport_disconnect",
				"error", err.Error())
		}

		logger.Info("Steward shutdown completed", "operation", "steward_shutdown", "status", "completed")
		return nil
	}

	// Standalone mode: --config was provided.
	useStandalone := configPath != ""
	if useStandalone {
		legacyLogger := logging.GetLogger()
		s, err := steward.NewStandalone(configPath, legacyLogger)
		if err != nil {
			return fmt.Errorf("failed to create standalone steward: %w", err)
		}
		logger.Info("Starting steward in standalone mode",
			"operation", "steward_start", "mode", "standalone", "config_path", configPath)

		errCh := make(chan error, 1)
		go func() {
			errCh <- s.Start(ctx)
		}()

		<-ctx.Done()
		logger.Info("Shutdown signal received", "operation", "steward_shutdown")

		stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer stopCancel()
		if stopErr := s.Stop(stopCtx); stopErr != nil {
			logger.Error("Error during shutdown", "operation", "steward_shutdown", "error", stopErr.Error())
		}

		if startErr := <-errCh; startErr != nil && startErr != context.Canceled {
			logger.Error("Steward start failed", "operation", "steward_run", "error", startErr.Error())
			return fmt.Errorf("steward start failed: %w", startErr)
		}

		logger.Info("Steward shutdown completed", "operation", "steward_shutdown", "status", "completed")
		return nil
	}

	// Structurally unreachable: runRootCommand's noFlags guard prevents calling
	// runSteward with both regToken and configPath empty.
	return nil
}

// buildInstallCommand builds the `cfgms-steward install` subcommand.
func buildInstallCommand() *cobra.Command {
	var regToken, controllerURL, caCertPath, fingerprint string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Copy binary to platform path and register as OS service",
		Long: `Install copies the cfgms-steward binary to the platform-standard location
and registers it as a persistent OS service that starts automatically on boot.

Platforms:
  Windows  C:\Program Files\CFGMS\cfgms-steward.exe  (Windows Service)
  Linux    /usr/local/bin/cfgms-steward               (systemd)
  macOS    /usr/local/bin/cfgms-steward               (launchd)

Requires elevated privileges (Administrator on Windows, root on Linux/macOS).
Install is idempotent: running it again updates the binary and restarts the service.

Compile-baked URL (default — binary built with -ldflags):

  cfgms-steward install --regtoken TOKEN

Install-pinned (private CA, self-hosted deployments — ADR-013 §3):

  cfgms-steward install --regtoken TOKEN \
    --controller-url https://ctrl.example.com \
    --controller-ca /path/to/ca.crt \
    --fingerprint HEXFP

TOFU — trust-on-first-use (lab environments):

  cfgms-steward install --regtoken TOKEN \
    --controller-url https://ctrl.example.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(regToken, controllerURL, caCertPath, fingerprint)
		},
	}

	cmd.Flags().StringVar(&regToken, "regtoken", "", "Registration token (required)")
	_ = cmd.MarkFlagRequired("regtoken")
	cmd.Flags().StringVar(&controllerURL, "controller-url", "", "Controller URL (install-pinned and TOFU modes; omit to use compile-time URL)")
	cmd.Flags().StringVar(&caCertPath, "controller-ca", "", "Path to controller CA certificate PEM file (install-pinned mode)")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "Expected SHA-256 fingerprint of the CA certificate (hex, from controller --init output)")

	return cmd
}

// buildUninstallCommand builds the `cfgms-steward uninstall` subcommand.
func buildUninstallCommand() *cobra.Command {
	var purge bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the OS service",
		Long: `Uninstall stops the running cfgms-steward service and removes the service
definition from the OS service manager. With --purge the installed binary is
also deleted.

Requires elevated privileges (Administrator on Windows, root on Linux/macOS).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(purge)
		},
	}

	cmd.Flags().BoolVar(&purge, "purge", false, "Also remove the installed binary")

	return cmd
}

// buildStatusCommand builds the `cfgms-steward status` subcommand.
func buildStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show service state, install path, and controller URL",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus()
		},
	}
}

// runInstall performs the install operation for the current platform.
func runInstall(regToken, controllerURL, caCertPath, fingerprint string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}

	var caCertPEM string
	if caCertPath != "" {
		data, readErr := os.ReadFile(caCertPath) //#nosec G304 -- path from --controller-ca flag, admin-controlled
		if readErr != nil {
			return fmt.Errorf("failed to read CA cert file %s: %w", caCertPath, readErr)
		}
		caCertPEM = string(data)
	}

	mgr := service.New(exe)

	if !mgr.IsElevated() {
		return fmt.Errorf("install requires elevated privileges\n" +
			"  Windows: right-click the binary and select 'Run as administrator'\n" +
			"  Linux/macOS: re-run with sudo")
	}

	return mgr.Install(regToken, controllerURL, caCertPEM, fingerprint)
}

// runUninstall performs the uninstall operation for the current platform.
func runUninstall(purge bool) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}

	mgr := service.New(exe)

	if !mgr.IsElevated() {
		return fmt.Errorf("uninstall requires elevated privileges\n" +
			"  Windows: right-click the binary and select 'Run as administrator'\n" +
			"  Linux/macOS: re-run with sudo")
	}

	return mgr.Uninstall(purge)
}

// runStatus prints the current service state without requiring elevated privileges.
func runStatus() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}

	mgr := service.New(exe)
	status, err := mgr.Status()
	if err != nil {
		return fmt.Errorf("failed to query service status: %w", err)
	}

	fmt.Printf("CFGMS Steward %s\n\n", version.Short())
	fmt.Printf("  Service name:  %s\n", status.ServiceName)
	fmt.Printf("  Install path:  %s\n", status.InstallPath)
	fmt.Printf("  Controller:    %s\n", controllerURLOrUnknown())

	if !status.Installed {
		fmt.Printf("  Status:        not installed\n")
		fmt.Printf("\n  To install: cfgms-steward install --regtoken TOKEN\n")
		return nil
	}

	state := "stopped"
	if status.Running {
		state = "running"
	}
	fmt.Printf("  Status:        %s\n", state)
	return nil
}

// controllerURLOrUnknown returns the compile-time controller URL or a
// human-friendly placeholder when the binary was built without one.
func controllerURLOrUnknown() string {
	if ControllerURL == "" {
		return "(not set — binary built without -ldflags \"-X main.ControllerURL=...\")"
	}
	return ControllerURL
}

// runInteractive enters the interactive terminal UI shown when the binary is
// launched with no arguments (including Windows double-click).
//
// Flow:
//  1. Print header with version
//  2. Prompt for registration token
//  3. Offer: [1] Install as service  [2] Run once  [3] Exit
//  4. Execute chosen action
func runInteractive() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("CFGMS Steward %s\n\n", version.Short())
	fmt.Printf("Controller: %s\n\n", controllerURLOrUnknown())

	fmt.Print("Registration token: ")
	token, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read registration token: %w", err)
	}
	token = strings.TrimSpace(token)

	if token == "" {
		return fmt.Errorf("registration token cannot be empty")
	}

	fmt.Println()
	fmt.Println("  [1] Install as service (recommended)")
	fmt.Println("  [2] Run once (foreground)")
	fmt.Println("  [3] Exit")
	fmt.Println()
	fmt.Print("Choice: ")

	choice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read choice: %w", err)
	}
	choice = strings.TrimSpace(choice)

	fmt.Println()

	switch choice {
	case "1":
		return runInstall(token, "", "", "")
	case "2":
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigChan
			cancel()
		}()

		fmt.Println("Running in foreground. Press Ctrl+C to stop.")
		return runSteward(ctx, token, "", "")
	case "3", "":
		fmt.Println("Exiting.")
		return nil
	default:
		return fmt.Errorf("invalid choice %q — enter 1, 2, or 3", choice)
	}
}

// logLevelFromEnv reads CFGMS_LOG_LEVEL and returns the uppercased level string.
// Accepts debug, info, warn, error (case-insensitive). Returns "INFO" for empty
// or unrecognised values.
func logLevelFromEnv() string {
	switch strings.ToLower(os.Getenv("CFGMS_LOG_LEVEL")) {
	case "debug", "info", "warn", "error":
		return strings.ToUpper(os.Getenv("CFGMS_LOG_LEVEL"))
	default:
		return "INFO"
	}
}

// resolveControllerHTTPSBaseURL returns the controller HTTPS REST base URL used by the
// desired_version self-fetch path (Issue #2833), read from CFGMS_CONTROLLER_HTTPS_URL.
// Distinct from the QUIC transport address the steward connects on. Returns "" when
// unset or malformed (not https) — the steward then degrades safe to awaiting a
// controller push rather than self-fetching. The steward host-pins this URL's host to
// the transport host before any fetch, so a stray value can never redirect the download.
func resolveControllerHTTPSBaseURL(logger logging.Logger) string {
	raw := strings.TrimSpace(os.Getenv("CFGMS_CONTROLLER_HTTPS_URL"))
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		logger.Warn("CFGMS_CONTROLLER_HTTPS_URL is set but not a valid https URL; self-fetch disabled",
			"value", logging.SanitizeLogValue(raw))
		return ""
	}
	// Normalize to scheme://host[:port] with no path/query.
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

// buildHTTPConfig constructs an HTTPConfig from environment variables and the provided arguments.
func buildHTTPConfig(controllerURL string, timeout time.Duration, logger logging.Logger) *registration.HTTPConfig {
	return buildHTTPConfigWithPlatformPath(controllerURL, timeout, defaultPlatformCACertPath(), logger)
}

// buildHTTPConfigWithPlatformPath is the testable core of buildHTTPConfig.
// platformPath is injected so tests can exercise all CA-resolution cases without
// depending on whether /etc/cfgms/controller-ca.crt exists on the host (e.g. self-hosted CI runners).
func buildHTTPConfigWithPlatformPath(controllerURL string, timeout time.Duration, platformPath string, logger logging.Logger) *registration.HTTPConfig {
	return &registration.HTTPConfig{
		ControllerURL: controllerURL,
		Timeout:       timeout,
		CACertPath:    doResolveRegistrationCACertPath(logger, platformPath),
		Logger:        logger,
	}
}

// buildHTTPConfigForInstallPinned returns an HTTPConfig that pins the TLS CA
// exclusively to installCAPEM with no web-PKI fallback (ADR-013 §3, Issue #1517).
func buildHTTPConfigForInstallPinned(controllerURL string, timeout time.Duration, installCAPEM string, logger logging.Logger) *registration.HTTPConfig {
	return &registration.HTTPConfig{
		ControllerURL: controllerURL,
		Timeout:       timeout,
		CAPEM:         installCAPEM,
		Logger:        logger,
	}
}

// resolveRegistrationCACertPath returns the first CA cert path that exists on disk,
// checking in priority order: env var override, platform-standard installer path,
// then empty string (system trust store). See doResolveRegistrationCACertPath for logic.
func resolveRegistrationCACertPath(logger logging.Logger) string {
	return doResolveRegistrationCACertPath(logger, defaultPlatformCACertPath())
}

// doResolveRegistrationCACertPath is the testable core of resolveRegistrationCACertPath.
// platformPath is injected so tests can exercise all priority levels without root access.
func doResolveRegistrationCACertPath(logger logging.Logger, platformPath string) string {
	// Priority 1: explicit env var override.
	if envPath := os.Getenv("CFGMS_HTTP_CA_CERT_PATH"); envPath != "" {
		// #nosec G703 -- this process-start environment value is controlled by
		// the steward administrator/service definition, not a remote request.
		if _, err := os.Stat(envPath); err == nil {
			return envPath
		}
		logger.Warn("CFGMS_HTTP_CA_CERT_PATH set but file not found, falling through", "path", envPath)
	}

	// Priority 2: platform-standard path written by the installer.
	if _, err := os.Stat(platformPath); err == nil {
		logger.Info("Using platform-standard CA cert path", "path", platformPath)
		return platformPath
	}

	// Priority 3: no cert found; caller uses system trust store.
	logger.Info("No CA cert found; using system trust store")
	return ""
}

// defaultPlatformCACertPath returns the OS-specific path where the installer writes
// the controller CA cert, mirroring the path convention used by the install package.
func defaultPlatformCACertPath() string {
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "cfgms", "controller-ca.crt")
	default: // linux and darwin
		return "/etc/cfgms/controller-ca.crt"
	}
}

// approvedRegistration holds the fields returned by the controller after a successful
// registration — either an immediate HTTP 200 or a manual-review poll approval.
// This allows connectWithApprovedRegistration to serve both paths without duplication.
type approvedRegistration struct {
	StewardID        string
	TenantID         string
	Group            string
	TransportAddress string
	ClientCert       string
	// ClientKey holds the steward's locally generated private key PEM (Issue
	// #3780, #3781) — never a value read off the wire. For the immediate-approval
	// and manual-review poll-approval paths it comes from RegistrationResponse's /
	// RegistrationStatusResponse's local (non-wire) ClientKeyPEM field, populated
	// by the registration client from the keypair it generated for the CSR. For
	// the registration-refresh path it comes from the fresh keypair
	// refreshAndConnect generates locally before submitting the refresh CSR.
	ClientKey      string
	CACert         string
	ServerCert     string
	SigningCert    string
	DeviceID       string // stable device identity ID (Issue #2094)
	IdentityKeyPub string // base64-encoded Ed25519 public key (Issue #2094)
	// IssuerChain is the PEM-concatenated chain from ClientCert's direct issuer up
	// to (but not including) CACert (Issue #3778). Empty for a self-hosted,
	// root-only controller.
	IssuerChain string
}

// registerAndConnect registers the steward using HTTP REST API
// and then establishes gRPC-over-QUIC connections for ongoing communication.
// Both control plane and data plane use the transport_address from the registration response.
//
// On restart with a valid stored cert and identity, HTTP registration is skipped
// and the steward reconnects directly using the persisted credentials (Issue #1719).
//
// When the steward's mTLS cert is expired but a stored identity and device identity key
// exist, registerAndConnect tries the registration-refresh handshake (Issue #2094) before
// falling through to full HTTP re-registration.
//
// When the controller uses registration.workflow: manual (Issue #1899), the steward
// persists the pending_id locally and polls GET /api/v1/registration/status/{pending_id}
// with exponential backoff (5s → 60s max) until approved, denied, or timed out.
// On restart, the persisted pending_id is resumed rather than creating a new pending record.
//
// trustSrc and installCAPEM implement the ADR-013 §3 trust anchoring model (Issue #1517).
// installCAPEM is non-empty only for install-pinned mode; TOFU and compile-baked pass "".
func loadConnectedRuntimeConfig(publicBeta bool) (stewardconfig.StewardConfig, error) {
	cfg, err := stewardconfig.LoadConfiguration("")
	if err != nil {
		if !errors.Is(err, stewardconfig.ErrNoConfiguration) {
			if publicBeta {
				return cfg, fmt.Errorf("public-beta connected configuration is invalid: %w", err)
			}
			return cfg, nil
		}
		if publicBeta {
			cfg.Steward.ScriptSigning = stewardconfig.ScriptSigningConfig{
				Policy:             stewardconfig.ScriptSigningPolicyOptional,
				RequireSignedAdhoc: true,
			}
		}
		return cfg, nil
	}
	if publicBeta && !cfg.Steward.ScriptSigning.RequireSignedAdhoc {
		return cfg, fmt.Errorf("public-beta connected configuration rejects require_signed_adhoc: false or omitted")
	}
	return cfg, nil
}

func registerAndConnect(ctx context.Context, token, controllerURL string, trustSrc TrustSource, installCAPEM string, ks *identity.FileKeyStore, publicBeta bool, logger logging.Logger) (*client.TransportClient, error) {
	logger.Info("Starting steward connect sequence")

	certStoreDir := defaultCertStoreDir()
	runtimeCfg, err := loadConnectedRuntimeConfig(publicBeta)
	if err != nil {
		return nil, err
	}

	// Downgrade guard: reject if stored enrollment had stronger trust assurance.
	if storedID, loadErr := loadIdentity(certStoreDir); loadErr == nil && storedID != nil {
		if dgErr := checkTrustDowngrade(trustSrc, installCAPEM, storedID); dgErr != nil {
			return nil, dgErr
		}
	}

	// Attempt cert-reuse reconnect (skips HTTP registration on restart).
	if tc, reconnErr := tryReconnectWithStoredIdentity(ctx, certStoreDir, token, trustSrc, runtimeCfg, publicBeta, logger); tc != nil {
		return tc, nil
	} else if reconnErr != nil {
		logger.Warn("Stored-identity reconnect failed; checking for expired-cert refresh path", "error", reconnErr)
	}

	// Expired-cert refresh path (Issue #2094): when a stored identity exists and all
	// client certs are expired, attempt the registration-refresh handshake before
	// falling through to full HTTP re-registration.
	if ks != nil && ks.DeviceID() != "" {
		if storedID, loadErr := loadIdentity(certStoreDir); loadErr == nil && storedID != nil {
			certMgr, certMgrErr := cert.NewManager(&cert.ManagerConfig{
				StoragePath:    certStoreDir,
				LoadExistingCA: true,
			})
			if certMgrErr == nil {
				if certs, listErr := certMgr.ListCertificates(); listErr == nil && hasExpiredClientCert(certs) {
					tc, refreshErr := refreshAndConnect(ctx, storedID, ks, certStoreDir, token, controllerURL, runtimeCfg, publicBeta, logger)
					if refreshErr == nil {
						return tc, nil
					}
					if errors.Is(refreshErr, registration.ErrRefreshPending) {
						logger.Warn("Registration refresh pending operator approval; retry later",
							"device_id", logging.SanitizeLogValue(ks.DeviceID()))
						return nil, refreshErr
					}
					if errors.Is(refreshErr, registration.ErrRefreshRejected) {
						logger.Error("Registration refresh rejected; steward must be manually re-admitted",
							"device_id", logging.SanitizeLogValue(ks.DeviceID()))
						return nil, refreshErr
					}
					logger.Warn("Registration refresh failed; falling back to HTTP re-registration", "error", refreshErr)
				}
			}
		}
	}

	logger.Info("Registering steward via HTTP API")

	var httpCfg *registration.HTTPConfig
	if trustSrc == trustSourceInstallPinned {
		httpCfg = buildHTTPConfigForInstallPinned(controllerURL, 30*time.Second, installCAPEM, logger)
	} else {
		httpCfg = buildHTTPConfig(controllerURL, 30*time.Second, logger)
	}
	// Enrollment into a controller cluster is the one event allowed to clear the
	// persisted Raft-term fence ratchet, so a rebuilt cluster (terms restart at 1)
	// does not permanently lock this steward out (Issue #3437). The registration
	// client clears it only after the enrollment response's certificate set verifies.
	// The refresh path (refreshAndConnect) deliberately leaves CertStoreDir unset:
	// re-issuing a certificate for the same cluster is not a cluster rebuild.
	httpCfg.CertStoreDir = certStoreDir
	httpClient, err := registration.NewHTTPClient(httpCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP registration client: %w", err)
	}

	// Load the approval poll timeout from optional local config (default: 24h).
	pollTimeout := 24 * time.Hour
	if runtimeCfg.Steward.RegistrationPollTimeout > 0 {
		pollTimeout = runtimeCfg.Steward.RegistrationPollTimeout
	}

	// Resume a pending registration from a previous run if one exists.
	// This avoids creating a duplicate pending record on every steward restart (Issue #1899).
	if pendingState, loadErr := loadPendingState(certStoreDir); loadErr != nil {
		logger.Warn("Failed to load pending registration state; re-registering", "error", loadErr)
	} else if pendingState != nil {
		switch pendingState.ClientKeyPEM {
		case "":
			// Pending-state file predates Issue #3780's follow-up (or the key field was
			// otherwise lost). There is no way to pair a later claim with a usable key
			// on this process instance, and a claimed pending record cannot be re-polled
			// (single-claim) — resuming would either hang or silently connect without
			// mTLS. Loud, and fall through to a fresh registration instead.
			logger.Warn("Persisted pending registration has no steward private key; cannot resume, re-registering",
				"pending_id", logging.SanitizeLogValue(pendingState.PendingID))
			if clearErr := clearPendingState(certStoreDir); clearErr != nil {
				logger.Warn("Failed to clear stale pending state file", "error", clearErr)
			}
		default:
			if resumeErr := httpClient.ResumePendingClientKey(pendingState.ClientKeyPEM); resumeErr != nil {
				logger.Warn("Failed to restore persisted steward private key for pending registration; re-registering",
					"pending_id", logging.SanitizeLogValue(pendingState.PendingID),
					"error", logging.SanitizeLogValue(resumeErr.Error()))
				if clearErr := clearPendingState(certStoreDir); clearErr != nil {
					logger.Warn("Failed to clear stale pending state file", "error", clearErr)
				}
				break
			}
			logger.Info("Resuming pending registration from previous run",
				"pending_id", logging.SanitizeLogValue(pendingState.PendingID))
			approved, pollErr := pollForApproval(ctx, httpClient, pendingState.PendingID, token,
				pollTimeout, 5*time.Second, 60*time.Second, logger)
			if pollErr != nil {
				_ = clearPendingState(certStoreDir)
				return nil, pollErr
			}
			if approved != nil {
				enrichApprovedWithDeviceIdentity(approved, ks)
				_ = clearPendingState(certStoreDir)
				return connectWithApprovedRegistration(ctx, *approved, certStoreDir, token, trustSrc, installCAPEM, runtimeCfg, publicBeta, logger)
			}
			// approved == nil: pending record expired (HTTP 410); fall through to fresh registration.
			logger.Info("Persisted pending record expired on controller; performing fresh registration")
			if clearErr := clearPendingState(certStoreDir); clearErr != nil {
				logger.Warn("Failed to clear stale pending state file", "error", clearErr)
			}
		}
	}

	regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
	defer regCancel()

	regReq := registration.RegistrationRequest{Token: token}
	if ks != nil && ks.DeviceID() != "" {
		regReq.DeviceID = ks.DeviceID()
		if pub := ks.PublicKey(); pub != nil {
			regReq.IdentityKeyPub = base64.StdEncoding.EncodeToString([]byte(pub))
		}
	}
	// Seed hostname and OS so the controller is not identity-blind before first DNA sync
	// (Issue #2640). Mirrors features/steward/dna/dna.go:227 without importing that package.
	if hostname, err := os.Hostname(); err == nil {
		regReq.Hostname = hostname
	}
	regReq.OS = runtime.GOOS

	regResp, pendingResp, err := httpClient.Register(regCtx, regReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP registration failed: %w", err)
	}

	if pendingResp != nil {
		// Controller returned HTTP 202: registration is pending operator approval.
		// Persist the pending_id so restarts resume this record rather than creating
		// a duplicate (Issue #1899).
		logger.Info("Registration is pending operator approval — polling for approval",
			"pending_id", logging.SanitizeLogValue(pendingResp.PendingID),
			"steward_id", logging.SanitizeLogValue(pendingResp.StewardID),
			"tenant_id", logging.SanitizeLogValue(pendingResp.TenantID))
		// Persist the private key generated for this CSR alongside the pending ID
		// (Issue #3780 follow-up) so a restart during the quarantine poll window can
		// resume this same key rather than losing the ability to pair an eventually
		// claimed certificate with a usable identity.
		pendingKeyPEM, pendingKeyErr := httpClient.PendingClientKeyPEM()
		if pendingKeyErr != nil {
			logger.Warn("Failed to retrieve steward private key for pending-registration persistence; a restart during quarantine will require re-registration",
				"error", logging.SanitizeLogValue(pendingKeyErr.Error()))
		}
		if saveErr := savePendingState(certStoreDir, PendingState{PendingID: pendingResp.PendingID, ClientKeyPEM: pendingKeyPEM}); saveErr != nil {
			logger.Warn("Failed to persist pending registration ID; restart will re-register", "error", saveErr)
		}
		approved, pollErr := pollForApproval(ctx, httpClient, pendingResp.PendingID, token,
			pollTimeout, 5*time.Second, 60*time.Second, logger)
		if pollErr != nil {
			_ = clearPendingState(certStoreDir)
			return nil, pollErr
		}
		if approved == nil {
			// 410 immediately after registration — controller record vanished unexpectedly.
			_ = clearPendingState(certStoreDir)
			return nil, fmt.Errorf("registration approval timed out after %s; re-run with a fresh token if needed", pollTimeout)
		}
		enrichApprovedWithDeviceIdentity(approved, ks)
		_ = clearPendingState(certStoreDir)
		return connectWithApprovedRegistration(ctx, *approved, certStoreDir, token, trustSrc, installCAPEM, runtimeCfg, publicBeta, logger)
	}

	// Immediate approval (HTTP 200): proceed directly to transport setup.
	logger.Info("Registration successful via HTTP",
		"steward_id", regResp.StewardID,
		"tenant_id", regResp.TenantID,
		"group", regResp.Group,
		"transport_address", regResp.TransportAddress)

	bundle := approvedRegistration{
		StewardID:        regResp.StewardID,
		TenantID:         regResp.TenantID,
		Group:            regResp.Group,
		TransportAddress: regResp.TransportAddress,
		ClientCert:       regResp.ClientCert,
		ClientKey:        regResp.ClientKeyPEM,
		CACert:           regResp.CACert,
		ServerCert:       regResp.ServerCert,
		SigningCert:      regResp.SigningCert,
		IssuerChain:      regResp.IssuerChain,
	}
	enrichApprovedWithDeviceIdentity(&bundle, ks)
	return connectWithApprovedRegistration(ctx, bundle, certStoreDir, token, trustSrc, installCAPEM, runtimeCfg, publicBeta, logger)
}

// pollForApproval polls GET /api/v1/registration/status/{pendingID} with exponential
// backoff until the controller approves, denies, or the timeout is reached.
//
// Intervals grow from initialInterval up to maxInterval. Pass initialInterval=0 to
// skip all sleeps (useful in tests via the PollStatus(0,0) pass-through).
//
// Returns:
//   - (*approvedRegistration, nil) when approved (status "claimed" with cert fields)
//   - (nil, nil) when the pending record expired (HTTP 410) — caller should re-register
//   - (nil, error) on denial, timeout, or context cancellation
func pollForApproval(
	ctx context.Context,
	httpClient *registration.HTTPClient,
	pendingID, regToken string,
	pollTimeout, initialInterval, maxInterval time.Duration,
	logger logging.Logger,
) (*approvedRegistration, error) {
	pollCtx, pollCancel := context.WithTimeout(ctx, pollTimeout)
	defer pollCancel()

	const pollJitter = 2 * time.Second
	currentInterval := initialInterval

	for {
		jitter := pollJitter
		if currentInterval == 0 {
			jitter = 0
		}

		resp, err := httpClient.PollStatus(pollCtx, pendingID, regToken, currentInterval, jitter)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return nil, fmt.Errorf("registration approval timed out after %s; re-run with a fresh token if needed", pollTimeout)
			}
			// Transient network error — log and retry with unchanged interval.
			logger.Warn("Transient error polling registration status; will retry", "error", err)
			continue
		}

		switch resp.Status {
		case "claimed":
			if resp.ClientCert == "" {
				// HTTP 410: pending record expired or already claimed by another process.
				logger.Info("Pending registration record expired or already claimed; will re-register")
				return nil, nil
			}
			logger.Info("Registration approved by operator",
				"steward_id", logging.SanitizeLogValue(resp.StewardID),
				"tenant_id", logging.SanitizeLogValue(resp.TenantID))
			return &approvedRegistration{
				StewardID:        resp.StewardID,
				TenantID:         resp.TenantID,
				Group:            resp.Group,
				TransportAddress: resp.TransportAddress,
				ClientCert:       resp.ClientCert,
				ClientKey:        resp.ClientKeyPEM,
				CACert:           resp.CACert,
				ServerCert:       resp.ServerCert,
				SigningCert:      resp.SigningCert,
				IssuerChain:      resp.IssuerChain,
			}, nil

		case "denied":
			return nil, fmt.Errorf("registration denied by operator")

		default:
			// "pending" or any other status — keep polling with backoff.
			logger.Info("Registration still pending operator approval; polling",
				"pending_id", logging.SanitizeLogValue(pendingID),
				"status", logging.SanitizeLogValue(resp.Status))
			if currentInterval > 0 && maxInterval > 0 {
				currentInterval = min(currentInterval*2, maxInterval)
			}
		}
	}
}

// connectWithApprovedRegistration persists the steward identity from an approved
// registration (immediate or manual-review poll), then builds and connects the
// transport client. Shared by the immediate-approval and poll-approval paths to
// avoid duplication.
//
// trustSrc and installCAPEM implement ADR-013 §3 trust anchoring (Issue #1517).
// For TOFU mode, the CA from reg.CACert is pinned to disk before the identity
// is saved. For install-pinned, the fingerprint of installCAPEM is recorded.
func connectWithApprovedRegistration(
	ctx context.Context,
	reg approvedRegistration,
	certStoreDir, token string,
	trustSrc TrustSource,
	installCAPEM string,
	runtimeCfg stewardconfig.StewardConfig,
	publicBeta bool,
	logger logging.Logger,
) (*client.TransportClient, error) {
	// An approved registration with no private key cannot form a usable mTLS
	// identity (Issue #3780 follow-up). This is a defense-in-depth check: the
	// normal case is caught earlier by re-registering instead of resuming a
	// pending record with no persisted key, but a caller reaching this function
	// with an empty key must fail loudly rather than fall through to connecting
	// without mTLS.
	if reg.ClientKey == "" {
		return nil, fmt.Errorf("approved registration carries no usable steward private key — the key generated for its CSR did not survive to this point (e.g. a restart during the quarantine poll window); re-run registration with a fresh token")
	}

	// Persist the identity record so that a subsequent restart can reconnect
	// without HTTP re-registration (Issue #1719).
	persistedID := StewardIdentity{
		StewardID:        reg.StewardID,
		TenantID:         reg.TenantID,
		TransportAddress: reg.TransportAddress,
		CACertPEM:        reg.CACert,
		ServerCertPEM:    reg.ServerCert,
		SigningCertPEM:   reg.SigningCert,
		DeviceID:         reg.DeviceID,
		IdentityKeyPub:   reg.IdentityKeyPub,
		TrustMode:        trustModeString(trustSrc),
	}

	// Record the CA pin fingerprint for install-pinned and TOFU modes.
	switch trustSrc {
	case trustSourceTOFU:
		if reg.CACert != "" {
			if err := pinTOFUCA(defaultPlatformCACertPath(), reg.CACert, &persistedID); err != nil {
				return nil, fmt.Errorf("TOFU CA pin failed: %w", err)
			}
		}
	case trustSourceInstallPinned:
		if installCAPEM != "" {
			fp, fpErr := computeCAPEMFingerprint(installCAPEM)
			if fpErr == nil {
				persistedID.CAPinFingerprint = fp
			} else {
				logger.Warn("Failed to compute install CA fingerprint; CAPinFingerprint not recorded", "error", fpErr)
			}
		}
	}

	if saveErr := saveIdentity(certStoreDir, persistedID); saveErr != nil {
		logger.Warn("Failed to persist steward identity; next restart will re-register", "error", saveErr)
	} else {
		logger.Info("Steward identity persisted for restart reuse", "steward_id", persistedID.StewardID)
	}

	// Optionally load the local steward config to apply custom replay window,
	// params-size limits, upgrade policy, and DNA refresh interval.
	// If no config file is found (the common case when the steward is purely
	// controller-managed), defaults apply.
	var commandReplayWindow time.Duration
	var commandMaxParamsBytes int
	var scriptSigning stewardconfig.ScriptSigningConfig
	var upgradeAllowDowngrade bool
	var dnaRefreshInterval time.Duration
	commandReplayWindow = runtimeCfg.Steward.SignedCommandReplayWindow
	commandMaxParamsBytes = runtimeCfg.Steward.SignedCommandMaxParamsBytes
	scriptSigning = runtimeCfg.Steward.ScriptSigning
	upgradeAllowDowngrade = runtimeCfg.Steward.Upgrade.AllowDowngrade
	dnaRefreshInterval = stewardconfig.GetDNARefreshInterval(runtimeCfg)
	observeSweepN := stewardconfig.GetObserveSweepN(runtimeCfg)

	// Build cert.Manager and SecretStore for on-demand TLS cert loading and
	// offline queue encryption (Issue #920).
	certMgr, secretStore := buildCertManagerAndSecretStore(reg.ClientCert, reg.ClientKey, reg.IssuerChain, logger)

	// Build the composite DNA collector early so we can wire the executor into it
	// after InitializeConfigExecutor creates it (Issue #2435).
	dnaAdapter := newDNACollectorAdapter(logger, nil)

	transportClient, err := client.NewTransportClient(&client.TransportConfig{
		ControllerURL:               reg.TransportAddress,
		ControllerHTTPSBaseURL:      resolveControllerHTTPSBaseURL(logger),
		RegistrationToken:           token,
		CACertPEM:                   reg.CACert,
		ClientCertPEM:               reg.ClientCert,
		ServerCertPEM:               reg.ServerCert,
		CertManager:                 certMgr,
		SecretStore:                 secretStore,
		SignedCommandReplayWindow:   commandReplayWindow,
		SignedCommandMaxParamsBytes: commandMaxParamsBytes,
		ScriptSigning:               scriptSigning,
		PublicBeta:                  publicBeta,
		CertStoreDir:                certStoreDir,
		UpgradeAllowDowngrade:       upgradeAllowDowngrade,
		UpgradePublisherTrustStore:  buildTestPublisherTrustStore(logger),
		DNARefreshInterval:          dnaRefreshInterval,
		DNACollector:                dnaAdapter,
		ObserveSweepN:               observeSweepN,
		ObserveModuleLoader:         newObserveModuleLoader(reg.StewardID, secretStore, logger),
		Logger:                      logger,
		IdentityPersistFunc: func(pems []string, at *time.Time) error {
			cur, loadErr := loadIdentity(certStoreDir)
			if loadErr != nil {
				return fmt.Errorf("persist signing cert: load identity: %w", loadErr)
			}
			if cur == nil {
				return fmt.Errorf("persist signing cert: identity not found")
			}
			cur.SigningCertPEMs = pems
			cur.OverlapExpiresAt = at
			return saveIdentity(certStoreDir, *cur)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create transport client: %w", err)
	}

	transportClient.SetStewardID(reg.StewardID)
	transportClient.SetTenantID(reg.TenantID)

	if err := transportClient.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to controller: %w", err)
	}

	logger.Info("Connected to controller via gRPC transport",
		"transport_address", reg.TransportAddress)

	if err := transportClient.SendHeartbeat(ctx, "healthy", nil); err != nil {
		logger.Warn("Failed to send initial heartbeat", "error", err)
	}

	if err := transportClient.InitializeConfigExecutor(reg.TenantID); err != nil {
		return nil, fmt.Errorf("failed to initialize config executor: %w", err)
	}

	logger.Info("Configuration executor initialized", "tenant_id", reg.TenantID)

	// Wire the CLIENT (not the executor instance) as the module DNA source. The
	// client delegates to its CURRENT c.configExecutor, so module DNA keeps flowing
	// even though InitializeConfigExecutor replaces the executor on each
	// connect/reconnect — a captured *Executor reference would go stale (#2520/#2435).
	dnaAdapter.setModuleDNASource(transportClient)

	return transportClient, nil
}

// tryReconnectWithStoredIdentity attempts to reconnect using the steward's
// persisted identity record and the client cert already in the cert store,
// skipping HTTP re-registration entirely.
//
// Returns (nil, nil) when no stored identity exists — caller falls through to
// HTTP registration (first run or manually cleared identity).
// Returns (nil, err) when a stored identity exists but reconnect fails — caller
// should log the error and fall back to HTTP registration.
func tryReconnectWithStoredIdentity(ctx context.Context, certStoreDir, token string, trustSrc TrustSource, runtimeCfg stewardconfig.StewardConfig, publicBeta bool, logger logging.Logger) (*client.TransportClient, error) {
	id, err := loadIdentity(certStoreDir)
	if err != nil {
		// corrupt/unreadable identity: log and treat as absent so the caller falls through
		logger.Warn("Could not load stored identity; falling back to HTTP registration", "error", err)
		return nil, nil
	}
	if id == nil {
		return nil, nil // first run; no stored identity
	}

	// Trust downgrade guard: reject reconnect if the current trust source would
	// weaken the assurance level of the stored enrollment (ADR-013 §3, Issue #1517).
	if id.TrustMode != "" {
		stored := trustSourceFromMode(id.TrustMode)
		if stored > 0 && trustSrc > 0 && trustSrc < stored {
			return nil, fmt.Errorf("trust downgrade rejected: enrolled with %s (level %d); "+
				"current source is %s (level %d) — wipe identity to change trust anchor",
				id.TrustMode, stored, trustModeString(trustSrc), trustSrc)
		}
	}

	// The reconnect path must be able to verify signed sync_config commands.
	// Without a controller server/signing cert the steward would reconnect but
	// silently reject every signed command, so treat an identity record that
	// lacks both as unusable and fall back to HTTP re-registration.
	if id.ServerCertPEM == "" && id.SigningCertPEM == "" && len(id.SigningCertPEMs) == 0 {
		return nil, fmt.Errorf("stored identity missing controller server/signing certificate; cannot verify signed commands")
	}

	// Load the cert manager from the existing cert store.
	certMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    certStoreDir,
		LoadExistingCA: true,
	})
	if err != nil {
		return nil, fmt.Errorf("cert store not loadable: %w", err)
	}

	// Require at least one valid (non-expired) client cert in the store.
	certs, err := certMgr.ListCertificates()
	if err != nil {
		return nil, fmt.Errorf("cert list unavailable: %w", err)
	}
	if !hasValidClientCert(certs) {
		return nil, fmt.Errorf("no valid client certificate found in cert store")
	}

	logger.Info("Stored identity and cert found; reconnecting without HTTP registration",
		"steward_id", logging.SanitizeLogValue(id.StewardID),
		"tenant_id", logging.SanitizeLogValue(id.TenantID),
		"transport_address", logging.SanitizeLogValue(id.TransportAddress))

	// Best-effort secret store for offline queue encryption.
	var secretStore secretsif.SecretStore
	if sp, spErr := secretsif.GetSecretProvider("steward"); spErr == nil {
		if store, storeErr := sp.CreateSecretStore(map[string]interface{}{}); storeErr == nil {
			secretStore = store
		}
	}

	var commandReplayWindow time.Duration
	var commandMaxParamsBytes int
	var upgradeAllowDowngradeReconnect bool
	var dnaRefreshIntervalReconnect time.Duration
	commandReplayWindow = runtimeCfg.Steward.SignedCommandReplayWindow
	commandMaxParamsBytes = runtimeCfg.Steward.SignedCommandMaxParamsBytes
	upgradeAllowDowngradeReconnect = runtimeCfg.Steward.Upgrade.AllowDowngrade
	dnaRefreshIntervalReconnect = stewardconfig.GetDNARefreshInterval(runtimeCfg)
	observeSweepNReconnect := stewardconfig.GetObserveSweepN(runtimeCfg)

	// Build the composite DNA collector early so we can wire the executor into it
	// after InitializeConfigExecutor creates it (Issue #2435).
	dnaAdapterReconnect := newDNACollectorAdapter(logger, nil)

	transportClient, err := client.NewTransportClient(&client.TransportConfig{
		ControllerURL:               id.TransportAddress,
		ControllerHTTPSBaseURL:      resolveControllerHTTPSBaseURL(logger),
		RegistrationToken:           token,
		CACertPEM:                   id.CACertPEM,
		ServerCertPEM:               id.ServerCertPEM,
		SigningCertPEM:              id.SigningCertPEM,  // backward compat seed; seeded into SigningCertPEMs in NewTransportClient when SigningCertPEMs is empty
		SigningCertPEMs:             id.SigningCertPEMs, // Issue #1816: mutable rotation set
		CertManager:                 certMgr,
		SecretStore:                 secretStore,
		SignedCommandReplayWindow:   commandReplayWindow,
		SignedCommandMaxParamsBytes: commandMaxParamsBytes,
		ScriptSigning:               runtimeCfg.Steward.ScriptSigning,
		PublicBeta:                  publicBeta,
		CertStoreDir:                certStoreDir,
		UpgradeAllowDowngrade:       upgradeAllowDowngradeReconnect,
		UpgradePublisherTrustStore:  buildTestPublisherTrustStore(logger),
		DNARefreshInterval:          dnaRefreshIntervalReconnect,
		DNACollector:                dnaAdapterReconnect,
		ObserveSweepN:               observeSweepNReconnect,
		ObserveModuleLoader:         newObserveModuleLoader(id.StewardID, secretStore, logger),
		Logger:                      logger,
		IdentityPersistFunc: func(pems []string, at *time.Time) error {
			cur, loadErr := loadIdentity(certStoreDir)
			if loadErr != nil {
				return fmt.Errorf("persist signing cert: load identity: %w", loadErr)
			}
			if cur == nil {
				return fmt.Errorf("persist signing cert: identity not found")
			}
			cur.SigningCertPEMs = pems
			cur.OverlapExpiresAt = at
			return saveIdentity(certStoreDir, *cur)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create transport client: %w", err)
	}

	transportClient.SetStewardID(id.StewardID)
	transportClient.SetTenantID(id.TenantID)

	if err := transportClient.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to controller with stored identity: %w", err)
	}

	logger.Info("Reconnected to controller via stored identity",
		"steward_id", logging.SanitizeLogValue(id.StewardID),
		"transport_address", logging.SanitizeLogValue(id.TransportAddress))

	// Populate currentDNAHash from a fresh collect so the first heartbeat after
	// reconnect is never empty. The collector is available now; the module DNA
	// source is wired in later (after InitializeConfigExecutor), but partial
	// hardware-fact DNA is still a truthful, non-empty hash. (Issue #2521)
	if err := transportClient.RefreshCurrentDNA(ctx); err != nil {
		logger.Warn("Initial DNA refresh failed; first heartbeat DNA hash will be empty", "error", err)
	}

	if err := transportClient.SendHeartbeat(ctx, "healthy", nil); err != nil {
		logger.Warn("Failed to send initial heartbeat after reconnect", "error", err)
	}

	if err := transportClient.InitializeConfigExecutor(id.TenantID); err != nil {
		return nil, fmt.Errorf("failed to initialize config executor: %w", err)
	}

	logger.Info("Configuration executor initialized after reconnect", "tenant_id", logging.SanitizeLogValue(id.TenantID))

	// Wire the CLIENT (not the executor instance) as the module DNA source — see the
	// registration-path rationale above: InitializeConfigExecutor swaps the executor,
	// so the adapter must delegate through the stable client (#2520/#2435).
	dnaAdapterReconnect.setModuleDNASource(transportClient)

	return transportClient, nil
}

// buildTestPublisherTrustStore reads CFGMS_TEST_STEWARD_PUBLISHER_KEY from the
// environment. When set, it returns a trust.TrustStore seeded with the
// base64-encoded Ed25519 public key so E2E upgrade tests can sign binaries with
// the corresponding known private key. Returns nil when the env var is absent or
// the key is malformed — the caller falls back to CFGMSPublisherIdentity().
// This path is never reachable in production because CFGMS_TEST_STEWARD_PUBLISHER_KEY
// is only set in ephemeral test environments.
func buildTestPublisherTrustStore(logger logging.Logger) trust.TrustStore {
	pubKeyBase64 := os.Getenv("CFGMS_TEST_STEWARD_PUBLISHER_KEY")
	if pubKeyBase64 == "" {
		return nil
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		if logger != nil {
			logger.Warn("CFGMS_TEST_STEWARD_PUBLISHER_KEY is set but malformed; ignoring")
		}
		return nil
	}
	ts := trust.NewInMemoryTrustStore()
	_ = ts.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: pubKeyBytes,
		Algorithm: "ed25519",
	})
	if logger != nil {
		logger.Info("Test mode: overriding steward binary publisher trust store (Issue #1948)")
	}
	return ts
}

// newObserveModuleLoader builds the module loader used by the Tier-2 whole-domain
// observe sweep (Issue #3104, ADR-024 Amendment 1 §3).
//
// It returns a factory.ModuleFactory — the same trust-verified, on-demand module
// load path the convergence executor uses — with an empty discovery registry, so
// a module resolved by the controller is pulled on first use and then served from
// the factory's instance cache on every later sweep. The observe sweep only calls
// Get, so the factory's error policy is the executor's default (a load failure is
// logged and skipped rather than aborting the sweep).
//
// The secret store is injected so observe modules implementing SecretStoreInjectable
// are usable without a separate wiring path.
func newObserveModuleLoader(stewardID string, secretStore secretsif.SecretStore, logger logging.Logger) *factory.ModuleFactory {
	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.NewWithStewardID(discovery.ModuleRegistry{}, errCfg, stewardID, logger)
	if secretStore != nil {
		f.SetSecretStore(secretStore)
	}
	return f
}

// hasValidClientCert reports whether certs contains at least one non-expired client certificate.
func hasValidClientCert(certs []*cert.CertificateInfo) bool {
	for _, c := range certs {
		if c.Type == cert.CertificateTypeClient && c.IsValid {
			return true
		}
	}
	return false
}

// hasExpiredClientCert reports true only when certs contains at least one client certificate
// AND every client certificate in the list is expired (IsValid == false).
// Returns false when certs contains no client certificates at all.
func hasExpiredClientCert(certs []*cert.CertificateInfo) bool {
	found := false
	for _, c := range certs {
		if c.Type == cert.CertificateTypeClient {
			found = true
			if c.IsValid {
				return false
			}
		}
	}
	return found
}

// enrichApprovedWithDeviceIdentity sets DeviceID and IdentityKeyPub on reg from ks when available,
// so the identity file persists the device identity across restarts (Issue #2094).
func enrichApprovedWithDeviceIdentity(reg *approvedRegistration, ks *identity.FileKeyStore) {
	if ks == nil || ks.DeviceID() == "" {
		return
	}
	reg.DeviceID = ks.DeviceID()
	if pub := ks.PublicKey(); pub != nil {
		reg.IdentityKeyPub = base64.StdEncoding.EncodeToString([]byte(pub))
	}
}

// completeRefreshWithFreshKeypair performs the credential half of a registration
// refresh (Issue #3781): it generates a fresh keypair for the renewed credential,
// submits only its public half as a CSR to /refresh/complete, and returns the
// controller's response paired with the PEM encoding of the private key it just
// generated.
//
// The private key never crosses the wire and is never read off the response —
// RefreshCompleteResponse carries no key field. The controller signs the CSR's
// public key into resp.ClientCert, so the returned keyPEM is the only value that
// completes the renewed mTLS identity: the caller must store that pair together.
//
// Errors from RefreshComplete (ErrRefreshPending on HTTP 202, ErrRefreshRejected
// on HTTP 403) are returned unwrapped so callers can match them with errors.Is.
func completeRefreshWithFreshKeypair(
	ctx context.Context,
	httpClient *registration.HTTPClient,
	deviceID, tenantID, nonce string,
	serverTS int64,
	pop []byte,
) (*registration.RefreshCompleteResponse, string, error) {
	renewedKey, err := registration.GenerateStewardKeypair()
	if err != nil {
		return nil, "", fmt.Errorf("generate renewed steward keypair: %w", err)
	}
	csrPEM, err := registration.BuildRegistrationCSR(renewedKey, deviceID)
	if err != nil {
		return nil, "", fmt.Errorf("build refresh certificate signing request: %w", err)
	}

	completeResp, err := httpClient.RefreshComplete(ctx, deviceID, tenantID, nonce, serverTS, pop, csrPEM)
	if err != nil {
		return nil, "", err // ErrRefreshPending or ErrRefreshRejected propagated to caller
	}

	renewedKeyPEM, err := registration.EncodeECDSAPrivateKeyPEM(renewedKey)
	if err != nil {
		return nil, "", fmt.Errorf("encode renewed steward private key: %w", err)
	}
	return completeResp, renewedKeyPEM, nil
}

// refreshAndConnect performs the registration-refresh handshake (ADR-011, Issue #2094)
// for a steward whose mTLS cert has expired. The handshake proves device identity via
// an Ed25519 proof-of-possession signature over a server-issued nonce.
//
// Returns ErrRefreshPending when the controller queues the request for manual approval.
// Returns ErrRefreshRejected when the controller refuses (revoked or dormant device).
// On success, persists the new cert via saveIdentity and reconnects.
func refreshAndConnect(
	ctx context.Context,
	id *StewardIdentity,
	ks *identity.FileKeyStore,
	certStoreDir, token, controllerURL string,
	runtimeCfg stewardconfig.StewardConfig,
	publicBeta bool,
	logger logging.Logger,
) (*client.TransportClient, error) {
	if controllerURL == "" {
		return nil, fmt.Errorf("controller URL not set; cannot perform registration refresh")
	}

	httpClient, err := registration.NewHTTPClient(buildHTTPConfig(controllerURL, 30*time.Second, logger))
	if err != nil {
		return nil, fmt.Errorf("create HTTP client for refresh: %w", err)
	}

	logger.Info("Attempting registration-refresh handshake",
		"device_id", logging.SanitizeLogValue(ks.DeviceID()),
		"steward_id", logging.SanitizeLogValue(id.StewardID))

	challengeCtx, challengeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer challengeCancel()

	challenge, err := httpClient.RefreshChallenge(challengeCtx, ks.DeviceID())
	if err != nil {
		return nil, fmt.Errorf("refresh challenge: %w", err)
	}

	// Decode the nonce from base64url.
	nonceBytes, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode refresh nonce: %w", err)
	}

	// Compute the PoP digest: sha256(nonce_bytes || device_id_utf8 || server_ts_big_endian_uint64)
	// per ADR-011 §4. This formula must match the controller's implementation exactly.
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], challenge.ServerTS)

	digestInput := make([]byte, 0, len(nonceBytes)+len(ks.DeviceID())+8)
	digestInput = append(digestInput, nonceBytes...)
	digestInput = append(digestInput, []byte(ks.DeviceID())...)
	digestInput = append(digestInput, tsBuf[:]...)
	digest := sha256.Sum256(digestInput)

	pop, err := ks.Sign(digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign refresh digest: %w", err)
	}

	completeCtx, completeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer completeCancel()

	if challenge.ServerTS > math.MaxInt64 {
		return nil, fmt.Errorf("refresh challenge server timestamp exceeds int64 range")
	}
	// #nosec G115 -- the controller-provided uint64 timestamp is explicitly
	// rejected above unless it fits the signed protocol field.
	serverTS := int64(challenge.ServerTS)

	completeResp, renewedKeyPEM, err := completeRefreshWithFreshKeypair(
		completeCtx, httpClient, ks.DeviceID(), id.TenantID, challenge.Nonce, serverTS, pop)
	if err != nil {
		return nil, err // ErrRefreshPending or ErrRefreshRejected propagated to caller
	}

	logger.Info("Registration refresh approved; storing new certificate",
		"steward_id", logging.SanitizeLogValue(id.StewardID))

	// Persist the refreshed identity with updated certs.
	// The controller's refresh response does not include TransportAddress or ServerCert
	// (the connection endpoint and signing cert do not change during cert refresh).
	// Preserve the stored values as authoritative fallbacks so the reconnect succeeds
	// even when the controller omits those optional fields.
	updatedID := *id
	updatedID.CACertPEM = completeResp.CACert
	if completeResp.ServerCert != "" {
		updatedID.ServerCertPEM = completeResp.ServerCert
	}
	if completeResp.TransportAddress != "" {
		updatedID.TransportAddress = completeResp.TransportAddress
	}
	if saveErr := saveIdentity(certStoreDir, updatedID); saveErr != nil {
		logger.Warn("Failed to persist refreshed identity; next restart may re-register", "error", saveErr)
	}

	bundle := approvedRegistration{
		StewardID:        id.StewardID,
		TenantID:         id.TenantID,
		TransportAddress: updatedID.TransportAddress,
		ClientCert:       completeResp.ClientCert,
		ClientKey:        renewedKeyPEM,
		CACert:           completeResp.CACert,
		ServerCert:       updatedID.ServerCertPEM,
		IssuerChain:      completeResp.IssuerChain,
	}
	enrichApprovedWithDeviceIdentity(&bundle, ks)
	// Preserve the stored trust mode on refresh — the trust anchor is already established.
	refreshTrustSrc := trustSourceFromMode(id.TrustMode)
	if refreshTrustSrc == 0 {
		refreshTrustSrc = trustSourceCompileBaked
	}
	return connectWithApprovedRegistration(ctx, bundle, certStoreDir, token, refreshTrustSrc, "", runtimeCfg, publicBeta, logger)
}

// buildCertManagerAndSecretStore initialises a cert.Manager (holding the
// steward's client certificate for on-demand TLS loading) and a SecretStore
// (for offline queue encryption key persistence). Both are best-effort — a nil
// return from either does not prevent the steward from connecting, it just
// disables the respective feature.
//
// issuerChainPEM is the PEM-concatenated chain from the client certificate's
// direct issuer up to (but not including) the CA certificate (Issue #3778).
// When non-empty it is appended after the leaf before import, so the stored
// certificate presents the full chain during the ongoing gRPC-over-QUIC
// transport's TLS handshake — tls.X509KeyPair (used by cert.Manager's
// GetClientCertificate) builds Certificate.Certificate from every DER block in
// the PEM, not just the first.
func buildCertManagerAndSecretStore(clientCertPEM, clientKeyPEM, issuerChainPEM string, logger logging.Logger) (*cert.Manager, secretsif.SecretStore) {
	// ── SecretStore ──────────────────────────────────────────────────────────
	var secretStore secretsif.SecretStore
	secretsProvider, err := secretsif.GetSecretProvider("steward")
	if err == nil {
		if store, storeErr := secretsProvider.CreateSecretStore(map[string]interface{}{}); storeErr == nil {
			secretStore = store
		} else {
			logger.Warn("Failed to create steward secret store; offline-queue key will not persist", "error", storeErr)
		}
	} else {
		logger.Warn("Steward secrets provider unavailable; offline-queue key will not persist", "error", err)
	}

	// ── cert.Manager ─────────────────────────────────────────────────────────
	if clientCertPEM == "" || clientKeyPEM == "" {
		return nil, secretStore
	}

	certMgr := buildClientCertManagerAtPath(defaultCertStoreDir(), clientCertPEM, clientKeyPEM, issuerChainPEM, logger)
	return certMgr, secretStore
}

// buildClientCertManagerAtPath initialises (or loads) a cert.Manager rooted at
// certStorePath and imports the steward's client certificate into it, returning
// nil on any failure (best-effort — see buildCertManagerAndSecretStore). Split
// out from buildCertManagerAndSecretStore so certStorePath can be a test-owned
// t.TempDir() rather than the hardcoded, platform-stable defaultCertStoreDir().
//
// issuerChainPEM is the PEM-concatenated chain from the client certificate's
// direct issuer up to (but not including) the CA certificate (Issue #3778).
// When non-empty it is appended after the leaf before import, so the stored
// certificate presents the full chain during the ongoing gRPC-over-QUIC
// transport's TLS handshake — tls.X509KeyPair (used by cert.Manager's
// GetClientCertificate) builds Certificate.Certificate from every DER block in
// the PEM, not just the first.
func buildClientCertManagerAtPath(certStorePath, clientCertPEM, clientKeyPEM, issuerChainPEM string, logger logging.Logger) *cert.Manager {
	// Try to load an existing local CA (created on a previous run).
	certMgr, mgrErr := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    certStorePath,
		LoadExistingCA: true,
	})
	if mgrErr != nil {
		// First run — create a local CA used only as a cert store.
		certMgr, mgrErr = cert.NewManager(&cert.ManagerConfig{
			StoragePath:    certStorePath,
			LoadExistingCA: false,
			CAConfig: &cert.CAConfig{
				Organization: "CFGMS Steward",
				Country:      "US",
				ValidityDays: 3650,
			},
		})
		if mgrErr != nil {
			logger.Warn("Failed to create cert.Manager; on-demand TLS cert loading disabled", "error", mgrErr)
			return nil
		}
	}

	// Import the client cert+key from the registration response. The issuer
	// chain, when present, is concatenated after the leaf so the stored
	// certificate carries the full chain (Issue #3778/#3780).
	fullChainPEM := clientCertPEM
	if issuerChainPEM != "" {
		fullChainPEM = clientCertPEM + issuerChainPEM
	}
	if _, impErr := certMgr.ImportCertificate(
		[]byte(fullChainPEM), []byte(clientKeyPEM), cert.CertificateTypeClient,
	); impErr != nil {
		logger.Warn("Failed to import client certificate into cert.Manager", "error", impErr)
		return nil
	}

	return certMgr
}

// defaultCertStoreDir returns the platform-specific stable directory for the
// steward's on-demand client certificate store. Uses the same path convention
// as the StewardProvider's defaultSecretsDir so operators find both under the
// same platform root (e.g. /var/lib/cfgms/ on Linux).
func defaultCertStoreDir() string {
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "cfgms", "steward", "certs")
	case "darwin":
		home, _ := os.UserHomeDir()
		if home == "" {
			home = "/tmp"
		}
		return filepath.Join(home, "Library", "Application Support", "cfgms", "steward", "certs")
	default:
		return "/var/lib/cfgms/steward/certs"
	}
}

// upgradeEventPublisher is the minimal interface required by checkUpgradeFlagFiles
// to emit upgrade lifecycle events. Satisfied by *client.TransportClient.
type upgradeEventPublisher interface {
	GetStewardID() string
	GetTenantID() string
}

// checkUpgradeFlagFiles reads launcher-written flag files in certStoreDir and
// emits the corresponding upgrade lifecycle events, then deletes each file.
//
// Flag files written by the launcher after a supervised restart:
//   - certStoreDir/upgrade-committed: new version passed its startup window.
//   - certStoreDir/upgrade-rolled-back: launcher auto-rolled-back to previous version.
//
// Each file's content is the version string (e.g. "v1.2.3\n") so the event
// carries the version. Missing or unreadable files are silently ignored.
// (Issue #1943)
func checkUpgradeFlagFiles(ctx context.Context, certStoreDir string, tc upgradeEventPublisher, logger logging.Logger) {
	files := []struct {
		name      string
		eventType string
	}{
		{"upgrade-committed", string(cpTypes.EventStewardUpgradeCommitted)},
		{"upgrade-rolled-back", string(cpTypes.EventStewardUpgradeRolledBack)},
	}

	for _, f := range files {
		flagPath := filepath.Join(certStoreDir, f.name)
		raw, err := os.ReadFile(flagPath) //#nosec G304 -- certStoreDir is from defaultCertStoreDir()
		if err != nil {
			if !os.IsNotExist(err) {
				logger.Warn("Could not read upgrade flag file",
					"path", flagPath, "error", err.Error())
			}
			continue
		}
		version := strings.TrimSpace(string(raw))
		logger.Info("Upgrade flag file detected",
			"flag", f.name, "version", version)

		// Emit the event before deleting the flag so a crash between the two
		// results in re-emitting on the next start (idempotent from the
		// controller's perspective) rather than silently losing the event.
		if pubErr := publishUpgradeLifecycleEvent(ctx, tc, f.eventType, version, logger); pubErr != nil {
			logger.Warn("Failed to publish upgrade lifecycle event",
				"event_type", f.eventType, "error", pubErr.Error())
		}

		if delErr := os.Remove(flagPath); delErr != nil && !os.IsNotExist(delErr) {
			logger.Warn("Failed to delete upgrade flag file",
				"path", flagPath, "error", delErr.Error())
		}
	}
}

// publishUpgradeLifecycleEvent emits a single upgrade lifecycle event via the
// transport client's control plane. Returns an error if the publish fails.
func publishUpgradeLifecycleEvent(ctx context.Context, tc upgradeEventPublisher, eventType, version string, logger logging.Logger) error {
	// TransportClient embeds publishEventWithQueue but that method is unexported.
	// Cast to the concrete type — main.go is in the same binary and this cast
	// is safe because main always creates a *client.TransportClient.
	type eventPublisher interface {
		upgradeEventPublisher
		PublishUpgradeLifecycleEvent(ctx context.Context, eventType, version string) error
	}
	if ep, ok := tc.(eventPublisher); ok {
		return ep.PublishUpgradeLifecycleEvent(ctx, eventType, version)
	}
	// Fallback: log the event locally when the interface is not satisfied.
	logger.Info("Upgrade lifecycle event (no control plane publish)",
		"event_type", eventType, "version", version)
	return nil
}

// moduleDNASource is the narrow surface the composite DNA collector needs to
// fold monitored-module state into the DNA attribute set (#2423) and to emit
// ADR-017 fragments for cluster:* resources (#2908). Satisfied by
// (*steward.Steward); nil when the running mode has no monitor-running steward
// engine (see newDNACollectorAdapter call sites).
type moduleDNASource interface {
	CollectModuleDNAAttributes(ctx context.Context) map[string]string
	CollectModuleFragments(ctx context.Context) []*commonpb.Fragment
}

// dnaCollectorAdapter adapts dna.Collector to the client.DNACollector interface
// by extracting the Attributes map from the proto DNA result (Issue #1915),
// merged with a flattened, namespaced snapshot of monitored module resource
// state when a moduleDNASource is wired (#2423 / #2435). Both attribute sets
// ride the same PublishDNAUpdate delta-compression path — a change in only a
// module attribute still triggers a publish.
type dnaCollectorAdapter struct {
	collector *dna.Collector
	logger    logging.Logger
	mu        sync.RWMutex
	modules   moduleDNASource
}

// newDNACollectorAdapter builds the composite DNA collector. modules may be nil;
// call setModuleDNASource after InitializeConfigExecutor to wire the real producer
// (Issue #2435).
func newDNACollectorAdapter(logger logging.Logger, modules moduleDNASource) *dnaCollectorAdapter {
	return &dnaCollectorAdapter{collector: dna.NewCollector(logger), logger: logger, modules: modules}
}

// setModuleDNASource wires the module DNA producer after construction. Thread-safe:
// the DNA refresh loop may be reading modules concurrently. Called once, right after
// InitializeConfigExecutor succeeds, at both registration and reconnect call sites
// (Issue #2435).
func (a *dnaCollectorAdapter) setModuleDNASource(src moduleDNASource) {
	a.mu.Lock()
	a.modules = src
	a.mu.Unlock()
}

// CollectAttributes returns the merged DNA attribute map — host-fact attributes
// from the Collector's internal raw map (not from the legacy flat attributes
// proto field, which Collect() no longer writes after Issue #3332) plus any
// module-owned attributes (cluster:*, vm:*, etc.) from the wired module DNA
// source. Returns host-only attributes when no module source is wired.
func (a *dnaCollectorAdapter) CollectAttributes(ctx context.Context) (map[string]string, error) {
	// Host-fact attributes from the Collector's internal flat map, not the DNA
	// result's now-unused legacy field.
	hostAttrs := a.collector.RawAttributes(ctx)

	a.mu.RLock()
	moduleSrc := a.modules
	a.mu.RUnlock()
	if moduleSrc == nil {
		return hostAttrs, nil
	}

	moduleAttrs := moduleSrc.CollectModuleDNAAttributes(ctx)
	if len(moduleAttrs) == 0 {
		return hostAttrs, nil
	}

	merged := make(map[string]string, len(hostAttrs)+len(moduleAttrs))
	for k, v := range hostAttrs {
		merged[k] = v
	}
	for k, v := range moduleAttrs {
		merged[k] = v
	}
	return merged, nil
}

// CollectFragments returns the union of ADR-017 host:* fragments (from the
// dna.Collector) and cluster:* fragments (from the wired module DNA source).
// Returns host:* fragments alone when moduleSrc is nil (hardware-facts-only mode).
func (a *dnaCollectorAdapter) CollectFragments(ctx context.Context) []*commonpb.Fragment {
	result, err := a.collector.Collect(ctx)
	if err != nil {
		a.logger.Warn("host-fact collection failed; host:* fragments omitted from this sync cycle",
			"error", logging.SanitizeLogValue(err.Error()))
	}

	a.mu.RLock()
	moduleSrc := a.modules
	a.mu.RUnlock()

	var frags []*commonpb.Fragment
	if result != nil {
		frags = append(frags, result.Fragments...)
	}
	if moduleSrc != nil {
		frags = append(frags, moduleSrc.CollectModuleFragments(ctx)...)
	}
	return frags
}

// CollectFragmentsTracked satisfies client.FragmentCollector so the transport
// client can update currentDNAFragments and currentDNAAggregateRoot for the
// ADR-017 §7 partial-sync protocol (Issue #3332). It is a thin wrapper that
// delegates to CollectFragments and always returns nil error.
func (a *dnaCollectorAdapter) CollectFragmentsTracked(ctx context.Context) ([]*commonpb.Fragment, error) {
	return a.CollectFragments(ctx), nil
}
