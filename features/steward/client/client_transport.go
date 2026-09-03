// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client provides transport client functionality for steward-controller communication.
//
// This package implements the steward-side client for communicating with
// the CFGMS controller using the gRPC-over-QUIC ControlPlaneProvider (control plane)
// and gRPC DataPlaneProvider (data plane). Both share the same transport_address
// received from the HTTP registration response.
// Story #516: Introduced TransportClient using gRPC providers.
package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/commands"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	dna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/driftdiff"
	"github.com/cfgis/cfgms/features/steward/execution"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	_ "github.com/cfgis/cfgms/pkg/dataplane/providers/grpc" // Register gRPC data plane provider
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/version"
)

// ErrCommandTermFenced is returned by the command receive path when an inbound
// command fails the Raft-term fence (Story #3436, ADR-029 Decision 6): its term
// is below the highest this steward has observed, or it omits the term after the
// ratchet has been set by a prior stamped command. It is a plain refusal, handled
// identically to the pre-existing ErrWrongSteward / ErrCommandReplay rejections —
// clientReceiveLoop (pkg/controlplane/providers/grpc/provider.go) only logs a
// non-nil handler error, so a fenced command never triggers a reconnect or a
// convergence-loop retry.
var ErrCommandTermFenced = errors.New("command rejected: raft term fenced")

// DNACollector is the interface used by the DNA refresh loop to re-collect
// system attributes on each tick. Production code wraps dna.Collector; tests
// inject a stub returning deterministic attribute maps without real I/O.
type DNACollector interface {
	CollectAttributes(ctx context.Context) (map[string]string, error)

	// CollectFragments returns ADR-017 fragments for cluster:* resources from the
	// module monitor cache. Returns nil when no module source is wired.
	CollectFragments(ctx context.Context) []*commonpb.Fragment
}

// ObserveModuleLoader loads steward modules by name for the Tier-2 whole-domain
// observe sweep (Issue #3104, ADR-024 Amendment 1 §3). Production code wraps
// factory.ModuleFactory; tests inject a deterministic in-memory implementation.
type ObserveModuleLoader interface {
	LoadModule(name string) (modules.Module, error)
}

// FragmentCollector is an optional extension of DNACollector. When the wired
// collector also implements this interface, the client maintains
// currentDNAFragments and currentDNAAggregateRoot for the partial-sync protocol
// (ADR-017 §7). The S5 story wires the real multi-fragment collector here.
//
// Named CollectFragmentsTracked (not CollectFragments) so a single type can
// implement both DNACollector.CollectFragments (no error, best-effort) and this
// tracked variant (error-returning, used for the partial-sync root) without a
// method-signature collision.
type FragmentCollector interface {
	CollectFragmentsTracked(ctx context.Context) ([]*commonpb.Fragment, error)
}

// maxRequestedFragmentIDs bounds the fragment_ids list accepted from a SYNC_DNA
// command. The controller only ever asks for IDs already in its stored manifest,
// so a list this long indicates a malformed or hostile command.
const maxRequestedFragmentIDs = 10000

// parseFragmentIDs normalises the fragment_ids param of a SYNC_DNA command into a
// []string.
//
// Command params cross the wire as map[string]string and are re-parsed on arrival:
// pkg/controlplane/providers/grpc.stringMapToInterfaceMap JSON-decodes any value
// that is valid JSON, so the JSON array the controller marshals arrives as
// []interface{}, NOT as the string it was sent as. Both shapes (plus a native
// []string from in-process transports) must therefore be accepted — asserting a
// single shape silently disables partial sync on the real control plane.
//
// Non-string elements and empty IDs are rejected rather than coerced, so a
// malformed command surfaces as an error instead of a silent no-op.
func parseFragmentIDs(raw interface{}) ([]string, error) {
	var ids []string

	switch v := raw.(type) {
	case nil:
		return nil, nil
	case string:
		if v == "" {
			return nil, nil
		}
		if err := json.Unmarshal([]byte(v), &ids); err != nil {
			return nil, fmt.Errorf("fragment_ids is not a JSON string array: %w", err)
		}
	case []string:
		ids = v
	case []interface{}:
		ids = make([]string, 0, len(v))
		for i, elem := range v {
			s, isString := elem.(string)
			if !isString {
				return nil, fmt.Errorf("fragment_ids[%d] is %T, want string", i, elem)
			}
			ids = append(ids, s)
		}
	default:
		return nil, fmt.Errorf("fragment_ids has unsupported type %T", raw)
	}

	if len(ids) > maxRequestedFragmentIDs {
		return nil, fmt.Errorf("fragment_ids contains %d entries, limit is %d",
			len(ids), maxRequestedFragmentIDs)
	}
	for i, id := range ids {
		if id == "" {
			return nil, fmt.Errorf("fragment_ids[%d] is empty", i)
		}
	}
	return ids, nil
}

// TransportClient represents the steward client using gRPC-over-QUIC for both
// control plane and data plane communication with the controller.
// Story #516: Connects once to transport_address for both CP and DP.
type TransportClient struct {
	mu sync.RWMutex

	// Steward identification
	stewardID string
	tenantID  string

	// Transport address (gRPC-over-QUIC, from registration response)
	transportAddress string

	// controllerHTTPSBaseURL is the controller HTTPS REST base for the desired_version
	// self-fetch path (Issue #2833). Empty disables self-fetch (degrade safe).
	controllerHTTPSBaseURL string

	// Control plane provider (gRPC, Story #516)
	controlPlane controlplaneInterfaces.ControlPlaneProvider

	// Data plane session (gRPC, Story #516)
	dataPlaneSession dataplaneInterfaces.DataPlaneSession

	// Certificate path for mTLS (disk-based fallback when PEM certs unavailable)
	certPath string

	// Certificate PEMs (from registration response)
	caCertPEM        string
	serverCertPEM    string     // Controller's server cert for config signature verification (Story #315)
	signingCertPEMs  []string   // Issue #1816: mutable set of signing certs (rotation support)
	overlapExpiresAt *time.Time // Issue #1816: rotation overlap deadline for client-side expiry

	// identityPersistFunc is called by the push-signing-cert handler to atomically
	// persist updated signing cert PEMs before in-memory state is updated (Issue #1816).
	// If nil, persistence is skipped and the cert is learned in memory only.
	identityPersistFunc func(signingCertPEMs []string, overlapExpiresAt *time.Time) error

	// certManager provides on-demand client certificate loading per TLS handshake (Issue #920).
	// When non-nil, GetClientCertificate is used instead of static PEM certs.
	certManager *cert.Manager

	// Command handler
	commandHandler *commands.Handler

	// Configuration executor (unified engine — same as standalone mode)
	configExecutor *execution.Executor

	// moduleDNAStore is the process-stable module-DNA snapshot shared across every
	// executor this client builds. InitializeConfigExecutor replaces configExecutor
	// on each connect/reconnect; a per-executor snapshot would be lost, so the store
	// lives on the (stable) client and is injected into each executor (#2520).
	moduleDNAStore *execution.ModuleDNASnapshot

	// eventEmitter sends convergence observation events to the controller via LogStream.
	// Initialised once by InitializeConfigExecutor; nil until then.
	eventEmitter *EventEmitter

	// Command authentication settings (Story #919)
	commandReplayWindow   time.Duration
	commandMaxParamsBytes int

	// Raft-term fence (Story #3436, ADR-029 Decision 6). Held on TransportClient,
	// not commands.Handler: setupCommandHandler builds a fresh Handler on every
	// reconnect, so scoping the ratchet there would let a forced reconnect silently
	// reset it. Guarded by mu.
	// fenceRatchet persists the two fields across restarts (#3437).
	termRatchetSet  bool
	highestTermSeen uint64
	fenceRatchet    *stewardconfig.FenceRatchet

	// Script signature verification policy (Issue #1671). Wired into the command
	// handler by setupCommandHandler so CommandExecuteScript signature enforcement
	// is active in controller-connected deployments, not just standalone mode.
	scriptSigning stewardconfig.ScriptSigningConfig
	publicBeta    bool

	// Last configuration received from the controller (for scheduled re-convergence)
	lastConfigYAML    []byte
	lastConfigMu      sync.RWMutex
	lastConfigVersion string

	// Convergence loop control
	convergenceStop  chan struct{}
	convergeInterval time.Duration // cfg-driven; updated on each sync_config
	// convergeIntervalCh wakes the convergence loop when convergeInterval
	// changes so it resets its ticker immediately. Without it the running
	// ticker keeps its stale period (the 30-minute startup default) until the
	// next tick fires — a cfg lowering converge_interval would not take effect
	// for up to 30 minutes. Buffered (1) so senders never block.
	convergeIntervalCh chan struct{}

	// Connection state — single flag for unified gRPC transport
	connected bool

	// disconnected guards the one-time close of heartbeatStop/convergenceStop/
	// dnaRefreshStop in Disconnect. A pushed-upgrade graceful self-exit (Issue #2001)
	// adds a second shutdown trigger path (runCancel → runCtx.Done → Disconnect), so
	// Disconnect can now legitimately be invoked more than once; closing an already-closed
	// channel panics, so the close is gated on this flag under c.mu.
	disconnected bool

	// Heartbeat
	heartbeatInterval time.Duration
	heartbeatStop     chan struct{}
	// rng is the per-instance RNG for per-tick heartbeat jitter (epic #1664).
	// Only accessed from the startHeartbeat goroutine; no mutex required.
	rng *rand.Rand

	// offlineQueue persists reports locally when the controller is unreachable.
	// Issue #419: drained in order after a successful reconnect.
	offlineQueue *OfflineQueue

	// secretStore is the steward's secret store, retained here so that
	// InitializeConfigExecutor can pass it to the unified Executor's default
	// factory. Modules implementing SecretStoreInjectable (e.g. hyperv) need
	// the store wired into the factory before Configure runs. Without this,
	// every controller-pushed config that touches a hyperv resource fails
	// with `hyperv: secret store must be injected before Configure`.
	secretStore secretsif.SecretStore

	// DNA state for hash-based sync (Issue #418).
	// dnaMu guards currentDNAHash, currentDNAAttrs, lastPublishedDNA,
	// currentDNAFragments, currentDNAAggregateRoot, and lastPublishedFragments.
	dnaMu                   sync.RWMutex
	currentDNAHash          string               // SHA-256 hash of most-recently collected DNA (Issue #2521)
	currentDNAAttrs         map[string]string    // full enriched snapshot of most-recently collected DNA (Issue #2521)
	lastPublishedDNA        map[string]string    // full DNA from the last PublishDNAUpdate call (used as config-apply fallback)
	currentDNAFragments     []*commonpb.Fragment // fragments from last fragment-collection (Issue #2906)
	currentDNAAggregateRoot string               // AggregateRoot of currentDNAFragments (Issue #2906)
	lastPublishedFragments  []*commonpb.Fragment // fragments from the last successful PublishDNAUpdate (Issue #3330)

	// driftDiffs buffers drift-diff records accumulated since the last DNA sync
	// (Issue #3373). The drift handler registered in InitializeConfigExecutor appends;
	// the DNA send path drains on each SYNC_DNA cycle. The buffer is bounded and
	// drop-oldest because only the controller triggers a drain: a partitioned steward
	// must not grow this without limit while waiting for SYNC_DNA. See
	// driftdiff.Accumulator. Held by value so a directly-constructed TransportClient
	// still gets a bounded, working buffer rather than a nil one that discards.
	driftDiffs driftdiff.Accumulator

	// DNA refresh loop control (Issue #1915).
	dnaRefreshInterval time.Duration
	dnaRefreshStop     chan struct{}
	// dnaCollector is the DNA collection implementation used by the refresh loop.
	// Injectable for testing; production code uses dna.NewCollector.
	dnaCollector DNACollector
	// dnaRefreshTick, when non-nil, receives one value after each fully-processed
	// refresh-loop tick (collection + optional publish). It is a deterministic
	// synchronization seam for tests: it is nil in production (the notify helper
	// early-returns), so it adds no overhead and never blocks the loop. Tests use
	// it to observe real ticks without wall-clock sleeps.
	dnaRefreshTick chan struct{}

	// Tier-2 whole-domain observe sweep (Issue #3104, ADR-024 Amendment 1 §3).
	// observeSweepN is the cadence: run sweep every Nth convergence cycle.
	// 0 = disabled. Protected by mu.
	observeSweepN int
	// observeSweepCounter counts convergence ticks toward the next sweep.
	// Resets to 0 after each sweep. Protected by mu.
	observeSweepCounter int
	// observeModuleLoader loads modules by name for the Tier-2 sweep.
	// Nil = disabled. Injectable for testing. Protected by mu.
	observeModuleLoader ObserveModuleLoader
	// observeSweepTick, when non-nil, receives one value after each call to
	// checkAndTriggerObserveSweep (whether or not a sweep fired). Nil in
	// production; non-nil in tests for deterministic cadence synchronisation.
	// Uses the same pattern as dnaRefreshTick.
	observeSweepTick chan struct{}
	// observeSweepInFlight is the single-flight guard for handleObserveModules.
	// Command handlers run one goroutine per command, and the cadence in
	// checkAndTriggerObserveSweep keeps firing while a sweep is still running
	// (a module Get slower than N convergence ticks yields two in-flight
	// observe_modules commands with distinct IDs, which replay de-duplication
	// does not catch). Overlapping sweeps would drive concurrent module loads
	// and concurrent fragment merges, so a second sweep is dropped while one is
	// in flight rather than queued — the dropped sweep's work is fully covered
	// by the next cadence tick.
	observeSweepInFlight atomic.Bool

	// certStoreDir is the on-disk cert/identity directory. The upgrade handler
	// downloads binaries to a subdirectory here. (Issue #1943)
	certStoreDir string

	// revokedVersions is the controller-supplied list of revoked steward versions.
	// Protected by revokedVersionsMu. Updated via SetRevokedVersions. (Issue #1943)
	revokedVersionsMu sync.RWMutex
	revokedVersions   []string

	// upgradeAllowDowngrade permits installing a version ≤ the running version.
	// From steward.cfg upgrade.allow_downgrade. Protected by mu. (Issue #1943)
	upgradeAllowDowngrade bool

	// lastStagedVersion and lastStagedBinaryPath record the version and on-disk
	// path of the binary most recently staged by handlePushStewardBinary.
	// TriggerConvergence uses them to re-issue the launcher swap when the
	// desired_version config key is set and the running binary hasn't changed yet.
	// Protected by mu. (Issue #2260)
	lastStagedVersion    string
	lastStagedBinaryPath string

	// launcherSwapFunc is the function invoked to call the launcher swap subcommand.
	// When nil the default exec.CommandContext implementation is used. Injectable
	// for testing so tests do not require the launcher binary on disk. (Issue #1943)
	launcherSwapFunc func(ctx context.Context, launcherPath, version, binaryPath string) error

	// upgradePublisherTrustStore, when non-nil, overrides CFGMSPublisherIdentity()
	// in the signature verification step. Injectable for testing. (Issue #1943)
	upgradePublisherTrustStore trust.TrustStore

	// upgradeHTTPClient, when non-nil, overrides the default mTLS HTTP client
	// used by the upgrade download step. Injectable for testing. (Issue #1943)
	upgradeHTTPClient *http.Client

	// launcherPathOverride, when non-empty, overrides the compile-time constant
	// launcher path returned by launcherPath(). Injectable for testing. (Issue #1943)
	launcherPathOverride string

	// shutdownFunc triggers a graceful shutdown of the steward process. After a
	// successful push_steward_binary swap the upgrade handler schedules this so
	// the launcher's supervise loop re-execs the now-current staged binary. In
	// production it is wired (via SetShutdownFunc) to cancel the steward's root
	// context, which drives the clean Disconnect+return path in runSteward — NOT
	// a hard os.Exit. Injectable for testing so unit tests never exit the test
	// binary. When nil the upgrade handler logs and skips the trigger. (Issue #2001)
	shutdownFunc func()

	// shutdownCtx is the steward's RUN context (process lifecycle). It is cancelled
	// only on a real shutdown path — SCM stop, OS signal, or runCancel — and is the
	// context the upgrade grace-delay timer watches for early-exit. It must NOT be a
	// per-command context: those are cancelled the instant a command handler returns
	// (executeCommand's `defer cancel()`), which would always win the race against
	// the grace delay and suppress the auto-apply self-exit. Wired via SetShutdownFunc.
	// When nil the upgrade handler falls back to a plain timer with no early-exit.
	// Protected by mu. (Issue #2003)
	shutdownCtx context.Context

	// pendingUpgradeSelfExit records that a launcher-managed push_steward_binary
	// swap was staged while shutdownFunc was still nil — the swap arrived in the
	// window between command subscription (Connect → SubscribeCommands) and the
	// SetShutdownFunc wiring in main.go. Without recovery the staged (possibly
	// broken) binary would silently defer to an unbounded "next restart" with the
	// launcher's startup-window auto-rollback never firing. When set, SetShutdownFunc
	// fires the deferred graceful self-exit as soon as the trigger is wired.
	// Protected by mu. (Issue #2602)
	pendingUpgradeSelfExit bool

	// launcherManaged reports whether this steward is supervised by a launcher
	// that will re-exec the staged binary after a graceful exit. It is defaulted
	// in NewTransportClient from os.Getenv(version.EnvStewardLauncherManaged)=="1"
	// (the launcher sets that env on its child). After a successful upgrade swap,
	// the handler self-exits ONLY when this is true; a bare/standalone steward
	// (dev, fleet-e2e, systemd-without-launcher) stages the binary and keeps
	// running, applying it on the next restart. Without this gate a bare steward
	// would self-exit with nothing to re-exec it — downtime, or a crash loop as
	// the controller redelivers the upgrade on each reconnect. Test-injectable
	// (set directly), consistent with launcherSwapFunc/shutdownFunc. Protected by
	// mu. (Issue #2003)
	launcherManaged bool

	// upgradeShutdownGraceDelay is how long the upgrade handler waits, after the
	// push_steward_binary handler returns, before invoking shutdownFunc. The delay
	// gives commands.Handler.executeCommand time to publish the EventCommand
	// completion ack before the process exits — otherwise the controller could
	// record the upgrade command as timed-out. A value of 0 (the zero value) means
	// "use defaultUpgradeShutdownGraceDelay (3s)"; tests that want a small real
	// timer set an explicit small positive value. Protected by mu. (Issue #2001)
	upgradeShutdownGraceDelay time.Duration

	// statusFunc returns the current health status string for the periodic heartbeat.
	// When nil, "healthy" is used as the default. Set via SetStatusFunc after
	// connection to wire in the subsystem state tracker. (Issue #2034)
	statusFunc func() string

	// shutdownScheduleFunc schedules trigger to run after delay. When nil the
	// default real implementation (a timer goroutine) is used. Injectable for
	// testing so the grace delay is exercised synchronously without time.Sleep
	// and without spawning detached goroutines. (Issue #2001)
	shutdownScheduleFunc func(delay time.Duration, trigger func())

	// Logger
	logger logging.Logger
}

// defaultUpgradeShutdownGraceDelay is the default grace period between the
// push_steward_binary handler returning and the graceful shutdown firing.
//
// 3s comfortably exceeds the in-process publish of EventCommandCompleted, which
// is sub-millisecond in tests. It does NOT guarantee the controller has
// network-acked the event before the process exits; the offline event queue is
// the durability backstop — if the steward exits before the ack reaches the
// controller, the queued completion event is redelivered on the next connect
// (drainOfflineQueue). (Issue #2001)
const defaultUpgradeShutdownGraceDelay = 3 * time.Second

// TransportConfig holds configuration for the gRPC-over-QUIC transport client.
type TransportConfig struct {
	// ControllerURL is the gRPC-over-QUIC transport address (e.g., "controller:4433").
	// Received from the registration response as transport_address.
	ControllerURL string

	// ControllerHTTPSBaseURL is the controller's HTTPS REST base (e.g.
	// "https://controller:9080"), used by the desired_version self-fetch path to
	// construct the installer download URL (Issue #2833). Distinct from ControllerURL,
	// which is the QUIC transport address. Sourced from steward config/env
	// (CFGMS_CONTROLLER_HTTPS_URL); when empty the steward cannot self-fetch and
	// degrades safe to awaiting a controller push. Its host is pinned to the transport
	// host before any fetch, so it can never point at another host.
	ControllerHTTPSBaseURL string

	// RegistrationToken for initial registration
	RegistrationToken string

	// TLSCertPath for mTLS (optional if PEM certs provided from registration)
	TLSCertPath string

	// CACertPEM is the CA certificate PEM (for TLS verification)
	CACertPEM string

	// ClientCertPEM is the client certificate PEM (for mTLS)
	ClientCertPEM string

	// ServerCertPEM is the controller's server certificate PEM (for config signature verification)
	// Story #315: Used to verify configurations signed by the controller
	ServerCertPEM string

	// SigningCertPEM is the controller's dedicated signing certificate PEM (Story #377).
	// When present and SigningCertPEMs is empty, it seeds the runtime signingCertPEMs slice
	// in NewTransportClient for backward compatibility. Registration call sites need not change.
	SigningCertPEM string

	// SigningCertPEMs is the mutable set of signing certs (Issue #1816).
	// When non-empty, takes precedence over SigningCertPEM for seeding signingCertPEMs.
	SigningCertPEMs []string

	// IdentityPersistFunc is called by the push-signing-cert handler to atomically
	// persist updated signing cert PEMs before the in-memory state is updated (Issue #1816).
	// If nil, persistence is skipped (cert learned in memory only).
	IdentityPersistFunc func(signingCertPEMs []string, overlapExpiresAt *time.Time) error

	// HeartbeatInterval for periodic heartbeats
	HeartbeatInterval time.Duration

	// QueueDir is the directory used to persist the offline report queue.
	// If empty the queue operates in-memory only (events are lost on restart).
	// Issue #419: set this to a stable path (e.g. steward data directory) for
	// durable offline queueing across restarts.
	QueueDir string

	// MaxQueueSize is the maximum number of events to retain in the offline
	// queue before the oldest is evicted. Defaults to 1000.
	MaxQueueSize int

	// MaxQueueAge is the maximum time an event is kept in the offline queue
	// before being discarded. Defaults to 24 hours.
	MaxQueueAge time.Duration

	// SignedCommandReplayWindow is the maximum age of an accepted command timestamp.
	// Commands older than this are rejected as potential replays.
	// Zero means the commands.Handler default (5 minutes) applies.
	SignedCommandReplayWindow time.Duration

	// SignedCommandMaxParamsBytes is the maximum JSON-serialized size of Command.Params.
	// Zero means the commands.Handler default (65536 bytes) applies.
	SignedCommandMaxParamsBytes int

	// ScriptSigning is the steward-level script signing policy loaded from the
	// local steward config. It is wired into the command handler so that
	// CommandExecuteScript signature verification (library-script TrustedKeys
	// enforcement, require_signed_adhoc, operator-cert CA chaining) is active in
	// controller-connected production deployments (Issue #1671). The zero value
	// means signing enforcement is inactive (policy: none).
	ScriptSigning stewardconfig.ScriptSigningConfig

	// PublicBeta enables the fail-closed connected-execution contract. It
	// requires signed ad-hoc commands and a valid, loaded controller CA root.
	// Development and tests must opt out explicitly by leaving this false.
	PublicBeta bool

	// CertManager provides on-demand client certificate loading for TLS handshakes
	// (Issue #920). When non-nil, GetClientCertificate is used per handshake so
	// certificate rotations are picked up automatically. When nil the client falls
	// back to disk-path or environment-variable certificate loading.
	CertManager *cert.Manager

	// SecretStore is used by the offline queue to persist its AES-256-GCM
	// encryption key across restarts (Issue #920). May be nil.
	SecretStore secretsif.SecretStore

	// CertStoreDir is the on-disk cert/identity directory used by the upgrade
	// handler to download and stage new steward binaries. When empty the upgrade
	// handler returns an error. (Issue #1943)
	CertStoreDir string

	// UpgradeAllowDowngrade, when true, permits the upgrade handler to install a
	// steward version older than or equal to the currently running version.
	// Mirrors steward.cfg upgrade.allow_downgrade. (Issue #1943)
	UpgradeAllowDowngrade bool

	// UpgradePublisherTrustStore, when non-nil, overrides CFGMSPublisherIdentity()
	// during steward binary signature verification. Intended for test environments
	// only — production deployments leave this nil. (Issue #1948)
	UpgradePublisherTrustStore trust.TrustStore

	// DNARefreshInterval is how often the connected steward re-collects and
	// publishes DNA attribute deltas (Issue #1915). Defaults to 30 minutes.
	DNARefreshInterval time.Duration

	// DNACollector is the implementation used by the DNA refresh loop to collect
	// system attributes. When nil, the refresh loop is disabled (no collection
	// is attempted). Injectable for testing — production code passes a real
	// dna.Collector via main.go after registration.
	DNACollector DNACollector

	// ObserveSweepN sets the Tier-2 observe sweep cadence: every Nth convergence
	// cycle the steward publishes an EventObserveSweepRequest so the controller can
	// push back the resolved observe-module set (Issue #3104, ADR-024 Amendment 1 §3).
	// 0 (the zero value) disables the sweep.
	ObserveSweepN int

	// ObserveModuleLoader loads steward modules by name for the Tier-2 sweep.
	// When nil, the sweep runs but cannot execute module Get calls (no-op).
	// Production code wires factory.ModuleFactory; tests inject a deterministic
	// in-memory implementation.
	ObserveModuleLoader ObserveModuleLoader

	// Logger for client logging
	Logger logging.Logger
}

func validControllerCARoots(caPEM string, now time.Time) (*x509.CertPool, error) {
	if caPEM == "" {
		return nil, fmt.Errorf("controller CA PEM is empty")
	}
	remaining := []byte(caPEM)
	validRoots := 0
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("controller CA PEM contains unexpected block %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse controller CA certificate: %w", err)
		}
		if !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("controller signing root %q is not a certificate authority", certificate.Subject.CommonName)
		}
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return nil, fmt.Errorf("controller signing root %q is not currently valid", certificate.Subject.CommonName)
		}
		validRoots++
	}
	if strings.TrimSpace(string(remaining)) != "" {
		return nil, fmt.Errorf("controller CA PEM contains malformed trailing data")
	}
	if validRoots == 0 {
		return nil, fmt.Errorf("controller CA PEM contains no valid certificate roots")
	}
	pool, err := cert.CertPoolFromPEM([]byte(caPEM))
	if err != nil {
		return nil, err
	}
	return pool, nil
}

// NewTransportClient creates a new steward transport client.
func NewTransportClient(cfg *TransportConfig) (*TransportClient, error) {
	if cfg.ControllerURL == "" {
		return nil, fmt.Errorf("controller URL is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if cfg.PublicBeta {
		if !cfg.ScriptSigning.RequireSignedAdhoc {
			return nil, fmt.Errorf("public-beta connected execution requires require_signed_adhoc: true")
		}
		if _, err := validControllerCARoots(cfg.CACertPEM, time.Now()); err != nil {
			return nil, fmt.Errorf("public-beta connected execution requires valid controller signing roots: %w", err)
		}
	}

	heartbeatInterval := cfg.HeartbeatInterval
	if heartbeatInterval == 0 {
		heartbeatInterval = 20 * time.Second // epic #1664: 20s base + [0,10s) jitter
	}

	dnaRefreshInterval := cfg.DNARefreshInterval
	if dnaRefreshInterval == 0 {
		dnaRefreshInterval = 30 * time.Minute
	}

	// Per-instance RNG for per-tick heartbeat jitter (epic #1664).
	rng := rand.New(rand.NewSource(time.Now().UnixNano())) //#nosec G404 -- non-crypto jitter

	// Initialize offline queue for durable report persistence (Issue #419).
	// Pass the SecretStore so the encryption key is persisted across restarts (Issue #920).
	offlineQueue, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:         cfg.QueueDir,
		MaxSize:     cfg.MaxQueueSize,
		MaxAge:      cfg.MaxQueueAge,
		SecretStore: cfg.SecretStore,
		Logger:      cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize offline queue: %w", err)
	}

	// Load Raft-term fence ratchet state persisted from a previous run (#3437).
	// If no state file exists (first boot or after an enrollment reset) both fields
	// default to zero — the ratchet starts in the "never seen a stamped command"
	// state and behaves identically to the pre-#3437 in-memory-only behaviour.
	fenceRatchet := stewardconfig.NewFenceRatchet(cfg.CertStoreDir)
	ratchetSet, highestTermSeen, err := fenceRatchet.Load()
	if err != nil {
		// Corrupt or unreadable state file: log and start fresh rather than
		// refusing to start. The fence still works in-memory for this run.
		cfg.Logger.Warn("failed to load persisted fence ratchet state; starting fresh",
			"error", logging.SanitizeLogValue(err.Error()))
	}

	// Seed signingCertPEMs from the multi-cert field if provided; otherwise
	// fall back to the singular SigningCertPEM for backward compatibility.
	signingCertPEMs := cfg.SigningCertPEMs
	if len(signingCertPEMs) == 0 && cfg.SigningCertPEM != "" {
		signingCertPEMs = []string{cfg.SigningCertPEM}
	}

	c := &TransportClient{
		heartbeatInterval:          heartbeatInterval,
		rng:                        rng,
		heartbeatStop:              make(chan struct{}),
		convergenceStop:            make(chan struct{}),
		dnaRefreshStop:             make(chan struct{}),
		convergeInterval:           30 * time.Minute,
		convergeIntervalCh:         make(chan struct{}, 1),
		dnaRefreshInterval:         dnaRefreshInterval,
		dnaCollector:               cfg.DNACollector,
		transportAddress:           cfg.ControllerURL,
		controllerHTTPSBaseURL:     cfg.ControllerHTTPSBaseURL,
		certPath:                   cfg.TLSCertPath,
		caCertPEM:                  cfg.CACertPEM,
		serverCertPEM:              cfg.ServerCertPEM,
		signingCertPEMs:            signingCertPEMs,
		certManager:                cfg.CertManager,
		offlineQueue:               offlineQueue,
		commandReplayWindow:        cfg.SignedCommandReplayWindow,
		commandMaxParamsBytes:      cfg.SignedCommandMaxParamsBytes,
		scriptSigning:              cfg.ScriptSigning,
		publicBeta:                 cfg.PublicBeta,
		identityPersistFunc:        cfg.IdentityPersistFunc,
		secretStore:                cfg.SecretStore,
		certStoreDir:               cfg.CertStoreDir,
		fenceRatchet:               fenceRatchet,
		termRatchetSet:             ratchetSet,
		highestTermSeen:            highestTermSeen,
		upgradeAllowDowngrade:      cfg.UpgradeAllowDowngrade,
		upgradePublisherTrustStore: cfg.UpgradePublisherTrustStore,
		// Self-exit after a pushed-upgrade swap only when a launcher is supervising
		// this process (it sets EnvStewardLauncherManaged=1 on its child). (Issue #2003)
		launcherManaged:     os.Getenv(version.EnvStewardLauncherManaged) == "1",
		observeSweepN:       cfg.ObserveSweepN,
		observeModuleLoader: cfg.ObserveModuleLoader,
		logger:              cfg.Logger,
	}

	return c, nil
}

// InitializeConfigExecutor creates and initializes the configuration executor.
// This must be called after the client is connected but before config sync.
// Uses the unified execution engine (all 7 modules, Get→Compare→Set→Verify).
func (c *TransportClient) InitializeConfigExecutor(tenantID string) error {
	c.mu.RLock()
	stewardID := c.stewardID
	controlPlane := c.controlPlane
	existingEmitter := c.eventEmitter // may already be set by setupCommandHandler (Issue #2143)
	c.mu.RUnlock()

	// Reuse the EventEmitter started in setupCommandHandler when available; otherwise
	// build one now (e.g. standalone InitializeConfigExecutor call without prior Connect).
	// ADR-012 §2: emitter shares the control-plane gRPC connection.
	emitter := existingEmitter
	if emitter == nil {
		if cp, ok := controlPlane.(*grpcCP.Provider); ok {
			if tc := cp.TransportClient(); tc != nil {
				emitter = NewEventEmitter(EventEmitterConfig{
					Client:    tc,
					StewardID: stewardID,
					Logger:    c.logger,
				})
			}
		}
	}

	// Ensure the shared module-DNA store exists so it survives executor re-init on
	// reconnect (#2520). Created once, reused by every executor this client builds.
	c.mu.Lock()
	if c.moduleDNAStore == nil {
		c.moduleDNAStore = execution.NewModuleDNASnapshot()
	}
	moduleDNAStore := c.moduleDNAStore
	c.mu.Unlock()

	execCfg := &execution.ExecutorConfig{
		TenantID:          tenantID,
		Logger:            c.logger,
		SecretStore:       c.secretStore,
		StewardID:         stewardID,
		ModuleDNASnapshot: moduleDNAStore,
		// Explicit rather than relying on executor.go's 120s fallback (Issue
		// #3801): now that sync_config's ApplyConfiguration/StartMonitors run
		// under a context with no command-level deadline (see the
		// CommandSyncConfig handler above), this is the real effective budget
		// per module.Get/Set/verifyChanges call (ADR-012 §7). 120s comfortably
		// covers observed cloud-image VM provisioning (25-27s) with headroom
		// for slower hosts while still bounding a wedged module.
		ModuleCallTimeoutSec: 120,
	}
	// Assign the emitter only when one was built. ExecutorConfig.EventEmitter is an
	// interface, so assigning a nil *EventEmitter unconditionally would store a
	// typed-nil: the executor's `if e.eventEmitter != nil` guard passes and the first
	// drift detection calls Enqueue on a nil receiver, panicking the steward. That
	// happens whenever the control plane is not a *grpcCP.Provider or has no
	// transport client yet.
	if emitter != nil {
		execCfg.EventEmitter = emitter
	}
	executor, err := execution.NewExecutor(execCfg)
	if err != nil {
		return fmt.Errorf("failed to create config executor: %w", err)
	}

	// Wire the drift-diff accumulator (ADR-022 §6, Issue #3373). The handler
	// builds a DriftDiffRecord from the StateDiff and appends it to the pending
	// accumulator; the DNA send path drains the accumulator on each sync cycle.
	executor.SetDriftEventHandler(func(resourceName string, _ string, diff *stewardtesting.StateDiff) {
		c.lastConfigMu.RLock()
		configRevision := c.lastConfigVersion
		c.lastConfigMu.RUnlock()

		rec := driftdiff.BuildRecord(diff, configRevision)
		if rec == nil {
			// No resource identifier on the diff: the record could not be addressed
			// to an entity-graph EID on the controller side, so it is not buffered.
			c.logger.Warn("managed resource drift carried no resource identifier; drift-diff record not produced",
				"resource", logging.SanitizeLogValue(resourceName))
			return
		}
		c.driftDiffs.Append(rec)
		c.logger.Debug("drift-diff record accumulated for next DNA sync",
			"resource", logging.SanitizeLogValue(resourceName),
			"fragment_id", logging.SanitizeLogValue(rec.FragmentID),
			"field_count", len(rec.Fields))
	})

	c.mu.Lock()
	c.configExecutor = executor
	if emitter != nil && c.eventEmitter == nil {
		c.eventEmitter = emitter
	}
	c.mu.Unlock()

	if emitter != nil {
		// Start is idempotent — a no-op if setupCommandHandler already started this emitter.
		// Uses context.Background() so the reconnect loop outlives any single request context.
		// Disconnect() calls Close() to drain and stop.
		emitter.Start(context.Background())
		c.logger.Info("Configuration executor initialized with event emitter",
			"tenant_id", tenantID, "steward_id", logging.RedactedID(stewardID))
	} else {
		c.logger.Info("Configuration executor initialized", "tenant_id", tenantID)
	}
	return nil
}

// Connect establishes gRPC control plane and data plane connections to the controller.
// Both use the unified transport_address over QUIC. The data plane is initialized
// eagerly alongside the control plane — no lazy connect_dataplane command required.
// Story #516: Unified gRPC-over-QUIC connection for both control and data plane.
func (c *TransportClient) Connect(ctx context.Context) error {
	c.logger.Info("Connecting to controller via gRPC transport")

	c.mu.RLock()
	stewardID := c.stewardID
	controlPlane := c.controlPlane
	transportAddress := c.transportAddress
	tenantID := c.tenantID
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered - call SetStewardID first")
	}

	// Create TLS configuration for gRPC-over-QUIC. mTLS is mandatory; a
	// configuration failure is fatal — there is no legitimate path without TLS.
	tlsConfig, err := c.createTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}

	// Initialize gRPC control plane provider if not already set
	if controlPlane == nil {
		c.logger.Info("Initializing gRPC control plane provider",
			"addr", transportAddress, "steward_id", logging.RedactedID(stewardID))

		provider := grpcCP.New(grpcCP.ModeClient)

		providerCfg := map[string]interface{}{
			"mode":       "client",
			"addr":       transportAddress,
			"steward_id": stewardID,
			"logger":     c.logger,
		}
		if tenantID != "" {
			providerCfg["tenant_id"] = tenantID
		}
		if tlsConfig != nil {
			providerCfg["tls_config"] = tlsConfig
		}

		if err := provider.Initialize(ctx, providerCfg); err != nil {
			return fmt.Errorf("failed to initialize gRPC control plane provider: %w", err)
		}

		controlPlane = provider
		c.mu.Lock()
		c.controlPlane = controlPlane
		c.mu.Unlock()
	}

	// Start the control plane (connects to gRPC server over QUIC)
	if !controlPlane.IsConnected() {
		c.logger.Info("Starting gRPC control plane connection", "addr", transportAddress)
		if err := controlPlane.Start(ctx); err != nil {
			return fmt.Errorf("failed to start gRPC control plane: %w", err)
		}
		c.logger.Info("gRPC control plane connection established")
	}

	// Initialize gRPC data plane provider eagerly — shares the same transport_address
	c.logger.Info("Initializing gRPC data plane provider", "addr", transportAddress)
	dpProvider := dataplaneInterfaces.GetProvider("grpc")
	if dpProvider == nil {
		return fmt.Errorf("gRPC data plane provider not registered")
	}

	dpCfg := map[string]interface{}{
		"mode":        "client",
		"server_addr": transportAddress,
		"steward_id":  stewardID,
	}
	if tlsConfig != nil {
		dpCfg["tls_config"] = tlsConfig
	}

	if err := dpProvider.Initialize(ctx, dpCfg); err != nil {
		return fmt.Errorf("failed to initialize gRPC data plane provider: %w", err)
	}

	if err := dpProvider.Start(ctx); err != nil {
		return fmt.Errorf("failed to start gRPC data plane provider: %w", err)
	}

	session, err := dpProvider.Connect(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to establish data plane session: %w", err)
	}

	c.mu.Lock()
	c.dataPlaneSession = session
	c.mu.Unlock()

	c.logger.Info("gRPC data plane initialized", "session_id", logging.RedactedID(session.ID()))

	// Setup command handler
	cmdHandler, err := c.setupCommandHandler(ctx, stewardID)
	if err != nil {
		return fmt.Errorf("failed to setup command handler: %w", err)
	}

	c.mu.Lock()
	c.commandHandler = cmdHandler
	c.mu.Unlock()

	// Subscribe to commands via gRPC control plane provider
	c.logger.Info("Subscribing to commands", "steward_id", logging.RedactedID(stewardID))
	if err := controlPlane.SubscribeCommands(ctx, stewardID, func(ctx context.Context, sc *cpTypes.SignedCommand) error {
		return c.receiveCommand(ctx, sc, cmdHandler.HandleCommand)
	}); err != nil {
		return fmt.Errorf("failed to subscribe to commands: %w", err)
	}

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	// Auto-initialize the config executor when the tenant ID is already known
	// and no executor has been set. This lets the on-connect sync below run
	// without the caller needing to call InitializeConfigExecutor first. (Issue #1720)
	c.mu.RLock()
	hasExecutor := c.configExecutor != nil
	knownTenant := c.tenantID
	c.mu.RUnlock()
	if !hasExecutor && knownTenant != "" {
		if initErr := c.InitializeConfigExecutor(knownTenant); initErr != nil {
			c.logger.Warn("Could not auto-initialize config executor during connect", "error", initErr)
		}
	}

	// Drain any events queued during the offline period (Issue #419).
	// Done synchronously before starting the heartbeat so the controller
	// receives a complete history before the next heartbeat arrives.
	c.drainOfflineQueue(ctx)

	// Pull any config stored while this steward was offline (Issue #1720).
	// Runs in a background goroutine so Connect() returns promptly. A non-nil
	// error (e.g. no config stored yet) is logged at Info level and ignored —
	// the absence of config is a valid first-connect state.
	// No outer deadline here: the executor's per-call ModuleCallTimeoutSec budget
	// (ADR-012 §7) already bounds each individual module.Get/Set/verifyChanges
	// invocation. An additional outer cap would silently truncate long-running but
	// legitimate Set calls (e.g. large installer downloads) to 30s even when the
	// module's declared budget is 120s (Issue #2480).
	// #nosec G118 -- on-connect sync intentionally survives Connect's caller;
	// every module operation is bounded by its declared ModuleCallTimeoutSec.
	go func() {
		if err := c.syncConfigNow(context.Background(), "on-connect", nil); err != nil {
			c.logger.Info("On-connect config sync skipped", "error", err)
		}
	}()

	// Start heartbeat
	// #nosec G118 -- heartbeat is client-owned, each send has a five-second
	// timeout, and Disconnect closes heartbeatStop to end the goroutine.
	go c.startHeartbeat()

	c.logger.Info("Connected to controller successfully via gRPC transport")
	return nil
}

// receiveCommand is the steward's command-receive path (Story #3436): it enforces
// the Raft-term fence before an inbound command reaches the authenticated dispatch
// pipeline (commands.Handler.HandleCommand, passed as dispatch). Extracted as its
// own method — rather than inlined in the SubscribeCommands closure — so the
// ordering (fence check strictly before dispatch) is directly unit-testable.
func (c *TransportClient) receiveCommand(
	ctx context.Context,
	sc *cpTypes.SignedCommand,
	dispatch func(context.Context, *cpTypes.SignedCommand) error,
) error {
	if err := c.checkTermFence(sc); err != nil {
		return err
	}
	return dispatch(ctx, sc)
}

// checkTermFence enforces ADR-029 Decision 6's three-state ratchet (Story #3436
// implements the comparison logic; Story #3437 adds persistence and the reset path):
//
//  1. Never seen a stamped (term > 0) command: accept any command, stamped or
//     not. A stamped command's term becomes the new high-water mark and sets the
//     ratchet; an unstamped one is accepted without changing state (genuine
//     bootstrap, or mid-rollout behind a controller predating #3390).
//  2. Ratchet set: an unstamped command is refused as a downgrade attempt (real
//     Raft terms are never 0 once a leader has been elected), and a stamped one
//     is accepted only when its term is at or above the high-water mark.
//
// When the ratchet advances, the new state is persisted to fenceRatchet so it
// survives a steward process restart (#3437). Persistence failures are logged
// and do not block command delivery — the in-memory state remains authoritative
// for the lifetime of this process.
//
// Every value in the rejection log line is attacker-influenced (a compromised or
// downgraded controller chooses Command.ID/Type/Term freely — Term is transport-
// trusted only, not covered by the command signature) and goes through
// logging.SanitizeLogValue() per this repo's standing log-injection rule.
func (c *TransportClient) checkTermFence(sc *cpTypes.SignedCommand) error {
	term := sc.Command.Term

	c.mu.Lock()
	ratchetSet := c.termRatchetSet
	highestSeen := c.highestTermSeen

	if term == 0 {
		if !ratchetSet {
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		c.logger.Warn("rejected inbound command: raft term fence — missing term after ratchet set",
			"command_id", logging.SanitizeLogValue(sc.Command.ID),
			"command_type", logging.SanitizeLogValue(string(sc.Command.Type)),
			"highest_seen_term", logging.SanitizeLogValue(fmt.Sprintf("%d", highestSeen)),
		)
		return fmt.Errorf("%w: command %q omits term but ratchet is set (highest seen %d)",
			ErrCommandTermFenced, sc.Command.ID, highestSeen)
	}

	if !ratchetSet || term >= highestSeen {
		c.termRatchetSet = true
		c.highestTermSeen = term
		c.mu.Unlock()
		// Persist the updated ratchet state so it survives a restart (#3437).
		// Done outside c.mu to avoid holding the client lock during file I/O:
		// inbound commands run one goroutine per command, so several accepted
		// commands can reach Save concurrently and in any order. FenceRatchet.Save
		// is the serialization point — it takes its own mutex, writes through a
		// uniquely named temp file, and refuses to lower the stored term — so the
		// persisted high-water mark cannot regress or be truncated by that race.
		if err := c.fenceRatchet.Save(true, term); err != nil {
			c.logger.Warn("failed to persist fence ratchet state; in-memory state is still authoritative",
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return nil
	}
	c.mu.Unlock()

	c.logger.Warn("rejected inbound command: raft term fence — term below highest seen",
		"command_id", logging.SanitizeLogValue(sc.Command.ID),
		"command_type", logging.SanitizeLogValue(string(sc.Command.Type)),
		"claimed_term", logging.SanitizeLogValue(fmt.Sprintf("%d", term)),
		"highest_seen_term", logging.SanitizeLogValue(fmt.Sprintf("%d", highestSeen)),
	)
	return fmt.Errorf("%w: command %q term %d below highest seen %d",
		ErrCommandTermFenced, sc.Command.ID, term, highestSeen)
}

// setupCommandHandler creates and configures the command handler with all command types.
// Story #516: connect_dataplane handler removed — DP is initialized eagerly in Connect().
func (c *TransportClient) setupCommandHandler(ctx context.Context, stewardID string) (*commands.Handler, error) {
	// Create status callback that publishes events via the offline-queued path
	// so events are not lost if the controller is temporarily unreachable (Issue #419).
	statusCallback := func(ctx context.Context, event *cpTypes.Event) {
		if err := c.publishEventWithQueue(ctx, event); err != nil {
			c.logger.Error("Failed to publish status event", "error", err)
		}
	}

	// Build the verifier on demand from the stored signing/server cert PEMs.
	// Not cached — Issue #920 removes the configVerifier field.
	verifier := c.buildVerifierOnDemand()

	// Wire script signature verification into the command handler (Issue #1671).
	// Without this, CommandExecuteScript signing enforcement is inactive in
	// controller-connected deployments: require_signed_adhoc is ignored, library
	// scripts fail TrustedKeys verification, and operator-cert CA chaining is skipped.
	c.mu.RLock()
	scriptSigning := c.scriptSigning
	caCertPEM := c.caCertPEM
	existingEmitter := c.eventEmitter
	c.mu.RUnlock()

	signingConfig := stewardconfig.BuildModuleSigningConfig(scriptSigning)

	// controllerCARoots verifies operator-signed inline command certs chain to the
	// controller CA — the same CA bundle used for mTLS. Left nil when no usable CA
	// PEM is available, which the handler treats as "skip operator-cert CA
	// verification". validControllerCARoots checks each root is a currently-valid
	// CA before building the pool, and builds it through pkg/cert (the central
	// certificate provider) rather than assembling an x509 pool locally.
	controllerCARoots, rootsErr := validControllerCARoots(caCertPEM, time.Now())
	if rootsErr != nil {
		if c.publicBeta {
			return nil, fmt.Errorf("public-beta connected execution requires valid controller signing roots: %w", rootsErr)
		}
		// Outside public beta an unusable bundle disables operator-cert chaining
		// rather than failing the connection. Say so, so a misconfigured CA is
		// diagnosable instead of silently reducing verification.
		c.logger.Warn("Controller CA PEM unusable for operator certificate verification",
			"error", rootsErr)
	}

	// A required-signature policy without roots would accept an otherwise valid
	// signature from an arbitrary certificate. Refuse to construct the connected
	// command handler rather than silently dropping operator-certificate chaining.
	if controllerCARoots == nil && scriptSigning.RequireSignedAdhoc {
		return nil, fmt.Errorf("require_signed_adhoc requires a valid controller CA certificate")
	}
	if c.publicBeta && !scriptSigning.RequireSignedAdhoc {
		return nil, fmt.Errorf("public-beta connected execution requires require_signed_adhoc: true")
	}

	// Build the EventEmitter for script output streaming (Issue #2143). Reuse the
	// already-started emitter when available; otherwise create one now so the command
	// handler can emit script_output LogEntries from the first connected session.
	// The emitter shares the control-plane gRPC connection — no extra TLS required.
	var scriptEmitter commands.EventEmitter // interface — nil unless we successfully build one
	if existingEmitter != nil {
		scriptEmitter = existingEmitter
	} else {
		c.mu.RLock()
		cp := c.controlPlane
		c.mu.RUnlock()
		if grpcProv, ok := cp.(*grpcCP.Provider); ok {
			if tc := grpcProv.TransportClient(); tc != nil {
				built := NewEventEmitter(EventEmitterConfig{
					Client:    tc,
					StewardID: stewardID,
					Logger:    c.logger,
				})
				built.Start(context.Background())
				c.mu.Lock()
				c.eventEmitter = built
				c.mu.Unlock()
				scriptEmitter = built
			}
		}
	}

	handler, err := commands.New(&commands.Config{
		StewardID:          stewardID,
		OnStatus:           statusCallback,
		Logger:             c.logger,
		Verifier:           verifier,
		ReplayWindow:       c.commandReplayWindow,
		MaxParamsBytes:     c.commandMaxParamsBytes,
		SigningConfig:      signingConfig,
		RequireSignedAdhoc: scriptSigning.RequireSignedAdhoc,
		ControllerCARoots:  controllerCARoots,
		// TenantID confines a fleet-wide authorized-WebAuthn-credential roster entry to
		// the tenant subtree its owning account belongs to (Issue #3697). Empty until
		// registration assigns one, in which case only a root-scope entry authorizes
		// inline execution.
		TenantID:     c.GetTenantID(),
		EventEmitter: scriptEmitter,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create command handler: %w", err)
	}

	// Register sync_config handler — delegates to syncConfigNow for both
	// command-triggered syncs and the on-connect pull (Issue #1720).
	handler.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, cmd *cpTypes.Command) error {
		c.logger.Info("Received sync_config command", "command_id", cmd.ID, "params_keys", paramKeys(cmd.Params))

		// Extract optional module filter from command params.
		var modules []string
		if modulesParam, ok := cmd.Params["modules"].([]interface{}); ok {
			for _, m := range modulesParam {
				if modStr, ok := m.(string); ok {
					modules = append(modules, modStr)
				}
			}
		}

		// ctx here is executeCommand's 30s-unless-overridden deadline
		// (handler.go:475) — fine for the fast config-retrieval leg inside
		// syncConfigNow, but syncConfigNow itself derives an independent
		// background context before ApplyConfiguration/StartMonitors so THAT
		// deadline does not also cap every module.Get/Set/verifyChanges call
		// (Issue #3801; see the comment at syncConfigNow's Apply step).
		return c.syncConfigNow(ctx, cmd.ID, modules)
	})

	// Register sync_dna handler — sends full DNA or a fragment delta over the
	// data plane. Triggered by the controller on initial registration (full sync),
	// hash mismatch (full sync), or aggregate-root mismatch (partial sync, ADR-017 §7).
	//
	// Branch on cmd.Params["fragment_ids"]:
	//   - absent → existing full-snapshot path (unchanged)
	//   - present → partial-sync: send only the requested fragments with Delta=true
	handler.RegisterHandler(cpTypes.CommandSyncDNA, func(ctx context.Context, cmd *cpTypes.Command) error {
		c.mu.RLock()
		session := c.dataPlaneSession
		sid := c.stewardID
		tid := c.tenantID
		c.mu.RUnlock()

		if session == nil || session.IsClosed() {
			return fmt.Errorf("data plane session not available for DNA sync")
		}

		// Partial-sync branch: fragment_ids param carries the IDs the controller
		// wants us to send (ADR-017 §7 step 2 response).
		if rawIDs, present := cmd.Params["fragment_ids"]; present {
			requestedIDs, parseErr := parseFragmentIDs(rawIDs)
			if parseErr != nil {
				return fmt.Errorf("failed to parse fragment_ids: %w", parseErr)
			}
			if len(requestedIDs) > 0 {
				c.dnaMu.RLock()
				currentFragments := make([]*commonpb.Fragment, len(c.currentDNAFragments))
				copy(currentFragments, c.currentDNAFragments)
				c.dnaMu.RUnlock()

				if len(currentFragments) > 0 {
					fragByID := make(map[string]*commonpb.Fragment, len(currentFragments))
					for _, f := range currentFragments {
						fragByID[f.GetFragmentId()] = f
					}

					selected := make([]*commonpb.Fragment, 0, len(requestedIDs))
					allFound := true
					for _, id := range requestedIDs {
						f, exists := fragByID[id]
						if !exists {
							// id originates from controller-supplied command params;
							// sanitize before logging (CLAUDE.md log-injection rule).
							c.logger.Warn("requested fragment not in current DNA; falling back to full sync",
								"fragment_id", logging.SanitizeLogValue(id),
								"command_id", logging.SanitizeLogValue(cmd.ID))
							allFound = false
							break
						}
						selected = append(selected, f)
					}

					if allFound {
						c.logger.Info("Received partial sync_dna command, sending fragment delta",
							"command_id", logging.SanitizeLogValue(cmd.ID),
							"fragment_count", len(selected))
						// Drain and encode accumulated drift-diff records for this sync.
						driftBytes := c.encodeDriftDiffs()
						deltaTransfer := &dpTypes.DNATransfer{
							ID:             fmt.Sprintf("dna_delta_%d", time.Now().UnixNano()),
							StewardID:      sid,
							TenantID:       tid,
							Timestamp:      time.Now(),
							Delta:          true,
							Fragments:      selected,
							DriftDiffBytes: driftBytes,
							Metadata: map[string]string{
								"command_id":       cmd.ID,
								"fragment_count":   fmt.Sprintf("%d", len(selected)),
								"drift_diff_count": fmt.Sprintf("%d", len(driftBytes)),
							},
						}
						if err := session.SendDNA(ctx, deltaTransfer); err != nil {
							return fmt.Errorf("failed to send partial DNA via data plane: %w", err)
						}
						c.logger.Info("Partial DNA sync completed via data plane",
							"command_id", logging.SanitizeLogValue(cmd.ID),
							"fragment_count", len(selected))
						return nil
					}
				}
				// Requested fragments not available — fall through to full sync.
				c.logger.Info("Fragment state unavailable; falling back to full DNA sync",
					"command_id", logging.SanitizeLogValue(cmd.ID))
			}
		}

		// Full-snapshot path (existing, unchanged).
		c.logger.Info("Received sync_dna command, initiating full DNA sync via data plane", "command_id", cmd.ID)

		// Read the current DNA snapshot maintained by #2521 — the same source
		// used for heartbeat DNA hashes, ensuring sync_dna ⇄ heartbeat hash
		// consistency. Unlike lastPublishedDNA, currentDNAAttrs is populated
		// by RefreshCurrentDNA before the first heartbeat, so this path never
		// fails due to an empty publish cache.
		c.dnaMu.RLock()
		currentDNA := copyStringMap(c.currentDNAAttrs)
		c.dnaMu.RUnlock()

		// If no snapshot exists yet (e.g. first run before any refresh),
		// collect one now so the handler streams a real snapshot. A full DNA
		// sync must never proceed with no internal DNA state (empty attrs AND
		// no fragments): doing so would tell the controller the steward has no
		// DNA and clobber its record. If we cannot produce any snapshot (refresh
		// error, or collector yields nothing), fail the command so the controller
		// can retry rather than corrupt its state. A zero-managed-resource
		// steward may have empty attrs but non-empty fragments — that is a valid
		// sync (Issue #3332).
		if len(currentDNA) == 0 {
			if refreshErr := c.RefreshCurrentDNA(ctx); refreshErr != nil {
				return fmt.Errorf("no DNA snapshot available and refresh failed for full sync: %w", refreshErr)
			}
			c.dnaMu.RLock()
			currentDNA = copyStringMap(c.currentDNAAttrs)
			fragmentsAfterRefresh := make([]*commonpb.Fragment, len(c.currentDNAFragments))
			copy(fragmentsAfterRefresh, c.currentDNAFragments)
			c.dnaMu.RUnlock()

			if len(currentDNA) == 0 && len(fragmentsAfterRefresh) == 0 {
				return fmt.Errorf("no DNA state available for full sync")
			}
		}

		// Collect module fragments (cluster:* resources) for the full DNA sync.
		// Without this the controller-side cluster registry (BuildRegistry) is
		// always empty in production because DNA.Fragments is never populated.
		c.mu.RLock()
		collector := c.dnaCollector
		c.mu.RUnlock()
		var fragBytes [][]byte
		if collector != nil {
			for _, frag := range collector.CollectFragments(ctx) {
				b, mErr := proto.Marshal(frag)
				if mErr != nil {
					c.logger.Warn("sync_dna: failed to marshal fragment, skipping",
						"fragment_id", logging.SanitizeLogValue(frag.GetFragmentId()), "error", mErr)
					continue
				}
				fragBytes = append(fragBytes, b)
			}
		}

		// Drain and encode accumulated drift-diff records for this sync.
		driftBytes := c.encodeDriftDiffs()
		transfer := &dpTypes.DNATransfer{
			ID:             fmt.Sprintf("dna_full_%d", time.Now().UnixNano()),
			StewardID:      sid,
			TenantID:       tid,
			Timestamp:      time.Now(),
			FragmentBytes:  fragBytes,
			Delta:          false, // full snapshot
			DriftDiffBytes: driftBytes,
			Metadata: map[string]string{
				"command_id":       cmd.ID,
				"dna_hash":         dna.ComputeHash(currentDNA),
				"attr_count":       fmt.Sprintf("%d", len(currentDNA)),
				"fragment_count":   fmt.Sprintf("%d", len(fragBytes)),
				"drift_diff_count": fmt.Sprintf("%d", len(driftBytes)),
			},
		}

		if err := session.SendDNA(ctx, transfer); err != nil {
			return fmt.Errorf("failed to send full DNA via data plane: %w", err)
		}

		c.logger.Info("Full DNA sync completed via data plane",
			"command_id", cmd.ID,
			"attributes", len(currentDNA))
		return nil
	})

	// Register reconnect handler — closes the current gRPC connection and launches
	// the backoff-reconnect loop so the steward re-establishes its ControlChannel
	// against the new Raft leader after an HA failover.
	handler.RegisterHandler(cpTypes.CommandReconnect, func(ctx context.Context, cmd *cpTypes.Command) error {
		c.logger.Info("Received reconnect command, reconnecting to controller",
			"command_id", logging.SanitizeLogValue(cmd.ID))
		c.mu.RLock()
		cp := c.controlPlane
		c.mu.RUnlock()
		if cp == nil {
			return fmt.Errorf("control plane not connected")
		}
		if err := cp.Reconnect(ctx); err != nil {
			return fmt.Errorf("reconnect failed: %w", err)
		}
		return nil
	})

	// Register execute_script handler — dispatches controller-sent scripts through
	// the script module executor and publishes EventScriptCompleted (Issue #1669).
	handler.RegisterExecuteScriptHandler()

	// Register open_terminal handler — steward dials out Terminal RPC and bridges
	// it to a local PTY for an interactive admin session. (Issue #2760)
	//
	// The dialer resolves the gRPC transport client lazily at Dial() time rather
	// than at setup time. Registering unconditionally (like every other handler)
	// removes the silent "no handler for command type" failure mode that occurred
	// when the transport client was not yet available at setup, and makes the
	// wiring exercisable with an in-process control plane.
	handler.RegisterOpenTerminalHandler(&terminalDialer{c: c})

	// Register push_signing_cert handler — controller pushes current signing cert on connect
	// or after rotation. The handler persists before updating in-memory state (Issue #1816).
	handler.RegisterHandler(cpTypes.CommandPushSigningCert, func(ctx context.Context, cmd *cpTypes.Command) error {
		return c.handlePushSigningCert(ctx, cmd)
	})

	// Register push_steward_binary handler — controller pushes a new steward binary.
	// The handler downloads, verifies, and stages the binary via the launcher. (Issue #1943)
	handler.RegisterHandler(cpTypes.CommandPushStewardBinary, func(ctx context.Context, cmd *cpTypes.Command) error {
		return c.handlePushStewardBinary(ctx, cmd)
	})

	// Register observe_modules handler — controller pushes the resolved Tier-2
	// observe-module set. The handler loads each module, runs Get read-only, and
	// merges the resulting fragments into the existing DNA fragment emission path.
	// (Issue #3104, ADR-024 Amendment 1 §3)
	handler.RegisterHandler(cpTypes.CommandObserveModules, func(ctx context.Context, cmd *cpTypes.Command) error {
		return c.handleObserveModules(ctx, cmd)
	})

	return handler, nil
}

// syncConfigNow pulls the latest config from the controller via the data plane and
// applies it. It is the shared implementation for the CommandSyncConfig handler and
// the on-(re)connect pull triggered in Connect() (Issue #1720).
//
// commandID is used only for log correlation; pass "" when triggered outside of a
// command context. modules filters which modules to sync; nil means all.
func (c *TransportClient) syncConfigNow(ctx context.Context, commandID string, modules []string) error {
	// Retrieve configuration via gRPC data plane.
	configData, version, err := c.GetConfiguration(ctx, modules)
	if err != nil {
		c.logger.Error("Failed to retrieve configuration", "command_id", commandID, "error", err)
		return fmt.Errorf("config retrieval failed: %w", err)
	}

	c.logger.Info("Configuration retrieved",
		"command_id", commandID,
		"version", version,
		"config_size", len(configData))

	// Compute SHA-256 of the raw wire bytes for DNA delivery verification (Issue #1316).
	configHash := fmt.Sprintf("%x", sha256.Sum256(configData))

	// Unmarshal protobuf SignedConfig.
	var signedProtoConfig controller.SignedConfig
	if err := proto.Unmarshal(configData, &signedProtoConfig); err != nil {
		c.logger.Error("Failed to unmarshal protobuf configuration",
			"command_id", commandID,
			"version", version,
			"error", err)
		return fmt.Errorf("failed to unmarshal protobuf config: %w", err)
	}

	// Verify configuration signature — verifier obtained on demand (Issue #920).
	verifier := c.buildVerifierOnDemand()

	if verifier == nil {
		return fmt.Errorf("configuration signature verification failed: verifier unavailable")
	}
	if signedProtoConfig.Signature == nil {
		c.logger.Error("Configuration is not signed",
			"command_id", commandID,
			"version", version)
		return fmt.Errorf("configuration signature verification failed: missing signature")
	}

	unsignedProtoConfig, err := signature.VerifyProtoConfig(verifier, &signedProtoConfig)
	if err != nil {
		c.logger.Error("Configuration signature verification failed",
			"command_id", commandID,
			"version", version,
			"error", err)
		return fmt.Errorf("configuration signature verification failed: %w", err)
	}

	c.logger.Info("Configuration signature verified",
		"command_id", commandID,
		"version", version)

	// Convert protobuf to Go struct.
	goConfig, err := stewardconfig.FromProto(unsignedProtoConfig)
	if err != nil {
		c.logger.Error("Failed to convert protobuf to Go struct",
			"command_id", commandID,
			"version", version,
			"error", err)
		return fmt.Errorf("failed to convert protobuf config: %w", err)
	}

	// Apply configuration using executor.
	c.mu.RLock()
	executor := c.configExecutor
	sid := c.stewardID
	c.mu.RUnlock()

	if executor == nil {
		c.logger.Error("Configuration executor not initialized", "command_id", commandID)
		return fmt.Errorf("configuration executor not available")
	}

	// Update convergence interval from the received cfg so the scheduled loop
	// respects the controller-delivered converge_interval value.
	newInterval := stewardconfig.GetConvergeInterval(*goConfig)
	c.mu.Lock()
	intervalChanged := c.convergeInterval != newInterval
	c.convergeInterval = newInterval
	c.mu.Unlock()
	if intervalChanged {
		// Wake the convergence loop so it resets its ticker to the new interval now,
		// rather than after the next (stale) tick fires.
		select {
		case c.convergeIntervalCh <- struct{}{}:
		default:
		}
	}

	// Thread drift mode from the controller-delivered cfg into the executor.
	// This is the only authorised source of DriftMode — local steward.cfg
	// cannot set it (the local-file loading path clears the field).
	executor.SetDriftMode(applyDriftModeDefault(goConfig.Steward.DriftMode))

	// Thread allow_downgrade from the controller-delivered cfg so both
	// handlePushStewardBinary and triggerVersionConvergence use the current value.
	c.mu.Lock()
	c.upgradeAllowDowngrade = goConfig.Steward.Upgrade.AllowDowngrade
	c.mu.Unlock()

	// Marshal to YAML for executor.
	configYAML, err := yaml.Marshal(goConfig)
	if err != nil {
		c.logger.Error("Failed to marshal config to YAML",
			"command_id", commandID,
			"version", version,
			"error", err)
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Store validated config for scheduled re-convergence runs.
	// Set before Apply so a failed apply still updates the retry baseline.
	c.lastConfigMu.Lock()
	c.lastConfigYAML = configYAML
	c.lastConfigVersion = version
	c.lastConfigMu.Unlock()

	// From here on, ApplyConfiguration/StartMonitors and everything that depends on
	// their result run under an independent background context rather than the
	// ctx this function was called with. Command-triggered syncs arrive with
	// executeCommand's 30s-unless-overridden deadline (handler.go:475), meant for
	// CommandExecuteScript/CommandOpenTerminal; letting it also bound
	// module.Get/Set/verifyChanges inside ApplyConfiguration would silently cap
	// every module call at whatever remained of that 30s instead of the executor's
	// own per-call ModuleCallTimeoutSec budget (ADR-012 §7) — even though that
	// budget defaults to 120s and is set explicitly at both NewExecutor call
	// sites. Mirrors the on-connect sync path (:993, Issue #2480), which already
	// passes context.Background() for this same reason. GetConfiguration above
	// deliberately keeps the caller's ctx: that leg is a fast data-plane fetch we
	// still want cut short by an expired or cancelled ctx (Issue #3801).
	applyCtx := context.Background()

	report, err := executor.ApplyConfiguration(applyCtx, configYAML, version)
	if err != nil {
		c.logger.Error("Configuration application failed", "command_id", commandID, "error", err)
		if report != nil {
			report.StewardID = sid
			if pubErr := c.publishConfigStatus(report); pubErr != nil {
				c.logger.Error("Failed to publish config status after error", "error", pubErr)
			}
		}
		return fmt.Errorf("config application failed: %w", err)
	}

	// Start module monitors for the new config's resources (Issue #2435).
	// Full stop+restart — previous engine (from any prior config push) is closed first.
	// TriggerConvergence re-applies the SAME config and must NOT restart monitors.
	if startErr := executor.StartMonitors(applyCtx, goConfig.Resources); startErr != nil {
		c.logger.Warn("Failed to start module monitors after config sync", "error", startErr)
	}

	// Publish configuration status report.
	report.StewardID = sid
	if err := c.publishConfigStatus(report); err != nil {
		c.logger.Error("Failed to publish config status", "error", err)
	}

	c.logger.Info("Configuration sync completed",
		"command_id", commandID,
		"version", version,
		"status", report.Status)

	// Publish DNA update carrying the config hash so the controller can verify
	// delivery via heartbeats (Issue #1316). A config apply IS a convergence, so
	// refresh the FULL composite DNA (hardware facts + freshly-observed module
	// state that ExecuteConfiguration just captured) rather than replaying the
	// stale last-published host-only snapshot — this is how module/cluster DNA
	// reaches the controller promptly instead of only on the 30m refresh tick
	// (#2520 mechanism 1). Falls back to the cached snapshot if the composite
	// collect is unavailable or empty.
	var currentDNA map[string]string
	c.mu.RLock()
	collector := c.dnaCollector
	c.mu.RUnlock()
	if collector != nil {
		if attrs, err := collector.CollectAttributes(applyCtx); err == nil && len(attrs) > 0 {
			c.setCurrentDNAFromAttrs(attrs)
			currentDNA = attrs
		} else if err != nil {
			c.logger.Info("Composite DNA collect after config apply failed; using cached snapshot", "error", err)
		}
	}
	if currentDNA == nil {
		c.dnaMu.RLock()
		currentDNA = copyStringMap(c.lastPublishedDNA)
		c.dnaMu.RUnlock()
		if currentDNA == nil {
			currentDNA = make(map[string]string)
		}
	}
	currentDNA["config_hash"] = configHash
	if pubErr := c.PublishDNAUpdate(applyCtx, currentDNA, configHash, ""); pubErr != nil {
		c.logger.Info("DNA update after config apply skipped", "error", pubErr)
	}

	// Version auto-convergence on config delivery. syncConfigNow is the config-change
	// entry point (on-connect pull + the sync_config command); the scheduled loop's
	// TriggerConvergence is the only other caller of triggerVersionConvergence. Without
	// this call, a freshly delivered desired_version would not be acted on until the
	// next scheduled convergence tick — up to converge_interval later. Running it here
	// makes "declare desired_version -> steward self-fetches and swaps" converge as soon
	// as the new config lands. Idempotent: a no-op when desired_version is absent, equals
	// the running version, or is already staged. (Issue #2833)
	c.triggerVersionConvergence(applyCtx, goConfig.Steward.Upgrade.DesiredVersion, goConfig.Steward.Upgrade.AllowDowngrade)

	return nil
}

// GetConfiguration retrieves configuration from the controller via gRPC data plane.
// Story #516: Uses DataPlaneSession.ReceiveConfig() over gRPC instead of raw QUIC streams.
func (c *TransportClient) GetConfiguration(ctx context.Context, modules []string) ([]byte, string, error) {
	c.logger.Info("Requesting configuration via gRPC data plane")

	c.mu.RLock()
	session := c.dataPlaneSession
	c.mu.RUnlock()

	if session == nil || session.IsClosed() {
		return nil, "", fmt.Errorf("data plane session not available")
	}

	transfer, err := session.ReceiveConfig(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to receive configuration: %w", err)
	}

	if len(transfer.Signature) == 0 {
		return nil, "", status.Error(codes.DataLoss, "config signature missing")
	}
	verifier := c.buildVerifierOnDemand()
	if verifier == nil {
		return nil, "", status.Error(codes.FailedPrecondition, "config signature verifier unavailable")
	}
	var sig signature.ConfigSignature
	if err := json.Unmarshal(transfer.Signature, &sig); err != nil {
		return nil, "", status.Error(codes.DataLoss, "config signature verification failed")
	}
	if err := verifier.Verify(transfer.Data, &sig); err != nil {
		c.logger.Error("Config transfer signature verification failed",
			"version", transfer.Version,
			"error", err)
		return nil, "", status.Error(codes.DataLoss, "config signature verification failed")
	}

	c.logger.Info("Configuration received",
		"version", transfer.Version,
		"data_size", len(transfer.Data))

	return transfer.Data, transfer.Version, nil
}

// SendHeartbeat sends a heartbeat to the controller via the gRPC control plane provider.
func (c *TransportClient) SendHeartbeat(ctx context.Context, status string, metrics map[string]string) error {
	c.mu.RLock()
	stewardID := c.stewardID
	tenantID := c.tenantID
	cp := c.controlPlane
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered")
	}

	if cp == nil {
		return fmt.Errorf("control plane not connected")
	}

	// Convert string metrics to interface{} map for the Heartbeat type
	var metricsMap map[string]interface{}
	if metrics != nil {
		metricsMap = make(map[string]interface{}, len(metrics))
		for k, v := range metrics {
			metricsMap[k] = v
		}
	}

	c.dnaMu.RLock()
	currentDNAHash := c.currentDNAHash
	currentDNAAggregateRoot := c.currentDNAAggregateRoot
	c.dnaMu.RUnlock()

	activeSessions := int32(0)
	connectionState := "disconnected"
	if cp.IsConnected() {
		activeSessions = 1
		connectionState = "connected"
	}

	heartbeat := &cpTypes.Heartbeat{
		StewardID:        stewardID,
		TenantID:         tenantID,
		Status:           cpTypes.HeartbeatStatus(status),
		Timestamp:        time.Now(),
		Metrics:          metricsMap,
		DNAHash:          currentDNAHash,
		DNAAggregateRoot: currentDNAAggregateRoot,
		ActiveSessions:   activeSessions,
		ConnectionState:  connectionState,
		Version:          version.Short(),
	}

	if err := cp.SendHeartbeat(ctx, heartbeat); err != nil {
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}

	return nil
}

// PublishDNAUpdate publishes DNA changes to the controller via the gRPC control plane provider.
//
// Whether to publish is decided by a fragment delta: c.currentDNAFragments is
// compared against c.lastPublishedFragments by (FragmentId, FragmentHash), and
// an empty delta suppresses the publish to minimise bandwidth (Issue #3330).
// On the first call after connection there is no previous state, so the delta
// is non-empty and a publish occurs. When a publish does occur, the payload is
// the full current fragment set, not just the changed fragments — the
// integrity check on the controller side requires seeing the complete picture
// on every delta publish. A non-empty configHash (config was applied) always
// triggers a publish regardless of fragment delta.
// If the controller is unreachable the event is queued locally and delivered on reconnect (Issue #419).
func (c *TransportClient) PublishDNAUpdate(ctx context.Context, dnaAttrs map[string]string, configHash, syncFingerprint string) error {
	// Always inject the running binary version so the controller fleet view is
	// always current. Copy to avoid mutating the caller's map. (Issue #2260)
	enriched := make(map[string]string, len(dnaAttrs)+1)
	for k, v := range dnaAttrs {
		enriched[k] = v
	}
	enriched["steward.version"] = version.Short()
	dnaAttrs = enriched

	// Always update local DNA state first so the hash is available for heartbeats
	// even when the control plane is temporarily unavailable. currentDNAAttrs and
	// currentDNAHash track the freshest collected state; lastPublishedDNA is kept
	// for the config-apply fallback at syncConfigNow. Fragment delta drives the
	// periodic publish decision; lastPublishedFragments tracks what was last sent.
	// A non-empty configHash means config was applied — that always triggers a
	// publish regardless of fragment delta. (Issue #3330)
	c.dnaMu.Lock()
	currentFrags := make([]*commonpb.Fragment, len(c.currentDNAFragments))
	copy(currentFrags, c.currentDNAFragments)
	fragDelta := computeFragmentDelta(c.lastPublishedFragments, currentFrags)
	newHash := dna.ComputeHash(dnaAttrs)
	c.lastPublishedDNA = copyStringMap(dnaAttrs)
	c.currentDNAAttrs = copyStringMap(dnaAttrs)
	c.currentDNAHash = newHash
	if len(fragDelta) > 0 {
		c.lastPublishedFragments = currentFrags
	}
	c.dnaMu.Unlock()

	// Skip periodic-refresh publishes when no fragment changed.
	// Config-apply publishes (configHash != "") always proceed so the controller
	// records the applied config hash even when DNA fragments are stable.
	if len(fragDelta) == 0 && configHash == "" {
		c.logger.Debug("No DNA fragment changes detected, skipping control plane publish")
		return nil
	}

	c.mu.RLock()
	stewardID := c.stewardID
	tenantID := c.tenantID
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered")
	}

	details := map[string]interface{}{
		"dna_hash":         newHash,
		"config_hash":      configHash,
		"sync_fingerprint": syncFingerprint,
		"is_delta":         true,
		"total_count":      len(currentFrags),
	}

	// Only include the fragment payload when there are fragments to send.
	// Config-apply events with no current fragments omit "dna" so the controller
	// does not process an empty fragment set. (Issue #3330)
	if len(currentFrags) > 0 {
		dnaPayload, err := marshalFragmentsToJSONString(currentFrags)
		if err != nil {
			return fmt.Errorf("failed to marshal fragment payload: %w", err)
		}
		details["dna"] = dnaPayload
	}

	event := &cpTypes.Event{
		ID:        fmt.Sprintf("evt_dna_%d", time.Now().UnixNano()),
		Type:      cpTypes.EventDNAChanged,
		StewardID: stewardID,
		TenantID:  tenantID,
		Timestamp: time.Now(),
		Details:   details,
	}

	if err := c.publishEventWithQueue(ctx, event); err != nil {
		return fmt.Errorf("failed to publish DNA fragment update: %w", err)
	}

	c.logger.Info("Published DNA fragment update",
		"changed_count", len(fragDelta),
		"total_count", len(currentFrags),
		"dna_hash", newHash)
	return nil
}

// publishConfigStatus publishes a config status report as an event (internal helper).
func (c *TransportClient) publishConfigStatus(report *cpTypes.ConfigStatusReport) error {
	ctx := context.Background()
	return c.ReportConfigurationStatus(ctx, report.ConfigVersion, report.Status, report.Message, report.Modules, report.ApplyOutcomes)
}

// ReportConfigurationStatus reports detailed configuration execution status to the controller.
// If the controller is unreachable the report is queued locally and delivered on reconnect (Issue #419).
func (c *TransportClient) ReportConfigurationStatus(
	ctx context.Context,
	configVersion string,
	overallStatus string,
	message string,
	moduleStatuses map[string]cpTypes.ModuleStatus,
	applyOutcomes []cpTypes.ApplyOutcomeRecord,
) error {
	c.mu.RLock()
	stewardID := c.stewardID
	tenantID := c.tenantID
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered")
	}

	event := &cpTypes.Event{
		ID:        fmt.Sprintf("evt_cfg_%d", time.Now().UnixNano()),
		Type:      cpTypes.EventConfigApplied,
		StewardID: stewardID,
		TenantID:  tenantID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"config_version": configVersion,
			"status":         overallStatus,
			"message":        message,
			"modules":        moduleStatuses,
			"apply_outcomes": applyOutcomes,
		},
	}

	if err := c.publishEventWithQueue(ctx, event); err != nil {
		return fmt.Errorf("failed to publish config status: %w", err)
	}

	c.logger.Info("Published configuration status report",
		"config_version", configVersion,
		"status", overallStatus,
		"modules", len(moduleStatuses),
		"apply_outcomes", len(applyOutcomes))

	return nil
}

// ValidateConfiguration validates a configuration with the controller without applying it.
// TODO: Add validation support to ControlPlaneProvider interface (Story #363 carried forward).
func (c *TransportClient) ValidateConfiguration(
	ctx context.Context,
	config []byte,
	version string,
) ([]string, error) {
	return nil, fmt.Errorf("configuration validation not yet supported via control plane provider")
}

// applyDriftModeDefault returns DriftModeApply when mode is empty.
// The proto does not carry drift_mode, so FromProto always returns "".
// Apply is the fleet default; this makes the intent explicit and testable.
func applyDriftModeDefault(mode stewardconfig.DriftMode) stewardconfig.DriftMode {
	if mode == "" {
		return stewardconfig.DriftModeApply
	}
	return mode
}

// StartConvergenceLoop starts a background goroutine that re-converges against
// the last-received cfg on a schedule driven by the cfg's converge_interval field.
//
// The initial interval defaults to 30 minutes and is updated automatically
// whenever a sync_config command delivers a cfg with a different converge_interval
// value. The ticker is reset when the interval changes so that the new value
// takes effect on the next tick.
//
// On each tick the loop calls TriggerConvergence, which re-applies the last
// verified cfg using the unified execution engine. If no cfg has been received
// yet the tick is skipped silently and the loop waits for the next interval.
//
// The loop stops when ctx is cancelled or Disconnect is called.
func (c *TransportClient) StartConvergenceLoop(ctx context.Context) {
	c.mu.RLock()
	interval := c.convergeInterval
	c.mu.RUnlock()

	c.logger.Info("Starting scheduled convergence loop", "interval", interval)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.convergenceStop:
				return
			case <-c.convergeIntervalCh:
				// A sync_config delivery changed converge_interval. Reset the
				// ticker now so the new interval takes effect on the next tick
				// instead of waiting out the stale (possibly 30-minute) period.
				c.mu.RLock()
				current := c.convergeInterval
				c.mu.RUnlock()
				if current != interval {
					interval = current
					ticker.Reset(interval)
					c.logger.Info("Convergence interval updated", "interval", interval)
				}
			case <-ticker.C:
				// Re-read the interval on every tick as a fallback in case an
				// interval-change signal was missed.
				c.mu.RLock()
				current := c.convergeInterval
				c.mu.RUnlock()
				if current != interval {
					interval = current
					ticker.Reset(interval)
					c.logger.Info("Convergence interval updated", "interval", interval)
				}
				c.logger.Info("Scheduled convergence triggered", "interval", interval)
				if err := c.TriggerConvergence(ctx); err != nil {
					c.logger.Warn("Scheduled convergence failed", "error", err)
				}
				// Tier-2 cadence: run whole-domain observe sweep every Nth cycle.
				// The counter increments regardless of convergence success so the
				// cadence is wall-clock-based, not config-dependent.
				c.checkAndTriggerObserveSweep(ctx)
			}
		}
	}()
}

// TriggerConvergence re-applies the last configuration received from the controller.
//
// This is called both by the scheduled convergence loop and can be used directly
// for immediate convergence outside the normal schedule (e.g. after reconnecting).
// Returns nil without error if no cfg has been received yet.
func (c *TransportClient) TriggerConvergence(ctx context.Context) error {
	c.lastConfigMu.RLock()
	lastCfg := c.lastConfigYAML
	lastVersion := c.lastConfigVersion
	c.lastConfigMu.RUnlock()

	if len(lastCfg) == 0 {
		c.logger.Info("No configuration available yet, skipping convergence run")
		return nil
	}

	c.mu.RLock()
	executor := c.configExecutor
	sid := c.stewardID
	c.mu.RUnlock()

	if executor == nil {
		return fmt.Errorf("configuration executor not available")
	}

	c.logger.Info("Running convergence against last-received cfg", "version", lastVersion)

	report, err := executor.ApplyConfiguration(ctx, lastCfg, lastVersion)
	if err != nil {
		return fmt.Errorf("convergence failed: %w", err)
	}

	if report != nil {
		report.StewardID = sid
		if pubErr := c.publishConfigStatus(report); pubErr != nil {
			c.logger.Warn("Failed to publish convergence status", "error", pubErr)
		}
		c.logger.Info("Convergence run completed", "version", lastVersion, "status", report.Status)
	} else {
		c.logger.Info("Convergence run completed", "version", lastVersion)
	}

	// Version auto-convergence: when desired_version is set and differs from
	// the running binary, retry the launcher swap for the already-staged binary.
	// Errors are non-fatal — the next convergence tick will retry. (Issue #2260)
	var parsedCfg stewardconfig.StewardConfig
	if unmarshalErr := yaml.Unmarshal(lastCfg, &parsedCfg); unmarshalErr == nil {
		c.triggerVersionConvergence(ctx, parsedCfg.Steward.Upgrade.DesiredVersion, parsedCfg.Steward.Upgrade.AllowDowngrade)
	}

	return nil
}

// triggerVersionConvergence checks whether the running binary version matches
// the controller-declared desired_version and, if not, re-issues the launcher
// swap using the last staged binary. It is idempotent: a no-op when versions
// already match, when desired_version is absent, or when no binary has been
// staged for the desired version yet. (Issue #2260)
func (c *TransportClient) triggerVersionConvergence(ctx context.Context, desiredVersion string, cfgAllowDowngrade bool) {
	if desiredVersion == "" {
		return
	}

	if !stewardBinaryVersionRe.MatchString(desiredVersion) {
		c.logger.Warn("desired_version has invalid format; skipping version convergence",
			"desired_version", logging.SanitizeLogValue(desiredVersion))
		return
	}

	runningVersion := version.Short()
	if desiredVersion == runningVersion {
		return
	}

	// Downgrade guard: refuse if desired_version is older and downgrade is not
	// permitted. cfgAllowDowngrade covers inheritance from the controller cfg;
	// c.upgradeAllowDowngrade covers the initial local steward.cfg value.
	c.mu.RLock()
	allowDowngrade := c.upgradeAllowDowngrade || cfgAllowDowngrade
	stagedVersion := c.lastStagedVersion
	stagedPath := c.lastStagedBinaryPath
	lPathOverride := c.launcherPathOverride
	c.mu.RUnlock()

	if !allowDowngrade && !isNewerVersion(desiredVersion, version.Version) {
		c.logger.Warn("desired_version is not newer than running version and downgrade is not permitted",
			"desired_version", logging.SanitizeLogValue(desiredVersion),
			"running_version", runningVersion)
		return
	}

	if stagedVersion != desiredVersion || stagedPath == "" {
		// Nothing staged for the desired version. Try to self-fetch it from the
		// controller (Issue #2833) so declaring a desired_version converges hands-off,
		// with no controller push required. selfFetchDesiredVersion verifies, stages,
		// and swaps on success; on any failure it degrades safe and we retry next cycle.
		if err := c.selfFetchDesiredVersion(ctx, desiredVersion); err != nil {
			if errors.Is(err, errSelfFetchNotConfigured) {
				c.logger.Info("Version convergence: desired_version differs from running; self-fetch not configured, awaiting controller binary push",
					"desired_version", logging.SanitizeLogValue(desiredVersion),
					"running_version", runningVersion,
					"staged_version", logging.SanitizeLogValue(stagedVersion))
			} else {
				c.logger.Warn("Version convergence: self-fetch failed; awaiting controller binary push or next retry",
					"desired_version", logging.SanitizeLogValue(desiredVersion),
					"running_version", runningVersion,
					"error", err.Error())
			}
		}
		return
	}

	lPath := lPathOverride
	if lPath == "" {
		lPath = launcherPath()
	}

	c.logger.Info("Version convergence: retrying launcher swap for desired version",
		"desired_version", logging.SanitizeLogValue(desiredVersion),
		"running_version", runningVersion)

	if err := c.execLauncherSwap(ctx, lPath, desiredVersion, stagedPath, allowDowngrade); err != nil {
		c.logger.Warn("Version convergence: launcher swap failed",
			"desired_version", logging.SanitizeLogValue(desiredVersion),
			"error", err)
		return
	}

	c.logger.Info("Version convergence: launcher swap succeeded",
		"desired_version", logging.SanitizeLogValue(desiredVersion))

	c.mu.RLock()
	launcherManaged := c.launcherManaged
	c.mu.RUnlock()
	if launcherManaged {
		c.scheduleGracefulShutdownAfterSwap()
	}
}

// setCurrentDNAFromAttrs enriches raw collected attributes with the running
// steward version, then atomically updates currentDNAAttrs and currentDNAHash
// under dnaMu. It does not touch lastPublishedDNA, so heartbeat hash and
// publish-delta state are tracked independently. (Issue #2521)
func (c *TransportClient) setCurrentDNAFromAttrs(attrs map[string]string) {
	enriched := make(map[string]string, len(attrs)+1)
	for k, v := range attrs {
		enriched[k] = v
	}
	enriched["steward.version"] = version.Short()
	hash := dna.ComputeHash(enriched)
	c.dnaMu.Lock()
	c.currentDNAAttrs = enriched
	c.currentDNAHash = hash
	c.dnaMu.Unlock()
}

// RefreshCurrentDNA collects the current DNA attributes from the configured
// DNACollector and updates currentDNAHash so the next heartbeat carries a
// truthful, non-empty hash. It does not publish a delta to the controller.
//
// If the collector also implements FragmentCollector, currentDNAFragments and
// currentDNAAggregateRoot are updated for the partial-sync protocol (ADR-017 §7).
//
// This is called by the reconnect path (tryReconnectWithStoredIdentity) before
// the first SendHeartbeat so the steward never reports an empty hash immediately
// after a reconnect. (Issue #2521)
func (c *TransportClient) RefreshCurrentDNA(ctx context.Context) error {
	c.mu.RLock()
	collector := c.dnaCollector
	c.mu.RUnlock()

	if collector == nil {
		return nil
	}

	attrs, err := collector.CollectAttributes(ctx)
	if err != nil {
		return fmt.Errorf("DNA collection failed: %w", err)
	}

	// Collect fragments before the empty-attrs guard so a hardware-facts-only
	// steward (whose attrs map is empty) still updates its partial-sync state
	// (ADR-017 §7) when fragments are present (Issue #3332).
	var frags []*commonpb.Fragment
	if fc, ok := collector.(FragmentCollector); ok {
		collected, fragErr := fc.CollectFragmentsTracked(ctx)
		if fragErr != nil {
			c.logger.Warn("fragment collection failed; partial-sync root not updated", "error", fragErr)
		} else {
			frags = collected
		}
	}

	if len(attrs) == 0 && len(frags) == 0 {
		return nil
	}
	if len(attrs) > 0 {
		c.setCurrentDNAFromAttrs(attrs)
	}
	if len(frags) > 0 {
		c.setCurrentDNAFragments(frags)
	}
	return nil
}

// setCurrentDNAFragments updates currentDNAFragments and currentDNAAggregateRoot
// under dnaMu. Called when the wired collector implements FragmentCollector.
func (c *TransportClient) setCurrentDNAFragments(fragments []*commonpb.Fragment) {
	manifest := make([]*commonpb.ManifestEntry, 0, len(fragments))
	for _, f := range fragments {
		manifest = append(manifest, &commonpb.ManifestEntry{
			FragmentId:   f.GetFragmentId(),
			FragmentHash: f.GetFragmentHash(),
		})
	}
	root, err := dna.AggregateRoot(manifest)
	if err != nil {
		c.logger.Warn("failed to compute aggregate root; partial-sync root not updated", "error", err)
		return
	}
	c.dnaMu.Lock()
	c.currentDNAFragments = fragments
	c.currentDNAAggregateRoot = root
	c.dnaMu.Unlock()
}

// PublishCurrentDNA collects the FULL composite DNA (hardware facts + module
// state) via the wired collector and publishes it. Every DNA publish must be
// composite: PublishDNAUpdate delta-compresses against the last publish, so a
// host-only publish would REMOVE previously-published module keys (cluster:*,
// vm:*) — the clobber that made module DNA flicker in and out (#2520). Use this
// for one-shot startup/selector publishes instead of a raw host-only collector.
func (c *TransportClient) PublishCurrentDNA(ctx context.Context) error {
	c.mu.RLock()
	collector := c.dnaCollector
	c.mu.RUnlock()
	if collector == nil {
		return nil
	}
	attrs, err := collector.CollectAttributes(ctx)
	if err != nil {
		return err
	}
	// Collect fragments alongside attrs so a hardware-facts-only steward (empty
	// attrs) still updates its partial-sync state (Issue #3332).
	frags := collector.CollectFragments(ctx)
	if len(attrs) == 0 && len(frags) == 0 {
		return nil
	}
	// Fragments are recorded whenever they are present, not only on the
	// attrs-empty path: a steward with managed resources has BOTH a non-empty
	// attribute map and host:* fragments, and returning early after the publish
	// would leave currentDNAFragments/currentDNAAggregateRoot stale for the
	// sync_dna partial-sync path. Same ordering as runDNARefreshTick.
	if len(frags) > 0 {
		c.setCurrentDNAFragments(frags)
	}
	if len(attrs) == 0 {
		// Nothing attribute-based to publish; the fragment state is updated above.
		return nil
	}
	c.setCurrentDNAFromAttrs(attrs)
	return c.PublishDNAUpdate(ctx, attrs, "", "")
}

// StartDNARefreshLoop starts a background goroutine that re-collects system DNA
// attributes on the configured interval and publishes delta updates to the
// controller when at least one attribute value has changed.
//
// If no DNACollector was provided, the loop exits immediately after logging a
// warning. The loop exits cleanly when ctx is cancelled or Disconnect is called.
// The existing 15-second graceful disconnect window applies — the loop does not
// block shutdown. (Issue #1915)
//
// It returns a channel that is closed when the loop goroutine has fully exited.
// When no collector is configured the returned channel is already closed (no
// goroutine is spawned). Production callers may ignore the return value; tests
// use it to confirm loop shutdown deterministically instead of sleeping.
func (c *TransportClient) StartDNARefreshLoop(ctx context.Context) <-chan struct{} {
	c.mu.RLock()
	interval := c.dnaRefreshInterval
	collector := c.dnaCollector
	tick := c.dnaRefreshTick
	c.mu.RUnlock()

	done := make(chan struct{})

	if collector == nil {
		c.logger.Warn("DNA refresh loop started without a collector; DNA will not be refreshed periodically")
		close(done)
		return done
	}

	c.logger.Info("Starting DNA refresh loop", "interval", interval)
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.dnaRefreshStop:
				return
			case <-ticker.C:
				// Re-read collector on each tick so tests can inject a new
				// implementation after the loop has started.
				c.mu.RLock()
				currentCollector := c.dnaCollector
				c.mu.RUnlock()
				if currentCollector != nil {
					c.runDNARefreshTick(ctx, currentCollector)
				}
				// Signal that this tick has been fully processed so tests can
				// synchronize without wall-clock sleeps. No-op in production.
				c.notifyDNARefreshTick(ctx, tick)
			}
		}
	}()
	return done
}

// runDNARefreshTick performs a single collect-and-publish cycle for the DNA
// refresh loop. Collection or publish errors are logged and swallowed so a
// transient failure never terminates the loop.
func (c *TransportClient) runDNARefreshTick(ctx context.Context, collector DNACollector) {
	attrs, err := collector.CollectAttributes(ctx)
	if err != nil {
		c.logger.Warn("DNA refresh collection failed", "error", err)
		return
	}
	// Collect fragments alongside attrs so a hardware-facts-only steward (empty
	// attrs) still updates its partial-sync state on each tick (Issue #3332).
	frags := collector.CollectFragments(ctx)
	if len(attrs) == 0 && len(frags) == 0 {
		return
	}
	// Update currentDNAFragments BEFORE PublishDNAUpdate so the fragment delta
	// computed inside PublishDNAUpdate reflects this tick's collected state, not
	// the previous tick's. (Issue #3330)
	if len(frags) > 0 {
		c.setCurrentDNAFragments(frags)
	}
	if len(attrs) > 0 {
		// Always refresh the current snapshot so heartbeats carry a truthful hash
		// even when no delta is published. (Issue #2521)
		c.setCurrentDNAFromAttrs(attrs)
		if err := c.PublishDNAUpdate(ctx, attrs, "", ""); err != nil {
			c.logger.Warn("DNA refresh publish failed", "error", err)
		}
	}
}

// notifyDNARefreshTick delivers a per-tick completion signal on the optional
// dnaRefreshTick channel. The send is guarded by ctx.Done and dnaRefreshStop so
// the loop never deadlocks at shutdown even if no receiver is waiting. When the
// channel is nil (production) it returns immediately.
func (c *TransportClient) notifyDNARefreshTick(ctx context.Context, tick chan struct{}) {
	if tick == nil {
		return
	}
	select {
	case tick <- struct{}{}:
	case <-ctx.Done():
	case <-c.dnaRefreshStop:
	}
}

// SetShutdownFunc wires the graceful-shutdown trigger used after a successful
// push_steward_binary swap. In production main.go passes the steward's RUN
// context (runCtx) and its cancel func (runCancel) so a pushed upgrade ends the
// process cleanly (runSteward then disconnects and returns), letting the launcher
// re-exec the staged binary. Passing a nil fn disables the auto-apply trigger (the
// steward would then only pick up the staged binary on the next restart).
//
// runCtx is stored so the grace-delay timer in scheduleGracefulShutdownAfterSwap
// can watch the PROCESS lifecycle for early-exit — never the per-command context,
// which is cancelled the instant a command handler returns and would always
// suppress the self-exit. (Issue #2001, #2003)
func (c *TransportClient) SetShutdownFunc(runCtx context.Context, fn func()) {
	c.mu.Lock()
	c.shutdownCtx = runCtx
	c.shutdownFunc = fn
	// A launcher-managed swap can be staged in the window between command
	// subscription (Connect) and this wiring, where scheduleGracefulShutdownAfterSwap
	// found shutdownFunc==nil and deferred the self-exit. Now that the trigger is
	// wired, fire it so the launcher re-execs the staged binary (its startup-window
	// auto-rollback still guards a broken binary). (Issue #2602)
	pending := c.pendingUpgradeSelfExit && fn != nil
	c.pendingUpgradeSelfExit = false
	c.mu.Unlock()

	if pending {
		c.logger.Info("Firing deferred launcher self-exit for a swap staged before the shutdown trigger was wired")
		c.scheduleGracefulShutdownAfterSwap()
	}
}

// Disconnect closes all gRPC connections to the controller.
func (c *TransportClient) Disconnect(ctx context.Context) error {
	c.logger.Info("Disconnecting from controller")

	c.mu.Lock()
	defer c.mu.Unlock()

	// Disconnect can be called more than once — e.g. a signal/SCM stop racing a
	// pushed-upgrade graceful self-exit (Issue #2001). Closing the stop channels
	// twice would panic, so gate the close on disconnected. Subsequent calls
	// still tear down the data/control planes (those Close/Stop calls are
	// idempotent at their own layers) and return cleanly.
	if !c.disconnected {
		c.disconnected = true
		// Stop heartbeat, convergence, and DNA refresh loops.
		close(c.heartbeatStop)
		close(c.convergenceStop)
		if c.dnaRefreshStop != nil {
			close(c.dnaRefreshStop)
		}
	}

	// Stop module monitors before closing connections so no further ExecuteResource
	// calls fire against a disconnected transport (Issue #2435).
	if c.configExecutor != nil {
		c.configExecutor.StopMonitors()
	}

	// Drain and stop the event emitter before closing the gRPC connection so
	// buffered convergence events are flushed to the controller first.
	if c.eventEmitter != nil {
		c.eventEmitter.Close()
	}

	// Close data plane session
	if c.dataPlaneSession != nil {
		if err := c.dataPlaneSession.Close(ctx); err != nil {
			c.logger.Warn("Failed to close data plane session", "error", err)
		}
	}

	// Stop control plane provider
	if c.controlPlane != nil {
		if err := c.controlPlane.Stop(ctx); err != nil {
			c.logger.Warn("Failed to stop control plane", "error", err)
		}
	}

	c.connected = false

	c.logger.Info("Disconnected from controller")
	return nil
}

// IsConnected returns whether the client is connected.
func (c *TransportClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetStewardID returns the steward ID.
func (c *TransportClient) GetStewardID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stewardID
}

// GetTenantID returns the tenant ID.
func (c *TransportClient) GetTenantID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tenantID
}

// SetStewardID sets the steward ID (used after HTTP registration).
func (c *TransportClient) SetStewardID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stewardID = id
}

// GetConfigExecutor returns the configuration executor. Returns nil when not yet
// initialized (before InitializeConfigExecutor is called). The executor implements
// moduleDNASource after StartMonitors is called — wire it into the DNA collector
// adapter immediately after InitializeConfigExecutor succeeds (Issue #2435).
func (c *TransportClient) GetConfigExecutor() *execution.Executor {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.configExecutor
}

// CollectModuleDNAAttributes delegates to the CURRENT config executor's module DNA
// snapshot. Wiring the DNA collector adapter to the client (not a captured executor
// instance) is deliberate: InitializeConfigExecutor replaces c.configExecutor on
// every connect/reconnect, so a captured *Executor reference goes stale and module
// DNA silently stops flowing (#2520). Delegating through the stable client always
// reads the live executor. Returns nil before the executor exists.
func (c *TransportClient) CollectModuleDNAAttributes(ctx context.Context) map[string]string {
	c.mu.RLock()
	executor := c.configExecutor
	c.mu.RUnlock()
	if executor == nil {
		return nil
	}
	return executor.CollectModuleDNAAttributes(ctx)
}

// CollectModuleFragments delegates to the CURRENT config executor's ADR-017
// fragment collector (cluster:* resources, #2908). It delegates through the
// stable client for the same reason CollectModuleDNAAttributes does:
// InitializeConfigExecutor replaces c.configExecutor on every connect/reconnect,
// so a captured *Executor reference would go stale. Returns nil before the
// executor exists.
func (c *TransportClient) CollectModuleFragments(ctx context.Context) []*commonpb.Fragment {
	c.mu.RLock()
	executor := c.configExecutor
	c.mu.RUnlock()
	if executor == nil {
		return nil
	}
	return executor.CollectModuleFragments(ctx)
}

// SetTenantID sets the tenant ID (used after HTTP registration).
func (c *TransportClient) SetTenantID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tenantID = id
}

// SetStatusFunc wires a health-status provider into the periodic heartbeat so the
// controller receives the real subsystem state instead of a hardcoded "healthy".
// Called from cmd/steward/main.go after connection to pass subsystemState.status.
// Thread-safe. (Issue #2034)
func (c *TransportClient) SetStatusFunc(f func() string) {
	c.mu.Lock()
	c.statusFunc = f
	c.mu.Unlock()
}

// heartbeatStatus returns the current health status string for the heartbeat.
// Returns the value from statusFunc if set, otherwise "healthy". (Issue #2034)
func (c *TransportClient) heartbeatStatus() string {
	c.mu.RLock()
	fn := c.statusFunc
	c.mu.RUnlock()
	if fn != nil {
		return fn()
	}
	return "healthy"
}

// SetRevokedVersions updates the cached list of revoked steward versions received
// from the controller. The upgrade handler checks this list before invoking the
// launcher swap. (Issue #1943)
func (c *TransportClient) SetRevokedVersions(versions []string) {
	c.revokedVersionsMu.Lock()
	defer c.revokedVersionsMu.Unlock()
	c.revokedVersions = make([]string, len(versions))
	copy(c.revokedVersions, versions)
}

// PublishUpgradeLifecycleEvent emits a single upgrade lifecycle event (committed
// or rolled-back) detected from launcher-written flag files on startup. Called by
// cmd/steward/main.go's checkUpgradeFlagFiles. (Issue #1943)
func (c *TransportClient) PublishUpgradeLifecycleEvent(ctx context.Context, eventType, version string) error {
	c.mu.RLock()
	sid := c.stewardID
	tid := c.tenantID
	c.mu.RUnlock()

	var et cpTypes.EventType
	switch eventType {
	case string(cpTypes.EventStewardUpgradeCommitted):
		et = cpTypes.EventStewardUpgradeCommitted
	case string(cpTypes.EventStewardUpgradeRolledBack):
		et = cpTypes.EventStewardUpgradeRolledBack
	default:
		return fmt.Errorf("unknown upgrade lifecycle event type %q", eventType)
	}

	return c.publishEventWithQueue(ctx, &cpTypes.Event{
		ID:        fmt.Sprintf("evt_upg_lc_%d", time.Now().UnixNano()),
		Type:      et,
		StewardID: sid,
		TenantID:  tid,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"version": version,
		},
	})
}

// createTLSConfig creates a TLS configuration for gRPC-over-QUIC with mTLS.
// Sets ALPN to "cfgms-grpc" required by the QUIC transport layer.
//
// Source priority (Issue #920):
//  1. certManager path: GetClientCertificate callback (on-demand per handshake)
//  2. Disk path (TLSCertPath): static cert loaded from files
//  3. Environment variables: CFGMS_TLS_CERT_PATH / KEY / CA
func (c *TransportClient) createTLSConfig() (*tls.Config, error) {
	c.mu.RLock()
	caCertPEMStr := c.caCertPEM
	certPath := c.certPath
	certMgr := c.certManager
	c.mu.RUnlock()

	var tlsConfig *tls.Config
	var caCertPEM []byte // used for CA pool and verifier fallback
	var err error

	if certMgr != nil {
		// Primary path (Issue #920): on-demand client cert per TLS handshake.
		c.logger.Info("Using on-demand TLS certificate loading via CertManager")
		if caCertPEMStr != "" {
			caCertPEM = []byte(caCertPEMStr)
		}
		tlsConfig, err = certMgr.CreateOnDemandClientTLSConfig(caCertPEM, tls.VersionTLS13)
		if err != nil {
			return nil, fmt.Errorf("failed to create on-demand TLS config: %w", err)
		}
		tlsConfig.NextProtos = []string{quictransport.ALPNProtocol}
		return tlsConfig, nil
	}

	// Fallback paths: build TLS config from static cert files.
	var clientCertPEM, clientKeyPEM []byte

	if certPath != "" {
		// Secondary path: certificates on disk.
		caCertPath := filepath.Join(certPath, "ca.crt")
		// #nosec G304 - Certificate paths are controlled via configuration
		caCertPEM, err = os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
		}

		clientCertPath := filepath.Join(certPath, "client.crt")
		clientKeyPath := filepath.Join(certPath, "client.key")
		// #nosec G304 - Certificate paths are controlled via configuration
		clientCertPEM, err = os.ReadFile(clientCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client certificate from %s: %w", clientCertPath, err)
		}
		// #nosec G304 - Certificate paths are controlled via configuration
		clientKeyPEM, err = os.ReadFile(clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client key from %s: %w", clientKeyPath, err)
		}

		c.logger.Info("Loaded TLS configuration from disk", "cert_path", certPath)
	} else {
		// Tertiary path: environment variables.
		certFile := os.Getenv("CFGMS_TLS_CERT_PATH")
		keyFile := os.Getenv("CFGMS_TLS_KEY_PATH")
		caFile := os.Getenv("CFGMS_TLS_CA_PATH")

		if certFile == "" || keyFile == "" || caFile == "" {
			// No TLS config available — provider will connect without mTLS.
			return nil, nil
		}

		// #nosec G304 G703 -- certificate paths come only from the steward's
		// administrator-controlled process environment, never protocol input.
		clientCertPEM, err = os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client certificate: %w", err)
		}
		// #nosec G304 G703 -- the private-key path is administrator-controlled
		// startup configuration and is not influenced by a controller request.
		clientKeyPEM, err = os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client key: %w", err)
		}
		// #nosec G304 G703 -- the CA path is administrator-controlled startup
		// configuration and is not influenced by a controller request.
		caCertPEM, err = os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		c.logger.Info("Loaded TLS configuration from environment variables")
	}

	tlsConfig, err = cert.CreateClientTLSConfig(clientCertPEM, clientKeyPEM, caCertPEM, "", tls.VersionTLS13)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	// gRPC-over-QUIC requires the cfgms-grpc ALPN protocol.
	tlsConfig.NextProtos = []string{quictransport.ALPNProtocol}

	return tlsConfig, nil
}

// handlePushSigningCert processes a COMMAND_TYPE_PUSH_SIGNING_CERT command from the
// controller. It validates the pushed cert, persists it atomically (persist-before-ack),
// then updates the in-memory signing cert set and rebuilds the MultiVerifier (Issue #1816).
func (c *TransportClient) handlePushSigningCert(_ context.Context, cmd *cpTypes.Command) error {
	c.logger.Info("Received push_signing_cert command", "command_id", cmd.ID)

	// Extract cert_pem (base64-encoded PEM) from params.
	certPEMB64, ok := cmd.Params["cert_pem"].(string)
	if !ok || certPEMB64 == "" {
		return fmt.Errorf("push_signing_cert: missing or empty cert_pem param")
	}

	// Decode base64 → PEM bytes.
	pemBytes, err := decodeBase64(certPEMB64)
	if err != nil {
		return fmt.Errorf("push_signing_cert: decode cert_pem: %w", err)
	}

	// Parse and validate the cert.
	x509Cert, err := cert.ParseCertificateFromPEM(pemBytes)
	if err != nil {
		return fmt.Errorf("push_signing_cert: parse cert: %w", err)
	}
	if time.Now().After(x509Cert.NotAfter) {
		return fmt.Errorf("push_signing_cert: pushed cert is expired (NotAfter=%s)", x509Cert.NotAfter.Format(time.RFC3339))
	}
	hasCodeSigning := false
	for _, eku := range x509Cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
			break
		}
	}
	if !hasCodeSigning {
		return fmt.Errorf("push_signing_cert: cert missing ExtKeyUsageCodeSigning")
	}

	// Parse optional overlap_expires_at (RFC3339).
	var overlapExpiresAt *time.Time
	if raw, ok := cmd.Params["overlap_expires_at"].(string); ok && raw != "" {
		t, parseErr := time.Parse(time.RFC3339, raw)
		if parseErr != nil {
			return fmt.Errorf("push_signing_cert: parse overlap_expires_at %q: %w", raw, parseErr)
		}
		overlapExpiresAt = &t
	}

	// Build updated cert PEMs slice: retire_old=true replaces; otherwise append.
	retireOld, _ := cmd.Params["retire_old"].(bool)

	c.mu.RLock()
	existing := make([]string, len(c.signingCertPEMs))
	copy(existing, c.signingCertPEMs)
	c.mu.RUnlock()

	var newPEMs []string
	newPEMStr := string(pemBytes)
	if retireOld {
		newPEMs = []string{newPEMStr}
	} else {
		newPEMs = append(existing, newPEMStr)
	}

	// Persist BEFORE updating in-memory state (persist-before-ack).
	// If persist fails, return error — controller will retry.
	if c.identityPersistFunc != nil {
		if err := c.identityPersistFunc(newPEMs, overlapExpiresAt); err != nil {
			return fmt.Errorf("push_signing_cert: persist identity: %w", err)
		}
	}

	// Update in-memory state under lock only after successful persistence.
	c.mu.Lock()
	c.signingCertPEMs = newPEMs
	c.overlapExpiresAt = overlapExpiresAt
	c.mu.Unlock()

	// Refresh the command handler's verifier so subsequent commands signed with the
	// newly pushed cert are accepted without reconnecting. Without this, the handler's
	// verifier remains a snapshot from connection time and rejects commands signed by
	// the new cert even after the steward's trust set has been updated (Issue #1844).
	c.mu.RLock()
	handler := c.commandHandler
	c.mu.RUnlock()
	if handler != nil {
		handler.UpdateVerifier(c.buildVerifierOnDemand())
	}

	// Resolve the applied cert's serial for the log. Prefer the controller-supplied
	// "serial" param (exact controller-side string form); fall back to the parsed
	// cert's serial so the serial is always recorded even for older controllers or
	// pushes that omit the param.
	appliedSerial, _ := cmd.Params["serial"].(string)
	if appliedSerial == "" {
		appliedSerial = x509Cert.SerialNumber.String()
	}

	c.logger.Info("Signing cert push applied",
		"command_id", cmd.ID,
		"serial", appliedSerial,
		"cert_count", len(newPEMs),
		"retire_old", retireOld)
	return nil
}

// decodeBase64 decodes a standard base64-encoded string, accepting both padded
// and unpadded variants.
func decodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	return b, err
}

// buildVerifierOnDemand constructs a config/command signature verifier from the
// controller's certificate PEMs stored in the client. Returns nil when no
// certificate is available — callers treat a nil verifier as "skip verification".
//
// When signingCertPEMs contains multiple entries (rotation overlap window), a
// MultiVerifier is returned so either cert can verify a signature. When
// overlapExpiresAt is set and in the past, only the newest cert is included.
//
// The verifier is NOT cached (Issue #920 removes the configVerifier field).
// The cost is trivial — each call parses a PEM block and builds a verifier struct.
func (c *TransportClient) buildVerifierOnDemand() signature.Verifier {
	c.mu.RLock()
	signingCertPEMs := make([]string, len(c.signingCertPEMs))
	copy(signingCertPEMs, c.signingCertPEMs)
	overlapAt := c.overlapExpiresAt
	serverCertPEM := c.serverCertPEM
	caCertPEM := c.caCertPEM
	certPath := c.certPath
	c.mu.RUnlock()

	// Build verifier from the signing cert set when available.
	if len(signingCertPEMs) > 0 {
		// Client-side overlap expiry: when the overlap window has passed, drop all
		// but the most recently pushed cert to close the replay-attack window.
		activePEMs := signingCertPEMs
		if overlapAt != nil && time.Now().After(*overlapAt) && len(signingCertPEMs) > 1 {
			activePEMs = signingCertPEMs[len(signingCertPEMs)-1:]
		}

		if len(activePEMs) == 1 {
			verifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: []byte(activePEMs[0])})
			if err != nil {
				c.logger.Warn("Failed to create signing cert verifier", "error", err)
				return nil
			}
			c.logger.Debug("Signing cert verifier built", "key_fingerprint", verifier.KeyFingerprint())
			return verifier
		}

		// Multiple active certs — build MultiVerifier for OR-semantics during overlap window.
		var certs []*x509.Certificate
		for _, pem := range activePEMs {
			x509Cert, parseErr := cert.ParseCertificateFromPEM([]byte(pem))
			if parseErr != nil {
				c.logger.Warn("Failed to parse signing cert PEM for verifier", "error", parseErr)
				continue
			}
			certs = append(certs, x509Cert)
		}
		if len(certs) == 0 {
			return nil
		}
		mv, err := signature.NewMultiVerifier(certs)
		if err != nil {
			c.logger.Warn("Failed to create multi-signing-cert verifier", "error", err)
			return nil
		}
		c.logger.Debug("Multi-signing-cert verifier built", "cert_count", len(certs), "key_fingerprint", mv.KeyFingerprint())
		return mv
	}

	// Legacy fallback paths (serverCertPEM, disk signing.crt, caCertPEM).
	var certPEM []byte

	switch {
	case serverCertPEM != "":
		certPEM = []byte(serverCertPEM)
		c.logger.Debug("Using server certificate for signature verification")
	case certPath != "":
		// Story #377: prefer signing.crt, fall back to server.crt.
		signingPath := filepath.Join(certPath, "signing.crt")
		serverPath := filepath.Join(certPath, "server.crt")
		// #nosec G304 - Certificate paths are controlled via configuration
		if raw, err := os.ReadFile(signingPath); err == nil {
			certPEM = raw
			c.logger.Debug("Using signing.crt from disk for signature verification")
		} else if raw, err := os.ReadFile(serverPath); err == nil {
			certPEM = raw
		} else if caCertPEM != "" {
			certPEM = []byte(caCertPEM)
			c.logger.Warn("Signing/server certificate not found; falling back to CA for signature verification")
		}
	case caCertPEM != "":
		certPEM = []byte(caCertPEM)
		c.logger.Warn("No server certificate available; using CA for signature verification")
	}

	if len(certPEM) == 0 {
		return nil
	}

	verifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: certPEM})
	if err != nil {
		c.logger.Warn("Failed to create configuration verifier", "error", err)
		return nil
	}
	c.logger.Debug("Configuration signature verifier built", "key_fingerprint", verifier.KeyFingerprint())
	return verifier
}

// publishEventWithQueue attempts to publish an event via the control plane.
// If the control plane is unavailable or the publish fails, the event is
// queued locally for delivery when the connection is restored (Issue #419).
//
// Returns nil when the event was either published or queued successfully.
// Returns an error only when the control plane is unavailable AND no offline
// queue is configured.
func (c *TransportClient) publishEventWithQueue(ctx context.Context, event *cpTypes.Event) error {
	c.mu.RLock()
	cp := c.controlPlane
	q := c.offlineQueue
	c.mu.RUnlock()

	if cp != nil {
		if err := cp.PublishEvent(ctx, event); err == nil {
			return nil
		}
		// Fall through to queue the event.
		c.logger.Warn("Failed to publish event to controller, queuing for later delivery",
			"event_id", event.ID, "event_type", event.Type)
	}

	if q != nil {
		if q.Enqueue(event) {
			c.logger.Info("Event queued for offline delivery",
				"event_id", event.ID, "event_type", event.Type, "queue_depth", q.Len())
		}
		return nil
	}

	return fmt.Errorf("control plane unavailable and no offline queue configured")
}

// drainOfflineQueue delivers all queued events to the controller in order.
// Called immediately after a successful Connect() to resync reports that
// accumulated during any offline period (Issue #419).
func (c *TransportClient) drainOfflineQueue(ctx context.Context) {
	c.mu.RLock()
	q := c.offlineQueue
	cp := c.controlPlane
	c.mu.RUnlock()

	if q == nil || q.Len() == 0 {
		return
	}

	depth := q.Len()
	c.logger.Info("Draining offline event queue after reconnect", "depth", depth)

	delivered := q.Drain(func(event *cpTypes.Event) error {
		return cp.PublishEvent(ctx, event)
	})

	c.logger.Info("Offline queue drain complete",
		"delivered", delivered, "remaining", q.Len())
}

// startHeartbeat starts the periodic heartbeat goroutine.
// Each tick fires after base + uniform jitter in [0, 10 s) so the effective
// interval is always in [20 s, 30 s). Jitter keeps 50k stewards from
// synchronising their heartbeats and spiking controller CPU (epic #1664).
// After each successful heartbeat, queued offline events are drained so the
// controller receives them promptly (Issue #419).
func (c *TransportClient) startHeartbeat() {
	const (
		jitterMax = 10 * time.Second
	)

	rng := c.rng
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano())) //#nosec G404 -- non-crypto jitter
	}

	nextInterval := func() time.Duration {
		return c.heartbeatInterval + time.Duration(rng.Int63n(int64(jitterMax)))
	}

	timer := time.NewTimer(nextInterval())
	defer timer.Stop()

	for {
		select {
		case <-c.heartbeatStop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := c.SendHeartbeat(ctx, c.heartbeatStatus(), nil); err != nil {
				c.logger.Warn("Failed to send heartbeat", "error", err)
			} else {
				// Heartbeat succeeded — drain any events queued during a
				// transient disconnect that did not trigger a full reconnect.
				c.drainOfflineQueue(ctx)
			}
			cancel()
			timer.Reset(nextInterval())
		}
	}
}

// ---------------------------------------------------------------------------
// DNA sync helpers (Issue #418)
// ---------------------------------------------------------------------------

// computeFragmentDelta returns fragments from current that differ from old by
// fragment_id/fragment_hash comparison. A fragment is "changed" when its
// fragment_id is absent from old, or its fragment_hash differs. Fragments
// present in old but absent from current are included as sentinel entries
// carrying only the fragment_id so the controller knows they were removed.
// Returns nil (empty) when nothing changed — callers check len(delta) > 0.
// (Issue #3330, replaces computeDelta's flat-map diff for the change-notification path)
func computeFragmentDelta(old, current []*commonpb.Fragment) []*commonpb.Fragment {
	oldByID := make(map[string]string, len(old))
	for _, f := range old {
		if f != nil {
			oldByID[f.GetFragmentId()] = f.GetFragmentHash()
		}
	}

	var delta []*commonpb.Fragment
	seen := make(map[string]bool, len(current))
	for _, f := range current {
		if f == nil {
			continue
		}
		seen[f.GetFragmentId()] = true
		oldHash, existed := oldByID[f.GetFragmentId()]
		if !existed || oldHash != f.GetFragmentHash() {
			delta = append(delta, f)
		}
	}

	// Sentinel entries for fragments removed from current.
	for _, f := range old {
		if f != nil && !seen[f.GetFragmentId()] {
			delta = append(delta, &commonpb.Fragment{FragmentId: f.GetFragmentId()})
		}
	}
	return delta
}

// marshalFragmentsToJSONString encodes each fragment with protojson and returns
// a JSON array string suitable for storage in an event Details value. protojson
// is used instead of encoding/json because commonpb.Fragment is a proto message
// and encoding/json mis-handles proto well-known types (timestamps, oneofs,
// enums-as-numbers). The plain JSON string round-trips safely through the
// control-plane envelope's encoding/json pass without requiring a byte-envelope.
// (Issue #3330)
func marshalFragmentsToJSONString(frags []*commonpb.Fragment) (string, error) {
	opts := protojson.MarshalOptions{EmitUnpopulated: false}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, frag := range frags {
		if i > 0 {
			sb.WriteByte(',')
		}
		b, err := opts.Marshal(frag)
		if err != nil {
			return "", fmt.Errorf("marshal fragment %q: %w", frag.GetFragmentId(), err)
		}
		sb.Write(b)
	}
	sb.WriteByte(']')
	return sb.String(), nil
}

// paramKeys returns the sorted key names from a command params map.
// Values are not logged — they may contain secret fingerprints, tokens, or paths.
func paramKeys(params map[string]interface{}) []string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// copyStringMap returns a shallow copy of a string→string map.
// Returns nil when the input is nil.
func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Tier-2 whole-domain observe sweep (Issue #3104, ADR-024 Amendment 1 §3)
// ---------------------------------------------------------------------------

// checkAndTriggerObserveSweep is called by StartConvergenceLoop on each
// convergence tick. It increments the Tier-2 counter; when the counter reaches
// observeSweepN it fires a whole-domain observe sweep request and resets the
// counter. N=0 disables the sweep.
//
// This method always signals observeSweepTick on completion so that tests can
// synchronize with the cadence counter without using wall-clock sleeps — the
// same pattern as notifyDNARefreshTick.
func (c *TransportClient) checkAndTriggerObserveSweep(ctx context.Context) {
	c.mu.Lock()
	n := c.observeSweepN
	if n <= 0 {
		c.mu.Unlock()
		c.notifyObserveSweepTick(ctx)
		return
	}
	c.observeSweepCounter++
	fire := c.observeSweepCounter >= n
	if fire {
		c.observeSweepCounter = 0
	}
	c.mu.Unlock()

	if fire {
		c.triggerObserveSweep(ctx)
	}
	c.notifyObserveSweepTick(ctx)
}

// notifyObserveSweepTick signals observeSweepTick after each
// checkAndTriggerObserveSweep call. Nil in production; non-nil in tests.
// The send is guarded by ctx.Done so an un-drained channel never blocks.
func (c *TransportClient) notifyObserveSweepTick(ctx context.Context) {
	c.mu.RLock()
	tick := c.observeSweepTick
	c.mu.RUnlock()
	if tick == nil {
		return
	}
	select {
	case tick <- struct{}{}:
	case <-ctx.Done():
	}
}

// observeSweepEventSeq is a monotonically increasing counter appended to
// Tier-2 observe sweep event IDs. time.Now().UnixNano() alone can collide
// when checkAndTriggerObserveSweep fires in tight succession under coarse
// clock resolution (observed on Windows CI runners); the offline queue
// de-duplicates events by ID, so a collision silently drops the later event.
// The counter guarantees uniqueness independent of clock resolution.
var observeSweepEventSeq atomic.Int64

// newObserveSweepEventID builds a collision-resistant ID for a Tier-2 observe
// sweep event from a nanosecond timestamp and a monotonic sequence number.
func newObserveSweepEventID(nowUnixNano, seq int64) string {
	return fmt.Sprintf("evt_obs_%d_%d", nowUnixNano, seq)
}

// triggerObserveSweep publishes an EventObserveSweepRequest carrying the current
// baseline DNA to the controller. The controller resolves the observe-module set
// and responds with CommandObserveModules. (Issue #3104, ADR-024 Amendment 1 §3)
func (c *TransportClient) triggerObserveSweep(ctx context.Context) {
	c.mu.RLock()
	sid := c.stewardID
	tid := c.tenantID
	c.mu.RUnlock()

	if sid == "" {
		c.logger.Debug("Tier-2 observe sweep skipped: steward not yet registered")
		return
	}

	c.dnaMu.RLock()
	attrs := copyStringMap(c.currentDNAAttrs)
	c.dnaMu.RUnlock()

	dnaJSON, err := json.Marshal(attrs)
	if err != nil {
		c.logger.Warn("Tier-2 observe sweep: failed to marshal baseline DNA", "error", err)
		return
	}

	event := &cpTypes.Event{
		ID:        newObserveSweepEventID(time.Now().UnixNano(), observeSweepEventSeq.Add(1)),
		Type:      cpTypes.EventObserveSweepRequest,
		StewardID: sid,
		TenantID:  tid,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"baseline_dna": string(dnaJSON),
		},
	}

	if err := c.publishEventWithQueue(ctx, event); err != nil {
		c.logger.Warn("Tier-2 observe sweep: failed to publish sweep request", "error", err)
	}
}

// handleObserveModules processes a COMMAND_TYPE_OBSERVE_MODULES command from the
// controller. It loads each specified module, calls Get read-only, and merges
// the resulting fragments into currentDNAFragments through the existing
// setCurrentDNAFragments path (ADR-024 Amendment 1 §2 — no new parallel channel).
//
// Sweeps are single-flight: while one sweep is running, any further
// observe_modules command is dropped instead of running concurrently. The
// controller re-requests on the next cadence tick, so no observation is lost.
func (c *TransportClient) handleObserveModules(ctx context.Context, cmd *cpTypes.Command) error {
	if !c.observeSweepInFlight.CompareAndSwap(false, true) {
		c.logger.Warn("observe_modules: sweep already in flight; dropping overlapping command",
			"command_id", logging.SanitizeLogValue(cmd.ID))
		return nil
	}
	defer c.observeSweepInFlight.Store(false)

	c.mu.RLock()
	loader := c.observeModuleLoader
	c.mu.RUnlock()

	if loader == nil {
		c.logger.Warn("observe_modules: no module loader configured; skipping observe sweep")
		return nil
	}

	specs, err := parseObserveModuleSpecs(cmd.Params["modules"])
	if err != nil {
		return fmt.Errorf("observe_modules: %w", err)
	}
	if len(specs) == 0 {
		return nil
	}

	// Load each module and build the inputs for Assembler.Assemble.
	activeModules := make(map[string]modules.Module, len(specs))
	ownership := make(map[string][]modules.OwnershipDeclaration, len(specs))
	for _, spec := range specs {
		mod, loadErr := loader.LoadModule(spec.Name)
		if loadErr != nil {
			c.logger.Warn("observe sweep: module load failed; skipping",
				"module", logging.SanitizeLogValue(spec.Name), "error", loadErr)
			continue
		}
		activeModules[spec.Name] = mod
		ownership[spec.Name] = []modules.OwnershipDeclaration{{Kind: spec.Kind}}
	}

	if len(activeModules) == 0 {
		return nil
	}

	// Snapshot current host-fact fragments as input to the assembler so that
	// module-owned kinds preempt the corresponding host-fact fragments
	// (ADR-016 clause 5, Assembler phase 3).
	c.dnaMu.RLock()
	hostFactFragments := make([]*commonpb.Fragment, len(c.currentDNAFragments))
	copy(hostFactFragments, c.currentDNAFragments)
	c.dnaMu.RUnlock()

	// Merge observe-module fragments with host-fact fragments. The Assembler
	// handles authority resolution per ADR-016 and ADR-017.
	assembler := dna.NewAssembler(c.logger)
	merged, _, assembleErr := assembler.Assemble(ctx, activeModules, ownership, hostFactFragments)
	if assembleErr != nil {
		return fmt.Errorf("observe sweep: assemble fragments: %w", assembleErr)
	}

	// Write through the existing fragment emission path (ADR-024 Amendment 1 §2).
	// setCurrentDNAFragments updates currentDNAAggregateRoot, which the heartbeat
	// loop carries to the controller; the controller detects the change and issues
	// CommandSyncDNA to pull the merged fragment set.
	c.setCurrentDNAFragments(merged)

	c.logger.Info("Tier-2 observe sweep completed",
		"observe_modules", len(activeModules),
		"total_fragments", len(merged))

	return nil
}

// parseObserveModuleSpecs converts the "modules" param from a CommandObserveModules
// command into a []cpTypes.ObserveModuleSpec. It handles the three shapes the param
// can arrive in:
//
//   - string: JSON-encoded array (gRPC wire path)
//   - []interface{}: already-parsed JSON array (in-process path)
//   - []cpTypes.ObserveModuleSpec: native slice (test path)
func parseObserveModuleSpecs(raw interface{}) ([]cpTypes.ObserveModuleSpec, error) {
	if raw == nil {
		return nil, nil
	}

	var specs []cpTypes.ObserveModuleSpec

	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil, nil
		}
		if err := json.Unmarshal([]byte(v), &specs); err != nil {
			return nil, fmt.Errorf("modules param is not a JSON array: %w", err)
		}
	case []interface{}:
		specs = make([]cpTypes.ObserveModuleSpec, 0, len(v))
		for i, elem := range v {
			m, ok := elem.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("modules[%d]: expected object, got %T", i, elem)
			}
			spec := cpTypes.ObserveModuleSpec{}
			if name, ok := m["name"].(string); ok {
				spec.Name = name
			}
			if kind, ok := m["kind"].(string); ok {
				spec.Kind = kind
			}
			specs = append(specs, spec)
		}
	case []cpTypes.ObserveModuleSpec:
		specs = v
	default:
		return nil, fmt.Errorf("modules param has unsupported type %T", raw)
	}

	for i, spec := range specs {
		if spec.Name == "" {
			return nil, fmt.Errorf("modules[%d]: name is required", i)
		}
		if spec.Kind == "" {
			return nil, fmt.Errorf("modules[%d]: kind is required", i)
		}
	}

	return specs, nil
}

// encodeDriftDiffs drains the bounded drift-diff accumulator and encodes each record
// as JSON bytes for DNATransfer.DriftDiffBytes. The returned slice is nil when no
// records are pending.
//
// Records dropped because the accumulator filled between syncs are reported here
// rather than in the drift handler: the drop is only meaningful relative to a sync
// cycle, and reporting at append time would let a drifting fleet spam the log.
func (c *TransportClient) encodeDriftDiffs() [][]byte {
	pending, dropped := c.driftDiffs.Drain()
	if dropped > 0 {
		c.logger.Warn("drift-diff records dropped: accumulator reached capacity between DNA syncs",
			"dropped", dropped, "capacity", c.driftDiffs.Capacity())
	}
	if len(pending) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(pending))
	for _, rec := range pending {
		b, err := json.Marshal(rec)
		if err != nil {
			c.logger.Warn("failed to encode drift-diff record; skipping",
				"fragment_id", logging.SanitizeLogValue(rec.FragmentID),
				"error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		out = append(out, b)
	}
	return out
}
