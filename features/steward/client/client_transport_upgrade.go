// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Upgrade handler for push_steward_binary commands (Issue #1943).
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/version"
)

// MaxBinarySizeBytes is the maximum steward binary size the upgrade handler
// will download (200 MiB). Downloads with Content-Length beyond this or
// whose body exceeds this limit during streaming are rejected. (Issue #1943)
const MaxBinarySizeBytes = 200 * 1024 * 1024

// ErrDowngradeDenied is returned when the upgrade version is not newer than
// the running version and allow_downgrade is not enabled. (Issue #1943)
var ErrDowngradeDenied = errors.New("downgrade denied: target version is not newer than running version")

// errUpgradeHTTPStatus wraps a non-200 status from the binary download so the
// self-fetch tenant fallback can distinguish 404 (try next tenant) from other
// failures. (Issue #2833)
var errUpgradeHTTPStatus = errors.New("unexpected http status")

// errSelfFetchNotConfigured is returned by the self-fetch path when no controller
// HTTPS base URL is configured, so the steward degrades safe to awaiting a push
// rather than treating it as a hard error. (Issue #2833)
var errSelfFetchNotConfigured = errors.New("self-fetch: controller HTTPS base URL not configured")

// stewardBinaryVersionRe validates version strings before using them in paths
// or commands. Accepts "v1.2.3" and "v1.2.3-pre.release" forms. (Issue #2260)
var stewardBinaryVersionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[a-zA-Z0-9][a-zA-Z0-9.-]*)?$`)

// upgradeSeq is used to generate unique temp file names without crypto/rand.
var upgradeSeq atomic.Int64

// launcherPath returns the compile-time constant launcher binary path for the
// current OS. The path is a hard-coded contract; operators install the launcher
// binary there. Using os.Executable() search is explicitly prohibited because
// the steward and launcher may not share a directory. (Issue #1943)
func launcherPath() string {
	if runtime.GOOS == "windows" {
		return `C:\Program Files\CFGMS\cfgms-steward-launcher.exe`
	}
	return "/usr/local/bin/cfgms-launcher"
}

// pushStewardBinaryParams contains the decoded params for CommandPushStewardBinary.
type pushStewardBinaryParams struct {
	Version         string `json:"version"`
	DownloadURL     string `json:"download_url"`
	SHA256          string `json:"sha256"`
	Platform        string `json:"platform"`
	Arch            string `json:"arch"`
	Publisher       string `json:"publisher"`
	BundleSignature []byte `json:"bundle_signature"`
}

// parsePushStewardBinaryParams decodes cmd.Params into pushStewardBinaryParams,
// returning an error if any required field is empty.
func parsePushStewardBinaryParams(raw map[string]interface{}) (*pushStewardBinaryParams, error) {
	// Re-encode to JSON then unmarshal into the typed struct so Go's
	// JSON codec handles type coercions (including base64 for []byte).
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	var p pushStewardBinaryParams
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal params: %w", err)
	}
	switch {
	case p.Version == "":
		return nil, errors.New("missing required param: version")
	case p.DownloadURL == "":
		return nil, errors.New("missing required param: download_url")
	case p.SHA256 == "":
		return nil, errors.New("missing required param: sha256")
	case p.Platform == "":
		return nil, errors.New("missing required param: platform")
	case p.Arch == "":
		return nil, errors.New("missing required param: arch")
	case p.Publisher == "":
		return nil, errors.New("missing required param: publisher")
	case len(p.BundleSignature) == 0:
		return nil, errors.New("missing required param: bundle_signature")
	}
	return &p, nil
}

// handlePushStewardBinary processes a push_steward_binary command from the controller.
//
// Algorithm:
//  1. Parse and validate params.
//  2. Host pinning: assert download_url host matches the controller endpoint host.
//  3. Version monotonicity check — fast pre-download gate.
//  4. Size cap: refuse if Content-Length > MaxBinarySizeBytes; enforce during streaming.
//  5. Download to certStoreDir/upgrades/<seq>.bin (dir 0700, file 0600).
//  6. SHA-256 verify: compare recomputed digest to cmd.SHA256.
//  7. Publisher signature verify via trust.VerifyBundleSignature.
//  8. Revocation check.
//  9. Emit EventStewardUpgradeDownloaded.
//  10. Emit EventStewardUpgradeSwapped.
//  11. Assert launcher binary exists at compile-time constant path.
//  12. exec launcher swap with 60 s timeout.
//  13. Return nil — OS service manager restarts steward automatically.
func (c *TransportClient) handlePushStewardBinary(ctx context.Context, cmd *cpTypes.Command) error {
	c.logger.Info("Received push_steward_binary command",
		"command_id", logging.SanitizeLogValue(cmd.ID))

	// Step 1: Parse params.
	params, err := parsePushStewardBinaryParams(cmd.Params)
	if err != nil {
		return fmt.Errorf("push_steward_binary: invalid params: %w", err)
	}

	// Step 2: URL host pinning — reject cross-host downloads.
	downloadURL, err := url.Parse(params.DownloadURL)
	if err != nil {
		return fmt.Errorf("push_steward_binary: cannot parse download_url: %w", err)
	}
	if downloadURL.Scheme != "https" {
		return fmt.Errorf("push_steward_binary: download_url scheme must be https, got %q", downloadURL.Scheme)
	}
	controllerHost := c.controllerEndpointHost()
	downloadHost := downloadURL.Hostname()
	if downloadHost != controllerHost {
		c.logger.Warn("push_steward_binary: host pinning violation",
			"download_host", logging.SanitizeLogValue(downloadHost),
			"controller_host", logging.SanitizeLogValue(controllerHost))
		return fmt.Errorf("push_steward_binary: download_url host %q does not match controller endpoint host %q",
			downloadHost, controllerHost)
	}

	// Step 3: Version monotonicity — fast pre-download gate avoids an unnecessary network
	// round-trip when the target version is already older than the running version.
	c.mu.RLock()
	allowDowngrade := c.upgradeAllowDowngrade
	c.mu.RUnlock()
	if !allowDowngrade && !isNewerVersion(params.Version, version.Version) {
		c.logger.Warn("push_steward_binary: downgrade denied",
			"target_version", logging.SanitizeLogValue(params.Version),
			"running_version", version.Version)
		return fmt.Errorf("push_steward_binary: %w (target=%q running=%q)",
			ErrDowngradeDenied, params.Version, version.Version)
	}

	// Ensure downloads directory exists with restricted permissions.
	c.mu.RLock()
	certStoreDir := c.certStoreDir
	c.mu.RUnlock()
	if certStoreDir == "" {
		return fmt.Errorf("push_steward_binary: cert store dir not configured")
	}
	upgradesDir := filepath.Join(certStoreDir, "upgrades")
	if err := os.MkdirAll(upgradesDir, 0o700); err != nil {
		return fmt.Errorf("push_steward_binary: create upgrades dir: %w", err)
	}

	// Step 4-5: Download to temp file.
	seq := upgradeSeq.Add(1)
	tmpPath := filepath.Join(upgradesDir, fmt.Sprintf("upgrade-%d.bin", seq))

	recomputedSHA256, sizeBytes, _, dlErr := c.downloadBinaryForUpgrade(ctx, params.DownloadURL, tmpPath)
	if dlErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("push_steward_binary: download failed: %w", dlErr)
	}

	// Steps 6-13: verify, revoke-check, stage, and swap. Shared with the self-fetch
	// path (Issue #2833) so both directions apply identical verification and swap logic.
	if err := c.finalizeStewardBinaryUpgrade(ctx, tmpPath, recomputedSHA256, sizeBytes, params); err != nil {
		return fmt.Errorf("push_steward_binary: %w", err)
	}
	return nil
}

// finalizeStewardBinaryUpgrade performs the shared post-download pipeline for both the
// controller-pushed and self-fetched upgrade paths (Issue #2833): SHA-256 integrity
// check, independent publisher-signature verification, revocation check, progress
// events, launcher swap, staged-binary recording, and the launcher self-exit. The
// binary is already downloaded to tmpPath with its locally recomputed digest in
// recomputedSHA256. On any verification failure tmpPath is removed and the steward
// stays on its current version. params carries the coordinates the CALLER derived —
// for self-fetch these are the steward's own requested version and detected
// platform/arch, never controller-supplied values.
func (c *TransportClient) finalizeStewardBinaryUpgrade(ctx context.Context, tmpPath, recomputedSHA256 string, sizeBytes int64, params *pushStewardBinaryParams) error {
	// Step 6: SHA-256 check.
	if !strings.EqualFold(recomputedSHA256, params.SHA256) {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sha256 mismatch: expected %q computed %q",
			params.SHA256, recomputedSHA256)
	}

	// Step 7: Publisher signature verification over the version-bound composite.
	if err := c.verifyBinarySignature(recomputedSHA256, params); err != nil {
		_ = os.Remove(tmpPath)
		c.logger.Warn("upgrade: signature verification failed",
			"version", logging.SanitizeLogValue(params.Version),
			"publisher", logging.SanitizeLogValue(params.Publisher),
			"error", err.Error())
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Step 8: Revocation check.
	if c.isVersionRevoked(params.Version) {
		_ = os.Remove(tmpPath)
		c.logger.Warn("upgrade: version is revoked",
			"version", logging.SanitizeLogValue(params.Version))
		return fmt.Errorf("version %q is in the revoked list",
			params.Version)
	}

	// Step 9: Emit EventStewardUpgradeDownloaded.
	c.mu.RLock()
	sid := c.stewardID
	tid := c.tenantID
	lPathOverride := c.launcherPathOverride
	c.mu.RUnlock()
	if pubErr := c.publishEventWithQueue(ctx, &cpTypes.Event{
		ID:        fmt.Sprintf("evt_upg_dl_%d", time.Now().UnixNano()),
		Type:      cpTypes.EventStewardUpgradeDownloaded,
		StewardID: sid,
		TenantID:  tid,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"version":    params.Version,
			"sha256":     params.SHA256,
			"size_bytes": sizeBytes,
		},
	}); pubErr != nil {
		c.logger.Warn("push_steward_binary: failed to publish downloaded event", "error", pubErr.Error())
	}

	// Step 10-11: Resolve launcher path and assert it exists.
	lPath := lPathOverride
	if lPath == "" {
		lPath = launcherPath()
	}
	if _, statErr := os.Stat(lPath); statErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("push_steward_binary: launcher not found at %q: %w", lPath, statErr)
	}

	// Emit EventStewardUpgradeSwapped before swap so the event is delivered
	// before the OS restarts the steward process. (Issue #1943)
	if pubErr := c.publishEventWithQueue(ctx, &cpTypes.Event{
		ID:        fmt.Sprintf("evt_upg_sw_%d", time.Now().UnixNano()),
		Type:      cpTypes.EventStewardUpgradeSwapped,
		StewardID: sid,
		TenantID:  tid,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"version":       params.Version,
			"launcher_path": lPath,
		},
	}); pubErr != nil {
		c.logger.Warn("push_steward_binary: failed to publish swapped event", "error", pubErr.Error())
	}

	// Step 12: Invoke launcher swap.
	c.mu.RLock()
	allowDowngrade := c.upgradeAllowDowngrade
	c.mu.RUnlock()
	if err := c.execLauncherSwap(ctx, lPath, params.Version, tmpPath, allowDowngrade); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("push_steward_binary: launcher swap failed: %w", err)
	}

	// Record the staged binary so TriggerConvergence can re-issue the swap if
	// the steward has not restarted yet when the convergence loop fires. (Issue #2260)
	c.mu.Lock()
	c.lastStagedVersion = params.Version
	c.lastStagedBinaryPath = tmpPath
	c.mu.Unlock()

	// Step 13: Swap succeeded — the new binary is now the launcher's "current".
	// Schedule a graceful shutdown so the launcher's supervise loop re-execs the
	// staged binary. The trigger is DEFERRED behind a short grace delay so it
	// fires only after commands.Handler.executeCommand has delivered this
	// command's completion ack to the controller (this handler runs synchronously
	// inside executeCommand; the ack is published after we return). Without the
	// delay the process would exit mid-flight and the controller would record the
	// upgrade as timed-out. The launcher's startup-window auto-rollback remains
	// the safety net for a bad pushed binary. (Issue #2001)
	// Self-exit only when launcher-managed: a successful swap wrote the staged
	// binary as the launcher's "current", and the launcher will re-exec it after
	// we exit. A bare/standalone steward (no launcher: dev, fleet-e2e,
	// systemd-without-launcher) must NOT self-exit — nothing would re-exec the
	// staged binary, so self-exiting would only cause downtime or a crash loop as
	// the controller redelivers push_steward_binary on each reconnect. (Issue #2003)
	c.mu.RLock()
	launcherManaged := c.launcherManaged
	c.mu.RUnlock()
	if !launcherManaged {
		c.logger.Info("Steward binary staged for upgrade; steward is not launcher-managed, new binary applies on next restart",
			"version", logging.SanitizeLogValue(params.Version),
			"launcher", lPath)
		return nil
	}

	c.logger.Info("Steward binary staged for upgrade; scheduling graceful restart so launcher re-execs new version",
		"version", logging.SanitizeLogValue(params.Version),
		"launcher", lPath)
	c.scheduleGracefulShutdownAfterSwap()
	return nil
}

// scheduleGracefulShutdownAfterSwap arranges for the steward to gracefully exit
// after the configured grace delay, so the launcher re-execs the freshly-staged
// binary. It is called only on a SUCCESSFUL launcher swap; failed/aborted swaps
// return early in handlePushStewardBinary and never reach here. (Issue #2001)
//
// The grace delay defers the shutdown until after this command's completion ack
// has been published (see handlePushStewardBinary step 13). Both the schedule
// mechanism and the shutdown action are injectable: tests set shutdownScheduleFunc
// to run the trigger synchronously and shutdownFunc to a recorder, so no real
// time.Sleep or process exit occurs.
//
// The default timer goroutine watches the steward's RUN context (shutdownCtx,
// wired via SetShutdownFunc) for early-exit — NOT the per-command context. The
// run context is cancelled only when the process is already shutting down via
// another path (signal/SCM stop, or a separate runCancel), in which case the
// goroutine exits promptly without firing the redundant trigger rather than
// lingering for the full grace delay. The per-command context is deliberately
// NOT used here: executeCommand cancels it (`defer cancel()`) the instant this
// handler returns — right after the completion ack — which always beats the
// grace delay and would suppress the auto-apply self-exit entirely (Issue #2003).
// If no run context is wired (shutdownCtx == nil, e.g. older tests) the goroutine
// falls back to a plain timer with no early-exit so the trigger still fires.
// shutdownFunc (runCancel in production) is idempotent — context cancel funcs are
// safe to call multiple times and only the first has effect.
func (c *TransportClient) scheduleGracefulShutdownAfterSwap() {
	c.mu.RLock()
	shutdown := c.shutdownFunc
	schedule := c.shutdownScheduleFunc
	delay := c.upgradeShutdownGraceDelay
	runCtx := c.shutdownCtx
	c.mu.RUnlock()

	if shutdown == nil {
		// The shutdown trigger is not wired yet — the swap arrived in the window
		// between command subscription (Connect → SubscribeCommands) and the
		// SetShutdownFunc wiring in main.go. Record the intent so SetShutdownFunc
		// fires the self-exit as soon as the trigger is available, instead of
		// silently deferring the (possibly broken) staged binary to an unbounded
		// "next restart" where the launcher's startup-window auto-rollback never
		// fires. (Issue #2602)
		c.mu.Lock()
		c.pendingUpgradeSelfExit = true
		c.mu.Unlock()
		c.logger.Warn("Upgrade staged before shutdown trigger was wired; deferring launcher self-exit until it is available")
		return
	}
	if delay <= 0 {
		delay = defaultUpgradeShutdownGraceDelay
	}

	trigger := func() {
		c.logger.Info("Grace period elapsed after staged upgrade; triggering graceful shutdown for launcher re-exec")
		shutdown()
	}

	if schedule != nil {
		schedule(delay, trigger)
		return
	}

	// Default real implementation: fire the trigger once after delay without
	// blocking the handler (which must return so the completion ack is sent).
	// Exit early if the RUN context is cancelled first — the steward is already
	// shutting down, so there is no point holding this goroutine for the full
	// grace delay. If no run context is wired, fall back to a plain timer so the
	// trigger still fires (no early-exit). (Issue #2003)
	go func() {
		t := time.NewTimer(delay)
		defer t.Stop()
		if runCtx == nil {
			<-t.C
			trigger()
			return
		}
		select {
		case <-t.C:
			trigger()
		case <-runCtx.Done():
			c.logger.Info("Run context cancelled before upgrade grace delay elapsed; skipping redundant shutdown trigger")
		}
	}()
}

// selfFetchDesiredVersion pulls, verifies, stages, and swaps to desiredVersion when no
// controller push has staged it (Issue #2833). It is the hands-off half of
// desired_version convergence: with the binary published on the controller, declaring a
// desired_version is enough — no push required.
//
// Security invariants (see #2833 / #2834):
//   - The composite verify coordinates (version, platform, arch) come ONLY from the
//     steward's own requested desiredVersion and detected runtime.GOOS/GOARCH — never
//     from a controller-supplied header or body — so a compromised controller cannot
//     replay an old, genuinely-signed binary at a new version's URL.
//   - The content hash fed to the signature check is the digest recomputed locally over
//     the downloaded bytes, not the X-CFGMS-SHA256 header.
//   - The trust anchor is the build-time-baked CFGMSPublisherIdentity. The
//     X-CFGMS-Publisher header is only a hint: it can never select a verification key,
//     and a value disagreeing with the baked-in identity is rejected outright.
//   - The download URL is https-only and host-pinned to the controller transport host,
//     so no cross-host fetch (SSRF) is possible.
//
// Any failure degrades safe: the temp file is removed, the steward stays on its current
// version, and the next convergence cycle retries.
func (c *TransportClient) selfFetchDesiredVersion(ctx context.Context, desiredVersion string) error {
	c.mu.RLock()
	baseURL := c.controllerHTTPSBaseURL
	certStoreDir := c.certStoreDir
	ownTenant := c.tenantID
	c.mu.RUnlock()

	if baseURL == "" {
		return errSelfFetchNotConfigured
	}
	if certStoreDir == "" {
		return fmt.Errorf("self-fetch: cert store dir not configured")
	}

	// Coordinates are the steward's own — NEVER controller-supplied.
	platform := runtime.GOOS
	arch := runtime.GOARCH
	if !isSupportedInstallerPlatform(platform) || !isSupportedInstallerArch(arch) {
		return fmt.Errorf("self-fetch: unsupported platform/arch %q/%q", platform, arch)
	}

	// Parse and host-pin the base once: scheme must be https and the host must match the
	// controller transport endpoint, so a misconfigured or hostile base cannot redirect
	// the fetch to another host.
	base, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("self-fetch: cannot parse controller HTTPS base %q: %w", baseURL, err)
	}
	if base.Scheme != "https" {
		return fmt.Errorf("self-fetch: controller HTTPS base scheme must be https, got %q", base.Scheme)
	}
	controllerHost := c.controllerEndpointHost()
	if base.Hostname() != controllerHost {
		return fmt.Errorf("self-fetch: HTTPS base host %q does not match controller endpoint host %q",
			base.Hostname(), controllerHost)
	}

	upgradesDir := filepath.Join(certStoreDir, "upgrades")
	if err := os.MkdirAll(upgradesDir, 0o700); err != nil {
		return fmt.Errorf("self-fetch: create upgrades dir: %w", err)
	}

	// Tenant resolution: own tenant first (a per-tenant override), then "default"
	// (the fleet-wide binary an MSP/root admin publishes). The steward only ever
	// requests tenants it is registered under.
	tenants := []string{ownTenant}
	if ownTenant != "default" {
		tenants = append(tenants, "default")
	}

	seq := upgradeSeq.Add(1)
	tmpPath := filepath.Join(upgradesDir, fmt.Sprintf("upgrade-%d.bin", seq))

	var (
		recomputedSHA string
		sizeBytes     int64
		headers       http.Header
		fetchURL      string
		fetched       bool
	)
	for _, tenant := range tenants {
		u := *base
		u.Path = fmt.Sprintf("/api/v1/public/steward-binaries/%s/%s/%s", desiredVersion, platform, arch)
		u.RawQuery = url.Values{"tenant": {tenant}}.Encode()
		fetchURL = u.String()

		sha, size, hdrs, dlErr := c.downloadBinaryForUpgrade(ctx, fetchURL, tmpPath)
		if dlErr == nil {
			recomputedSHA, sizeBytes, headers, fetched = sha, size, hdrs, true
			break
		}
		// A 404 under this tenant just means "not published here" — try the next.
		if errors.Is(dlErr, errUpgradeHTTPStatus) && strings.Contains(dlErr.Error(), fmt.Sprintf("%d", http.StatusNotFound)) {
			c.logger.Info("self-fetch: binary not found under tenant, trying next",
				"version", logging.SanitizeLogValue(desiredVersion),
				"tenant", logging.SanitizeLogValue(tenant))
			continue
		}
		_ = os.Remove(tmpPath)
		return fmt.Errorf("self-fetch: download failed: %w", dlErr)
	}
	if !fetched {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("self-fetch: %s not found for %s/%s under any tenant", desiredVersion, platform, arch)
	}

	// The X-CFGMS-Publisher header is a hint only. Reject if it disagrees with the
	// baked-in identity; never use it to select a verification key.
	expectedPublisher := trust.CFGMSPublisherIdentity().Name
	if hdrPub := headers.Get("X-CFGMS-Publisher"); hdrPub != "" && hdrPub != expectedPublisher {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("self-fetch: publisher header %q does not match expected %q", hdrPub, expectedPublisher)
	}

	sigB64 := headers.Get("X-CFGMS-Signature")
	if sigB64 == "" {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("self-fetch: response missing X-CFGMS-Signature header")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("self-fetch: decode signature header: %w", err)
	}

	// Coordinates below are all steward-derived (desiredVersion, platform, arch) or the
	// locally recomputed digest — the signature header is the only controller-supplied
	// value, and it must verify against the baked-in publisher over the composite.
	params := &pushStewardBinaryParams{
		Version:         desiredVersion,
		DownloadURL:     fetchURL,
		SHA256:          headers.Get("X-CFGMS-SHA256"),
		Platform:        platform,
		Arch:            arch,
		Publisher:       expectedPublisher,
		BundleSignature: sigBytes,
	}
	if params.SHA256 == "" {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("self-fetch: response missing X-CFGMS-SHA256 header")
	}

	c.logger.Info("self-fetch: binary downloaded; verifying and staging",
		"version", logging.SanitizeLogValue(desiredVersion),
		"platform", platform, "arch", arch)

	if err := c.finalizeStewardBinaryUpgrade(ctx, tmpPath, recomputedSHA, sizeBytes, params); err != nil {
		return fmt.Errorf("self-fetch: %w", err)
	}
	return nil
}

// isSupportedInstallerPlatform / isSupportedInstallerArch mirror the controller's
// validPlatforms / validArchs allow-lists (handlers_installer.go) so the steward never
// constructs a fetch URL for a platform/arch the controller would reject.
func isSupportedInstallerPlatform(p string) bool {
	return p == "windows" || p == "linux" || p == "darwin"
}

func isSupportedInstallerArch(a string) bool {
	return a == "amd64" || a == "arm64"
}

// controllerEndpointHost extracts the host component from c.transportAddress.
// transportAddress is host:port; returns just the host.
func (c *TransportClient) controllerEndpointHost() string {
	c.mu.RLock()
	addr := c.transportAddress
	c.mu.RUnlock()
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// downloadBinaryForUpgrade downloads the binary at rawURL to dstPath with mode 0600.
// It enforces MaxBinarySizeBytes via Content-Length check and io.LimitedReader.
// Returns the hex SHA-256 of the downloaded content, the byte count, and the
// response headers (so the self-fetch path can read X-CFGMS-SHA256 / -Signature /
// -Publisher, which the pushed path carries out-of-band in the command instead).
// A non-200 status is surfaced as errUpgradeHTTPStatus wrapping the code so the
// self-fetch tenant fallback can distinguish 404 from other failures.
func (c *TransportClient) downloadBinaryForUpgrade(ctx context.Context, rawURL, dstPath string) (hexSHA256 string, sizeBytes int64, respHeaders http.Header, err error) {
	httpClient, err := c.buildHTTPClientForUpgrade()
	if err != nil {
		return "", 0, nil, fmt.Errorf("build http client: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil) //#nosec G107 -- URL is host-pinned before this call
	if err != nil {
		return "", 0, nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 0, nil, fmt.Errorf("http get: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", 0, resp.Header, fmt.Errorf("%w: %d", errUpgradeHTTPStatus, resp.StatusCode)
	}

	// Step 3: size cap via Content-Length header.
	if cl := resp.ContentLength; cl > MaxBinarySizeBytes {
		return "", 0, resp.Header, fmt.Errorf("Content-Length %d exceeds MaxBinarySizeBytes %d", cl, MaxBinarySizeBytes)
	}

	// Create temp file with 0600 — only the steward process may read it.
	f, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //#nosec G304 -- dstPath is built from certStoreDir + seq
	if err != nil {
		return "", 0, resp.Header, fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	hasher := sha256.New()
	limited := &io.LimitedReader{R: resp.Body, N: MaxBinarySizeBytes + 1}
	tee := io.TeeReader(limited, hasher)

	written, err := io.Copy(f, tee)
	if err != nil {
		return "", 0, resp.Header, fmt.Errorf("write temp file: %w", err)
	}
	if limited.N == 0 {
		return "", 0, resp.Header, fmt.Errorf("body exceeds MaxBinarySizeBytes %d; download aborted", MaxBinarySizeBytes)
	}

	return hex.EncodeToString(hasher.Sum(nil)), written, resp.Header, nil
}

// buildHTTPClientForUpgrade creates an *http.Client that authenticates using the
// steward's mTLS client certificate against the controller's HTTPS download endpoint.
// When c.upgradeHTTPClient is non-nil (injectable for tests), it is returned directly.
func (c *TransportClient) buildHTTPClientForUpgrade() (*http.Client, error) {
	c.mu.RLock()
	override := c.upgradeHTTPClient
	caCertPEM := c.caCertPEM
	certMgr := c.certManager
	certPath := c.certPath
	c.mu.RUnlock()

	if override != nil {
		return override, nil
	}

	var tlsCfg *tls.Config
	var err error

	switch {
	case certMgr != nil:
		tlsCfg, err = certMgr.CreateOnDemandClientTLSConfig([]byte(caCertPEM), tls.VersionTLS13)
		if err != nil {
			return nil, fmt.Errorf("cert manager TLS config: %w", err)
		}
	case certPath != "":
		caCertBytes, caErr := os.ReadFile(filepath.Join(certPath, "ca.crt")) //#nosec G304 -- certPath is from config
		if caErr != nil {
			return nil, fmt.Errorf("read CA cert: %w", caErr)
		}
		clientCertBytes, certErr := os.ReadFile(filepath.Join(certPath, "client.crt")) //#nosec G304
		if certErr != nil {
			return nil, fmt.Errorf("read client cert: %w", certErr)
		}
		clientKeyBytes, keyErr := os.ReadFile(filepath.Join(certPath, "client.key")) //#nosec G304
		if keyErr != nil {
			return nil, fmt.Errorf("read client key: %w", keyErr)
		}
		tlsCfg, err = cert.CreateClientTLSConfig(clientCertBytes, clientKeyBytes, caCertBytes, "", tls.VersionTLS13)
		if err != nil {
			return nil, fmt.Errorf("build TLS config from cert path: %w", err)
		}
	default:
		// No mTLS material — connect without client cert.  The server may reject
		// the request; we surface that as an HTTP error rather than failing here.
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS13} //#nosec G402
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Minute,
	}, nil
}

// verifyBinarySignature constructs an ephemeral trust store and calls
// trust.VerifyStewardBinarySignature. In tests, c.upgradePublisherTrustStore may
// override the default CFGMSPublisherIdentity() store.
//
// The signature is verified over the canonical (content hash, version, platform, arch)
// message, so a genuinely signed binary for one release cannot be replayed as another
// (Issue #2834). hexSHA256 MUST be the digest recomputed locally over the received
// bytes — never a value echoed by the serving controller.
func (c *TransportClient) verifyBinarySignature(hexSHA256 string, params *pushStewardBinaryParams) error {
	c.mu.RLock()
	overrideStore := c.upgradePublisherTrustStore
	c.mu.RUnlock()

	var store trust.TrustStore
	if overrideStore != nil {
		store = overrideStore
	} else {
		ts := trust.NewInMemoryTrustStore()
		_ = ts.AddPublisher(trust.CFGMSPublisherIdentity())
		store = ts
	}

	sig := bundle.BundleSignature{
		Publisher: params.Publisher,
		Algorithm: "ed25519",
		Signature: params.BundleSignature,
	}
	return trust.VerifyStewardBinarySignature(hexSHA256, params.Version, params.Platform, params.Arch, sig, store)
}

// isVersionRevoked checks whether v is in the cached revoked versions list.
func (c *TransportClient) isVersionRevoked(v string) bool {
	c.revokedVersionsMu.RLock()
	defer c.revokedVersionsMu.RUnlock()
	for _, rev := range c.revokedVersions {
		if rev == v {
			return true
		}
	}
	return false
}

// execLauncherSwap invokes the launcher swap subcommand.
// Uses c.launcherSwapFunc when set (injectable for tests); otherwise uses
// exec.CommandContext with a 60-second timeout.
func (c *TransportClient) execLauncherSwap(ctx context.Context, lPath, ver, binaryPath string, allowDowngrade bool) error {
	c.mu.RLock()
	swapFn := c.launcherSwapFunc
	c.mu.RUnlock()

	if swapFn != nil {
		return swapFn(ctx, lPath, ver, binaryPath)
	}

	swapCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	// launcherPath is a compile-time constant; ver and binaryPath are verified
	// above (host-pinned URL, SHA-256 + signature checked). G204 is intentional.
	args := []string{"swap"}
	if allowDowngrade {
		args = append(args, "--allow-downgrade")
	}
	args = append(args, ver, binaryPath)
	cmd := exec.CommandContext(swapCtx, lPath, args...) //#nosec G204
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w; launcher output: %s", err, out.String())
	}
	return nil
}

// isNewerVersion reports whether candidate is strictly newer than running.
// Invalid versions fail closed instead of falling back to lexical ordering.
func isNewerVersion(candidate, running string) bool {
	cmp, err := version.CompareSemantic(candidate, running)
	return err == nil && cmp > 0
}
