// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/features/steward/modules/install"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/subscribers/systemlog"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Tamper alarm.
//
// Four refusals mean the steward must not enforce anything from the material it
// found: an insecure data directory, a trust-source downgrade, a pinned CA that
// is unreadable or does not match its pin, and a bad or downgrading security
// profile. None of them ends the process or retries silently. The steward opens
// the report-only link on its stored identity and reports the tamper code on
// every heartbeat.
//
// The alarm latches. Once any tamper code is raised the steward stays
// report-only until BOTH the local fault has cleared (re-checked at the slow
// interval) AND the controller has sent TamperState{locked: false} (an operator
// restore). The latch is persisted so a restart does not drop it. A latch file
// that is present but unreadable, corrupt or of an unknown version counts as
// latched; a missing one is recovered when the controller sends
// TamperState{locked: true} on connect.
//
// A restore only counts once the controller has acknowledged the lock with
// TamperState{locked: true} for this latch. A controller that sends its current
// state on connect would otherwise release a host it has not yet been told is
// tampered.

const (
	// tamperReasonComponent is the heartbeat reason component of the alarm.
	tamperReasonComponent = "tamper"

	tamperLatchFileName = "tamper_latch.json"
	tamperLatchVersion  = 1

	// moduleStagePrefix starts the name of every transient directory the module
	// installer leaves under the bundle root (install.stagePrefix).
	moduleStagePrefix = ".cfgms-bundle-"
)

// tamperRecheckInterval is how often the local fault is re-checked while
// latched; tamperConnectRetry is how often a failed alarm link is retried.
var (
	tamperRecheckInterval = time.Hour
	tamperConnectRetry    = 30 * time.Second
)

// errTamperBrokenTrust means the alarm could not be sent: the stored identity's
// CA does not verify against its anchor and no pin-verified CA can be rebuilt
// from the install source. The identity cannot be used even for the alarm, so
// the caller falls to the broken-trust fallback (S20) and the reason is kept
// locally only.
var errTamperBrokenTrust = errors.New("tamper alarm: stored identity cannot be verified")

// tamperMessages are fixed so a reason never carries a path or file content.
var tamperMessages = map[string]string{
	cpTypes.ReasonCodeTamperDataDir:         "the steward data directory is not secure; nothing is enforced",
	cpTypes.ReasonCodeTamperTrustDowngrade:  "the configured trust source is weaker than the one this steward enrolled with; nothing is enforced",
	cpTypes.ReasonCodeTamperCAMismatch:      "the pinned controller CA is unreadable or does not match its pin; nothing is enforced",
	cpTypes.ReasonCodeTamperSecurityProfile: "the security profile is invalid or downgrades the compiled profile; nothing is enforced",
	client.ReasonTamperLocked:               "the controller reports this host locked; nothing is enforced",
}

// tamperFault is one tamper condition found by a scan.
type tamperFault struct {
	code string
}

// tamperLatchFile is the persisted latch.
type tamperLatchFile struct {
	Version          int      `json:"version"`
	Codes            []string `json:"codes"`
	ControllerLocked bool     `json:"controller_locked"`
}

// tamperLatch holds the latch in memory and on disk.
type tamperLatch struct {
	mu               sync.Mutex
	path             string
	logger           logging.Logger
	latched          bool
	codes            []string
	controllerLocked bool
	restore          bool
	// wake is signalled when the controller's TamperState changes the latch.
	wake chan struct{}
}

// openTamperLatch loads the latch from dir. It fails closed: a file that is
// present but cannot be read or understood is a latch, never a release.
func openTamperLatch(dir string, logger logging.Logger) *tamperLatch {
	l := &tamperLatch{path: filepath.Join(dir, tamperLatchFileName), logger: logger, wake: make(chan struct{}, 1)}
	info, err := os.Lstat(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return l
	}
	l.latched = true
	// Anything but a regular file is never opened: reading a pipe planted in
	// the cert store would hang startup before the alarm is sent.
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	var raw []byte
	if err == nil {
		// #nosec G304 -- path is the latch file inside the steward cert store.
		raw, err = os.ReadFile(l.path)
	}
	if err != nil {
		l.codes = []string{cpTypes.ReasonCodeTamperDataDir}
		logger.Error("Tamper latch file is unreadable; staying latched", "operation", "tamper_latch")
		return l
	}
	var f tamperLatchFile
	if jsonErr := json.Unmarshal(raw, &f); jsonErr != nil || f.Version != tamperLatchVersion || !validLatchCodes(f.Codes) {
		l.codes = []string{cpTypes.ReasonCodeTamperDataDir}
		logger.Error("Tamper latch file is corrupt or of an unknown version; staying latched", "operation", "tamper_latch")
		return l
	}
	l.codes = f.Codes
	l.controllerLocked = f.ControllerLocked
	return l
}

func validLatchCodes(codes []string) bool {
	if len(codes) == 0 {
		return false
	}
	for _, c := range codes {
		if !cpTypes.IsTamperCode(c) && c != client.ReasonTamperLocked {
			return false
		}
	}
	return true
}

// onlyCode reports whether code is the one and only reason the latch holds.
func (l *tamperLatch) onlyCode(code string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.latched && !l.controllerLocked && len(l.codes) == 1 && l.codes[0] == code
}

func (l *tamperLatch) isLatched() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.latched
}

// codesSnapshot returns the codes the latch holds.
func (l *tamperLatch) codesSnapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.codes...)
}

// primaryCode is the code the heartbeat reports: the first one raised.
func (l *tamperLatch) primaryCode() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.codes) == 0 {
		return client.ReasonTamperLocked
	}
	return l.codes[0]
}

// restoreReady reports whether the controller has restored a latch it had locked.
func (l *tamperLatch) restoreReady() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.latched && l.restore
}

// raise latches code.
func (l *tamperLatch) raise(code string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.raiseLocked(code)
}

func (l *tamperLatch) raiseLocked(code string) {
	known := false
	for _, c := range l.codes {
		known = known || c == code
	}
	if !known {
		l.codes = append(l.codes, code)
	}
	l.latched = true
	l.persistLocked()
}

// onController applies a TamperState from the controller.
func (l *tamperLatch) onController(locked bool) {
	l.mu.Lock()
	if locked {
		l.restore = false
		l.controllerLocked = true
		l.raiseLocked(client.ReasonTamperLocked)
	} else if l.latched && l.controllerLocked {
		l.restore = true
	}
	l.mu.Unlock()
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *tamperLatch) persistLocked() {
	data, err := json.Marshal(tamperLatchFile{Version: tamperLatchVersion, Codes: l.codes, ControllerLocked: l.controllerLocked})
	if err == nil {
		err = writeFileAtomic(l.path, data)
	}
	if err != nil {
		// The in-memory latch still holds; the controller re-latches a restart.
		l.logger.Error("Tamper latch could not be saved", "operation", "tamper_latch",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// release drops the latch. If the file cannot be removed the latch stays.
func (l *tamperLatch) release() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove tamper latch: %w", err)
	}
	l.latched, l.codes, l.controllerLocked, l.restore = false, nil, false, false
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tamper-latch-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// startupFacts are the values the connected path needs, found by scanning.
type startupFacts struct {
	publicBeta   bool
	installCAPEM string
	trustSrc     TrustSource
	resolvedURL  string
}

// scanStartupTamper checks the security profile, the pinned CA and the trust
// source. The profile is checked first and, when it is bad, the facts carry
// public-beta (the strictest) for the alarm path. A non-tamper error (no
// controller URL) is returned as err.
func scanStartupTamper(storedID *StewardIdentity, controllerURL string, logger logging.Logger) (startupFacts, *tamperFault, error) {
	var facts startupFacts
	publicBeta, profileErr := publicBetaSecurityEnabled()
	if profileErr != nil {
		facts.publicBeta = true
		logger.Error("Security profile refused", "operation", "tamper_security_profile",
			"error", logging.SanitizeLogValue(profileErr.Error()))
		return facts, &tamperFault{code: cpTypes.ReasonCodeTamperSecurityProfile}, nil
	}
	facts.publicBeta = publicBeta

	installCAPEM, caErr := loadInstallCAPEM(storedID, logger)
	if caErr != nil {
		logger.Error("Pinned CA refused", "operation", "tamper_ca_mismatch",
			"error", logging.SanitizeLogValue(caErr.Error()))
		return facts, &tamperFault{code: cpTypes.ReasonCodeTamperCAMismatch}, nil
	}
	facts.installCAPEM = installCAPEM
	if storedID != nil && storedID.CACertPEM != "" {
		if _, err := verifyPersistedCA(storedID.CACertPEM, storedID.CAPinFingerprint); err != nil {
			logger.Error("Stored identity CA refused", "operation", "tamper_ca_mismatch",
				"error", logging.SanitizeLogValue(err.Error()))
			return facts, &tamperFault{code: cpTypes.ReasonCodeTamperCAMismatch}, nil
		}
	}

	trustSrc, resolvedURL, trustErr := resolveTrustSourceForStart(ControllerURL, controllerURL, installCAPEM, storedID)
	if trustErr != nil {
		return facts, nil, trustErr
	}
	facts.trustSrc, facts.resolvedURL = trustSrc, resolvedURL
	if storedID != nil {
		if dgErr := checkTrustDowngrade(trustSrc, installCAPEM, storedID); dgErr != nil {
			logger.Error("Trust-anchor downgrade refused", "operation", "tamper_trust_downgrade",
				"error", logging.SanitizeLogValue(dgErr.Error()))
			if isTrustDowngrade(dgErr) {
				return facts, &tamperFault{code: cpTypes.ReasonCodeTamperTrustDowngrade}, nil
			}
			return facts, &tamperFault{code: cpTypes.ReasonCodeTamperCAMismatch}, nil
		}
	}
	return facts, nil, nil
}

// reconstructPinnedCA returns a CA that verifies against the identity's pin,
// rebuilt from the install source (the installer CA file) when the CA the link
// would normally use does not verify. It returns "" when there is none. An
// identity without a pin has nothing to verify against.
func reconstructPinnedCA(id *StewardIdentity, logger logging.Logger) string {
	if id.CAPinFingerprint == "" {
		return ""
	}
	path := resolveRegistrationCACertPath(logger)
	if path == "" {
		return ""
	}
	// #nosec G304 -- path comes from resolveRegistrationCACertPath: the explicit
	// installer CA option or the fixed service CA path.
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// repairPersistedCA is pure: it never rewrites the installer file.
	canonical, err := repairPersistedCA(string(raw), id.CAPinFingerprint)
	if err != nil {
		return ""
	}
	return canonical
}

// tamperAlarm runs the report-only link while the latch holds.
type tamperAlarm struct {
	latch *tamperLatch
	// rescan re-runs the local checks and returns the fault still present, or nil.
	rescan func() *tamperFault
	// resetDerived rebuilds derived local state on release.
	resetDerived func()
	// brokenTrust, when set, runs when the stored identity cannot carry the alarm
	// because its CA does not verify. It returns true when it began the
	// broken-trust fallback: the device re-keyed and the old identity is gone.
	brokenTrust func(ctx context.Context) bool
	// recovered is set once brokenTrust began the fallback; run then releases
	// the latch so the steward connects and registers as a new device.
	recovered bool
	// repair performs a signed RepairRequest while the latch holds.
	repair *repairer
	sink   systemLogWriter
	// sinkFn opens the local system log the first time it is needed.
	sinkFn func() systemLogWriter
	logger logging.Logger
}

// run holds the steward report-only until the latch is released. It returns
// true when released and false when ctx ended first.
func (a *tamperAlarm) run(ctx context.Context) (bool, error) {
	var tc *client.TransportClient
	// The reason belongs to this alarm only; it never outlives it in the
	// process-wide startup reasons.
	defer startupReasons.Clear(tamperReasonComponent)
	defer func() { closeTamperLink(tc) }()

	recheck := time.NewTicker(tamperRecheckInterval)
	defer recheck.Stop()
	retry := time.NewTimer(0)
	defer retry.Stop()

	defer a.repair.clearAll()
	tc = a.repair.start(ctx, tc)

	for {
		a.publishReason(tc)
		a.repair.republish(tc)
		if tc == nil {
			tc = a.connectLink(ctx, retry)
			if ctx.Err() != nil {
				return false, nil
			}
			a.reportQuarantined(tc)
			a.repair.confirmOutcome(ctx, tc)
		}

		if a.tryRelease(tc) {
			return true, nil
		}

		select {
		case <-ctx.Done():
			return false, nil
		case <-a.repair.wakeChan():
			tc = a.repair.service(ctx, tc)
		case <-a.latch.wake:
		case <-recheck.C:
			a.repair.refresh(tc)
		case <-retry.C:
		}
	}
}

// reportQuarantined sends the planted links the last rights reset removed to the
// controller, once, over the link opened on the new credential.
func (a *tamperAlarm) reportQuarantined(tc *client.TransportClient) {
	links := quarantinedLinks.Swap(nil)
	if tc == nil || links == nil {
		return
	}
	for _, link := range *links {
		tc.EnqueueLog(&transportpb.LogEntry{
			Level:     transportpb.Severity_SEVERITY_WARNING,
			Message:   "repair removed a planted link; its target was not touched",
			Timestamp: timestamppb.Now(),
			Fields:    map[string]string{"source": "repair", "path": logging.SanitizeLogValue(link)},
		})
	}
}

// closeTamperLink disconnects the alarm's report-only link, if one is open.
func closeTamperLink(tc *client.TransportClient) {
	if tc == nil {
		return
	}
	dctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = tc.Disconnect(dctx)
}

// connectLink opens the report-only link. It returns nil when the link could
// not be opened, and then arms retry for the next attempt.
func (a *tamperAlarm) connectLink(ctx context.Context, retry *time.Timer) *client.TransportClient {
	link, err := a.openLink(ctx)
	switch {
	case err == nil:
		return link
	case errors.Is(err, errTamperBrokenTrust), errors.Is(err, errReportOnlyNoIdentity), errors.Is(err, errReportOnlyNoClientCert):
		// The identity cannot carry the alarm. The reason is kept locally. With
		// a registration token and a trusted anchor, an unverifiable CA is the
		// broken-trust fallback's case (broken_trust.go); otherwise this stays
		// the no-token loop.
		a.recordLocalOnly(err)
		if errors.Is(err, errTamperBrokenTrust) && a.brokenTrust != nil && a.brokenTrust(ctx) {
			a.recovered = true
		}
	case errors.Is(err, errRepairHoldsDials):
		// A repair is completing: no dial may present the credential it retires.
	default:
		a.logger.Warn("Tamper alarm link failed; retrying", "operation", "tamper_alarm_connect",
			"error", logging.SanitizeLogValue(err.Error()))
	}
	retry.Reset(tamperConnectRetry)
	return nil
}

// releaseAfterRecovery drops the latch after the broken-trust fallback removed
// the identity whose CA did not verify.
func (a *tamperAlarm) releaseAfterRecovery() bool {
	if err := a.latch.release(); err != nil {
		a.logger.Error("Tamper latch could not be released", "operation", "tamper_release",
			"error", logging.SanitizeLogValue(err.Error()))
		return false
	}
	a.recovered = false
	startupReasons.Clear(tamperReasonComponent)
	if a.resetDerived != nil {
		a.resetDerived()
	}
	return true
}

// tryRelease releases the latch when the controller has restored this host and
// the local fault is cleared. It returns true when the latch was released.
func (a *tamperAlarm) tryRelease(tc *client.TransportClient) bool {
	if a.recovered {
		// The broken-trust fallback removed the identity the fault was about.
		return a.releaseAfterRecovery()
	}
	if !a.latch.restoreReady() || !a.localFaultCleared() {
		return false
	}
	if err := a.latch.release(); err != nil {
		a.logger.Error("Tamper latch could not be released", "operation", "tamper_release",
			"error", logging.SanitizeLogValue(err.Error()))
		return false
	}
	a.logger.Info("Tamper latch released: the local fault is cleared and the controller restored this host",
		"operation", "tamper_release")
	startupReasons.Clear(tamperReasonComponent)
	if tc != nil {
		tc.ClearHealthReason(tamperReasonComponent)
	}
	if a.repair != nil {
		a.repair.clearAll()
		if tc != nil {
			for _, c := range []string{cpTypes.HealthComponentRepair, cpTypes.ReasonCodeRepairLossLocalLogs, cpTypes.ReasonCodeRepairLossActionHistory} {
				tc.ClearHealthReason(c)
			}
		}
	}
	if a.resetDerived != nil {
		a.resetDerived()
	}
	return true
}

// localFaultCleared re-checks the local fault. A fault still present is
// latched again under its own code.
func (a *tamperAlarm) localFaultCleared() bool {
	f := a.rescan()
	if f == nil {
		return true
	}
	a.latch.raise(f.code)
	return false
}

// publishReason sets the reason the heartbeat carries.
func (a *tamperAlarm) publishReason(tc *client.TransportClient) {
	code := a.latch.primaryCode()
	msg := tamperMessages[code]
	startupReasons.Set(tamperReasonComponent, code, msg)
	if tc != nil {
		tc.SetHealthReason(tamperReasonComponent, code, msg)
	}
}

// recordLocalOnly writes the reason where the platform keeps local records.
func (a *tamperAlarm) recordLocalOnly(cause error) {
	code := a.latch.primaryCode()
	a.logger.Error("Tamper alarm cannot reach the controller; reason kept locally",
		"operation", "tamper_local_only",
		"code", code,
		"error", logging.SanitizeLogValue(cause.Error()))
	if a.sink == nil && a.sinkFn != nil {
		a.sink = a.sinkFn()
		a.sinkFn = nil
	}
	if a.sink != nil {
		if err := a.sink.WriteOnce(systemlog.LevelWarning, code, tamperMessages[code]); err != nil {
			a.logger.Warn("system log write failed", "operation", "tamper_local_only",
				"error", logging.SanitizeLogValue(err.Error()))
		}
	}
}

// openLink opens the report-only link on the stored identity. A CA that does
// not verify against its anchor is rebuilt from the install source when that
// verifies against the pin; otherwise errTamperBrokenTrust is returned and
// nothing is dialed.
func (a *tamperAlarm) openLink(ctx context.Context) (*client.TransportClient, error) {
	if a.repair != nil && a.repair.dialsHeld.Load() {
		return nil, errRepairHoldsDials
	}
	dir := certStoreDirResolver()
	id, _ := loadIdentity(dir)
	var src TrustSource
	if id != nil {
		src = trustSourceFromMode(id.TrustMode)
	}
	opts := reportOnlyLinkOptions{prepare: a.watchController}
	tc, err := connectReportOnlyLink(ctx, dir, src, opts, a.logger)
	if err == nil || !errors.Is(err, errReportOnlyAnchor) || id == nil {
		return tc, err
	}
	// An install-pinned steward takes its CA from the install source only; the
	// identity file may not stand in for it.
	opts.anchorPEM = reconstructPinnedCA(id, a.logger)
	if opts.anchorPEM == "" {
		return nil, fmt.Errorf("%w: %w", errTamperBrokenTrust, err)
	}
	return connectReportOnlyLink(ctx, dir, src, opts, a.logger)
}

// watchController feeds the controller's TamperState into the latch. It is
// installed before the client connects so the state sent on connect is seen.
func (a *tamperAlarm) watchController(tc *client.TransportClient) {
	tc.SetTamperStateHandler(a.latch.onController)
	if a.repair != nil {
		tc.SetRepairHandler(a.repair.onRequest)
	}
}

// watchControllerLock latches when the controller locks a normally connected
// steward. The client has already entered report-only itself; the latch makes
// that survive a restart and holds the steward report-only until restored. It
// returns a channel signalled on the first lock.
func watchControllerLock(tc *client.TransportClient, latch *tamperLatch) <-chan struct{} {
	locked := make(chan struct{}, 1)
	signal := func() {
		select {
		case locked <- struct{}{}:
		default:
		}
	}
	tc.SetTamperStateHandler(func(isLocked bool) {
		if isLocked {
			latch.onController(true)
			signal()
		}
	})
	// A lock that arrived before the handler was installed left its reason.
	for _, r := range tc.HealthReasons() {
		if r.Component == client.ReportOnlyReasonComponent && r.Code == client.ReasonTamperLocked {
			latch.onController(true)
			signal()
		}
	}
	return locked
}

// watchRepairWhileNotLocked answers a RepairRequest that reaches a steward that
// is not latched: it reports repair.not_locked and changes nothing. A latched
// steward's request is the alarm's (repair.go).
func watchRepairWhileNotLocked(tc *client.TransportClient, latch *tamperLatch) {
	tc.SetRepairHandler(func(req cpTypes.RepairRequest) {
		if validRepairID(req.RepairID) && !latch.isLatched() {
			tc.SetHealthReason(cpTypes.HealthComponentRepair, cpTypes.ReasonCodeRepairNotLocked, req.RepairID)
			// Report it now rather than at the next periodic heartbeat.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = tc.SendHeartbeat(ctx, string(cpTypes.StatusDegraded), nil)
			}()
		}
	})
}

// resetDerivedState is called on release. Config is pulled from the controller
// on every connect and kept in memory, so the connect that follows a release
// refetches it. Installed module bundles are verified against their publisher
// signatures when they load, and the baseline modules ship in the installer
// payload, so only the transient staging directories are cleared here.
func resetDerivedState(logger logging.Logger) {
	root := install.DefaultRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), moduleStagePrefix) {
			if rmErr := os.RemoveAll(filepath.Join(root, e.Name())); rmErr != nil {
				logger.Warn("Module staging directory could not be cleared", "operation", "tamper_release",
					"error", logging.SanitizeLogValue(rmErr.Error()))
			}
		}
	}
}

// newTamperAlarm builds the alarm runStewardInternal holds while the latch is
// set. A CA that cannot be verified hands off to the broken-trust fallback when
// a registration token and a trusted anchor exist (broken_trust.go).
func newTamperAlarm(latch *tamperLatch, logger logging.Logger, controllerURL string) *tamperAlarm {
	alarm := &tamperAlarm{
		latch: latch,
		rescan: func() *tamperFault {
			if err := dataDirCheck(logger); err != nil {
				return &tamperFault{code: cpTypes.ReasonCodeTamperDataDir}
			}
			storedID, _ := loadIdentity(certStoreDirResolver())
			_, fault, _ := scanStartupTamper(storedID, controllerURL, logger)
			return fault
		},
		sinkFn: newSystemLogSink,
		logger: logger,
	}
	alarm.repair = newRepairer(latch, alarm.rescan, controllerURL, logger)
	alarm.resetDerived = func() { resetDerivedState(logger) }
	alarm.brokenTrust = func(ctx context.Context) bool {
		return rekeyFromAlarm(ctx, latch, controllerURL, alarm.logger)
	}
	return alarm
}
