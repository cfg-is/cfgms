// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	"github.com/cfgis/cfgms/pkg/security"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Repair.
//
// A latched steward repairs itself when the controller sends a signed
// RepairRequest. One request is one transaction, in this order:
//
//  1. verify the request (signature on a host with a baked root list, expiry,
//     latch, CA-class anchor rule);
//  2. assess what the repair would lose and compare it with what the operator
//     approved; nothing is deleted without an exact match;
//  3. close the report-only link, so no dial presents the credential about to be
//     retired, and keep it closed until the completion has finished;
//  4. reset the rights of the declared paths without following links
//     (security.TakeOverForRepair), so the tree is the steward's alone and its
//     links are quarantined; only then delete the approved items, never through
//     a parent link, and reset and verify the rights again;
//  5. discard trust material written while the folder was exposed;
//  6. only inside the verified directory: stage a new identity key and a new mTLS
//     key, and complete the rotation with the controller, proving possession of
//     both identity keys;
//  7. persist the new certificate, keys and identity record, keeping the steward
//     ID, local logs and action history, and only then drop the old keys;
//  8. re-run the local tamper checks and report the outcome on the new credential.
//
// The steward stays latched; the controller's TamperState{locked: false} releases
// it (tamper_alarm.go). A failure at any step keeps the old keys and reports
// repair.failed; it never retries on its own with a weaker credential.

const (
	repairStateFileName   = "steward-repair.json"
	repairStateVersion    = 1
	maxRepairIDLen        = 128
	actionHistoryFileName = "action-history.jsonl"

	// Flushing sends the tail of each readable file in a bounded number of
	// chunks so the emitter's queue (256 entries) never drops one.
	repairFlushMaxBytesPerFile = 1 << 20
	repairFlushChunkBytes      = 32 << 10
	repairFlushMaxEntries      = 200
	repairProbeBytes           = 64 << 10
	repairMaxHistoryLineBytes  = 1 << 20
)

var (
	// repairRetryBase and repairRetryMax pace the retry of a completion whose
	// request or response was lost; the same new key is sent each time.
	repairRetryBase = 30 * time.Second
	repairRetryMax  = 5 * time.Minute

	// repairTakeOver resets the rights of the declared paths (N8). Tests that run
	// without root substitute the owner it assigns; nothing else is replaced.
	repairTakeOver = security.TakeOverForRepair

	// repairRemoveItem deletes one approved item. It is called for nothing but
	// the items of an approved loss set.
	repairRemoveItem = removeRepairItem

	// repairOpenKeyStore opens the device key store the rotation signs with.
	repairOpenKeyStore = openDeviceKeyStore

	// repairPathsResolver names the declared paths a repair may touch.
	repairPathsResolver = defaultRepairPaths

	// repairRightsCheck verifies the rights after the reset: the same check
	// secureStewardDataDir makes at startup.
	repairRightsCheck = func(logger logging.Logger) error { return dataDirCheck(logger) }
)

// errRepairHoldsDials is returned by a dial attempted while a repair completes.
var errRepairHoldsDials = errors.New("a repair is completing; no dial may present the retiring credential")

// errRepairTransient marks a completion that may be retried with the same keys:
// the request or its response was lost, or the controller was unavailable.
var errRepairTransient = errors.New("repair completion not finished; will retry with the same keys")

// repairPaths are the only directories a repair touches.
type repairPaths struct {
	dataDir      string
	certStoreDir string
	logDir       string
}

// defaultRepairPaths returns the declared steward data, cert store and log
// directories. The data directory is %ProgramData%\cfgms on Windows and the
// parent of the cert store elsewhere. An unset log directory is not touched.
func defaultRepairPaths() repairPaths {
	certStore := certStoreDirResolver()
	data := filepath.Dir(certStore)
	if runtime.GOOS == "windows" {
		data = stewardDataDirResolver()
	}
	return repairPaths{dataDir: data, certStoreDir: certStore, logDir: os.Getenv("CFGMS_LOG_DIR")}
}

// roots returns the absolute, de-duplicated directories to reset. A directory
// inside another root is covered by it. A directory too close to the top of a
// volume to be a steward directory is dropped rather than reset.
func (p repairPaths) roots() []string {
	var abs []string
	for _, d := range []string{p.dataDir, p.certStoreDir, p.logDir} {
		if a, ok := stewardDir(d); ok {
			abs = append(abs, a)
		}
	}
	var out []string
	for _, a := range abs {
		if !coveredByOther(a, abs) && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// stewardDir returns d as an absolute path when it can be a steward directory:
// not empty, not the top of a volume and not a direct child of it.
func stewardDir(d string) (string, bool) {
	if d == "" {
		return "", false
	}
	a, err := filepath.Abs(d)
	if err != nil || filepath.Dir(a) == a || filepath.Dir(filepath.Dir(a)) == filepath.Dir(a) {
		return "", false
	}
	return a, true
}

// coveredByOther reports whether a lies inside another entry of abs.
func coveredByOther(a string, abs []string) bool {
	for _, b := range abs {
		if a != b && within(b, a) {
			return true
		}
	}
	return false
}

// actionHistory is the file the steward's action history is kept in.
func (p repairPaths) actionHistory() string {
	return filepath.Join(p.dataDir, actionHistoryFileName)
}

// within reports whether path is dir or below it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// repairAssessment is what a repair would lose.
type repairAssessment struct {
	// Codes is the sorted set of loss codes; empty means the repair loses nothing.
	Codes []string
	// items names, per code, the paths that cannot be kept.
	items map[string][]string
}

func (a repairAssessment) digest() string { return cpTypes.LossDigest(a.Codes) }

// assessRepairLoss returns the local data that cannot be kept: log files and the
// action history that are unreadable or corrupt, and entries the rights reset
// could not take over earlier (refused). A reset that works in place loses
// nothing. It reads files but changes nothing.
func assessRepairLoss(p repairPaths, refused []string) repairAssessment {
	items := map[string][]string{}
	add := func(code, path string) {
		if !slices.Contains(items[code], path) {
			items[code] = append(items[code], path)
		}
	}
	if p.logDir != "" {
		for _, path := range unkeepableLogs(p.logDir) {
			add(cpTypes.ReasonCodeRepairLossLocalLogs, path)
		}
	}
	history := p.actionHistory()
	if historyUnkeepable(history) {
		add(cpTypes.ReasonCodeRepairLossActionHistory, history)
	}
	for _, path := range refused {
		if code := lossCodeOf(p, path); code != "" {
			add(code, path)
		}
	}
	var codes []string
	for code, paths := range items {
		sort.Strings(paths)
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return repairAssessment{Codes: codes, items: items}
}

// lossCodeOf names the loss code an entry belongs to by where it lives, or "" for
// a path outside the declared log directory and action history.
func lossCodeOf(p repairPaths, path string) string {
	switch {
	case p.logDir != "" && within(p.logDir, path) && path != p.logDir:
		return cpTypes.ReasonCodeRepairLossLocalLogs
	case path == p.actionHistory():
		return cpTypes.ReasonCodeRepairLossActionHistory
	}
	return ""
}

// unkeepableLogs lists the entries of logDir that cannot be read. Links are not
// opened: the rights reset removes the link itself and never reads its target.
func unkeepableLogs(logDir string) []string {
	var bad []string
	if _, err := os.Lstat(logDir); err != nil {
		return nil // no log directory, nothing to lose
	}
	_ = filepath.WalkDir(logDir, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			if path != logDir || !errors.Is(err, fs.ErrNotExist) {
				bad = append(bad, path)
			}
			return fs.SkipDir
		case d.Type()&fs.ModeSymlink != 0, d.IsDir():
			return nil
		case !d.Type().IsRegular():
			bad = append(bad, path) // a special file: the reset refuses it
			return nil
		}
		if !probeReadable(path) {
			bad = append(bad, path)
		}
		return nil
	})
	return bad
}

// probeReadable opens path and reads its first bytes.
func probeReadable(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- path is under the declared log directory
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(io.Discard, io.LimitReader(f, repairProbeBytes))
	return err == nil
}

// historyUnkeepable reports whether the action history exists but is unreadable
// or corrupt (a line that is not a JSON value, or a file that is not a plain
// file).
func historyUnkeepable(path string) bool {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return false // a link is quarantined, not kept or lost
	}
	if !info.Mode().IsRegular() {
		return true
	}
	f, err := os.Open(path) // #nosec G304 -- the declared action-history file
	if err != nil {
		return true
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), repairMaxHistoryLineBytes)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !json.Valid([]byte(line)) {
			return true
		}
	}
	return sc.Err() != nil
}

// withDeclaredRoot runs fn on path inside the declared steward directory that
// holds it. Every access goes through an os.Root opened on that directory, so no
// component of path, a link planted in a parent included, can lead out of it: the
// steward acts as root or SYSTEM and the tree is not trusted yet.
func withDeclaredRoot(path string, fn func(root *os.Root, rel string) error) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for _, dir := range repairPathsResolver().roots() {
		if !within(dir, abs) {
			continue
		}
		rel, err := filepath.Rel(dir, abs)
		if err != nil || rel == "." {
			return fmt.Errorf("%s is a steward directory itself", path)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		return fn(root, rel)
	}
	return fmt.Errorf("%s is outside the declared steward directories", path)
}

// removeRepairItem deletes one approved item without following links. Every
// parent component below the declared directory must be a plain directory: a
// link or junction in a parent is refused even when it points inside the root,
// so the delete can only reach the entry the assessment named. The caller has
// already taken the tree over, so no other account can swap a component after
// this check.
func removeRepairItem(path string) error {
	return withDeclaredRoot(path, func(root *os.Root, rel string) error {
		parts := strings.Split(rel, string(filepath.Separator))
		for i := 1; i < len(parts); i++ {
			parent := filepath.Join(parts[:i]...)
			pinfo, err := root.Lstat(parent)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				return nil // the parent is gone (a quarantined link): nothing to delete
			case err != nil:
				return err
			case pinfo.Mode().Type() != fs.ModeDir:
				return fmt.Errorf("%s has a parent that is not a plain directory", path)
			}
		}
		info, err := root.Lstat(rel)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			return err
		case info.Mode()&fs.ModeSymlink != 0:
			return nil // the reset quarantines links; their targets are never touched
		case info.IsDir():
			return root.RemoveAll(rel)
		}
		return root.Remove(rel)
	})
}

// repairDecision is the outcome of comparing the assessment with the approval.
type repairDecision int

const (
	repairProceed repairDecision = iota
	repairRefusedDataLoss
	repairLossSetChanged
)

// decideRepairLoss applies the approval rule on the steward's side. The request's
// digest is signed by the controller on a baked host, so it is what the operator
// approved; the list beside it only has to agree with it.
//
//   - nothing lost: proceed (an approval of anything is a different set, refused
//     as changed);
//   - something lost and nothing approved: refused_data_loss, no delete at all;
//   - otherwise the recomputed digest must equal the approved one. A set that
//     grew, shrank or differs since the request is loss_set_changed.
func decideRepairLoss(req cpTypes.RepairRequest, a repairAssessment) repairDecision {
	if len(a.Codes) > 0 && len(req.ApprovedLossCodes) == 0 {
		return repairRefusedDataLoss
	}
	if a.digest() != req.LossDigest {
		return repairLossSetChanged
	}
	return repairProceed
}

// repairState is a repair that has generated its new keys and not yet seen the
// controller's answer persisted. It lets a restart resume with the same
// repair_id, the same new mTLS key and the same new identity key.
//
// ClientKeyPEM is the new mTLS private key in the clear, at mode 0600 in the
// steward's private cert store: the same protection the cert store gives the
// client key it replaces and PendingState gives a pending registration's key. It
// is removed with the rest of the state once the repair has finished.
type repairState struct {
	Version        int    `json:"version"`
	RepairID       string `json:"repair_id"`
	ClientKeyPEM   string `json:"client_key_pem"`
	CSRPEM         string `json:"csr_pem"`
	NewKeyPub      string `json:"new_key_pub"` // base64url of the staged identity public key
	ImportedSerial string `json:"imported_serial,omitempty"`
}

func loadRepairState(dir string) (*repairState, error) {
	// #nosec G304 -- fixed file name under the steward's private cert store.
	data, err := os.ReadFile(filepath.Join(dir, repairStateFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read repair state: %w", err)
	}
	var st repairState
	if err := json.Unmarshal(data, &st); err != nil || st.Version != repairStateVersion || !validRepairID(st.RepairID) {
		return nil, errors.New("repair state is corrupt")
	}
	return &st, nil
}

func saveRepairState(dir string, st repairState) error {
	st.Version = repairStateVersion
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, repairStateFileName), data)
}

func clearRepairState(dir string) error {
	if err := os.Remove(filepath.Join(dir, repairStateFileName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("clear repair state: %w", err)
	}
	return nil
}

// validRepairID reports whether id is a repair ID this steward will act on.
func validRepairID(id string) bool {
	if id == "" || len(id) > maxRepairIDLen {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}

// repairer carries the repair of one tamper alarm.
type repairer struct {
	logger        logging.Logger
	controllerURL string
	latch         *tamperLatch
	// rescan re-runs the local tamper checks and returns the fault still present.
	rescan func() *tamperFault

	// requests carries RepairRequests from the link's receive goroutine to the
	// alarm loop, which owns the link; wake tells the loop that a request or a
	// retry is due.
	requests chan cpTypes.RepairRequest
	wake     chan struct{}
	// dialsHeld is set from the moment the link is closed for a repair until its
	// completion has finished: nothing may dial in between.
	dialsHeld atomic.Bool

	mu      sync.Mutex
	reasons *client.HealthReasonRegistry
	// refused remembers entries an earlier reset could not take over, so the next
	// assessment names them.
	refused []string

	// retry state of a completion that is not finished.
	pendingID  string
	attempts   int
	retryTimer *time.Timer
	retryDue   atomic.Bool
}

func newRepairer(latch *tamperLatch, rescan func() *tamperFault, controllerURL string, logger logging.Logger) *repairer {
	return &repairer{
		logger: logger, controllerURL: controllerURL, latch: latch, rescan: rescan,
		requests: make(chan cpTypes.RepairRequest, 1),
		wake:     make(chan struct{}, 1),
		reasons:  client.NewHealthReasonRegistry(),
	}
}

// onRequest is the link's RepairRequest callback. It only queues the request; the
// alarm loop does the work, because the repair closes and reopens the link.
func (r *repairer) onRequest(req cpTypes.RepairRequest) {
	select {
	case r.requests <- req:
		r.signal()
	default:
		r.logger.Warn("Repair request dropped: another is waiting", "operation", "repair")
	}
}

func (r *repairer) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// wakeChan is the channel the alarm loop waits on; nil without a repairer.
func (r *repairer) wakeChan() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.wake
}

// start runs when the alarm starts: it publishes the loss set and resumes a repair
// that was mid-completion when the process stopped, with the same repair_id,
// before anything dials (the controller may already have retired the credential
// the stored identity presents).
func (r *repairer) start(ctx context.Context, tc *client.TransportClient) *client.TransportClient {
	if r == nil {
		return tc
	}
	r.refresh(nil)
	if r.pending() == "" {
		return tc
	}
	r.dialsHeld.Store(true)
	tc = r.resume(ctx, tc)
	r.armRetry()
	return tc
}

// service runs what woke the loop: a queued request, else a due retry.
func (r *repairer) service(ctx context.Context, tc *client.TransportClient) *client.TransportClient {
	select {
	case req := <-r.requests:
		tc = r.handle(ctx, tc, req)
	default:
		if r.retryDue.CompareAndSwap(true, false) {
			tc = r.resume(ctx, tc)
		}
	}
	r.armRetry()
	return tc
}

// armRetry schedules the next attempt of a completion that is not finished.
func (r *repairer) armRetry() {
	if !r.retrying() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retryTimer != nil {
		r.retryTimer.Stop()
	}
	r.retryTimer = time.AfterFunc(r.nextDelayLocked(), func() {
		r.retryDue.Store(true)
		r.signal()
	})
}

// setReason publishes a reason on the heartbeat now and on every link opened
// later. tc may be nil.
func (r *repairer) setReason(tc *client.TransportClient, component, code, message string) {
	r.reasons.Set(component, code, message)
	startupReasons.Set(component, code, message)
	if tc != nil {
		tc.SetHealthReason(component, code, message)
	}
}

func (r *repairer) clearReason(tc *client.TransportClient, component string) {
	r.reasons.Clear(component)
	startupReasons.Clear(component)
	if tc != nil {
		tc.ClearHealthReason(component)
	}
}

// outcome reports the repair's progress or result, carrying the repair ID.
func (r *repairer) outcome(tc *client.TransportClient, code, repairID string) {
	r.setReason(tc, cpTypes.HealthComponentRepair, code, repairID)
	if tc != nil {
		// A report-only link always reports error status. The operator should not
		// wait for the next periodic heartbeat to read the result.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tc.SendHeartbeat(ctx, string(cpTypes.StatusError), nil); err != nil {
				r.logger.Debug("Repair outcome heartbeat not sent", "operation", "repair",
					"error", logging.SanitizeLogValue(err.Error()))
			}
		}()
	}
}

// publishLoss makes the heartbeat list exactly the codes in a, one component per
// code, before any request arrives.
func (r *repairer) publishLoss(tc *client.TransportClient, a repairAssessment) {
	for _, code := range []string{cpTypes.ReasonCodeRepairLossLocalLogs, cpTypes.ReasonCodeRepairLossActionHistory} {
		if slices.Contains(a.Codes, code) {
			r.setReason(tc, code, code, "this local data cannot be kept by a repair; an operator must approve its loss")
		} else {
			r.clearReason(tc, code)
		}
	}
}

func (r *repairer) refusedSnapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.refused...)
}

// refresh re-assesses and publishes the loss set.
func (r *repairer) refresh(tc *client.TransportClient) repairAssessment {
	if r == nil {
		return repairAssessment{}
	}
	a := assessRepairLoss(repairPathsResolver(), r.refusedSnapshot())
	r.publishLoss(tc, a)
	return a
}

// republish re-applies every repair reason to a freshly opened link.
func (r *repairer) republish(tc *client.TransportClient) {
	if r == nil || tc == nil {
		return
	}
	for _, reason := range r.reasons.List() {
		tc.SetHealthReason(reason.Component, reason.Code, reason.Message)
	}
}

// clearAll drops every repair reason; the latch has been released.
func (r *repairer) clearAll() {
	if r == nil {
		return
	}
	for _, reason := range r.reasons.List() {
		r.reasons.Clear(reason.Component)
		startupReasons.Clear(reason.Component)
	}
}

// bakedHost reports whether this binary carries a usable baked root list.
func bakedHost() bool { return bakedRootReason() == "" }

// verifyRepairRequest decides whether req may be acted on. It returns "" when it
// may, else the reason code to report; "-" means the request is ignored without a
// report.
//
// On a host with a baked root list the signature over (steward ID, repair_id,
// loss digest, expiry) must verify through a chain whose root is a baked
// fingerprint, and the approved list must agree with the signed digest. On a host
// without one the request is honored on any session that passed the anchor check
// (the provider delivers nothing else), the same rule as TamperState{locked:
// false}. The residual: whoever can impersonate the controller to this steward
// must have rewritten the anchor in the data folder, so could already delete the
// local logs directly. Exception: a CA-class fault means the anchor itself is
// under suspicion, so a request that does not verify to a baked fingerprint is
// refused with repair.anchor_untrusted.
func verifyRepairRequest(stewardID string, req cpTypes.RepairRequest, tamperCodes []string, now time.Time) string {
	if !validRepairID(req.RepairID) {
		return "-"
	}
	expired := req.ExpiresAtUnix <= 0 || now.Unix() > req.ExpiresAtUnix
	if bakedHost() {
		payload := cpTypes.RepairSigningPayload(stewardID, req.RepairID, req.LossDigest, req.ExpiresAtUnix)
		if expired || cpTypes.LossDigest(req.ApprovedLossCodes) != req.LossDigest ||
			commands.VerifyLockedSigner(req.SignerChainPEM, req.Signature, payload) != nil {
			return cpTypes.ReasonCodeRepairSignatureInvalid
		}
		return ""
	}
	if hasCAClassCode(tamperCodes) {
		return cpTypes.ReasonCodeRepairAnchorUntrusted
	}
	if expired {
		return cpTypes.ReasonCodeRepairNotLocked
	}
	if cpTypes.LossDigest(req.ApprovedLossCodes) != req.LossDigest {
		return cpTypes.ReasonCodeRepairSignatureInvalid
	}
	return ""
}

// hasCAClassCode reports whether the latch holds a fault about the trust anchor.
func hasCAClassCode(codes []string) bool {
	return slices.Contains(codes, cpTypes.ReasonCodeTamperCAMismatch) ||
		slices.Contains(codes, cpTypes.ReasonCodeTamperTrustDowngrade)
}

// handle runs one RepairRequest. It owns the link: the link is closed before any
// credential changes and the returned link is nil, so the alarm loop dials again
// on the new credential.
func (r *repairer) handle(ctx context.Context, tc *client.TransportClient, req cpTypes.RepairRequest) *client.TransportClient {
	id, ok := r.admit(tc, req)
	if !ok {
		return tc
	}
	assessment, ok := r.approved(tc, req)
	if !ok {
		return tc
	}
	return r.execute(ctx, tc, id, req.RepairID, assessment)
}

// admit decides whether req may be acted on: a well-formed repair ID, a stored
// identity, a latched steward and a request that verifies. When it may not, the
// reason has been reported (or, for a malformed ID, nothing is).
func (r *repairer) admit(tc *client.TransportClient, req cpTypes.RepairRequest) (*StewardIdentity, bool) {
	repairID := req.RepairID
	if !validRepairID(repairID) {
		return nil, false
	}
	id, _ := loadIdentity(certStoreDirResolver())
	if id == nil {
		r.outcome(tc, cpTypes.ReasonCodeRepairFailed, repairID)
		return nil, false
	}
	if !r.latch.isLatched() {
		r.outcome(tc, cpTypes.ReasonCodeRepairNotLocked, repairID)
		return nil, false
	}
	reason := verifyRepairRequest(id.StewardID, req, r.latch.codesSnapshot(), time.Now())
	if reason != "" {
		r.logger.Warn("Repair request refused", "operation", "repair", "reason", reason,
			"repair_id", logging.SanitizeLogValue(repairID))
		r.outcome(tc, reason, repairID)
	}
	return id, reason == ""
}

// approved assesses the loss and compares it with the approval. Without an exact
// match it reports why and the repair does not go on.
func (r *repairer) approved(tc *client.TransportClient, req cpTypes.RepairRequest) (repairAssessment, bool) {
	r.outcome(tc, cpTypes.ReasonCodeRepairRunning, req.RepairID)
	assessment := r.refresh(tc)
	switch decideRepairLoss(req, assessment) {
	case repairRefusedDataLoss:
		r.outcome(tc, cpTypes.ReasonCodeRepairRefusedDataLoss, req.RepairID)
		return assessment, false
	case repairLossSetChanged:
		r.outcome(tc, cpTypes.ReasonCodeRepairLossSetChanged, req.RepairID)
		return assessment, false
	}
	return assessment, true
}

// execute carries out an approved repair. It closes the link first and returns nil,
// so the alarm loop dials again on whatever credential the repair leaves.
func (r *repairer) execute(ctx context.Context, tc *client.TransportClient, id *StewardIdentity, repairID string, assessment repairAssessment) *client.TransportClient {
	// Hold every dial from here until the completion has finished: the retired
	// credential must never be presented again, and a stream evicted by the
	// controller must not reconnect with it.
	r.dialsHeld.Store(true)
	if len(assessment.Codes) > 0 {
		r.flushOutbound(tc, assessment, repairID)
	}
	closeTamperLink(tc)

	// The flush took time: assess once more, so only what was approved is deleted.
	again := assessRepairLoss(repairPathsResolver(), r.refusedSnapshot())
	if again.digest() != assessment.digest() {
		r.outcome(nil, cpTypes.ReasonCodeRepairLossSetChanged, repairID)
		r.dialsHeld.Store(false)
		return nil
	}
	// Take the tree over before anything is deleted: once it is root (SYSTEM)
	// owned and its links are quarantined, no other account can swap a parent of
	// an approved item for a link between the check and the delete.
	if !r.takeOverBeforeDelete(repairPathsResolver(), again, repairID) {
		return nil
	}
	// The items to delete are the ones just re-assessed, not the first assessment's.
	if err := r.deleteApproved(again); err != nil {
		r.fail(repairID, "approved items could not be deleted", err)
		return nil
	}
	if !r.resetRights(repairPathsResolver(), repairID) {
		return nil
	}
	if err := r.discardExposed(id); err != nil {
		r.fail(repairID, "exposed trust material could not be discarded", err)
		return nil
	}
	resetDerivedState(r.logger)
	r.finish(ctx, repairID)
	return nil
}

// fail reports repair.failed and releases the dial hold; the steward stays
// latched with its old keys.
func (r *repairer) fail(repairID, why string, cause error) {
	r.logger.Error("Repair failed: "+why, "operation", "repair",
		"repair_id", logging.SanitizeLogValue(repairID),
		"error", logging.SanitizeLogValue(cause.Error()))
	r.outcome(nil, cpTypes.ReasonCodeRepairFailed, repairID)
	r.dialsHeld.Store(false)
}

// deleteApproved deletes exactly the items of the assessment, which decide has
// already matched to the approval. With nothing to lose no delete is made.
func (r *repairer) deleteApproved(a repairAssessment) error {
	for _, code := range a.Codes {
		for _, path := range a.items[code] {
			if err := repairRemoveItem(path); err != nil {
				return fmt.Errorf("delete %s: %w", code, err)
			}
		}
	}
	return nil
}

// takeOverBeforeDelete resets the rights of the declared paths ahead of the
// approved delete. Entries the reset refuses are acceptable only when they are
// approved items or lie inside one (a special file in the log directory is both
// unkeepable and refused); any other refusal stops the repair before a delete.
// It reports whether the repair may go on; on false it has already reported.
func (r *repairer) takeOverBeforeDelete(paths repairPaths, approved repairAssessment, repairID string) bool {
	report, err := repairTakeOver(paths.roots())
	for _, link := range report.Quarantined {
		r.logger.Warn("Repair removed a planted link; its target was not touched",
			"operation", "repair", "path", logging.SanitizeLogValue(link))
	}
	r.recordQuarantined(report.Quarantined)
	if err == nil {
		return true
	}
	refused := refusedPaths(report.Refused)
	for _, path := range refused {
		if !approved.covers(path) {
			r.mu.Lock()
			r.refused = append([]string(nil), refused...)
			r.mu.Unlock()
			r.fail(repairID, "the rights of the steward directories could not be reset", err)
			return false
		}
	}
	return true
}

// covers reports whether path is one of the assessment's items or lies inside one.
func (a repairAssessment) covers(path string) bool {
	for _, code := range a.Codes {
		for _, item := range a.items[code] {
			if within(item, path) {
				return true
			}
		}
	}
	return false
}

// resetRights resets the rights of the declared paths and verifies them. It
// reports whether the repair may go on; on false it has already reported.
func (r *repairer) resetRights(paths repairPaths, repairID string) bool {
	report, err := repairTakeOver(paths.roots())
	for _, link := range report.Quarantined {
		r.logger.Warn("Repair removed a planted link; its target was not touched",
			"operation", "repair", "path", logging.SanitizeLogValue(link))
	}
	r.recordQuarantined(report.Quarantined)
	if err != nil {
		r.mu.Lock()
		r.refused = append([]string(nil), refusedPaths(report.Refused)...)
		r.mu.Unlock()
		r.fail(repairID, "the rights of the steward directories could not be reset", err)
		return false
	}
	if err := repairRightsCheck(r.logger); err != nil {
		r.fail(repairID, "the rights did not verify after the reset", err)
		return false
	}
	r.mu.Lock()
	r.refused = nil
	r.mu.Unlock()
	return true
}

// refusedPaths extracts the path from each "path: reason" entry the reset refused.
func refusedPaths(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		path, _, _ := strings.Cut(e, ": ")
		out = append(out, path)
	}
	return out
}

// quarantinedLinks are the planted links the last reset removed; they are sent to
// the controller once the new link is up.
var quarantinedLinks atomic.Pointer[[]string]

func (r *repairer) recordQuarantined(links []string) {
	if len(links) == 0 {
		return
	}
	quarantinedLinks.Store(&links)
}

// discardExposed rewrites the identity without the trust material written while
// the folder was exposed, and re-anchors the CA. A CA that cannot be re-anchored
// stops the repair before any key changes.
func (r *repairer) discardExposed(id *StewardIdentity) error {
	ca, err := reanchoredCA(id, r.logger)
	if err != nil {
		return err
	}
	cleaned := withoutExposedTrust(*id)
	cleaned.CACertPEM = ca
	return saveIdentity(certStoreDirResolver(), cleaned)
}

// flushOutbound sends the readable local data of the kinds about to lose items
// off the host, so the loss is of local copies only. It is best effort per file.
func (r *repairer) flushOutbound(tc *client.TransportClient, a repairAssessment, repairID string) {
	if tc == nil {
		return
	}
	paths := repairPathsResolver()
	sent := 0
	send := func(code, path string) {
		for _, chunk := range readTailChunks(path) {
			if sent >= repairFlushMaxEntries {
				return
			}
			entry := &transportpb.LogEntry{
				Level:     transportpb.Severity_SEVERITY_INFO,
				Message:   chunk,
				Timestamp: timestamppb.Now(),
				Fields: map[string]string{
					"source": "repair_flush", "kind": code, "file": filepath.Base(path), "repair_id": repairID,
				},
			}
			if tc.EnqueueLog(entry) {
				sent++
			}
		}
	}
	if slices.Contains(a.Codes, cpTypes.ReasonCodeRepairLossLocalLogs) && paths.logDir != "" {
		_ = filepath.WalkDir(paths.logDir, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				send(cpTypes.ReasonCodeRepairLossLocalLogs, path)
			}
			return nil
		})
	}
	if slices.Contains(a.Codes, cpTypes.ReasonCodeRepairLossActionHistory) {
		send(cpTypes.ReasonCodeRepairLossActionHistory, paths.actionHistory())
	}
}

// readTailChunks reads up to the last repairFlushMaxBytesPerFile bytes of path in
// chunks. An unreadable file yields none.
func readTailChunks(path string) []string {
	var data []byte
	err := withDeclaredRoot(path, func(root *os.Root, rel string) error {
		var err error
		data, err = readRootFileTail(root, rel)
		return err
	})
	if err != nil {
		return nil
	}
	var chunks []string
	for len(data) > 0 {
		n := min(len(data), repairFlushChunkBytes)
		chunks = append(chunks, strings.ToValidUTF8(string(data[:n]), "?"))
		data = data[n:]
	}
	return chunks
}

// readRootFileTail reads up to the last repairFlushMaxBytesPerFile bytes of the
// regular file rel inside root. Anything but a regular file is refused, before
// and after it is opened.
func readRootFileTail(root *os.Root, rel string) ([]byte, error) {
	if info, err := root.Lstat(rel); err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > repairFlushMaxBytesPerFile {
		if _, err := f.Seek(info.Size()-repairFlushMaxBytesPerFile, io.SeekStart); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, repairFlushMaxBytesPerFile))
	if err != nil && len(data) == 0 {
		return nil, err
	}
	return data, nil
}

// finish completes the rotation, persists it, verifies the result and reports.
// It releases the dial hold unless the completion must be retried, in which case
// the hold stays until it finishes.
func (r *repairer) finish(ctx context.Context, repairID string) {
	err := r.complete(ctx, repairID)
	switch {
	case errors.Is(err, errRepairTransient):
		r.mu.Lock()
		r.pendingID = repairID
		r.mu.Unlock()
		r.logger.Warn("Repair completion not finished; retrying with the same keys",
			"operation", "repair", "repair_id", logging.SanitizeLogValue(repairID),
			"error", logging.SanitizeLogValue(err.Error()))
		r.outcome(nil, cpTypes.ReasonCodeRepairRunning, repairID)
		return
	case err != nil:
		r.mu.Lock()
		r.pendingID, r.attempts = "", 0
		r.mu.Unlock()
		r.fail(repairID, "the controller did not accept the new keys", err)
		return
	}
	r.mu.Lock()
	r.pendingID, r.attempts = "", 0
	r.mu.Unlock()
	if fault := r.rescan(); fault != nil {
		r.latch.raise(fault.code)
		r.outcome(nil, cpTypes.ReasonCodeRepairFaultPersists, repairID)
	} else {
		r.outcome(nil, cpTypes.ReasonCodeRepairCompleted, repairID)
	}
	r.dialsHeld.Store(false)
}

// nextDelayLocked returns how long to wait before the next completion attempt and
// counts the attempt.
func (r *repairer) nextDelayLocked() time.Duration {
	d := repairRetryBase
	for i := 0; i < r.attempts && d < repairRetryMax; i++ {
		d *= 2
	}
	r.attempts++
	return min(d, repairRetryMax)
}

// retrying reports whether a completion is waiting to be retried.
func (r *repairer) retrying() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pendingID != ""
}

// pending returns the repair ID of a completion still to finish, from memory or,
// after a restart, from the state file.
func (r *repairer) pending() string {
	r.mu.Lock()
	id := r.pendingID
	r.mu.Unlock()
	if id != "" {
		return id
	}
	st, err := loadRepairState(certStoreDirResolver())
	if err != nil || st == nil {
		return ""
	}
	return st.RepairID
}

// resume retries a completion that is not finished: the same repair_id, the same
// new keys. The link is closed first, as for a fresh repair.
func (r *repairer) resume(ctx context.Context, tc *client.TransportClient) *client.TransportClient {
	repairID := r.pending()
	if repairID == "" {
		return tc
	}
	r.dialsHeld.Store(true)
	closeTamperLink(tc)
	if err := repairRightsCheck(r.logger); err != nil {
		r.fail(repairID, "the rights did not verify before resuming", err)
		return nil
	}
	r.outcome(nil, cpTypes.ReasonCodeRepairRunning, repairID)
	r.finish(ctx, repairID)
	return nil
}

// complete rotates the identity key and the mTLS key with the controller. The old
// identity key keeps signing until the controller has accepted the new one and the
// response is persisted; only then is the new key promoted and the old one dropped.
func (r *repairer) complete(ctx context.Context, repairID string) error {
	dir := certStoreDirResolver()
	id, err := loadIdentity(dir)
	if err != nil || id == nil {
		return errors.New("no stored identity")
	}
	ks, err := repairOpenKeyStore(ctx, dir, r.logger)
	if err != nil {
		return fmt.Errorf("open device key store: %w", err)
	}
	rot, ok := ks.(identity.StagedRotator)
	if !ok {
		return errors.New("the device key store cannot stage a replacement key; the old key is kept")
	}
	st := r.stateFor(dir, rot, repairID)
	if st != nil && rot.StagedPublicKey() == nil {
		return r.finishPromoted(dir, ks, st)
	}
	if st == nil {
		if st, err = r.stageKeys(ctx, dir, ks, rot, repairID); err != nil {
			return err
		}
	}
	return r.exchange(ctx, dir, id, ks, rot, st)
}

// stateFor returns the recorded state of this repair, or nil when there is none.
// A state that cannot be read, or that belongs to another repair, is discarded
// together with its staged key: a different repair supersedes an unfinished one.
func (r *repairer) stateFor(dir string, rot identity.StagedRotator, repairID string) *repairState {
	st, err := loadRepairState(dir)
	if st != nil && err == nil && st.RepairID == repairID {
		return st
	}
	if st != nil || err != nil {
		_ = rot.DiscardStaged()
		_ = clearRepairState(dir)
	}
	return nil
}

// stageKeys generates the new identity key and the new mTLS key and records them.
func (r *repairer) stageKeys(ctx context.Context, dir string, ks identity.KeyStore, rot identity.StagedRotator, repairID string) (*repairState, error) {
	pub, alg, err := rot.StageNext(ctx)
	if err != nil {
		return nil, fmt.Errorf("stage new identity key: %w", err)
	}
	if alg != ks.Algorithm() || rank(rot.ProtectionLevel()) < rank(ks.ProtectionLevel()) {
		_ = rot.DiscardStaged()
		return nil, errors.New("the new identity key would be weaker than the old one")
	}
	pubBytes, err := identity.EncodePublicKeyBytes(alg, pub)
	if err != nil {
		_ = rot.DiscardStaged()
		return nil, err
	}
	mtlsKey, err := registration.GenerateStewardKeypair()
	if err != nil {
		_ = rot.DiscardStaged()
		return nil, err
	}
	keyPEM, err := registration.EncodeECDSAPrivateKeyPEM(mtlsKey)
	if err != nil {
		_ = rot.DiscardStaged()
		return nil, err
	}
	csrPEM, err := registration.BuildRegistrationCSR(mtlsKey, ks.DeviceID())
	if err != nil {
		_ = rot.DiscardStaged()
		return nil, err
	}
	st := &repairState{RepairID: repairID, ClientKeyPEM: keyPEM, CSRPEM: csrPEM,
		NewKeyPub: base64.RawURLEncoding.EncodeToString(pubBytes)}
	if err := saveRepairState(dir, *st); err != nil {
		_ = rot.DiscardStaged()
		return nil, fmt.Errorf("record repair state: %w", err)
	}
	return st, nil
}

// rank orders protection levels: file < tpm < secure-enclave.
func rank(l identity.ProtectionLevel) int {
	switch l {
	case identity.ProtectionSecureEnclave:
		return 2
	case identity.ProtectionTPM:
		return 1
	}
	return 0
}

// exchange sends the completion and persists the answer.
func (r *repairer) exchange(ctx context.Context, dir string, id *StewardIdentity, ks identity.KeyStore, rot identity.StagedRotator, st *repairState) error {
	httpc, err := r.httpClient(id)
	if err != nil {
		return err
	}
	stagedPub := rot.StagedPublicKey()
	pubBytes, err := identity.EncodePublicKeyBytes(ks.Algorithm(), stagedPub)
	if err != nil {
		return err
	}
	digest := cpTypes.RepairRotationProofDigest(id.StewardID, st.RepairID, pubBytes, st.CSRPEM)
	oldProof, err := ks.Sign(digest)
	if err != nil {
		return fmt.Errorf("old identity key proof: %w", err)
	}
	newProof, err := rot.SignStaged(digest)
	if err != nil {
		return fmt.Errorf("new identity key proof: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := httpc.RepairComplete(callCtx, ks.DeviceID(), registration.RepairCompleteRequest{
		TenantID:            id.TenantID,
		CSRPEM:              st.CSRPEM,
		RepairID:            st.RepairID,
		NewIdentityKeyPub:   base64.RawURLEncoding.EncodeToString(pubBytes),
		NewIdentityKeyAlg:   string(ks.Algorithm()),
		NewIdentityKeyLevel: string(rot.ProtectionLevel()),
		OldKeyProof:         base64.RawURLEncoding.EncodeToString(oldProof),
		NewKeyProof:         base64.RawURLEncoding.EncodeToString(newProof),
	})
	var refused *registration.RepairRefusedError
	switch {
	case errors.As(err, &refused):
		// The controller refused: the old keys stay and nothing is retried.
		_ = rot.DiscardStaged()
		_ = clearRepairState(dir)
		return fmt.Errorf("controller refused the repair completion (HTTP %d)", refused.Status)
	case err != nil:
		return fmt.Errorf("%w: %v", errRepairTransient, err)
	}
	if resp.ClientCert == "" {
		return fmt.Errorf("%w: the response carried no client certificate", errRepairTransient)
	}
	return r.persist(dir, id, ks, rot, st, resp)
}

// httpClient builds the client for the refresh endpoints from the compile or
// install URL and the trust configuration registration uses, not from the
// report-only link.
func (r *repairer) httpClient(id *StewardIdentity) (*registration.HTTPClient, error) {
	installCA, caErr := loadInstallCAPEM(id, r.logger)
	if caErr != nil {
		installCA = ""
	}
	src, url, err := resolveTrustSourceForStart(ControllerURL, r.controllerURL, installCA, id)
	if err != nil {
		return nil, err
	}
	httpc, err := registration.NewHTTPClient(registrationHTTPConfig(url, src, installCA, r.logger))
	if err != nil {
		return nil, fmt.Errorf("create HTTP client for repair: %w", err)
	}
	return httpc, nil
}

// persist stores the accepted credential: the new certificate and mTLS key, the
// identity record with the new key, then the new identity key; the old
// certificates go last. A crash before the promotion leaves the old identity key
// in place, so the same completion can be sent again.
func (r *repairer) persist(dir string, id *StewardIdentity, ks identity.KeyStore, rot identity.StagedRotator, st *repairState, resp *registration.RefreshCompleteResponse) error {
	fullChain := resp.ClientCert + resp.IssuerChain
	if _, err := tls.X509KeyPair([]byte(fullChain), []byte(st.ClientKeyPEM)); err != nil {
		return fmt.Errorf("the issued certificate does not match the new mTLS key: %w", err)
	}
	certMgr, err := cert.NewManager(&cert.ManagerConfig{StoragePath: dir, LoadExistingCA: true})
	if err != nil {
		certMgr, err = cert.NewManager(&cert.ManagerConfig{
			StoragePath: dir,
			CAConfig:    &cert.CAConfig{Organization: "CFGMS Steward", Country: "US", ValidityDays: 3650},
		})
	}
	if err != nil {
		return fmt.Errorf("%w: open cert store: %v", errRepairTransient, err)
	}
	imported, err := certMgr.ImportCertificate([]byte(fullChain), []byte(st.ClientKeyPEM), cert.CertificateTypeClient)
	if err != nil {
		return fmt.Errorf("%w: store the new client certificate: %v", errRepairTransient, err)
	}
	st.ImportedSerial = imported.SerialNumber
	if err := saveRepairState(dir, *st); err != nil {
		return fmt.Errorf("%w: record repair state: %v", errRepairTransient, err)
	}
	updated, err := withRotatedIdentityKey(*id, ks.Algorithm(), rot.ProtectionLevel(), rot.StagedPublicKey())
	if err != nil {
		return err
	}
	if err := saveIdentity(dir, updated); err != nil {
		return fmt.Errorf("%w: save identity: %v", errRepairTransient, err)
	}
	if err := rot.PromoteStaged(); err != nil {
		return fmt.Errorf("%w: promote the new identity key: %v", errRepairTransient, err)
	}
	return r.finishPromoted(dir, ks, st)
}

// finishPromoted drops the old client certificates and the repair state once the
// new identity key is current.
func (r *repairer) finishPromoted(dir string, ks identity.KeyStore, st *repairState) error {
	if ks.PublicKey() != nil {
		if encoded, err := identity.EncodePublicKeyBytes(ks.Algorithm(), ks.PublicKey()); err != nil ||
			base64.RawURLEncoding.EncodeToString(encoded) != st.NewKeyPub {
			_ = clearRepairState(dir)
			return errors.New("the current identity key is not the repair's new key")
		}
	}
	certMgr, err := cert.NewManager(&cert.ManagerConfig{StoragePath: dir, LoadExistingCA: true})
	if err != nil {
		return fmt.Errorf("%w: open cert store: %v", errRepairTransient, err)
	}
	certs, err := certMgr.ListCertificates()
	if err != nil {
		return fmt.Errorf("%w: list certificates: %v", errRepairTransient, err)
	}
	for _, c := range certs {
		if c.Type == cert.CertificateTypeClient && c.SerialNumber != st.ImportedSerial {
			if err := certMgr.DeleteCertificate(c.SerialNumber); err != nil {
				return fmt.Errorf("%w: remove a retired client certificate: %v", errRepairTransient, err)
			}
		}
	}
	return clearRepairState(dir)
}
