// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	common "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/directory"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dptypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Bulk lane bounds. The host-lane constants (maxDNATransferFragments,
// maxDeltaFragments, maxDNAFragmentBytes, maxDeltaCanonicalBytes,
// maxDeltaStreamBytes) are unchanged and keep governing the host lane; the bulk
// lane adds its own limits on top of the shared fragment id rules.
const (
	// maxBulkBatchFragments bounds the fragments requested, and accepted, per delta.
	maxBulkBatchFragments = 2000

	// maxBulkBatchBytes bounds the summed canonical bytes accepted per delta.
	maxBulkBatchBytes = 8 << 20

	// maxBulkManifestBuckets bounds the buckets requested per bulk=manifest, which
	// keeps one manifest reply well inside the reassembly cap even at the
	// per-steward fragment limit.
	maxBulkManifestBuckets = 16

	// bulkRoundMinInterval and bulkRoundsPerHour bound how often one steward can
	// force a round. A steward whose bulk root changes on every heartbeat gets one
	// round a minute, and no more than twenty an hour.
	bulkRoundMinInterval = 60 * time.Second
	bulkRoundsPerHour    = 20
	bulkRoundWindow      = time.Hour

	// bulkRoundStaleAfter is how long a round may go without progress before the
	// next heartbeat is allowed to replace it. A round whose steward reconnected to
	// another node never sees a reply; this is what abandons it.
	bulkRoundStaleAfter = 60 * time.Second

	bulkSweepInterval = time.Minute
)

// PerObjectKindLister answers which per-object fragment kinds the controller
// accepts from a steward of tenantID. A nil lister, an error, or an empty answer
// rejects every bulk delta (fail closed).
type PerObjectKindLister interface {
	ListPerObjectKinds(tenantID string) ([]string, error)
}

type bulkPhase int

const (
	bulkPhaseBuckets bulkPhase = iota
	bulkPhaseManifest
	bulkPhaseFragments
)

// bulkRound is the state of one in-progress bulk round for one steward. It lives
// on the node that received the heartbeat and issued the commands; no other node
// ever sees it.
type bulkRound struct {
	mu sync.Mutex

	steward     string
	claimedRoot string
	kinds       map[string]struct{}
	startedAt   time.Time
	progressAt  time.Time
	phase       bulkPhase
	done        bool

	stored      []*common.ManifestEntry // read at start; reduced after the buckets reply
	storedTotal int
	bucketRoots [][]byte // the steward's, from the buckets reply

	diffBuckets []int
	groupIdx    int
	storedByID  map[string]string // stored id -> hash, differing buckets only
	remoteHash  map[string]string // ids to fetch -> hash the steward's manifest declared
	toFetch     []string
	removed     []string

	batchIdx int
	pending  map[string]struct{} // ids of the current batch not yet received
}

// roundLimiter enforces the per-steward round rate limit.
type roundLimiter struct {
	mu     sync.Mutex
	starts map[string][]time.Time
}

func (l *roundLimiter) allow(steward string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.prune(steward, now)
	if len(s) >= bulkRoundsPerHour {
		return false
	}
	return len(s) == 0 || now.Sub(s[len(s)-1]) >= bulkRoundMinInterval
}

func (l *roundLimiter) record(steward string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.starts == nil {
		l.starts = make(map[string][]time.Time)
	}
	l.starts[steward] = append(l.prune(steward, now), now)
}

// prune drops starts older than the window. Callers hold l.mu.
func (l *roundLimiter) prune(steward string, now time.Time) []time.Time {
	s := l.starts[steward]
	i := 0
	for i < len(s) && now.Sub(s[i]) >= bulkRoundWindow {
		i++
	}
	s = s[i:]
	if len(s) == 0 {
		delete(l.starts, steward)
		return nil
	}
	l.starts[steward] = s
	return s
}

func (l *roundLimiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id := range l.starts {
		l.prune(id, now)
	}
}

// WithBulkLane wires the bulk lane's controller-side dependencies: the per-object
// kind allowlist, the directory membership sink, and the directory authority
// verifier. A nil kinds rejects every bulk delta. A nil sink or verifier means
// directory fragments are stored and written to the entity graph but never reach
// the membership state. Returns h for chaining.
func (h *DNAHandler) WithBulkLane(kinds PerObjectKindLister, sink directory.MembershipSink, auth dnasync.DirectoryAuthority) *DNAHandler {
	h.bulkKinds = kinds
	h.membershipSink = sink
	h.directoryAuth = auth
	return h
}

// WithHostPartialSync turns the host-lane partial sync on or off. It is off by
// default: with it off, HandleHeartbeatRoot starts no host round.
func (h *DNAHandler) WithHostPartialSync(enabled bool) *DNAHandler {
	h.hostPartialSync = enabled
	return h
}

func (h *DNAHandler) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}

// HandleHeartbeatBulkRoot is called by the heartbeat service when a heartbeat
// carries a dna_bulk_root. A claimed root that differs from the stored one starts
// a bulk round: bucket roots, a bucket diff, bounded fragment fetches, removals
// and root verification, each step triggered by the previous reply.
func (h *DNAHandler) HandleHeartbeatBulkRoot(ctx context.Context, stewardID, claimedRoot string) {
	if h.store == nil || h.publisher == nil {
		return
	}
	safeID := logging.SanitizeLogValue(stewardID)
	if !isValidAggregateRoot(claimedRoot) {
		h.logger.Warn("bulk-sync: rejecting malformed bulk root",
			"steward_id", safeID, "root_length", len(claimedRoot))
		return
	}
	if v, ok := h.verifiedBulkRoots.Load(stewardID); ok && v.(string) == claimedRoot {
		return
	}

	now := h.clock()
	h.sweepBulkState(now)

	if existing, ok := h.bulkRounds.Load(stewardID); ok {
		r := existing.(*bulkRound)
		r.mu.Lock()
		fresh := !r.done && now.Sub(r.progressAt) < bulkRoundStaleAfter
		if !fresh {
			r.done = true
		}
		r.mu.Unlock()
		if fresh {
			return // one round at a time per steward
		}
		h.bulkRounds.CompareAndDelete(stewardID, existing)
	}
	if !h.bulkLimiter.allow(stewardID, now) {
		h.logger.Debug("bulk-sync: round rate limited", "steward_id", safeID)
		return
	}

	manifest, err := h.store.CurrentManifest(stewardID)
	if err != nil {
		h.logger.Warn("bulk-sync: failed to read stored manifest",
			"steward_id", safeID, "error", logging.SanitizeLogValue(err.Error()))
		return
	}
	if sdna.BulkRoot(manifest) == claimedRoot {
		h.verifiedBulkRoots.Store(stewardID, claimedRoot)
		return
	}

	kinds, err := h.allowedKinds(stewardID)
	if err != nil {
		h.logger.Warn("bulk-sync: kind allowlist unavailable; no round started",
			"steward_id", safeID, "error", logging.SanitizeLogValue(err.Error()))
		return
	}

	r := &bulkRound{
		steward: stewardID, claimedRoot: claimedRoot, kinds: kinds,
		startedAt: now, progressAt: now, phase: bulkPhaseBuckets,
		stored: manifest, storedTotal: len(manifest),
	}
	h.bulkLimiter.record(stewardID, now)
	h.bulkRounds.Store(stewardID, r)

	if err := h.publishBulk(ctx, stewardID, cpTypes.SyncDNABulkBuckets, nil); err != nil {
		h.abortBulkRound(r, "publish failed", err)
		return
	}
	h.logger.Info("bulk-sync: round started", "steward_id", safeID)
}

// allowedKinds resolves the per-object kind allowlist for the steward's tenant.
// The tenant comes from the controller's registry, never from the heartbeat.
func (h *DNAHandler) allowedKinds(stewardID string) (map[string]struct{}, error) {
	if h.bulkKinds == nil {
		return nil, errors.New("no per-object kind lookup wired")
	}
	if h.tenantResolver == nil {
		return nil, errors.New("no tenant resolver wired")
	}
	tenant, known := h.tenantResolver.TenantForDevice(stewardID)
	if !known || tenant == "" {
		return nil, errors.New("steward tenant unknown")
	}
	list, err := h.bulkKinds.ListPerObjectKinds(tenant)
	if err != nil {
		return nil, fmt.Errorf("list per-object kinds: %w", err)
	}
	set := make(map[string]struct{}, len(list))
	for _, k := range list {
		if k != "" {
			set[k] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil, errors.New("no per-object kinds are owned for this tenant")
	}
	return set, nil
}

func (h *DNAHandler) publishBulk(ctx context.Context, stewardID, mode string, extra map[string]interface{}) error {
	params := map[string]interface{}{cpTypes.SyncDNAParamBulk: mode}
	for k, v := range extra {
		params[k] = v
	}
	_, err := h.publisher.PublishCommand(ctx, stewardID, cpTypes.CommandSyncDNA, params)
	return err
}

// sweepBulkState drops round state and limiter history that can no longer matter.
func (h *DNAHandler) sweepBulkState(now time.Time) {
	h.bulkSweepMu.Lock()
	due := now.Sub(h.bulkSweptAt) >= bulkSweepInterval
	if due {
		h.bulkSweptAt = now
	}
	h.bulkSweepMu.Unlock()
	if !due {
		return
	}
	h.bulkRounds.Range(func(k, v any) bool {
		r := v.(*bulkRound)
		r.mu.Lock()
		stale := r.done || now.Sub(r.progressAt) >= bulkRoundStaleAfter
		if stale {
			r.done = true
		}
		r.mu.Unlock()
		if stale {
			h.bulkRounds.CompareAndDelete(k, v)
		}
		return true
	})
	h.bulkLimiter.sweep(now)
}

func (h *DNAHandler) abortBulkRound(r *bulkRound, reason string, err error) {
	r.mu.Lock()
	r.done = true
	r.mu.Unlock()
	h.bulkRounds.CompareAndDelete(r.steward, r)
	attrs := []any{"steward_id", logging.SanitizeLogValue(r.steward), "reason", reason}
	if err != nil {
		attrs = append(attrs, "error", logging.SanitizeLogValue(err.Error()))
	}
	h.logger.Warn("bulk-sync: round abandoned", attrs...)
}

// failLocked marks the round finished while r.mu is held.
func (h *DNAHandler) failLocked(r *bulkRound, reason string, err error) error {
	r.done = true
	h.bulkRounds.CompareAndDelete(r.steward, r)
	attrs := []any{"steward_id", logging.SanitizeLogValue(r.steward), "reason", reason}
	if err != nil {
		attrs = append(attrs, "error", logging.SanitizeLogValue(err.Error()))
	}
	h.logger.Warn("bulk-sync: round abandoned", attrs...)
	if err != nil {
		return fmt.Errorf("bulk round: %s: %w", reason, err)
	}
	return fmt.Errorf("bulk round: %s", reason)
}

// bulkKindOf returns the kind prefix of a bulk fragment id, or "" when the id has
// no kind prefix or no object part.
func bulkKindOf(id string) string {
	kind, rest, ok := strings.Cut(id, ":")
	if !ok || kind == "" || rest == "" {
		return ""
	}
	return kind
}

// validBulkID applies the shared fragment id rules plus the round's kind allowlist.
func (r *bulkRound) validBulkID(id string) error {
	if err := validateFragmentID(id); err != nil {
		return err
	}
	kind := bulkKindOf(id)
	if kind == "" {
		return errors.New("fragment_id has no kind prefix")
	}
	if _, ok := r.kinds[kind]; !ok {
		return errors.New("fragment kind is not a per-object kind owned for this steward")
	}
	return nil
}

func bulkRootOfBucketRoots(roots [][]byte) string {
	h := sha256.New()
	for _, r := range roots {
		_, _ = h.Write(r)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// lookupBulkRound returns the live round for stewardID in the wanted phase, locked.
func (h *DNAHandler) lookupBulkRound(stewardID string, phase bulkPhase) (*bulkRound, error) {
	v, ok := h.bulkRounds.Load(stewardID)
	if !ok {
		return nil, errors.New("no bulk round in progress")
	}
	r := v.(*bulkRound)
	r.mu.Lock()
	if r.done || r.phase != phase {
		r.mu.Unlock()
		return nil, errors.New("bulk reply does not match the round phase")
	}
	if h.clock().Sub(r.progressAt) >= bulkRoundStaleAfter {
		h.failLocked(r, "round timed out", nil) //nolint:errcheck // already reported
		r.mu.Unlock()
		return nil, errors.New("bulk round timed out")
	}
	return r, nil
}

// handleBulkRoots processes the bulk=buckets reply.
func (h *DNAHandler) handleBulkRoots(ctx context.Context, peerID string, roots [][]byte) error {
	r, err := h.lookupBulkRound(peerID, bulkPhaseBuckets)
	if err != nil {
		return err
	}
	defer r.mu.Unlock()

	if len(roots) != sdna.BucketCount {
		return h.failLocked(r, "bucket roots have the wrong length", nil)
	}
	for _, b := range roots {
		if len(b) != sha256.Size {
			return h.failLocked(r, "bucket root has the wrong size", nil)
		}
	}
	if bulkRootOfBucketRoots(roots) != r.claimedRoot {
		return h.failLocked(r, "bucket roots do not hash to the heartbeat bulk root", nil)
	}

	stored := sdna.BucketRoots(r.stored)
	var diff []int
	for b := range roots {
		if !bytes.Equal(roots[b], stored[b]) {
			diff = append(diff, b)
		}
	}
	if len(diff) == 0 {
		h.verifiedBulkRoots.Store(peerID, r.claimedRoot)
		r.done = true
		h.bulkRounds.CompareAndDelete(peerID, r)
		return nil
	}

	inDiff := make(map[int]struct{}, len(diff))
	for _, b := range diff {
		inDiff[b] = struct{}{}
	}
	r.storedByID = make(map[string]string)
	for _, e := range r.stored {
		if _, ok := inDiff[sdna.BucketOf(e.GetFragmentId())]; ok {
			r.storedByID[e.GetFragmentId()] = e.GetFragmentHash()
		}
	}
	r.stored = nil
	r.bucketRoots = roots
	r.diffBuckets = diff
	r.remoteHash = make(map[string]string)
	r.phase = bulkPhaseManifest
	r.groupIdx = 0
	r.progressAt = h.clock()
	return h.requestManifestGroup(ctx, r)
}

func (r *bulkRound) group() []int {
	lo := r.groupIdx * maxBulkManifestBuckets
	hi := lo + maxBulkManifestBuckets
	if hi > len(r.diffBuckets) {
		hi = len(r.diffBuckets)
	}
	return r.diffBuckets[lo:hi]
}

func (h *DNAHandler) requestManifestGroup(ctx context.Context, r *bulkRound) error {
	buckets, _ := json.Marshal(r.group())
	if err := h.publishBulk(ctx, r.steward, cpTypes.SyncDNABulkManifest,
		map[string]interface{}{cpTypes.SyncDNAParamBuckets: string(buckets)}); err != nil {
		return h.failLocked(r, "publish failed", err)
	}
	return nil
}

// handleBulkManifest processes a bulk=manifest reply for the current bucket group.
func (h *DNAHandler) handleBulkManifest(ctx context.Context, peerID string, entries []*common.ManifestEntry) error {
	r, err := h.lookupBulkRound(peerID, bulkPhaseManifest)
	if err != nil {
		return err
	}
	defer r.mu.Unlock()

	group := r.group()
	inGroup := make(map[int][]*common.ManifestEntry, len(group))
	for _, b := range group {
		inGroup[b] = nil
	}
	remote := make(map[string]string, len(entries))
	if len(entries) > MaxBulkFragmentsPerSteward {
		return h.failLocked(r, "manifest exceeds the per-steward fragment limit", nil)
	}
	for _, e := range entries {
		id := e.GetFragmentId()
		if vErr := r.validBulkID(id); vErr != nil {
			return h.failLocked(r, "manifest entry rejected", vErr)
		}
		if !sdna.IsValidAggregateRoot(e.GetFragmentHash()) {
			return h.failLocked(r, "manifest entry hash is malformed", nil)
		}
		if _, dup := remote[id]; dup {
			return h.failLocked(r, "manifest repeats an entry", nil)
		}
		b := sdna.BucketOf(id)
		if _, ok := inGroup[b]; !ok {
			return h.failLocked(r, "manifest entry is outside the requested buckets", nil)
		}
		remote[id] = e.GetFragmentHash()
		inGroup[b] = append(inGroup[b], e)
	}
	// Every bucket's entries must hash to the root the steward advertised for it,
	// which in turn hashes to the heartbeat root. A withheld or altered entry
	// breaks this chain.
	for _, b := range group {
		var got string
		if len(inGroup[b]) == 0 {
			got = hex.EncodeToString(sdna.EmptyBucketRoot())
		} else {
			root, rErr := sdna.AggregateRoot(inGroup[b])
			if rErr != nil {
				return h.failLocked(r, "manifest bucket root not computable", rErr)
			}
			got = root
		}
		if got != hex.EncodeToString(r.bucketRoots[b]) {
			return h.failLocked(r, "manifest does not match the advertised bucket root", nil)
		}
	}

	inThisGroup := make(map[int]struct{}, len(group))
	for _, b := range group {
		inThisGroup[b] = struct{}{}
	}
	for id, hash := range remote {
		if cur, ok := r.storedByID[id]; !ok || cur != hash {
			r.toFetch = append(r.toFetch, id)
			r.remoteHash[id] = hash
		}
	}
	for id := range r.storedByID {
		if _, ok := inThisGroup[sdna.BucketOf(id)]; !ok {
			continue
		}
		if _, still := remote[id]; !still {
			r.removed = append(r.removed, id)
		}
	}
	if r.storedTotal+len(r.toFetch)-len(r.removed) > MaxBulkFragmentsPerSteward {
		return h.failLocked(r, "round would exceed the per-steward fragment limit", nil)
	}
	r.progressAt = h.clock()

	r.groupIdx++
	if r.groupIdx*maxBulkManifestBuckets < len(r.diffBuckets) {
		return h.requestManifestGroup(ctx, r)
	}
	sort.Strings(r.toFetch)
	sort.Strings(r.removed)
	r.phase = bulkPhaseFragments
	r.batchIdx = -1
	return h.advanceBatch(ctx, r)
}

// advanceBatch requests the next batch of ids, or finishes the round when none
// are left. Called with r.mu held.
func (h *DNAHandler) advanceBatch(ctx context.Context, r *bulkRound) error {
	r.batchIdx++
	lo := r.batchIdx * maxBulkBatchFragments
	if lo >= len(r.toFetch) {
		return h.finishBulkRound(ctx, r)
	}
	hi := lo + maxBulkBatchFragments
	if hi > len(r.toFetch) {
		hi = len(r.toFetch)
	}
	ids := r.toFetch[lo:hi]
	r.pending = make(map[string]struct{}, len(ids))
	for _, id := range ids {
		r.pending[id] = struct{}{}
	}
	idsJSON, _ := json.Marshal(ids)
	if err := h.publishBulk(ctx, r.steward, cpTypes.SyncDNABulkFragments,
		map[string]interface{}{cpTypes.SyncDNAParamFragmentIDs: string(idsJSON)}); err != nil {
		return h.failLocked(r, "publish failed", err)
	}
	r.progressAt = h.clock()
	return nil
}

// validateBulkFragments applies the bulk lane's delta bounds: count, bytes,
// per-fragment size, id rules and kind allowlist, membership in the requested
// set, and the hash the steward's own manifest declared for the id.
func (r *bulkRound) validateBulkFragments(received []*common.Fragment) error {
	if len(received) > maxBulkBatchFragments {
		return fmt.Errorf("delta carries %d fragments, limit is %d", len(received), maxBulkBatchFragments)
	}
	if err := validateDeltaFragments(received, r.pending); err != nil {
		return err
	}
	total := 0
	for _, f := range received {
		if err := r.validBulkID(f.GetFragmentId()); err != nil {
			return err
		}
		if proto.Size(f) > maxDNAFragmentBytes {
			return fmt.Errorf("fragment %q exceeds the %d byte limit", logging.SanitizeLogValue(f.GetFragmentId()), maxDNAFragmentBytes)
		}
		total += len(f.GetCanonicalBytes())
		if total > maxBulkBatchBytes {
			return fmt.Errorf("delta canonical_bytes exceed the %d byte limit", maxBulkBatchBytes)
		}
	}
	return nil
}

// handleBulkFragments processes one bulk=fragments delta transfer.
func (h *DNAHandler) handleBulkFragments(ctx context.Context, peerID string, transfer *dptypes.DNATransfer) error {
	r, err := h.lookupBulkRound(peerID, bulkPhaseFragments)
	if err != nil {
		return err
	}
	defer r.mu.Unlock()

	received := transfer.Fragments
	if len(received) == 0 {
		return h.failLocked(r, "delta carries no fragments", nil)
	}
	if vErr := r.validateBulkFragments(received); vErr != nil {
		return h.failLocked(r, "delta rejected", vErr)
	}
	if lErr := verifyFragmentLeaves(received); lErr != nil {
		return h.failLocked(r, "delta rejected", lErr)
	}
	for _, f := range received {
		if sdna.FragmentHash(f.GetCanonicalBytes()) != r.remoteHash[f.GetFragmentId()] {
			return h.failLocked(r, "fragment does not match the manifest entry", nil)
		}
	}

	// The membership sink goes first. If it fails nothing of this batch is
	// committed, and the next round re-diffs and fetches it again.
	if sErr := h.applyBulkToSink(ctx, peerID, received, nil); sErr != nil {
		return h.failLocked(r, "membership sink failed", sErr)
	}
	if aErr := h.store.ApplyDelta(peerID, received); aErr != nil {
		return h.failLocked(r, "commit failed", aErr)
	}
	if h.egWriter != nil && h.egTaxonomy != nil {
		if egErr := h.egWriter.WriteFragmentsPartial(ctx, peerID, received, nil, h.egTaxonomy); egErr != nil {
			h.logger.Warn("bulk-sync: entity-graph write failed; manifest committed, graph may lag",
				"peer_id", logging.SanitizeLogValue(peerID), "error", logging.SanitizeLogValue(egErr.Error()))
		}
	}
	for _, f := range received {
		delete(r.pending, f.GetFragmentId())
	}
	r.storedTotal += len(received)
	r.progressAt = h.clock()
	if len(r.pending) > 0 {
		return nil // more transfers of this batch are expected
	}
	return h.advanceBatch(ctx, r)
}

// finishBulkRound verifies the recomputed bulk root, then applies removals.
// Called with r.mu held after the last batch.
func (h *DNAHandler) finishBulkRound(ctx context.Context, r *bulkRound) error {
	manifest, err := h.store.CurrentManifest(r.steward)
	if err != nil {
		return h.failLocked(r, "stored manifest unreadable", err)
	}
	gone := make(map[string]struct{}, len(r.removed))
	for _, id := range r.removed {
		gone[id] = struct{}{}
	}
	kept := manifest[:0:0]
	for _, e := range manifest {
		if _, drop := gone[e.GetFragmentId()]; !drop {
			kept = append(kept, e)
		}
	}
	if sdna.BulkRoot(kept) != r.claimedRoot {
		return h.failLocked(r, "recomputed bulk root does not match the heartbeat root", nil)
	}

	for lo := 0; lo < len(r.removed); lo += maxBulkBatchFragments {
		hi := lo + maxBulkBatchFragments
		if hi > len(r.removed) {
			hi = len(r.removed)
		}
		batch := r.removed[lo:hi]
		if sErr := h.applyBulkToSink(ctx, r.steward, nil, batch); sErr != nil {
			return h.failLocked(r, "membership sink failed on removal", sErr)
		}
		if h.egWriter != nil && h.egTaxonomy != nil {
			if rErr := h.egWriter.RetractFragments(ctx, r.steward, retractable(batch), h.egTaxonomy); rErr != nil {
				return h.failLocked(r, "entity-graph retraction failed", rErr)
			}
		}
		if rmErr := h.store.RemoveFragments(r.steward, batch); rmErr != nil {
			return h.failLocked(r, "removal failed", rmErr)
		}
	}

	r.done = true
	h.bulkRounds.CompareAndDelete(r.steward, r)
	h.verifiedBulkRoots.Store(r.steward, r.claimedRoot)
	h.logger.Info("bulk-sync: round complete",
		"steward_id", logging.SanitizeLogValue(r.steward),
		"fetched", len(r.toFetch), "removed", len(r.removed))
	return nil
}

// retractable drops directory ids from a retraction list: their entity ids need
// the directory domain, which a bare fragment id does not carry, so the
// membership sink alone handles their removal.
func retractable(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if k := bulkKindOf(id); k == egtypes.KindDirectoryUser || k == egtypes.KindDirectoryGroup {
			continue
		}
		out = append(out, id)
	}
	return out
}

// applyBulkToSink hands the batch's directory fragments to the membership sink.
// Only fragments the directory authority verifier accepts are upserted; the
// authority passed is the verifier's answer for the fragment's domain, never a
// value derived from fragment content alone. Removed directory ids are passed as
// removals.
func (h *DNAHandler) applyBulkToSink(ctx context.Context, peer string, upserts []*common.Fragment, removedIDs []string) error {
	if h.membershipSink == nil {
		return nil
	}
	byAuthority := map[string][]directory.Fragment{}
	for _, f := range upserts {
		kind := bulkKindOf(f.GetFragmentId())
		if kind != egtypes.KindDirectoryUser && kind != egtypes.KindDirectoryGroup {
			continue
		}
		if h.directoryAuth == nil {
			continue
		}
		attrs, err := sdna.DecodeCanonicalFragment(f.GetCanonicalBytes())
		if err != nil {
			continue
		}
		rawDomain, _ := attrs[egtypes.PayloadDirectoryDomain].(string)
		domain, ok := egtypes.NormalizeDirectoryDomain(rawDomain)
		if !ok || !h.directoryAuth.IsDirectoryAuthority(peer, domain) {
			continue
		}
		_, objectID, _ := strings.Cut(f.GetFragmentId(), ":")
		authority := "directory:" + domain
		byAuthority[authority] = append(byAuthority[authority], directory.Fragment{
			Kind: kind, ObjectID: objectID, Attributes: attrs,
		})
	}

	var removed []directory.RemovedFragment
	for _, id := range removedIDs {
		kind, objectID, _ := strings.Cut(id, ":")
		if kind == egtypes.KindDirectoryUser || kind == egtypes.KindDirectoryGroup {
			removed = append(removed, directory.RemovedFragment{Kind: kind, ObjectID: objectID})
		}
	}

	authorities := make([]string, 0, len(byAuthority))
	for a := range byAuthority {
		authorities = append(authorities, a)
	}
	sort.Strings(authorities)
	for _, a := range authorities {
		if _, err := h.membershipSink.ApplyBatch(ctx, peer, a, byAuthority[a], nil); err != nil {
			return err
		}
	}
	if len(removed) > 0 {
		if _, err := h.membershipSink.ApplyBatch(ctx, peer, "", nil, removed); err != nil {
			return err
		}
	}
	return nil
}

// handleBulkTransfer routes a bulk-flagged transfer from the verified peer to the
// round that asked for it. A bulk transfer never falls through to the host lane
// or the full-snapshot persister.
func (h *DNAHandler) handleBulkTransfer(ctx context.Context, peerID string, transfer *dptypes.DNATransfer) error {
	switch {
	case transfer.Delta:
		return h.handleBulkFragments(ctx, peerID, transfer)
	case len(transfer.BucketRoots) > 0:
		return h.handleBulkRoots(ctx, peerID, transfer.BucketRoots)
	default:
		return h.handleBulkManifest(ctx, peerID, transfer.Manifest)
	}
}
