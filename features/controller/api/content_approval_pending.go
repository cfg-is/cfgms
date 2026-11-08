// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// Config-store namespaces of pending content changes. They are written only by
// the functions of this file, in the owner tenant's own partition.
const (
	contentApprovalPendingNamespace = "content-approval-pending"
	contentApprovalFloodNamespace   = "content-approval-pending-window"
)

const (
	// pendingChangeCap bounds, per owner tenant and window, the pending records
	// created and the notices sent for them. A change beyond it is still refused
	// by the evaluator; it is not recorded and not mailed, and the first one
	// beyond the cap sends one summary notice instead.
	pendingChangeCap = 10

	// pendingChangeWindow is the length of the flood window. The count is kept
	// in the config store, so it holds across restarts and across nodes.
	pendingChangeWindow = time.Hour
)

// PendingChange records that an approved script changed and its new approval hash
// awaits an approval. TenantID is the OWNER tenant of the script. The record
// holds identifiers only, never script text; the diff is derived from the
// library when an authorized caller reads it.
type PendingChange struct {
	TenantID             string    `json:"tenant_id"`
	ScriptID             string    `json:"script_id"`
	Version              string    `json:"version"`
	ApprovalHash         string    `json:"approval_hash"`
	ContentHash          string    `json:"content_hash"`
	PreviousVersion      string    `json:"previous_version"`
	PreviousApprovalHash string    `json:"previous_approval_hash"`
	FirstSeen            time.Time `json:"first_seen"`
}

// pendingWindow is the stored flood counter of one owner tenant.
type pendingWindow struct {
	TenantID    string    `json:"tenant_id"`
	WindowStart time.Time `json:"window_start"`
	Used        int       `json:"used"`
	SummarySent bool      `json:"summary_sent"`
}

// active reports whether the window still counts at now.
func (w *pendingWindow) active(now time.Time) bool {
	return now.Sub(w.WindowStart) < pendingChangeWindow
}

// pendingSlot is the outcome of asking for a notice slot in the current window.
type pendingSlot int

const (
	// pendingSlotGranted: record the change and send its notice.
	pendingSlotGranted pendingSlot = iota
	// pendingSlotSummary: over the cap and nobody has summarised this window yet;
	// the caller sends the one summary notice and records nothing.
	pendingSlotSummary
	// pendingSlotSuppressed: over the cap and already summarised.
	pendingSlotSuppressed
)

// pendingName derives the storage-safe name of one (script, version, approval
// hash) record, with the same length-prefixed encoding as approvalName.
func pendingName(id, version, hash string) string {
	sum := sha256.Sum256([]byte(strconv.Itoa(len(id)) + ":" + id + "\x00" + strconv.Itoa(len(version)) + ":" + version + "\x00" + hash))
	return "pending-" + hex.EncodeToString(sum[:])
}

func pendingKey(owner, id, version, hash string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: owner, Namespace: contentApprovalPendingNamespace, Name: pendingName(id, version, hash)}
}

func pendingWindowKey(owner string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: owner, Namespace: contentApprovalFloodNamespace, Name: "window"}
}

func (s *ContentApprovalStore) pendingEntry(key *cfgconfig.ConfigKey, v any, at time.Time) (*cfgconfig.ConfigEntry, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("content approval pending: encode record: %w", err)
	}
	return &cfgconfig.ConfigEntry{
		Key: key, Data: data, Format: cfgconfig.ConfigFormatJSON,
		Checksum:  fmt.Sprintf("%x", sha256.Sum256(data)),
		UpdatedAt: at, UpdatedBy: contentApprovalPendingNamespace, Source: contentApprovalPendingNamespace,
	}, nil
}

// pendingExists reports whether a record for the exact tuple is stored.
func (s *ContentApprovalStore) pendingExists(ctx context.Context, owner, id, version, hash string) (bool, error) {
	_, err := s.store.GetConfig(ctx, pendingKey(owner, id, version, hash))
	if errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("content approval pending: read record: %w", err)
	}
	return true, nil
}

// createPending stores pc only if no record for the same tuple exists. It
// reports whether this call created it: the one caller that gets true is the one
// that announces the change. The primitive is cfgconfig.CreateIfAbsent, which is
// a compare-and-swap on a cluster-atomic store and a per-key file lock on a
// single-host store, and refuses to run on a store that cannot be atomic in a
// configured cluster. Any error means nothing was recorded.
func (s *ContentApprovalStore) createPending(ctx context.Context, pc *PendingChange) (bool, error) {
	entry, err := s.pendingEntry(pendingKey(pc.TenantID, pc.ScriptID, pc.Version, pc.ApprovalHash), pc, pc.FirstSeen)
	if err != nil {
		return false, err
	}
	if err := cfgconfig.CreateIfAbsent(ctx, s.store, entry); err != nil {
		if errors.Is(err, cfgconfig.ErrAlreadyExists) {
			return false, nil
		}
		return false, fmt.Errorf("content approval pending: create record: %w", err)
	}
	return true, nil
}

// ListPending lists the owner tenant's pending changes, oldest first.
func (s *ContentApprovalStore) ListPending(ctx context.Context, owner string) ([]*PendingChange, error) {
	if owner == "" {
		return nil, errors.New("content approval pending: tenant is required")
	}
	entries, err := s.store.ListConfigs(ctx, &cfgconfig.ConfigFilter{TenantID: owner, Namespace: contentApprovalPendingNamespace})
	if err != nil {
		return nil, fmt.Errorf("content approval pending: list records: %w", err)
	}
	out := make([]*PendingChange, 0, len(entries))
	for _, e := range entries {
		var pc PendingChange
		if err := json.Unmarshal(e.Data, &pc); err != nil {
			return nil, fmt.Errorf("content approval pending: decode record: %w", err)
		}
		if pc.TenantID == owner {
			out = append(out, &pc)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].ScriptID+"/"+out[i].Version < out[j].ScriptID+"/"+out[j].Version
	})
	return out, nil
}

// ClearPending removes the record of the exact tuple. Clearing an absent record
// changes nothing.
func (s *ContentApprovalStore) ClearPending(ctx context.Context, owner, id, version, hash string) error {
	err := s.store.DeleteConfig(ctx, pendingKey(owner, id, version, hash))
	if err != nil && !errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return fmt.Errorf("content approval pending: clear record: %w", err)
	}
	return nil
}

// previousApproval returns the owner's latest approval of a different approval
// hash of the same script, or nil when the script has none.
func (s *ContentApprovalStore) previousApproval(ctx context.Context, owner, id, excludeHash string) (*ContentApproval, error) {
	approvals, err := s.ListApprovals(ctx, owner, LibraryKindScript)
	if err != nil {
		return nil, err
	}
	for i := len(approvals) - 1; i >= 0; i-- { // oldest first: the last match is the latest
		if a := approvals[i]; a.ContentID == id && a.ContentHash != excludeHash {
			return a, nil
		}
	}
	return nil, nil
}

// take takes one slot of w, returning the advanced window and the outcome.
func (w pendingWindow) take() (pendingWindow, pendingSlot) {
	switch {
	case w.Used < pendingChangeCap:
		w.Used++
		return w, pendingSlotGranted
	case !w.SummarySent:
		w.SummarySent = true
		return w, pendingSlotSummary
	}
	return w, pendingSlotSuppressed
}

// currentWindow decodes the stored counter of owner. An absent counter, one that
// cannot be decoded, one that names another tenant and an expired one all read as
// a fresh window starting at now: it holds only a count.
func currentWindow(cur *cfgconfig.ConfigEntry, owner string, now time.Time) pendingWindow {
	fresh := pendingWindow{TenantID: owner, WindowStart: now}
	if cur == nil {
		return fresh
	}
	var stored pendingWindow
	if json.Unmarshal(cur.Data, &stored) != nil || stored.TenantID != owner || !stored.active(now) {
		return fresh
	}
	return stored
}

// windowSuppressed reports, from a plain read, that owner is over the cap and
// has already been summarised. That is the steady state of a flood; answering it
// from a read keeps repeated evaluations from each writing.
func (s *ContentApprovalStore) windowSuppressed(ctx context.Context, owner string, now time.Time) bool {
	cur, err := s.store.GetConfig(ctx, pendingWindowKey(owner))
	if err != nil {
		return false
	}
	_, slot := currentWindow(cur, owner, now).take()
	return slot == pendingSlotSuppressed
}

// reservePendingSlot takes one slot of the owner tenant's current flood window.
// The counter is read-modified-written with cfgconfig.AtomicUpdate, so concurrent
// callers on any node cannot take more slots than the cap.
func (s *ContentApprovalStore) reservePendingSlot(ctx context.Context, owner string) (pendingSlot, error) {
	now := s.now()
	if s.windowSuppressed(ctx, owner, now) {
		return pendingSlotSuppressed, nil
	}
	key := pendingWindowKey(owner)
	slot := pendingSlotGranted
	err := cfgconfig.AtomicUpdate(ctx, s.store, key, func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		var w pendingWindow
		w, slot = currentWindow(cur, owner, now).take()
		return s.pendingEntry(key, w, now)
	})
	if err != nil {
		return pendingSlotSuppressed, fmt.Errorf("content approval pending: reserve notice slot: %w", err)
	}
	return slot, nil
}

// RecordPendingAndNotify records that vs, resolved from ownerTenant's library,
// changed after an earlier approval of the same script and now awaits approval,
// and announces it once to the owner tenant's administrators.
//
// Only a route that has just refused a run calls it, with the pending Decision it
// got from the evaluator (Story #5843). The evaluator and the list routes never
// call it, so reading never creates a record or mail. It does nothing for a
// decision that is not an approve-logic pending, for a version that is already
// approved, and for a script with no earlier approval (a first approval is not a
// change). The decision is checked against the version again here, so a stale or
// foreign Decision is an error and records nothing.
//
// The durable PendingChange record, created with create-if-absent in the config
// store, decides which caller announces: a repeat on this node or any other finds
// the record and sends nothing. A record count and a notice count per owner
// tenant and window bound a flood; the excess is refused but unrecorded and
// collapses into one summary notice. The notice goes out on a tracked goroutine,
// so a slow mail server never delays the refusal; a delivery failure is logged
// and changes nothing, and neither it nor any error returned here ever makes a
// run proceed.
func (s *Server) RecordPendingAndNotify(ctx context.Context, ownerTenant string, vs *script.VersionedScript, d Decision) error {
	st := s.ContentApprovalStore()
	if st == nil {
		return errors.New("content approval pending: approval store is not available")
	}
	hash, act, err := checkPendingDecision(ownerTenant, vs, d)
	if err != nil || !act {
		return err
	}
	pc, err := st.changeToRecord(ctx, ownerTenant, vs, hash)
	if err != nil || pc == nil {
		return err
	}
	slot, err := st.reservePendingSlot(ctx, ownerTenant)
	if err != nil {
		return err
	}
	switch slot {
	case pendingSlotSummary:
		s.logger.Warn("Pending content change notices reached the window cap",
			"tenant_id", logging.SanitizeLogValue(ownerTenant))
		s.announcePendingSummary(ctx, ownerTenant)
	case pendingSlotGranted:
		return s.recordAndAnnounce(ctx, st, pc)
	}
	return nil
}

// recordAndAnnounce stores pc and announces it when this call created the record.
func (s *Server) recordAndAnnounce(ctx context.Context, st *ContentApprovalStore, pc *PendingChange) error {
	created, err := st.createPending(ctx, pc)
	if err != nil || !created {
		return err
	}
	s.announcePendingChange(ctx, pc)
	return nil
}

// checkPendingDecision validates the call and returns the approval hash of vs.
// act is false for a decision that is not an approve-logic pending, which is not
// an error and records nothing. A decision that does not describe vs under
// ownerTenant is an error.
func checkPendingDecision(ownerTenant string, vs *script.VersionedScript, d Decision) (hash string, act bool, err error) {
	if reason := checkEvaluationInput("pending", vs, ownerTenant); reason != "" {
		return "", false, errors.New("content approval pending: " + reason)
	}
	if d.State != ContentDecisionPending || !d.AwaitingApproval {
		return "", false, nil
	}
	hash = script.ScriptApprovalHash(ownerTenant, vs)
	if d.OwnerTenant != ownerTenant || hash == "" || d.ApprovalHash != hash {
		return "", false, errors.New("content approval pending: decision does not match the script version")
	}
	return hash, true, nil
}

// changeToRecord returns the PendingChange to record for vs, or nil when there is
// nothing to record: the change is already recorded, the version is approved, or
// the script has no earlier approval to have changed from.
func (s *ContentApprovalStore) changeToRecord(ctx context.Context, owner string, vs *script.VersionedScript, hash string) (*PendingChange, error) {
	id, version := vs.Metadata.ID, vs.Metadata.Version.String()
	exists, err := s.pendingExists(ctx, owner, id, version, hash)
	if err != nil || exists {
		return nil, err
	}
	state, _, _, err := s.evaluateScriptApproval(ctx, owner, vs)
	if err != nil || state == ScriptApprovalApproved {
		return nil, err
	}
	prev, err := s.previousApproval(ctx, owner, id, hash)
	if err != nil || prev == nil {
		return nil, err
	}
	return &PendingChange{
		TenantID: owner, ScriptID: id, Version: version, ApprovalHash: hash, ContentHash: vs.Hash,
		PreviousVersion: prev.Version, PreviousApprovalHash: prev.ContentHash, FirstSeen: s.now(),
	}, nil
}

// pendingDiffLimits keep one diff's work and size bounded.
const (
	diffContextLines = 3
	// diffMaxCells bounds the line-by-line comparison to about 1000 x 1000
	// lines; a larger changed region is shown as removed then added.
	diffMaxCells = 1_000_000
)

// diffOp is one line of an edit script: ' ' kept, '-' removed, '+' added.
type diffOp struct {
	kind byte
	text string
}

// unifiedDiff returns the unified diff of oldText against newText, or "" when
// they have the same lines. Line endings are normalised first.
func unifiedDiff(oldName, newName, oldText, newText string) string {
	a, b := splitDiffLines(oldText), splitDiffLines(newText)
	ops := diffOps(a, b)
	hunks := diffHunks(ops)
	if len(hunks) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("--- " + oldName + "\n+++ " + newName + "\n")
	for _, h := range hunks {
		writeHunk(&sb, ops, h)
	}
	return sb.String()
}

func splitDiffLines(s string) []string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// diffOps builds the edit script: the common prefix and suffix are kept, and the
// changed middle is compared with a longest-common-subsequence table when it is
// small enough, or shown as removed then added when it is not.
func diffOps(a, b []string) []diffOp {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	am, bm := a[pre:len(a)-suf], b[pre:len(b)-suf]

	ops := make([]diffOp, 0, len(a)+len(b))
	for _, l := range a[:pre] {
		ops = append(ops, diffOp{' ', l})
	}
	ops = append(ops, diffMiddle(am, bm)...)
	for _, l := range a[len(a)-suf:] {
		ops = append(ops, diffOp{' ', l})
	}
	return ops
}

func diffMiddle(a, b []string) []diffOp {
	if len(a) == 0 || len(b) == 0 || len(a)*len(b) > diffMaxCells {
		return replaceOps(a, b)
	}
	return walkLCS(a, b, lcsTable(a, b))
}

// replaceOps shows a as removed, then b as added.
func replaceOps(a, b []string) []diffOp {
	ops := make([]diffOp, 0, len(a)+len(b))
	for _, l := range a {
		ops = append(ops, diffOp{'-', l})
	}
	for _, l := range b {
		ops = append(ops, diffOp{'+', l})
	}
	return ops
}

// lcsTable returns the table whose entry (i, j), at i*(len(b)+1)+j, is the common
// subsequence length of a[i:] and b[j:].
func lcsTable(a, b []string) []int32 {
	w := len(b) + 1
	lcs := make([]int32, (len(a)+1)*w)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
			} else {
				lcs[i*w+j] = max(lcs[(i+1)*w+j], lcs[i*w+j+1])
			}
		}
	}
	return lcs
}

// walkLCS reads the edit script of a and b off their lcsTable.
func walkLCS(a, b []string, lcs []int32) []diffOp {
	w := len(b) + 1
	ops := make([]diffOp, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{' ', a[i]})
			i++
			j++
		case lcs[(i+1)*w+j] >= lcs[i*w+j+1]:
			ops = append(ops, diffOp{'-', a[i]})
			i++
		default:
			ops = append(ops, diffOp{'+', b[j]})
			j++
		}
	}
	return append(ops, replaceOps(a[i:], b[j:])...)
}

// diffHunk is a half-open range of ops, context included.
type diffHunk struct{ from, to int }

// diffHunks groups the changed ops with diffContextLines of context, merging
// groups whose context would touch.
func diffHunks(ops []diffOp) []diffHunk {
	var hunks []diffHunk
	for i, op := range ops {
		if op.kind == ' ' {
			continue
		}
		from, to := max(i-diffContextLines, 0), min(i+1+diffContextLines, len(ops))
		if n := len(hunks); n > 0 && from <= hunks[n-1].to {
			hunks[n-1].to = to
			continue
		}
		hunks = append(hunks, diffHunk{from, to})
	}
	return hunks
}

func writeHunk(sb *strings.Builder, ops []diffOp, h diffHunk) {
	oldStart, newStart := 1, 1
	for _, op := range ops[:h.from] {
		if op.kind != '+' {
			oldStart++
		}
		if op.kind != '-' {
			newStart++
		}
	}
	var oldCount, newCount int
	for _, op := range ops[h.from:h.to] {
		if op.kind != '+' {
			oldCount++
		}
		if op.kind != '-' {
			newCount++
		}
	}
	// An empty range is named by the line before it, as in any unified diff.
	if oldCount == 0 {
		oldStart--
	}
	if newCount == 0 {
		newStart--
	}
	fmt.Fprintf(sb, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
	for _, op := range ops[h.from:h.to] {
		sb.WriteByte(op.kind)
		sb.WriteString(op.text)
		sb.WriteByte('\n')
	}
}
