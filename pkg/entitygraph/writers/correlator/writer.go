// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package correlator implements the MAC-identity correlator — an entity-graph
// internal writer that asserts same-as edges between entities whose normalized
// MAC addresses agree (ADR-022 §3, Issue #3369).
//
// Matching rule (v0):
//   - Primary join key: MAC address (normalized to uppercase colon-delimited form).
//   - Corroborating key: VM GUID — corroborating-only; GUID agreement alone (no
//     MAC agreement) never produces a same-as edge.
//   - A same-as edge is asserted between any two entities from different authority
//     segments that share at least one normalized MAC address.
//   - Confidence: ConfidenceHigh (single tenant-cut-secure primary key per v0 rule).
//
// Join-key hygiene:
//
//	A MAC only identifies a machine while it is globally unique. Collectors emit
//	addresses that are not: the steward DNA network collector reports
//	iface.HardwareAddr for every non-loopback adapter, and Windows WAN Miniport,
//	tunnel and loopback adapters report all-zero or fixed vendor addresses that
//	repeat across the entire fleet. normalizeMAC therefore rejects non-identifying
//	addresses (all-zero, multicast/broadcast, known fixed virtual-adapter MACs),
//	and Correlate skips any MAC shared by more than maxJoinGroupSize entities.
//	See "Fan-out bounds" on Correlate.
//
// Query strategy:
//
//	QueryEntities's EntityFilter.Attributes field is declared in the provider
//	interface but not implemented by the SQLite provider — the query only filters
//	by Kind and TenantFilter. network_adapters is a list of maps (not a flat
//	scalar column), so an attribute-value index query is not feasible even with
//	a future provider. A full entity scan + in-process attribute match is therefore
//	used for v0: O(fleet size) per sweep, per ADR-022 §9's known tension.
//
// Invocation:
//
//	This package is a standalone-invokable writer pending controller-startup
//	wiring (#3253). Call New(provider) then Correlate(ctx). The correlator
//	operates controller-wide (no tenant filter) — the read-time tenant cut in
//	GetEntity gates visibility for end users.
package correlator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// observationSource is the source name carried by every observation this writer
// emits, and the batch source used for its writes.
const observationSource = "correlator:mac"

const (
	// maxMACsPerEntity bounds the MAC addresses considered for one entity. MACs
	// come from steward-supplied attributes, and each shared MAC can become a
	// same-as edge, so an unbounded list is unbounded edge growth. A real
	// machine, or a Hyper-V VM, has far fewer adapters; the excess is dropped
	// and counted in a warning.
	maxMACsPerEntity = 64

	// maxJoinGroupSize bounds the number of distinct entities that may share one
	// normalized MAC before the correlator treats that MAC as a non-identity
	// signal and skips it entirely.
	//
	// A genuinely unique MAC is observed by a small, bounded set of authorities:
	// the machine's own steward, the hypervisor host's steward, an outpost that
	// scanned it, a cluster collector. A MAC appearing on dozens of entities is
	// not a machine seen from many angles — it is a duplicated or spoofed
	// address, and pairing it would assert ConfidenceHigh identity between
	// unrelated machines. Skipping (rather than downgrading) keeps the v0
	// single-confidence-tier rule intact; a future confidence-scoring layer may
	// emit a weaker edge for these groups instead.
	//
	// The cap is also the fan-out bound: the pairwise loop is O(k^2), so
	// uncapped a MAC shared by k hosts emits k(k-1)/2 edges. At 50k stewards a
	// single fleet-wide junk MAC would emit hundreds of millions of same-as
	// observations in one sweep. Capped, one group costs at most 120 pairs.
	maxJoinGroupSize = 16

	// maxObservationBatch bounds the observations handed to one
	// ReportObservations call. Providers ingest a batch in a single transaction
	// (the SQLite provider holds one write transaction for the whole batch), so
	// an unbounded batch is both an unbounded allocation and an unbounded
	// write-lock hold. Correlate flushes at this size instead of accumulating
	// the whole sweep in memory.
	maxObservationBatch = 1000

	// maxScopesPerBatch bounds the claim scopes (one per anchor) declared in one
	// ReportObservations call. A batch of scopes with no observations is valid.
	maxScopesPerBatch = 500

	// sameAsEdgeType is the edge type this writer asserts and scopes.
	sameAsEdgeType = "same-as"
)

// Effective per-batch caps. They equal the constants above and are variables only
// so internal tests can force a sweep across several flushes.
var (
	observationBatchLimit = maxObservationBatch
	scopeBatchLimit       = maxScopesPerBatch
)

// nonIdentifyingMACs are unicast, non-zero MACs that are nevertheless fixed
// across every machine that has the corresponding virtual adapter, so they carry
// no identity. They pass every structural check and can only be excluded by
// value.
var nonIdentifyingMACs = map[string]bool{
	// Microsoft KM-TEST Loopback Adapter — the same address on every Windows
	// host that has the adapter installed.
	"02:00:4C:4F:4F:50": true,
}

// Writer is the MAC-identity correlator entity-graph writer.
type Writer struct {
	provider interfaces.EntityGraphProvider
}

// New returns a Writer backed by provider. provider must not be nil.
func New(provider interfaces.EntityGraphProvider) (*Writer, error) {
	if provider == nil {
		return nil, fmt.Errorf("correlator/writer: provider must not be nil")
	}
	return &Writer{provider: provider}, nil
}

// Correlate runs one identity-correlation sweep. It enumerates all entities,
// groups them by normalized MAC address, and asserts same-as edges between
// pairs from different authority segments. It also retracts same-as edges whose
// MAC match has stopped being true.
//
// VM GUID agreement alone (no MAC agreement) never produces a same-as edge —
// GUID is corroborating-only per ADR-022 §3.
//
// Retraction: every entity the sweep enumerates is an anchor, and each flushed
// batch declares one edge-addressed claim scope (same-as, TraversalBoth) per
// anchor it contains. A provider diffs a scope against the observations of the
// single ReportObservations call that carries it, so a batch holds the complete
// current same-as edge set of every anchor it scopes; an edge between A and B is
// emitted in both A's and B's batch. Anchors are packed into batches whole, so
// one flush never retracts what another flush asserted.
//
// Fan-out bounds: a MAC shared by more than maxJoinGroupSize entities is skipped
// (see maxJoinGroupSize), and observations are flushed to the provider in
// batches of at most maxObservationBatch observations and maxScopesPerBatch
// scopes rather than accumulated for the whole sweep. An anchor whose edge set
// alone exceeds the observation cap is skipped with a warning and declares no
// scope: its stale edges stay rather than risk a false retraction.
//
// Fail closed: a GetEntity error other than interfaces.ErrNotFound aborts the
// sweep before anything is reported, and a ReportObservations failure stops the
// sweep at once. Flushing mid-sweep can leave the batches written before a
// failure in place; that is safe because each batch is self-consistent and the
// sweep is idempotent, so a re-run reconverges.
func (w *Writer) Correlate(ctx context.Context) error {
	truncatedEntities := 0
	candidates, anchors, err := w.collectMACs(ctx, &truncatedEntities)
	if err != nil {
		return fmt.Errorf("correlator: collect MACs: %w", err)
	}
	if truncatedEntities > 0 {
		slog.Warn("correlator: MAC list capped for entities",
			"entities", truncatedEntities,
			"limit", maxMACsPerEntity)
	}

	// Build MAC → []EID index.
	macIndex := make(map[string][]types.EID)
	for eid, macs := range candidates {
		for _, mac := range macs {
			macIndex[mac] = append(macIndex[mac], eid)
		}
	}

	// Per-anchor current same-as subject sets.
	edgeSets := make(map[string]map[string]struct{}, len(anchors))
	for _, members := range macIndex {
		members = dedupEIDs(members)
		if len(members) < 2 {
			continue // nothing to pair
		}
		if len(members) > maxJoinGroupSize {
			// Duplicated/spoofed address, not an identity signal. Skipping
			// before the pairwise loop also bounds its O(k^2) cost.
			continue
		}
		for i := 0; i < len(members); i++ {
			for j := i + 1; j < len(members); j++ {
				a, b := members[i], members[j]
				if a.AuthoritySegment() == b.AuthoritySegment() {
					continue
				}
				subject, ok := sameAsSubject(a, b)
				if !ok {
					continue // EID carries the edge-subject delimiter — see sameAsSubject
				}
				for _, end := range [2]string{a.String(), b.String()} {
					set := edgeSets[end]
					if set == nil {
						set = make(map[string]struct{})
						edgeSets[end] = set
					}
					set[subject] = struct{}{}
				}
			}
		}
	}

	now := time.Now().UTC()
	pk := newBatchPacker(w, now)
	for _, anchor := range anchors {
		key := anchor.String()
		if !validAnchor(key) {
			continue // forged anchor must not become a scope key
		}
		set := edgeSets[key]
		if len(set) > observationBatchLimit {
			slog.Warn("correlator: anchor edge set exceeds batch cap; skipping retraction scope",
				"edges", len(set),
				"limit", observationBatchLimit)
			continue
		}
		subjects := make([]string, 0, len(set))
		for s := range set {
			subjects = append(subjects, s)
		}
		sort.Strings(subjects)
		if err := pk.add(ctx, anchor, subjects); err != nil {
			return err
		}
	}
	return pk.flush(ctx)
}

// validAnchor reports whether an EID string may be declared as a scope anchor.
func validAnchor(eid string) bool {
	return !strings.Contains(eid, edgeSubjectSep) && !strings.Contains(eid, "\x1f")
}

// batchPacker packs whole anchors into bounded ObservationBatches.
type batchPacker struct {
	w      *Writer
	now    time.Time
	obs    []types.Observation
	seen   map[string]struct{}
	scopes []types.ClaimScope
}

func newBatchPacker(w *Writer, now time.Time) *batchPacker {
	return &batchPacker{w: w, now: now, seen: make(map[string]struct{})}
}

// add appends the anchor's scope and complete subject set, flushing first when
// the anchor would not fit in the current batch.
func (p *batchPacker) add(ctx context.Context, anchor types.EID, subjects []string) error {
	fresh := 0
	for _, s := range subjects {
		if _, dup := p.seen[s]; !dup {
			fresh++
		}
	}
	if len(p.scopes) >= scopeBatchLimit || len(p.obs)+fresh > observationBatchLimit {
		if err := p.flush(ctx); err != nil {
			return err
		}
	}
	for _, s := range subjects {
		if _, dup := p.seen[s]; dup {
			continue
		}
		p.seen[s] = struct{}{}
		p.obs = append(p.obs, types.Observation{
			Source:     observationSource,
			ObservedAt: p.now,
			RecordedAt: p.now,
			Subject:    s,
			Kind:       types.ObservationKindState,
			Confidence: types.ConfidenceHigh,
			Payload:    map[string]interface{}{},
		})
	}
	p.scopes = append(p.scopes, types.ClaimScope{
		Source: observationSource,
		Pattern: types.ClaimScopePattern{
			Edge: &types.EdgeScopePattern{
				EdgeType:  sameAsEdgeType,
				AnchorEID: anchor,
				Direction: types.TraversalBoth,
			},
		},
		AsOf: p.now,
	})
	return nil
}

// flush reports the pending batch and starts a fresh one.
func (p *batchPacker) flush(ctx context.Context) error {
	obs, scopes := p.obs, p.scopes
	// Fresh backing arrays: the flushed slices are owned by the provider for the
	// duration of its call.
	p.obs, p.scopes = nil, nil
	p.seen = make(map[string]struct{})
	return p.w.report(ctx, obs, scopes)
}

// report writes one bounded batch. An empty batch is a no-op.
func (w *Writer) report(ctx context.Context, observations []types.Observation, scopes []types.ClaimScope) error {
	if len(observations) == 0 && len(scopes) == 0 {
		return nil
	}
	if err := w.provider.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:       observationSource,
		Observations: observations,
		ClaimScopes:  scopes,
	}); err != nil {
		return fmt.Errorf("correlator: report observations: %w", err)
	}
	return nil
}

// collectMACs enumerates all entities and returns a map from EID to their
// normalized MAC addresses, plus every enumerated entity as an anchor. The sweep
// uses no tenant filter — the correlator operates controller-wide.
//
// Only interfaces.ErrNotFound (entity removed between query and fetch) skips an
// entity, and a skipped entity is not an anchor. Any other GetEntity error
// aborts the sweep: it must never be read as "MAC no longer reported".
func (w *Writer) collectMACs(ctx context.Context, truncatedEntities *int) (map[types.EID][]string, []types.EID, error) {
	result := make(map[types.EID][]string)
	var anchors []types.EID
	seenAnchors := make(map[string]struct{})
	page := interfaces.PageToken{PageSize: 500}

	for {
		entityPage, err := w.provider.QueryEntities(ctx, interfaces.EntityFilter{}, page)
		if err != nil {
			return nil, nil, fmt.Errorf("correlator: query entities: %w", err)
		}

		for _, ev := range entityPage.Entities {
			// QueryEntities returns shallow views (Attributes is empty); GetEntity
			// is required for the full merged attribute set including network_adapters.
			full, err := w.provider.GetEntity(ctx, ev.Entity.EID, interfaces.GetEntityOpts{})
			if err != nil {
				if errors.Is(err, interfaces.ErrNotFound) {
					continue // entity deleted between query and fetch — skip
				}
				return nil, nil, fmt.Errorf("correlator: get entity: %w", err)
			}
			if _, dup := seenAnchors[ev.Entity.EID.String()]; !dup {
				seenAnchors[ev.Entity.EID.String()] = struct{}{}
				anchors = append(anchors, ev.Entity.EID)
			}
			macs, truncated := extractMACsCapped(full)
			if truncated {
				*truncatedEntities++
			}
			if len(macs) > 0 {
				result[ev.Entity.EID] = macs
			}
		}

		if entityPage.NextToken == "" {
			break
		}
		page.Token = entityPage.NextToken
	}

	return result, anchors, nil
}

// extractMACsCapped returns the normalized (uppercase colon-delimited) MAC addresses
// for an entity. Two attribute layouts are supported:
//
//   - host entities (steward self-registration): mac_addresses (comma-separated
//     string) and/or primary_mac (single string).
//   - VM/cluster entities (Hyper-V module): network_adapters ([]interface{} of
//     map[string]interface{}{"mac_address": "..."}).
//
// Both sides may use colon-delimited, hyphen-delimited, or bare 12-hex-char
// notation. All are normalized before comparison.
//
// At most maxMACsPerEntity addresses are returned; the bool reports whether
// valid addresses beyond the limit were dropped.
func extractMACsCapped(view *types.EntityView) ([]string, bool) {
	if view == nil || view.Entity == nil {
		return nil, false
	}
	truncated := false
	attrs := view.Entity.Attributes

	seen := make(map[string]bool)
	var macs []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if n := normalizeMAC(raw); n != "" && !seen[n] {
			if len(macs) >= maxMACsPerEntity {
				truncated = true
				return
			}
			seen[n] = true
			macs = append(macs, n)
		}
	}

	// Steward host registration: comma-separated mac_addresses.
	if v, ok := attrs["mac_addresses"]; ok {
		if s, ok := v.(string); ok {
			for _, m := range strings.Split(s, ",") {
				add(m)
			}
		}
	}
	// Steward host registration: primary_mac (first adapter; may overlap mac_addresses).
	if v, ok := attrs["primary_mac"]; ok {
		if s, ok := v.(string); ok {
			add(s)
		}
	}
	// Hyper-V module: network_adapters list ([]interface{} after JSON round-trip).
	if v, ok := attrs["network_adapters"]; ok {
		if adapters, ok := v.([]interface{}); ok {
			for _, a := range adapters {
				if am, ok := a.(map[string]interface{}); ok {
					if m, ok := am["mac_address"].(string); ok {
						add(m)
					}
				}
			}
		}
	}

	return macs, truncated
}

// normalizeMAC normalizes a MAC address string to uppercase colon-delimited
// Ethernet form (e.g. "00:11:22:33:44:55"). Returns empty string for invalid,
// empty, or non-identifying inputs (see identifiesEndpoint).
//
// Supported input formats:
//   - Colon-delimited: "00:11:22:33:44:55" (Go net package default)
//   - Hyphen-delimited: "00-11-22-33-44-55" (Windows format)
//   - No-delimiter 12 hex chars: "001122334455" (Hyper-V PowerShell output)
func normalizeMAC(s string) string {
	if s == "" {
		return ""
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		// net.ParseMAC handles colon- and hyphen-delimited forms. For bare
		// 12-hex-char MACs (Hyper-V PowerShell output, e.g. "001122AABBCC"),
		// insert colons and retry.
		if len(s) == 12 {
			var buf [17]byte
			for i := 0; i < 6; i++ {
				buf[i*3] = s[i*2]
				buf[i*3+1] = s[i*2+1]
				if i < 5 {
					buf[i*3+2] = ':'
				}
			}
			hw, err = net.ParseMAC(string(buf[:]))
			if err != nil {
				return ""
			}
		} else {
			return ""
		}
	}
	if len(hw) != 6 {
		return "" // not an Ethernet MAC
	}
	if !identifiesEndpoint(hw) {
		return ""
	}
	return strings.ToUpper(hw.String())
}

// identifiesEndpoint reports whether a 6-byte Ethernet address can serve as an
// identity join key. It rejects addresses that are syntactically valid but are
// not unique to one endpoint, and therefore correlate machines that are not the
// same machine:
//
//   - All-zero (00:00:00:00:00:00) — reported by Windows WAN Miniport, tunnel
//     and other pseudo-adapters, and by any adapter with no address. The steward
//     DNA collector emits it for every such adapter, so it recurs fleet-wide.
//   - Multicast/group bit set (hw[0]&1 == 1) — never a station address. This
//     also covers the broadcast address ff:ff:ff:ff:ff:ff.
//   - Known fixed virtual-adapter addresses (nonIdentifyingMACs).
//
// The locally-administered bit is deliberately NOT rejected: hypervisors assign
// locally-administered addresses to real VM adapters, and those are exactly the
// addresses the correlator exists to join on.
func identifiesEndpoint(hw net.HardwareAddr) bool {
	if len(hw) != 6 {
		return false
	}
	if hw[0]&0x01 != 0 {
		return false // multicast / broadcast
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}
	return !nonIdentifyingMACs[strings.ToUpper(hw.String())]
}

// edgeSubjectSep is the delimiter of the observation edge-subject format
// "edge_type|from_eid|to_eid". The SQLite provider parses the subject back with
// strings.SplitN(subject, "|", 3) (parseEdgeSubject), so the encoding is only
// injective while no component contains the delimiter.
const edgeSubjectSep = "|"

// sameAsSubject returns the canonical edge-subject string for a same-as edge
// between a and b, and reports whether the subject is well-formed. EIDs are
// sorted lexicographically so the same edge always produces the same subject
// regardless of argument order.
//
// A pair is rejected (ok == false) when either EID string contains
// edgeSubjectSep. Authority names are collector-controlled — types.ParseEID
// rejects only '/' in an authority name, and the dnasync writer mints EIDs from
// steward-supplied fragment IDs — so an EID such as "cluster:victim|host:pad"
// is reachable and is indexed as an entity by the provider. Emitting it inside
// a subject would make the round-trip non-injective: "same-as|cluster:victim|
// host:pad|host:other" splits into from="cluster:victim", to="host:pad|host:other",
// binding the edge (and, via resolveCollapseGroup's prefix match, the collapse
// group) to a different entity than the one whose MAC actually matched. Skipping
// the pair keeps the forged EID confined to its own authority segment.
func sameAsSubject(a, b types.EID) (string, bool) {
	as, bs := a.String(), b.String()
	if strings.Contains(as, edgeSubjectSep) || strings.Contains(bs, edgeSubjectSep) {
		return "", false
	}
	if as > bs {
		as, bs = bs, as
	}
	return sameAsEdgeType + edgeSubjectSep + as + edgeSubjectSep + bs, true
}

// dedupEIDs returns a copy of eids with duplicate EID strings removed,
// preserving order of first occurrence.
func dedupEIDs(eids []types.EID) []types.EID {
	seen := make(map[string]bool, len(eids))
	out := make([]types.EID, 0, len(eids))
	for _, e := range eids {
		if !seen[e.String()] {
			seen[e.String()] = true
			out = append(out, e)
		}
	}
	return out
}
