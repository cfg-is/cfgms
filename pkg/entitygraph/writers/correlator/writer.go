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
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// observationSource is the source name carried by every observation this writer
// emits, and the batch source used for its writes.
const observationSource = "correlator:mac"

const (
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
// pairs from different authority segments.
//
// VM GUID agreement alone (no MAC agreement) never produces a same-as edge —
// GUID is corroborating-only per ADR-022 §3.
//
// Fan-out bounds: a MAC shared by more than maxJoinGroupSize entities is skipped
// (see maxJoinGroupSize), and observations are flushed to the provider in
// batches of at most maxObservationBatch rather than accumulated for the whole
// sweep. Together these bound both the edges a single MAC can assert and the
// memory and transaction size of one sweep, independent of fleet size.
//
// Flushing mid-sweep means a provider failure can leave the edges written before
// it in place. That is safe: same-as observations are content-hash deduped and
// the sweep is idempotent, so a re-run reconverges.
func (w *Writer) Correlate(ctx context.Context) error {
	candidates, err := w.collectMACs(ctx)
	if err != nil {
		return fmt.Errorf("correlator: collect MACs: %w", err)
	}

	// Build MAC → []EID index.
	macIndex := make(map[string][]types.EID)
	for eid, macs := range candidates {
		for _, mac := range macs {
			macIndex[mac] = append(macIndex[mac], eid)
		}
	}

	now := time.Now().UTC()
	batch := make([]types.Observation, 0, maxObservationBatch)

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
				batch = append(batch, types.Observation{
					Source:     observationSource,
					ObservedAt: now,
					RecordedAt: now,
					Subject:    subject,
					Kind:       types.ObservationKindState,
					Confidence: types.ConfidenceHigh,
					Payload:    map[string]interface{}{},
				})
				if len(batch) == maxObservationBatch {
					if err := w.report(ctx, batch); err != nil {
						return err
					}
					// Fresh backing array: the flushed slice is now owned by
					// the provider for the duration of its call.
					batch = make([]types.Observation, 0, maxObservationBatch)
				}
			}
		}
	}

	return w.report(ctx, batch)
}

// report writes one bounded observation batch. An empty batch is a no-op.
func (w *Writer) report(ctx context.Context, observations []types.Observation) error {
	if len(observations) == 0 {
		return nil
	}
	if err := w.provider.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:       observationSource,
		Observations: observations,
	}); err != nil {
		return fmt.Errorf("correlator: report observations: %w", err)
	}
	return nil
}

// collectMACs enumerates all entities and returns a map from EID to their
// normalized MAC addresses. The sweep uses no tenant filter — the correlator
// operates controller-wide.
func (w *Writer) collectMACs(ctx context.Context) (map[types.EID][]string, error) {
	result := make(map[types.EID][]string)
	page := interfaces.PageToken{PageSize: 500}

	for {
		entityPage, err := w.provider.QueryEntities(ctx, interfaces.EntityFilter{}, page)
		if err != nil {
			return nil, fmt.Errorf("correlator: query entities: %w", err)
		}

		for _, ev := range entityPage.Entities {
			// QueryEntities returns shallow views (Attributes is empty); GetEntity
			// is required for the full merged attribute set including network_adapters.
			full, err := w.provider.GetEntity(ctx, ev.Entity.EID, interfaces.GetEntityOpts{})
			if err != nil {
				continue // entity deleted between query and fetch — skip
			}
			if macs := extractMACs(full); len(macs) > 0 {
				result[ev.Entity.EID] = macs
			}
		}

		if entityPage.NextToken == "" {
			break
		}
		page.Token = entityPage.NextToken
	}

	return result, nil
}

// extractMACs returns the normalized (uppercase colon-delimited) MAC addresses
// for an entity. Two attribute layouts are supported:
//
//   - host entities (steward self-registration): mac_addresses (comma-separated
//     string) and/or primary_mac (single string).
//   - VM/cluster entities (Hyper-V module): network_adapters ([]interface{} of
//     map[string]interface{}{"mac_address": "..."}).
//
// Both sides may use colon-delimited, hyphen-delimited, or bare 12-hex-char
// notation. All are normalized before comparison.
func extractMACs(view *types.EntityView) []string {
	if view == nil || view.Entity == nil {
		return nil
	}
	attrs := view.Entity.Attributes

	seen := make(map[string]bool)
	var macs []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if n := normalizeMAC(raw); n != "" && !seen[n] {
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

	return macs
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
	return "same-as" + edgeSubjectSep + as + edgeSubjectSep + bs, true
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
