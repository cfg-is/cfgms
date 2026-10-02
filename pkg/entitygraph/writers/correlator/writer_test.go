// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package correlator_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	sqliteprovider "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/correlator"
)

// --- helpers ---

func newTestProvider(t *testing.T) *sqliteprovider.SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := sqliteprovider.NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func newTestWriter(t *testing.T, p *sqliteprovider.SQLiteEntityGraphProvider) *correlator.Writer {
	t.Helper()
	w, err := correlator.New(p)
	require.NoError(t, err)
	return w
}

// reportEntity adds a single entity observation to the provider.
func reportEntity(t *testing.T, p *sqliteprovider.SQLiteEntityGraphProvider, subject string, payload map[string]interface{}) {
	t.Helper()
	now := time.Now().UTC()
	err := p.ReportObservations(context.Background(), interfaces.ObservationBatch{
		Source: "test",
		Observations: []types.Observation{
			{
				Source:     "test",
				ObservedAt: now,
				RecordedAt: now,
				Subject:    subject,
				Kind:       types.ObservationKindState,
				Confidence: types.ConfidenceHigh,
				Payload:    payload,
			},
		},
	})
	require.NoError(t, err)
}

// getSameAsEdges returns all same-as edges currently in the provider.
func getSameAsEdges(t *testing.T, p *sqliteprovider.SQLiteEntityGraphProvider) []*interfaces.EdgeView {
	t.Helper()
	edges, err := p.GetEdges(context.Background(), interfaces.EdgeFilter{
		Types: []string{"same-as"},
	})
	require.NoError(t, err)
	return edges
}

// --- tests ---

// TestADR022_S3_MotivatingExample is the REQUIRED TEST: a Hyper-V-observed VM
// entity and the VM guest's own steward-registered host entity join via shared
// MAC address, producing a same-as edge (ADR-022 §3 motivating example).
//
// The Hyper-V host steward (authority "hyperv-host-001") reports the VM entity
// host:hyperv-host-001/vm:my-vm with a virtual adapter MAC observed via
// Hyper-V PowerShell (bare 12-hex-char format). The VM guest's own steward
// (authority "vm-guest-device") reports itself as host:vm-guest-device with
// the same MAC in colon-delimited format. These two entities share a MAC but
// come from different authority segments, so the correlator must assert a
// same-as edge between them.
func TestADR022_S3_MotivatingExample(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	// Hyper-V host observes VM — MAC in bare 12-hex-char format (Hyper-V PowerShell).
	reportEntity(t, p, "host:hyperv-host-001/vm:my-vm", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-a",
		"name":          "my-vm",
		"vm_guid":       "abc-def-012",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": "001122AABBCC"},
		},
	})

	// VM guest's own steward reports itself — same MAC in colon-delimited format.
	reportEntity(t, p, "host:vm-guest-device", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-a",
		"hostname":      "vm-guest01",
		"primary_mac":   "00:11:22:AA:BB:CC",
		"mac_addresses": "00:11:22:AA:BB:CC",
	})

	require.NoError(t, w.Correlate(ctx))

	edges := getSameAsEdges(t, p)
	require.Len(t, edges, 1, "expected exactly one same-as edge")

	edge := edges[0].Edge
	require.Equal(t, "same-as", edge.Type)
	require.Equal(t, "correlator:mac", edges[0].Edge.Sources[0].Source)

	// EIDs in the edge are sorted lexicographically; verify both endpoints.
	fromStr := edge.From.String()
	toStr := edge.To.String()
	require.ElementsMatch(t,
		[]string{"host:hyperv-host-001/vm:my-vm", "host:vm-guest-device"},
		[]string{fromStr, toStr},
		"same-as edge must connect the VM entity and the host entity",
	)
}

// TestGUIDAloneNoSameAsEdge verifies that VM GUID agreement without any MAC
// address match does not produce a same-as edge (GUID is corroborating-only
// per ADR-022 §3).
func TestGUIDAloneNoSameAsEdge(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	// VM entity has a GUID but no network adapters.
	reportEntity(t, p, "host:hyperv-host-002/vm:guid-only-vm", map[string]interface{}{
		"entity_kind":      "host",
		"owning_tenant":    "root",
		"vm_guid":          "shared-guid-xyz",
		"network_adapters": []interface{}{}, // no adapters
	})

	// Host entity has a different MAC but also has the same vm_guid attribute.
	reportEntity(t, p, "host:other-device", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"primary_mac":   "AA:BB:CC:DD:EE:FF",
		"mac_addresses": "AA:BB:CC:DD:EE:FF",
		"vm_guid":       "shared-guid-xyz",
	})

	require.NoError(t, w.Correlate(ctx))

	edges := getSameAsEdges(t, p)
	require.Empty(t, edges, "GUID agreement alone must not produce a same-as edge")
}

// TestTenantBoundary_CrossTenantEdge documents and verifies the chosen behavior
// when two entities in different tenant subtrees share a MAC address (e.g. a
// duplicate or spoofed adapter). The correlator asserts the edge controller-wide;
// the read-time tenant cut gates visibility for end users per ADR-022 §3.
//
// Chosen behavior: assert the edge regardless of tenant boundary. This enables
// cross-tenant duplicate detection. The collapse rule (§3) applies the tenant
// cut at read time — a caller scoped to one tenant cannot see the merged entity
// if the other member is outside their subtree.
func TestTenantBoundary_CrossTenantEdge(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	sharedMAC := "DE:AD:BE:EF:00:01"

	// Entity in tenant root/msp-a.
	reportEntity(t, p, "host:device-tenant-a", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-a",
		"primary_mac":   sharedMAC,
		"mac_addresses": sharedMAC,
	})

	// Entity in tenant root/msp-b — same MAC (duplicate/spoofed adapter).
	reportEntity(t, p, "host:device-tenant-b", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-b",
		"primary_mac":   sharedMAC,
		"mac_addresses": sharedMAC,
	})

	require.NoError(t, w.Correlate(ctx))

	// The correlator asserts the edge across tenant boundaries.
	edges := getSameAsEdges(t, p)
	require.Len(t, edges, 1, "cross-tenant MAC match must produce a same-as edge")

	edge := edges[0].Edge
	require.Equal(t, "same-as", edge.Type)
	require.ElementsMatch(t,
		[]string{"host:device-tenant-a", "host:device-tenant-b"},
		[]string{edge.From.String(), edge.To.String()},
	)
}

// TestSameAuthoritySegment_NoEdge verifies that two entities from the same
// authority segment sharing a MAC do not produce a same-as edge. This covers
// the case where one steward reports multiple sub-entities (e.g. itself and a
// fragment) — both carry the same MAC but are from the same authority.
func TestSameAuthoritySegment_NoEdge(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	// Both entities share authority segment "host:same-steward". The MAC is a
	// unicast station address (even first octet) so the pair is suppressed by the
	// authority-segment rule under test, not by the join-key hygiene filter.
	reportEntity(t, p, "host:same-steward", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"primary_mac":   "12:22:33:44:55:66",
		"mac_addresses": "12:22:33:44:55:66",
	})
	reportEntity(t, p, "host:same-steward/network:eth0", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"primary_mac":   "12:22:33:44:55:66",
	})

	require.NoError(t, w.Correlate(ctx))

	edges := getSameAsEdges(t, p)
	require.Empty(t, edges, "same authority segment must not produce a same-as edge")
}

// TestMACNormalization verifies that colon-delimited, hyphen-delimited, and
// bare 12-hex-char MAC formats all normalize to the same canonical form and
// are treated as a match.
func TestMACNormalization(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	// Entity A: Hyper-V PowerShell bare format (no delimiter).
	reportEntity(t, p, "host:hyperv-host-x/vm:norm-test", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": "AABBCCDDEEFF"}, // bare 12-hex
		},
	})

	// Entity B: steward colon-delimited format.
	reportEntity(t, p, "host:steward-y", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"primary_mac":   "aa:bb:cc:dd:ee:ff", // colon lowercase
		"mac_addresses": "aa:bb:cc:dd:ee:ff",
	})

	require.NoError(t, w.Correlate(ctx))

	edges := getSameAsEdges(t, p)
	require.Len(t, edges, 1, "normalized MAC match must produce exactly one same-as edge")
}

// TestHyphenDelimitedMAC verifies that hyphen-delimited MAC addresses (Windows
// format) are normalized and matched correctly.
func TestHyphenDelimitedMAC(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	reportEntity(t, p, "host:win-hyperv/vm:win-vm", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": "00-50-56-AB-CD-EF"}, // hyphen Windows
		},
	})

	reportEntity(t, p, "host:win-guest", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"primary_mac":   "00:50:56:ab:cd:ef", // colon lowercase
		"mac_addresses": "00:50:56:ab:cd:ef",
	})

	require.NoError(t, w.Correlate(ctx))

	edges := getSameAsEdges(t, p)
	require.Len(t, edges, 1, "hyphen-delimited MAC must normalize and match")
}

// TestMultipleAdapters verifies that an entity with multiple network adapters
// matches another entity that shares any one of those MACs.
func TestMultipleAdapters(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	// VM with two adapters.
	reportEntity(t, p, "host:hyperv-host-multi/vm:multi-adapter", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": "AA:BB:CC:11:22:33"},
			map[string]interface{}{"mac_address": "DC:EE:FF:44:55:66"},
		},
	})

	// Guest reports only the second adapter.
	reportEntity(t, p, "host:multi-guest", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"primary_mac":   "DC:EE:FF:44:55:66",
		"mac_addresses": "DC:EE:FF:44:55:66",
	})

	require.NoError(t, w.Correlate(ctx))

	edges := getSameAsEdges(t, p)
	require.Len(t, edges, 1, "MAC match via second adapter must produce one same-as edge")
}

// TestIdempotent verifies that running Correlate twice does not create duplicate
// edges (same-as observations are content-hash deduped).
func TestIdempotent(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	reportEntity(t, p, "host:hv/vm:vm-idem", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": "FE:EE:DD:CC:BB:AA"},
		},
	})
	reportEntity(t, p, "host:guest-idem", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"primary_mac":   "FE:EE:DD:CC:BB:AA",
		"mac_addresses": "FE:EE:DD:CC:BB:AA",
	})

	require.NoError(t, w.Correlate(ctx))
	require.NoError(t, w.Correlate(ctx)) // second run — must not duplicate

	edges := getSameAsEdges(t, p)
	require.Len(t, edges, 1, "second Correlate run must not create duplicate edges")
}

// TestNoEntitiesNoError verifies that Correlate on an empty entity graph returns
// nil and writes no observations.
func TestNoEntitiesNoError(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)

	require.NoError(t, w.Correlate(context.Background()))
	require.Empty(t, getSameAsEdges(t, p))
}

// TestNilProvider verifies that New rejects a nil provider.
func TestNilProvider(t *testing.T) {
	_, err := correlator.New(nil)
	require.Error(t, err)
}

// TestNoMACNoEdge verifies that entities without any MAC attributes do not
// produce same-as edges, even if they share other attributes.
func TestNoMACNoEdge(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	reportEntity(t, p, "host:no-mac-a", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"hostname":      "server-a",
	})
	reportEntity(t, p, "host:no-mac-b", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"hostname":      "server-b",
	})

	require.NoError(t, w.Correlate(ctx))
	require.Empty(t, getSameAsEdges(t, p))
}

// TestNonIdentifyingMACsDoNotCorrelate verifies end to end that hosts sharing
// only a non-identifying MAC produce no same-as edges, while their real adapter
// addresses still correlate normally in the same sweep.
//
// The fixture is the shape the steward DNA network collector actually produces:
// it appends iface.HardwareAddr for every non-loopback adapter to a
// comma-separated mac_addresses string, so a Windows host contributes its real
// NIC address alongside the all-zero address of its WAN Miniport/tunnel
// pseudo-adapters and the fixed Microsoft KM-TEST loopback address. Those junk
// values repeat on every host in the fleet, and each steward is its own
// authority segment, so correlating on them would collapse the whole fleet — and
// every tenant in it — into one identity.
func TestNonIdentifyingMACsDoNotCorrelate(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	// Junk addresses every Windows host reports, plus a per-host real NIC.
	const junk = "00:00:00:00:00:00,ff:ff:ff:ff:ff:ff,02:00:4c:4f:4f:50,01:00:5e:00:00:01"

	reportEntity(t, p, "host:win-a", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-a",
		"mac_addresses": junk + ",00:15:5D:00:00:0A",
		"primary_mac":   "00:15:5D:00:00:0A",
	})
	reportEntity(t, p, "host:win-b", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-b",
		"mac_addresses": junk + ",00:15:5D:00:00:0B",
		"primary_mac":   "00:15:5D:00:00:0B",
	})
	reportEntity(t, p, "host:win-c", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-c",
		"mac_addresses": junk + ",00:15:5D:00:00:0C",
		"primary_mac":   "00:15:5D:00:00:0C",
	})

	require.NoError(t, w.Correlate(ctx))
	require.Empty(t, getSameAsEdges(t, p),
		"hosts sharing only non-identifying MACs must not correlate")

	// The real NIC of host win-a, observed from a second authority, still
	// correlates — the hygiene filter does not suppress genuine matches.
	reportEntity(t, p, "host:hyperv-obs/vm:win-a-vm", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-a",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": "000000000000"},
			map[string]interface{}{"mac_address": "00155D00000A"},
		},
	})

	require.NoError(t, w.Correlate(ctx))

	edges := getSameAsEdges(t, p)
	require.Len(t, edges, 1, "the genuine MAC match must still produce exactly one edge")
	require.ElementsMatch(t,
		[]string{"host:win-a", "host:hyperv-obs/vm:win-a-vm"},
		[]string{edges[0].Edge.From.String(), edges[0].Edge.To.String()},
	)
}

// TestQueryEntitiesErrorPropagates verifies that a QueryEntities failure during
// the entity sweep is wrapped and returned to Correlate's caller rather than
// silently yielding an empty correlation result. The failure is induced with a
// real provider by closing its connection pool before the sweep runs.
func TestQueryEntitiesErrorPropagates(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)

	require.NoError(t, p.Close())

	err := w.Correlate(context.Background())
	require.Error(t, err, "closed provider must fail the entity sweep")
	require.ErrorContains(t, err, "correlator: query entities:")
	require.ErrorContains(t, err, "correlator: collect MACs:")
}

// TestReportObservationsErrorPropagates verifies that a ReportObservations
// failure is returned to Correlate's caller. The read half must succeed so the
// write path is actually reached: entities are loaded through a writable
// provider, which is then closed and reopened read-only against the same file.
// The sweep reads the two MAC-matched entities, then the same-as observation
// write fails on the read-only database.
func TestReportObservationsErrorPropagates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eg.db")

	rw, err := sqliteprovider.NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err)

	reportEntity(t, rw, "host:hv-ro/vm:ro-vm", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": "0A:1B:2C:3D:4E:5F"},
		},
	})
	reportEntity(t, rw, "host:ro-guest", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"primary_mac":   "0A:1B:2C:3D:4E:5F",
		"mac_addresses": "0A:1B:2C:3D:4E:5F",
	})
	require.NoError(t, rw.Close())

	ro, err := sqliteprovider.NewSQLiteEntityGraphProvider("file:" + path + "?mode=ro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ro.Close() })

	w, err := correlator.New(ro)
	require.NoError(t, err)

	// The read half succeeds: both entities are visible through this provider.
	page, err := ro.QueryEntities(context.Background(), interfaces.EntityFilter{}, interfaces.PageToken{PageSize: 500})
	require.NoError(t, err)
	require.Len(t, page.Entities, 2, "read path must succeed so the write path is reached")

	err = w.Correlate(context.Background())
	require.Error(t, err, "read-only provider must fail the observation write")
	require.ErrorContains(t, err, "readonly database")
	require.Empty(t, getSameAsEdges(t, ro))
}

// TestEdgeSubjectDelimiterRejected verifies that an entity whose EID contains
// the edge-subject delimiter '|' never contributes a same-as edge.
//
// types.ParseEID rejects only '/' in an authority name, and authority names are
// collector-supplied, so an attacker-controlled entity can be named
// "cluster:victim-cluster|host:pad". The provider parses edge subjects with
// strings.SplitN(subject, "|", 3), so emitting "same-as|cluster:victim-cluster|
// host:pad|host:legit-guest" would store an edge with from="cluster:victim-cluster"
// — a different, real entity than the one whose MAC matched — and pull the
// forged member into that victim's collapse group. The pair must be skipped.
func TestEdgeSubjectDelimiterRejected(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	const sharedMAC = "0A:0B:0C:0D:0E:0F"

	// A real victim entity that the attacker does not control.
	reportEntity(t, p, "cluster:victim-cluster", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-a",
		"hostname":      "victim-cluster",
	})

	// Attacker-authored entity whose authority name embeds the delimiter plus
	// the victim's EID, carrying a MAC that matches a legitimate host.
	reportEntity(t, p, "cluster:victim-cluster|host:pad", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-b",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": sharedMAC},
		},
	})

	// Legitimate host sharing the MAC, from a different authority segment.
	reportEntity(t, p, "host:legit-guest", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/msp-a",
		"primary_mac":   sharedMAC,
		"mac_addresses": sharedMAC,
	})

	require.NoError(t, w.Correlate(ctx))

	require.Empty(t, getSameAsEdges(t, p),
		"an EID containing the edge-subject delimiter must not produce a same-as edge")
}

// TestEdgeSubjectDelimiterRejected_UnaffectedPairsStillMatch verifies that
// skipping a delimiter-bearing pair does not suppress correlation between two
// well-formed entities that share the same MAC in the same sweep.
func TestEdgeSubjectDelimiterRejected_UnaffectedPairsStillMatch(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	const sharedMAC = "1A:2B:3C:4D:5E:6F"

	reportEntity(t, p, "cluster:other-victim|host:pad", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": sharedMAC},
		},
	})
	reportEntity(t, p, "host:hv-clean/vm:clean-vm", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": sharedMAC},
		},
	})
	reportEntity(t, p, "host:clean-guest", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root",
		"primary_mac":   sharedMAC,
		"mac_addresses": sharedMAC,
	})

	require.NoError(t, w.Correlate(ctx))

	edges := getSameAsEdges(t, p)
	require.Len(t, edges, 1, "the two well-formed entities must still correlate")
	require.ElementsMatch(t,
		[]string{"host:hv-clean/vm:clean-vm", "host:clean-guest"},
		[]string{edges[0].Edge.From.String(), edges[0].Edge.To.String()},
	)
}
