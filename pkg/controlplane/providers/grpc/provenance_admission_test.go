// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// spyProvenanceChecker delegates to a real checker and records every call.
type spyProvenanceChecker struct {
	inner ProvenanceChecker

	mu    sync.Mutex
	calls int
	last  ProvenanceAssessment
}

func (s *spyProvenanceChecker) CheckProvenance(ctx context.Context, id string, attrs map[string]string) ProvenanceAssessment {
	a := s.inner.CheckProvenance(ctx, id, attrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.last = a
	return a
}

func (s *spyProvenanceChecker) snapshot() (int, ProvenanceAssessment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.last
}

type provEnv struct {
	*revocationEnv
	store    business.StewardStore
	audit    business.AuditStore
	auditMgr *audit.Manager
	spy      *spyProvenanceChecker
}

const baselineJSON = `{"machine_id":"m-1","nic_macs":"aa:bb","disk_serials":"d-1","install_date":"2026-01-01"}`

func newProvEnv(t *testing.T, stewardID, baseline string) *provEnv {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	store := sm.GetStewardStore()
	require.NoError(t, store.RegisterSteward(context.Background(), &business.StewardRecord{
		ID: stewardID, TenantID: "tenant-a", Hostname: "h", Platform: "linux", Arch: "amd64",
		Version: "1", Status: business.StewardStatusActive, LastProvenanceJSON: baseline,
	}))
	mgr, err := audit.NewManager(sm.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })
	return &provEnv{
		revocationEnv: newRevocationEnv(t),
		store:         store,
		audit:         sm.GetAuditStore(),
		auditMgr:      mgr,
		spy:           &spyProvenanceChecker{inner: NewStewardStoreProvenanceChecker(store, mgr, logging.NewNoopLogger())},
	}
}

func (e *provEnv) connect(t *testing.T, stewardID string, attrs map[string]string, extra ...option) {
	t.Helper()
	server, reg := e.startServer(t, append([]option{WithProvenanceChecker(e.spy)}, extra...)...)
	tlsCfg, _ := e.clientTLS(t, stewardID)
	client := New(ModeClient, WithHostAttributes(func() map[string]string { return attrs }))
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": server.ListenAddr(), "tls_config": tlsCfg, "steward_id": stewardID,
	}))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	require.NoError(t, client.Start(context.Background()))
	require.Eventually(t, func() bool { _, ok := reg.Get(stewardID); return ok }, 5*time.Second, 10*time.Millisecond)
}

func (e *provEnv) auditEntries(t *testing.T, action string) []*business.AuditEntry {
	t.Helper()
	require.NoError(t, e.auditMgr.Flush(context.Background()))
	entries, err := e.audit.ListAuditEntries(context.Background(), &business.AuditFilter{Actions: []string{action}})
	require.NoError(t, err)
	return entries
}

func (e *provEnv) baseline(t *testing.T, id string) string {
	t.Helper()
	rec, err := e.store.GetSteward(context.Background(), id)
	require.NoError(t, err)
	return rec.LastProvenanceJSON
}

func TestControlChannel_ProvenanceBelowThreshold_ReportsCopy(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-copy", baselineJSON)
	env.connect(t, "steward-copy", map[string]string{
		"machine_id": "m-1", "nic_macs": "cc:dd", "disk_serials": "d-9", "install_date": "2030-01-01",
	})

	calls, got := env.spy.snapshot()
	require.Equal(t, 1, calls)
	assert.Equal(t, ProvenanceCopy, got.Decision)
	assert.Equal(t, 1, got.MatchedFields)
	assert.Equal(t, 4, got.TotalFields)
	assert.ElementsMatch(t, []string{"nic_macs", "disk_serials", "install_date"}, got.DivergentKeys)

	entries := env.auditEntries(t, "steward_provenance_divergence")
	require.Len(t, entries, 1)
	assert.Equal(t, business.AuditSeverityHigh, entries[0].Severity)
	assert.Equal(t, business.AuditEventSecurityEvent, entries[0].EventType)
	assert.Equal(t, "tenant-a", entries[0].TenantID)
	for _, v := range entries[0].Details {
		assert.NotContains(t, toString(v), "cc:dd", "attribute values must never reach the audit log")
	}
	assert.JSONEq(t, baselineJSON, env.baseline(t, "steward-copy"), "a copy must never overwrite the baseline")
}

func TestControlChannel_ProvenanceAtOrAboveThreshold_ApprovedMachine(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-ok", baselineJSON)
	// 3 of 4 = 0.75 >= 0.60
	env.connect(t, "steward-ok", map[string]string{
		"machine_id": "m-1", "nic_macs": "aa:bb", "disk_serials": "d-1", "install_date": "2030-01-01",
	})

	_, got := env.spy.snapshot()
	assert.Equal(t, ProvenanceApprovedMachine, got.Decision)
	assert.Equal(t, 3, got.MatchedFields)
	assert.Empty(t, env.auditEntries(t, "steward_provenance_divergence"))
	assert.JSONEq(t, baselineJSON, env.baseline(t, "steward-ok"))
}

func TestControlChannel_NoAttributesSent_AdmittedAsUnknown(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-old", baselineJSON)
	env.connect(t, "steward-old", nil)

	calls, _ := env.spy.snapshot()
	assert.Zero(t, calls, "no attributes: the checker has nothing to compare")
	assert.Empty(t, env.auditEntries(t, "steward_provenance_divergence"))
	assert.JSONEq(t, baselineJSON, env.baseline(t, "steward-old"))
}

func TestControlChannel_OversizedAttrHeader_TreatedAsNoAttributes(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-big", baselineJSON)
	env.connect(t, "steward-big", map[string]string{"machine_id": "m-1", "pad": strings.Repeat("x", MaxHostAttrsHeaderBytes)})

	calls, _ := env.spy.snapshot()
	assert.Zero(t, calls)
	assert.Empty(t, env.auditEntries(t, "steward_provenance_divergence"))
}

func TestControlChannel_ProvenanceCannotAdmitRevoked(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-rev", baselineJSON)
	server, reg := env.startServer(t, WithProvenanceChecker(env.spy), WithRevocationChecker(env.mgr))
	tlsCfg, serial := env.clientTLS(t, "steward-rev")
	require.NoError(t, env.mgr.Revoke(serial))

	_, err := startRevocationClient(t, server.ListenAddr(), tlsCfg, "steward-rev", 5*time.Second)
	require.Error(t, err)
	assert.ErrorIs(t, err, interfaces.ErrIdentityRejected)
	_, ok := reg.Get("steward-rev")
	assert.False(t, ok)
	calls, _ := env.spy.snapshot()
	assert.Zero(t, calls, "provenance must not be consulted for a revoked serial")
}

func TestControlChannel_FirstAdmission_WritesBaselineOnce(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-first", "")
	attrs := map[string]string{"machine_id": "m-1", "nic_macs": "aa:bb"}
	env.connect(t, "steward-first", attrs)

	_, got := env.spy.snapshot()
	assert.Equal(t, ProvenanceUnknown, got.Decision, "no baseline yet: admitted as unknown")
	assert.JSONEq(t, `{"machine_id":"m-1","nic_macs":"aa:bb"}`, env.baseline(t, "steward-first"))
	assert.Len(t, env.auditEntries(t, "steward_provenance_baseline_recorded"), 1)
}

func TestHostAttrsFromContext_RejectsMalformed(t *testing.T) {
	ctxWith := func(v string) context.Context {
		return metadata.NewIncomingContext(context.Background(), metadata.Pairs(HostAttrsHeader, v))
	}
	assert.Nil(t, hostAttrsFromContext(context.Background()))
	assert.Nil(t, hostAttrsFromContext(ctxWith("!!not-base64!!")))
	assert.Nil(t, hostAttrsFromContext(ctxWith(base64.StdEncoding.EncodeToString([]byte("not json")))))
	assert.Nil(t, hostAttrsFromContext(ctxWith(base64.StdEncoding.EncodeToString([]byte(`["a"]`)))))
	got := hostAttrsFromContext(ctxWith(base64.StdEncoding.EncodeToString([]byte(`{"machine_id":"m","os_version":"x"}`))))
	assert.Equal(t, map[string]string{"machine_id": "m"}, got, "DNA keys are dropped")
}

func toString(v interface{}) string { return fmt.Sprint(v) }

// An unchanged host must score 1.0 whichever path wrote the baseline and
// however that path formatted it: the baseline here is stored un-normalised
// (padded values, an empty value, a DNA key), the way an earlier writer could
// have left it, while the connect path presents the collected attributes.
func TestControlChannel_UnchangedHost_ScoresOneAcrossPaths(t *testing.T) {
	t.Parallel()
	attrs := map[string]string{
		"machine_id":   "m-1",
		"nic_macs":     "aa:bb:cc:dd:ee:ff",
		"install_date": "2026-01-01",
	}
	stored, err := json.Marshal(map[string]string{
		"machine_id":   " m-1\n",
		"nic_macs":     "aa:bb:cc:dd:ee:ff ",
		"install_date": "2026-01-01",
		"disk_serials": "",
		"os_version":   "6.1",
	})
	require.NoError(t, err)

	env := newProvEnv(t, "steward-same", string(stored))
	env.connect(t, "steward-same", attrs)

	_, got := env.spy.snapshot()
	assert.Equal(t, ProvenanceApprovedMachine, got.Decision)
	assert.InDelta(t, 1.0, got.Score, 0.0001)
	assert.Equal(t, 3, got.TotalFields)
	assert.Empty(t, got.DivergentKeys)
	assert.Empty(t, env.auditEntries(t, "steward_provenance_divergence"))
}

// A host that genuinely diverges must still read as a copy once both sides
// are normalised: formatting noise in the stored baseline is ignored, but the
// keys whose values really changed are reported, sorted, without values.
func TestCheckProvenance_DivergentHostAfterNormalisation_ReportsCopy(t *testing.T) {
	t.Parallel()
	stored, err := json.Marshal(map[string]string{
		"machine_id":   " m-1 ",
		"nic_macs":     "aa:bb\n",
		"install_date": "2026-01-01",
		"disk_serials": "",
		"os_version":   "6.1",
	})
	require.NoError(t, err)
	env := newProvEnv(t, "steward-div", string(stored))

	got := env.spy.inner.CheckProvenance(context.Background(), "steward-div", map[string]string{
		"machine_id": "m-1", "nic_macs": "cc:dd", "os_version": "9.9",
	})

	assert.Equal(t, ProvenanceCopy, got.Decision)
	assert.Equal(t, 1, got.MatchedFields)
	assert.Equal(t, 3, got.TotalFields, "empty values and DNA keys never count")
	assert.Equal(t, []string{"install_date", "nic_macs"}, got.DivergentKeys)
	entries := env.auditEntries(t, "steward_provenance_divergence")
	require.Len(t, entries, 1)
	for _, v := range entries[0].Details {
		assert.NotContains(t, toString(v), "cc:dd")
	}
	assert.JSONEq(t, string(stored), env.baseline(t, "steward-div"), "a copy must never overwrite the baseline")
}

// Attributes that normalise to nothing must not be recorded as a baseline:
// an empty baseline would leave the steward unscoreable forever.
func TestCheckProvenance_FirstUse_NothingUsable_RecordsNoBaseline(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-empty", "")

	got := env.spy.inner.CheckProvenance(context.Background(), "steward-empty", map[string]string{
		"os_version": "6.1", "machine_id": "  ", " ": "x",
	})

	assert.Equal(t, ProvenanceUnknown, got.Decision)
	assert.Equal(t, "", env.baseline(t, "steward-empty"))
	assert.Empty(t, env.auditEntries(t, "steward_provenance_baseline_recorded"))
}

// First use with padded attributes stores the canonical form.
func TestCheckProvenance_FirstUse_StoresNormalisedBaseline(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-norm", "")

	got := env.spy.inner.CheckProvenance(context.Background(), "steward-norm", map[string]string{
		"machine_id": " m-1\n", "nic_macs": "aa:bb", "uptime_seconds": "5",
	})

	assert.Equal(t, ProvenanceUnknown, got.Decision)
	assert.JSONEq(t, `{"machine_id":"m-1","nic_macs":"aa:bb"}`, env.baseline(t, "steward-norm"))
	assert.Len(t, env.auditEntries(t, "steward_provenance_baseline_recorded"), 1)
}

// A stored baseline that is not valid JSON cannot be scored: the steward is
// admitted as unknown, nothing is audited and the stored value is left alone.
func TestCheckProvenance_InvalidStoredBaseline_Unknown(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-bad", "not json")

	got := env.spy.inner.CheckProvenance(context.Background(), "steward-bad", map[string]string{"machine_id": "m-1"})

	assert.Equal(t, ProvenanceUnknown, got.Decision)
	assert.Empty(t, got.DivergentKeys)
	assert.Empty(t, env.auditEntries(t, "steward_provenance_divergence"))
	assert.Equal(t, "not json", env.baseline(t, "steward-bad"))
}

// Key names are steward-chosen; every element must be sanitised before it
// reaches a log line.
func TestSanitizeKeyNames_StripsControlCharacters(t *testing.T) {
	got := sanitizeKeyNames([]string{"machine_id", "evil\r\nlevel=error msg=forged", "tab\tkey"})
	require.Len(t, got, 3)
	assert.Equal(t, "machine_id", got[0])
	for _, k := range got {
		assert.NotContains(t, k, "\n")
		assert.NotContains(t, k, "\r")
		assert.NotContains(t, k, "\t")
	}
	assert.Empty(t, sanitizeKeyNames(nil))
}
