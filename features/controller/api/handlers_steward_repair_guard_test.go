// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// guardClock is a settable clock for the repair guard windows. The audit events
// carry real timestamps, so moving the clock forward moves the guard past the
// quiet window or the watch window.
type guardClock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *guardClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *guardClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset = d
}

// guardEnv is a repair environment with a clock and, on demand, a mail server.
type guardEnv struct {
	*repairEnv
	clock *guardClock
	smtp  *emailTestSMTPServer
}

func newGuardEnv(t *testing.T) *guardEnv {
	t.Helper()
	env := newRepairEnv(t)
	clock := &guardClock{}
	env.server.repairClock = clock.now
	return &guardEnv{repairEnv: env, clock: clock}
}

// withMail attaches an in-process mail server and an administrator contact to
// the steward's tenant.
func (e *guardEnv) withMail(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, ensureTestRootTenant(ctx, e.server.tenantManager))
	if _, err := e.server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: cloneTenant, ParentID: testRootTenantID}); err != nil && !errors.Is(err, tenant.ErrTenantExists) {
		require.NoError(t, err)
	}
	_, err := e.server.tenantManager.SetAdminContacts(ctx, cloneTenant, []string{"admin@acme-corp.example"})
	require.NoError(t, err)
	e.smtp = newEmailTestSMTPServer(t)
	attachEmail(t, e.server, e.smtp)
}

func (e *guardEnv) status(t *testing.T, id string) business.StewardStatus {
	t.Helper()
	rec, err := e.steward.GetSteward(context.Background(), id)
	require.NoError(t, err)
	return rec.Status
}

// events returns the audit entries of one action for one steward.
func (e *guardEnv) events(t *testing.T, action, stewardID string) []*business.AuditEntry {
	t.Helper()
	var out []*business.AuditEntry
	for _, en := range auditEntries(t, e.server, cloneTenant) {
		if en.Action == action && en.ResourceID == stewardID {
			out = append(out, en)
		}
	}
	return out
}

// completedRepair is a steward whose repair has completed through the real
// completion flow.
type completedRepair struct {
	rs        *repairSteward
	newSerial string
	oldSerial string
}

// completeRepair requests and completes a repair for a fresh tampered steward.
func (e *guardEnv) completeRepair(t *testing.T, id string) *completedRepair {
	t.Helper()
	rs := newRepairSteward(t, e.repairEnv, id, "file")
	rec := rs.complete(rs.request(t, rs.newKS, nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	done := e.events(t, auditActionTamperRepairCompleted, id)
	require.Len(t, done, 1)
	newSerial := auditString(done[0].Details, "new_serial")
	require.NotEmpty(t, newSerial)
	return &completedRepair{rs: rs, newSerial: newSerial, oldSerial: rs.preCerts[0]}
}

// reportCompleted is the heartbeat reasons of a steward that finished repair.
func reportCompleted(repairID string, extra ...controlplaneTypes.HealthReason) []controlplaneTypes.HealthReason {
	return append([]controlplaneTypes.HealthReason{{
		Component: "repair", Code: controlplaneTypes.ReasonCodeRepairCompleted, Message: repairID,
	}}, extra...)
}

// returnToTrusted moves the clock past the quiet window and sends the clean
// heartbeat on the new serial.
func (e *guardEnv) returnToTrusted(t *testing.T, c *completedRepair) {
	t.Helper()
	e.server.ObserveAdmittedPeer(context.Background(), c.rs.id, c.newSerial)
	e.clock.advance(repairQuietWindow + time.Minute)
	e.server.HandleRepairHeartbeat(context.Background(), c.rs.id, c.newSerial, reportCompleted(c.rs.repairID))
	require.Equal(t, business.StewardStatusActive, e.status(t, c.rs.id))
}

func (e *guardEnv) requireContested(t *testing.T, id, source string) {
	t.Helper()
	e.requireContestedEvent(t, id, source)
	assert.Equal(t, repairStateContested, e.repairStatus(t, id).State)
}

// requireContestedEvent checks the status and the audit event, for a steward
// with no repair request for GET to report on.
func (e *guardEnv) requireContestedEvent(t *testing.T, id, source string) {
	t.Helper()
	assert.Equal(t, business.StewardStatusTampered, e.status(t, id))
	ev := e.events(t, auditActionTamperRepairContested, id)
	require.NotEmpty(t, ev, "repair.contested is audited; the steward's repair events were:\n%s", e.describeRepairEvents(t, id))
	assert.Equal(t, source, auditString(ev[len(ev)-1].Details, "source"))
}

// describeRepairEvents lists the steward's repair audit events, oldest first by
// write order, for a failure message: action, timestamp and sequence number.
func (e *guardEnv) describeRepairEvents(t *testing.T, stewardID string) string {
	t.Helper()
	var evs []*business.AuditEntry
	for _, en := range auditEntries(t, e.server, cloneTenant) {
		if en.ResourceID == stewardID && slices.Contains(repairGuardActions, en.Action) {
			evs = append(evs, en)
		}
	}
	return formatRepairEvents(evs)
}

func formatRepairEvents(evs []*business.AuditEntry) string {
	if len(evs) == 0 {
		return "  (none)"
	}
	sortRepairEventsOldestFirst(evs)
	var b strings.Builder
	for _, en := range evs {
		fmt.Fprintf(&b, "  action=%s timestamp=%s sequence=%d\n", en.Action, en.Timestamp.Format(time.RFC3339Nano), en.SequenceNumber)
	}
	return strings.TrimRight(b.String(), "\n")
}

func (e *guardEnv) requireNotContested(t *testing.T, id string, want business.StewardStatus) {
	t.Helper()
	assert.Equal(t, want, e.status(t, id))
	assert.Empty(t, e.events(t, auditActionTamperRepairContested, id), "no repair.contested")
}

func TestRepairGuard_HonestRepair_NeverContestedAndReturnsAfterQuietWindow(t *testing.T) {
	env := newGuardEnv(t)
	// The steward holds a live control stream when the repair completes; the
	// controller evicts it.
	evicted := make(chan error, 1)
	require.NoError(t, env.server.registry.Register(&registry.StewardConnection{
		StewardID: "s-honest", Sender: nopSender{}, Evict: func(err error) { evicted <- err },
	}))
	c := env.completeRepair(t, "s-honest")
	select {
	case err := <-evicted:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("the old control stream was not evicted")
	}

	// The controller evicted the old stream and the steward's own reconnects
	// dial with the old certificate until it has installed the new one: refused,
	// and not a contested signal, because the new serial was never seen yet.
	for i := 0; i < 3; i++ {
		env.server.ObserveRevokedPeer(context.Background(), c.rs.id, c.oldSerial)
	}
	env.requireNotContested(t, c.rs.id, business.StewardStatusTampered)

	// The first connection on the new serial is recorded once.
	env.server.ObserveAdmittedPeer(context.Background(), c.rs.id, c.newSerial)
	env.server.ObserveAdmittedPeer(context.Background(), c.rs.id, c.newSerial)
	assert.Len(t, env.events(t, auditActionTamperRepairNewSerialSeen, c.rs.id), 1, "recorded once")

	// A clean heartbeat on the new serial before the quiet window does not return it.
	env.server.HandleRepairHeartbeat(context.Background(), c.rs.id, c.newSerial, reportCompleted(c.rs.repairID))
	env.requireNotContested(t, c.rs.id, business.StewardStatusTampered)
	assert.Equal(t, repairStateCompleted, env.repairStatus(t, c.rs.id).State)

	// After the window it does, and the steward is told it is released.
	env.clock.advance(repairQuietWindow + time.Second)
	env.server.HandleRepairHeartbeat(context.Background(), c.rs.id, c.newSerial, reportCompleted(c.rs.repairID))
	env.requireNotContested(t, c.rs.id, business.StewardStatusActive)
	assert.Equal(t, []bool{false}, env.tamperEnv.sender.states(c.rs.id), "TamperState{locked: false} is sent")
	repaired := env.events(t, auditActionTamperRepaired, c.rs.id)
	require.Len(t, repaired, 1)
	assert.Equal(t, c.newSerial, auditString(repaired[0].Details, "new_serial"))
	assert.Equal(t, repairStateCompleted, env.repairStatus(t, c.rs.id).State)
}

func TestRepairGuard_RevokedSerialArmedOnlyAfterNewSerialSeen(t *testing.T) {
	t.Run("before the first new-serial connection: not contested", func(t *testing.T) {
		env := newGuardEnv(t)
		c := env.completeRepair(t, "s-before")
		env.server.ObserveRevokedPeer(context.Background(), c.rs.id, c.oldSerial)
		env.requireNotContested(t, c.rs.id, business.StewardStatusTampered)
	})
	t.Run("after the first new-serial connection: contested", func(t *testing.T) {
		env := newGuardEnv(t)
		env.withMail(t)
		c := env.completeRepair(t, "s-after")
		env.server.ObserveAdmittedPeer(context.Background(), c.rs.id, c.newSerial)
		env.server.ObserveRevokedPeer(context.Background(), c.rs.id, c.oldSerial)
		env.requireContested(t, c.rs.id, repairContestRevokedSerial)
		env.server.crossingNotifyWG.Wait()
		msgs := env.smtp.Messages()
		require.Len(t, msgs, 1, "admins are notified")
		assert.Contains(t, msgs[0], c.rs.id)
	})
	t.Run("completion older than the quiet window and the event absent: armed", func(t *testing.T) {
		env := newGuardEnv(t)
		c := env.completeRepair(t, "s-absent")
		env.clock.advance(repairQuietWindow + time.Second)
		env.server.ObserveRevokedPeer(context.Background(), c.rs.id, c.oldSerial)
		env.requireContested(t, c.rs.id, repairContestRevokedSerial)
	})
	t.Run("a new serial of another steward is not recorded", func(t *testing.T) {
		env := newGuardEnv(t)
		c := env.completeRepair(t, "s-other")
		env.server.ObserveAdmittedPeer(context.Background(), c.rs.id, "999999")
		assert.Empty(t, env.events(t, auditActionTamperRepairNewSerialSeen, c.rs.id))
	})
	t.Run("a steward that was never repaired is not contested", func(t *testing.T) {
		env := newGuardEnv(t)
		env.addTamperedWithKey(t, "s-plain", newDeviceKey(t), "file")
		env.server.ObserveRevokedPeer(context.Background(), "s-plain", "12345")
		env.requireNotContested(t, "s-plain", business.StewardStatusTampered)
	})
}

func TestRepairGuard_PrunedCompletionIsInsideTheWindow(t *testing.T) {
	// The completion event is gone, but the first new-serial connection and the
	// retired-device tombstone are not: the steward is treated as inside the window.
	t.Run("another repair event shows a completion", func(t *testing.T) {
		env := newGuardEnv(t)
		env.addTamperedWithKey(t, "s-pruned", newDeviceKey(t), "file")
		rec, err := env.steward.GetSteward(context.Background(), "s-pruned")
		require.NoError(t, err)
		env.server.recordRepairAudit(context.Background(), rec, auditActionTamperRepairNewSerialSeen, business.AuditResultSuccess,
			map[string]interface{}{"repair_id": "r-1", "serial": "4242"})
		require.Empty(t, env.events(t, auditActionTamperRepairCompleted, "s-pruned"))
		env.server.ObserveRevokedPeer(context.Background(), "s-pruned", "1111")
		env.requireContestedEvent(t, "s-pruned", repairContestRevokedSerial)
	})
	t.Run("a tombstone shows a completion", func(t *testing.T) {
		env := newGuardEnv(t)
		oldKS := newDeviceKey(t)
		env.addTamperedWithKey(t, "s-tomb", oldKS, "file")
		tomb, _ := json.Marshal(repairRetiredEntry{
			StewardID: "s-tomb", OldDeviceID: "retired-device", CompletedAt: time.Now().UTC(),
			OldKeyPub: pubBytes(t, oldKS), OldKeyAlg: string(oldKS.Algorithm()),
		})
		require.NoError(t, env.server.nonceStore.PutNonce(context.Background(), repairRetiredKeyPrefix+"retired-device", tomb, time.Hour))
		// Without proof of the retired key nothing changes.
		env.server.contestOnRetiredDevice(context.Background(), "retired-device", func(*repairRetiredEntry) bool { return false })
		env.requireNotContested(t, "s-tomb", business.StewardStatusTampered)
		env.server.contestOnRetiredDevice(context.Background(), "retired-device", func(got *repairRetiredEntry) bool {
			return bytes.Equal(got.OldKeyPub, pubBytes(t, oldKS))
		})
		env.requireContestedEvent(t, "s-tomb", repairContestRetiredKeyRefresh)
		// The tombstone is only read: it is still there for the next signal.
		got, ok := env.server.retiredDevice(context.Background(), "retired-device")
		require.True(t, ok)
		assert.Equal(t, "s-tomb", got.StewardID)
	})
	t.Run("a tombstone without a retired key never contests", func(t *testing.T) {
		env := newGuardEnv(t)
		env.addTamperedWithKey(t, "s-nokey", newDeviceKey(t), "file")
		tomb, _ := json.Marshal(repairRetiredEntry{StewardID: "s-nokey", OldDeviceID: "retired-nokey", CompletedAt: time.Now().UTC()})
		require.NoError(t, env.server.nonceStore.PutNonce(context.Background(), repairRetiredKeyPrefix+"retired-nokey", tomb, time.Hour))
		env.server.contestOnRetiredDevice(context.Background(), "retired-nokey", func(*repairRetiredEntry) bool { return true })
		env.requireNotContested(t, "s-nokey", business.StewardStatusTampered)
	})
	t.Run("no evidence of a repair is not a pruned one", func(t *testing.T) {
		env := newGuardEnv(t)
		env.addTamperedWithKey(t, "s-none", newDeviceKey(t), "file")
		assert.False(t, env.server.markRepairContested(context.Background(), "s-none", repairContestCloneOf))
	})
	t.Run("a pruned completion cannot return to trusted", func(t *testing.T) {
		env := newGuardEnv(t)
		env.addTamperedWithKey(t, "s-pruned2", newDeviceKey(t), "file")
		env.clock.advance(time.Hour)
		env.server.HandleRepairHeartbeat(context.Background(), "s-pruned2", "4242", reportCompleted("r-1"))
		assert.Equal(t, business.StewardStatusTampered, env.status(t, "s-pruned2"))
	})
}

func TestRepairGuard_HooksContestInsideTheWindowOnly(t *testing.T) {
	type hook struct {
		name   string
		source string
		fire   func(t *testing.T, env *guardEnv, c *completedRepair)
	}
	hooks := []hook{
		{"revoked serial admission", repairContestRevokedSerial, func(t *testing.T, env *guardEnv, c *completedRepair) {
			env.server.ObserveRevokedPeer(context.Background(), c.rs.id, c.oldSerial)
		}},
		{"refresh addressed to the retired device ID, proven with the retired key", repairContestRetiredKeyRefresh, func(t *testing.T, env *guardEnv, c *completedRepair) {
			rec := retiredDeviceRefresh(t, env, c.rs.oldKS.DeviceID(), c.rs.oldKS, time.Now())
			assert.Equal(t, http.StatusNotFound, rec.Code, "the response is the usual not-found")
		}},
		{"registration naming the steward as clone_of", repairContestCloneOf, func(t *testing.T, env *guardEnv, c *completedRepair) {
			rec := httptest.NewRecorder()
			ok := env.server.registrationTokenUsable(rec, httptest.NewRequest(http.MethodPost, "/x", nil),
				RegistrationRequest{Token: env.regToken, CloneOf: c.rs.id}, &registration.Token{Token: env.regToken, TenantID: cloneTenant})
			assert.True(t, ok, "the registration itself is not refused")
		}},
	}
	for _, h := range hooks {
		t.Run(h.name+" inside the window", func(t *testing.T) {
			env := newGuardEnv(t)
			env.withMail(t)
			c := env.completeRepair(t, "s-in")
			env.returnToTrusted(t, c)
			env.clock.advance(time.Hour)
			h.fire(t, env, c)
			env.requireContested(t, c.rs.id, h.source)
			env.server.crossingNotifyWG.Wait()
			assert.Len(t, env.smtp.Messages(), 1, "admins are notified")
			assert.Equal(t, []bool{false, true}, env.tamperEnv.sender.states(c.rs.id), "released, then locked again")
		})
		t.Run(h.name+" outside the window", func(t *testing.T) {
			env := newGuardEnv(t)
			env.withMail(t)
			c := env.completeRepair(t, "s-out")
			env.returnToTrusted(t, c)
			env.clock.advance(repairWatchWindow + time.Minute)
			h.fire(t, env, c)
			env.requireNotContested(t, c.rs.id, business.StewardStatusActive)
			env.server.crossingNotifyWG.Wait()
			assert.Empty(t, env.smtp.Messages())
		})
	}
}

func TestRepairGuard_HeartbeatRules(t *testing.T) {
	env := newGuardEnv(t)
	c := env.completeRepair(t, "s-hb")
	ctx := context.Background()
	env.server.ObserveAdmittedPeer(ctx, c.rs.id, c.newSerial)

	// A clean heartbeat from an old-serial stream still open in the revocation
	// window never counts, not even after the quiet window.
	env.clock.advance(repairQuietWindow + time.Minute)
	env.server.HandleRepairHeartbeat(ctx, c.rs.id, c.oldSerial, reportCompleted(c.rs.repairID))
	env.server.HandleRepairHeartbeat(ctx, c.rs.id, "", reportCompleted(c.rs.repairID))
	assert.Equal(t, business.StewardStatusTampered, env.status(t, c.rs.id))

	// A heartbeat for another repair, or without repair.completed, never counts.
	env.server.HandleRepairHeartbeat(ctx, c.rs.id, c.newSerial, reportCompleted("some-other-repair"))
	env.server.HandleRepairHeartbeat(ctx, c.rs.id, c.newSerial, nil)
	assert.Equal(t, business.StewardStatusTampered, env.status(t, c.rs.id))

	// A heartbeat that still carries a tamper code after the window leaves it tampered.
	env.server.HandleRepairHeartbeat(ctx, c.rs.id, c.newSerial, reportCompleted(c.rs.repairID, controlplaneTypes.HealthReason{
		Component: "integrity", Code: controlplaneTypes.ReasonCodeTamperDataDir,
	}))
	assert.Equal(t, business.StewardStatusTampered, env.status(t, c.rs.id))
	assert.Empty(t, env.tamperEnv.sender.states(c.rs.id))

	// The clean one on the new serial does.
	env.server.HandleRepairHeartbeat(ctx, c.rs.id, c.newSerial, reportCompleted(c.rs.repairID))
	assert.Equal(t, business.StewardStatusActive, env.status(t, c.rs.id))
	assert.Equal(t, []bool{false}, env.tamperEnv.sender.states(c.rs.id))

	// A later tamper code re-enters tampered through the alarm.
	env.server.HandleStewardTamperAlarm(ctx, c.rs.id, tamperReasons)
	assert.Equal(t, business.StewardStatusTampered, env.status(t, c.rs.id))
}

func TestRepairGuard_ContestedStewardNeverReturnsToTrusted(t *testing.T) {
	env := newGuardEnv(t)
	c := env.completeRepair(t, "s-contested")
	ctx := context.Background()
	env.server.ObserveAdmittedPeer(ctx, c.rs.id, c.newSerial)
	env.server.ObserveRevokedPeer(ctx, c.rs.id, c.oldSerial)
	env.requireContested(t, c.rs.id, repairContestRevokedSerial)

	env.clock.advance(repairQuietWindow + time.Hour)
	env.server.HandleRepairHeartbeat(ctx, c.rs.id, c.newSerial, reportCompleted(c.rs.repairID))
	assert.Equal(t, business.StewardStatusTampered, env.status(t, c.rs.id), "a contested signal ends the quiet window for good")
	assert.Empty(t, env.events(t, auditActionTamperRepaired, c.rs.id))
}

// useTiedRepairEvents points the server at its own real audit store and writes a
// completion event that issued newSerial, then, when seen is true, the first
// new-serial connection. Every event carries the identical timestamp and
// increasing sequence numbers in write order, which is what a coarse wall clock
// produces for two events written moments apart. The timestamp is inside the
// quiet window, so only the new-serial event can arm the revoked-serial source.
func (e *guardEnv) useTiedRepairEvents(t *testing.T, stewardID, newSerial string, seen bool) {
	t.Helper()
	ctx := context.Background()
	store := pkgtesting.SetupTestStorage(t).GetAuditStore()
	mgr, err := audit.NewManager(store, "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })
	e.server.auditManager = mgr

	tied := time.Now().UTC().Add(-time.Minute)
	write := func(seq uint64, action string, details map[string]interface{}) {
		require.NoError(t, store.StoreAuditEntry(ctx, &business.AuditEntry{
			ID: fmt.Sprintf("tied-%s-%d", stewardID, seq), TenantID: cloneTenant, Timestamp: tied, SequenceNumber: seq,
			EventType: business.AuditEventSecurityEvent, Action: action, Result: business.AuditResultSuccess,
			Severity: business.AuditSeverityHigh, UserID: stewardID, UserType: business.AuditUserTypeSystem,
			ResourceType: "steward", ResourceID: stewardID, Details: details,
		}))
	}
	write(1, auditActionTamperRepairCompleted, map[string]interface{}{"repair_id": "r-tied", "new_serial": newSerial})
	if seen {
		write(2, auditActionTamperRepairNewSerialSeen, map[string]interface{}{"repair_id": "r-tied", "serial": newSerial})
	}
}

// A completion and the first new-serial connection that share one timestamp are
// folded in write order, so a revoked-serial use afterwards is contested.
func TestRepairGuard_TiedTimestampsFoldInSequenceOrder(t *testing.T) {
	ctx := context.Background()
	t.Run("new serial seen: revoked serial is contested", func(t *testing.T) {
		env := newGuardEnv(t)
		env.addTamperedWithKey(t, "s-tied", newDeviceKey(t), "file")
		env.useTiedRepairEvents(t, "s-tied", "4242", true)
		env.server.ObserveRevokedPeer(ctx, "s-tied", "1111")
		env.requireContestedEvent(t, "s-tied", repairContestRevokedSerial)
		assert.Len(t, env.events(t, auditActionTamperRepairContested, "s-tied"), 1)
	})
	t.Run("new serial not seen: stays not armed", func(t *testing.T) {
		env := newGuardEnv(t)
		env.addTamperedWithKey(t, "s-tied-unseen", newDeviceKey(t), "file")
		env.useTiedRepairEvents(t, "s-tied-unseen", "4242", false)
		env.server.ObserveRevokedPeer(ctx, "s-tied-unseen", "1111")
		env.requireNotContested(t, "s-tied-unseen", business.StewardStatusTampered)
	})
}

func TestSortRepairEventsOldestFirst(t *testing.T) {
	t0 := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	entry := func(action string, ts time.Time, seq uint64) *business.AuditEntry {
		return &business.AuditEntry{Action: action, Timestamp: ts, SequenceNumber: seq}
	}
	entries := []*business.AuditEntry{
		entry("c", t0.Add(time.Second), 4),
		entry("b2", t0, 3),
		entry("b1", t0, 2),
		entry("a", t0.Add(-time.Second), 9),
	}
	sortRepairEventsOldestFirst(entries)
	var got []string
	for _, e := range entries {
		got = append(got, e.Action)
	}
	assert.Equal(t, []string{"a", "b1", "b2", "c"}, got, "timestamp first, sequence number on a tie")
}

func TestFormatRepairEvents(t *testing.T) {
	assert.Equal(t, "  (none)", formatRepairEvents(nil))
	ts := time.Date(2026, 11, 9, 10, 0, 0, 123456789, time.UTC)
	out := formatRepairEvents([]*business.AuditEntry{
		{Action: auditActionTamperRepairNewSerialSeen, Timestamp: ts, SequenceNumber: 8},
		{Action: auditActionTamperRepairCompleted, Timestamp: ts, SequenceNumber: 7},
	})
	assert.Equal(t, "  action=steward_tamper_repair_completed timestamp=2026-11-09T10:00:00.123456789Z sequence=7\n"+
		"  action=steward_tamper_repair_new_serial_seen timestamp=2026-11-09T10:00:00.123456789Z sequence=8", out)
}

func TestRepairGuard_RepeatedSignalsAreAuditedOnce(t *testing.T) {
	env := newGuardEnv(t)
	c := env.completeRepair(t, "s-flood")
	ctx := context.Background()
	env.server.ObserveAdmittedPeer(ctx, c.rs.id, c.newSerial)
	for i := 0; i < 5; i++ {
		env.server.ObserveRevokedPeer(ctx, c.rs.id, c.oldSerial)
	}
	assert.Len(t, env.events(t, auditActionTamperRepairContested, c.rs.id), 1)
}

func TestRepairGuard_BannedStewardIsLeftBanned(t *testing.T) {
	env := newGuardEnv(t)
	c := env.completeRepair(t, "s-banned")
	ctx := context.Background()
	env.server.ObserveAdmittedPeer(ctx, c.rs.id, c.newSerial)
	transitioned, err := env.steward.TransitionStewardStatus(ctx, c.rs.id, business.StewardStatusRevoked, business.StewardStatusTampered)
	require.NoError(t, err)
	require.True(t, transitioned)
	env.server.ObserveRevokedPeer(ctx, c.rs.id, c.oldSerial)
	assert.Equal(t, business.StewardStatusRevoked, env.status(t, c.rs.id))
	assert.Empty(t, env.events(t, auditActionTamperRepairContested, c.rs.id))
}

func TestRepairGuard_IdentityConflictWhilePendingCancelsTheRepair(t *testing.T) {
	env := newGuardEnv(t)
	rs := newRepairSteward(t, env.repairEnv, "s-conflict", "file")
	require.True(t, env.nonceLive(t, rs.id, rs.repairID))

	env.server.ObserveIdentityConflict(context.Background(), rs.id)

	assert.False(t, env.nonceLive(t, rs.id, rs.repairID), "the nonce is gone")
	env.requireContested(t, rs.id, repairContestIdentityConflict)
	rec := rs.complete(rs.request(t, rs.newKS, nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "the nonce can no longer complete: %s", rec.Body.String())
	rs.requireUnchanged(t)
	// A request made again after the conflict is a new repair.
	again := env.requestRepair(t, rs.id, nil)
	assert.NotEqual(t, rs.repairID, again.RepairID)
	assert.Equal(t, repairStateWaiting, env.repairStatus(t, rs.id).State)
}

func TestRepairGuard_IdentityConflictWithoutRepairDoesNothing(t *testing.T) {
	env := newGuardEnv(t)
	env.addTamperedWithKey(t, "s-nothing", newDeviceKey(t), "file")
	env.server.ObserveIdentityConflict(context.Background(), "s-nothing")
	env.requireNotContested(t, "s-nothing", business.StewardStatusTampered)
}

// TestRepairGuard_Race runs the two holders of the same pre-repair keys in both
// orders. The first valid completion wins and holds the new key; the other one is
// refused, and the steward ends tampered with repair.contested, never active.
func TestRepairGuard_Race(t *testing.T) {
	for _, order := range []string{"party-a-first", "party-b-first"} {
		t.Run(order, func(t *testing.T) {
			env := newGuardEnv(t)
			env.withMail(t)
			const id = "s-race"
			a := newRepairSteward(t, env.repairEnv, id, "file")
			// Party b holds the same pre-repair keys and the same repair request.
			b := &repairSteward{env: env.repairEnv, id: id, oldKS: a.oldKS, newKS: newDeviceKey(t), repairID: a.repairID, preCerts: a.preCerts}
			_, _, err := b.newKS.GenerateOrLoad(context.Background())
			require.NoError(t, err)

			winner, loser := a, b
			if order == "party-b-first" {
				winner, loser = b, a
			}
			require.Equal(t, http.StatusOK, winner.complete(winner.request(t, winner.newKS, nil)).Code)
			rec := loser.complete(loser.request(t, loser.newKS, nil))
			assert.GreaterOrEqual(t, rec.Code, 400, "the loser is refused: %s", rec.Body.String())

			after, err := env.steward.GetSteward(context.Background(), id)
			require.NoError(t, err)
			assert.Equal(t, pubBytes(t, winner.newKS), after.IdentityKeyPub, "the winner holds the new key")
			env.requireContested(t, id, repairContestRetiredKeyRefresh)

			// The loser's old certificates are refused, and nothing returns the
			// steward to trusted afterwards.
			newSerial := auditString(env.events(t, auditActionTamperRepairCompleted, id)[0].Details, "new_serial")
			env.server.ObserveAdmittedPeer(context.Background(), id, newSerial)
			env.server.ObserveRevokedPeer(context.Background(), id, a.preCerts[0])
			env.clock.advance(repairQuietWindow + time.Hour)
			env.server.HandleRepairHeartbeat(context.Background(), id, newSerial, reportCompleted(a.repairID))
			assert.Equal(t, business.StewardStatusTampered, env.status(t, id), "never active")
			assert.Equal(t, repairStateContested, env.repairStatus(t, id).State)
			env.server.crossingNotifyWG.Wait()
			assert.NotEmpty(t, env.smtp.Messages(), "admins are notified")
		})
	}
}

// retiredDeviceRefresh sends a refresh completion for deviceID whose
// proof-of-possession signer makes over a fresh nonce and issuedAt. The challenge
// endpoint answers not found for a retired device ID, so there is no stored
// challenge to bind to.
func retiredDeviceRefresh(t *testing.T, env *guardEnv, deviceID string, signer *identity.FileKeyStore, issuedAt time.Time) *httptest.ResponseRecorder {
	t.Helper()
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	require.NoError(t, err)
	ts := issuedAt.UnixNano()
	// #nosec G115 -- ts is a positive UnixNano of a current time.
	sig, err := signer.Sign(refreshPoPMessage(nonceBytes, deviceID, uint64(ts)))
	require.NoError(t, err)
	return postComplete(env.server, deviceID, RefreshCompleteRequest{
		TenantID: cloneTenant, Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes), IssuedAt: ts,
		KeyAlgorithm: string(signer.Algorithm()), Signature: base64.RawURLEncoding.EncodeToString(sig), CSRPEM: testValidCSRPEM,
	})
}

// TestRepairGuard_RetiredDeviceWithoutProofNeverContests covers callers that know
// the retired device ID (the hash of a public key, not a secret) and the repair
// ID but do not hold the retired key: each is refused and audited, and the
// repaired steward stays trusted with no contested event and no admin notice.
func TestRepairGuard_RetiredDeviceWithoutProofNeverContests(t *testing.T) {
	attempts := []struct {
		name string
		fire func(t *testing.T, env *guardEnv, c *completedRepair) int
	}{
		{"refresh without a challenge or proof", func(t *testing.T, env *guardEnv, c *completedRepair) int {
			body, _ := json.Marshal(RefreshCompleteRequest{CSRPEM: testValidCSRPEM, TenantID: cloneTenant})
			r := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
			r = mux.SetURLVars(r, map[string]string{"device_id": c.rs.oldKS.DeviceID()})
			rec := httptest.NewRecorder()
			env.server.handleRefreshComplete(rec, r)
			return rec.Code
		}},
		{"refresh signed by another key", func(t *testing.T, env *guardEnv, c *completedRepair) int {
			other := newDeviceKey(t)
			_, _, err := other.GenerateOrLoad(context.Background())
			require.NoError(t, err)
			return retiredDeviceRefresh(t, env, c.rs.oldKS.DeviceID(), other, time.Now()).Code
		}},
		{"refresh signed by the retired key over a stale timestamp", func(t *testing.T, env *guardEnv, c *completedRepair) int {
			return retiredDeviceRefresh(t, env, c.rs.oldKS.DeviceID(), c.rs.oldKS, time.Now().Add(-2*nonceMaxAge)).Code
		}},
		{"repair retry with junk proofs and the real repair ID", func(t *testing.T, env *guardEnv, c *completedRepair) int {
			other := newDeviceKey(t)
			_, _, err := other.GenerateOrLoad(context.Background())
			require.NoError(t, err)
			junk := base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
			return c.rs.complete(c.rs.request(t, other, func(req *RefreshCompleteRequest) {
				req.OldKeyProof = junk
				req.NewKeyProof = junk
			})).Code
		}},
		{"repair retry with the old proof made by another key", func(t *testing.T, env *guardEnv, c *completedRepair) int {
			impostor := &repairSteward{env: c.rs.env, id: c.rs.id, oldKS: newDeviceKey(t), repairID: c.rs.repairID}
			_, _, err := impostor.oldKS.GenerateOrLoad(context.Background())
			require.NoError(t, err)
			req := impostor.request(t, c.rs.newKS, nil)
			// Addressed to the real retired device ID.
			return c.rs.complete(req).Code
		}},
		{"repair completion with an unknown repair ID and junk proofs", func(t *testing.T, env *guardEnv, c *completedRepair) int {
			junk := base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
			return c.rs.complete(c.rs.request(t, c.rs.newKS, func(req *RefreshCompleteRequest) {
				req.RepairID = "unknown-repair"
				req.OldKeyProof = junk
			})).Code
		}},
	}
	for _, a := range attempts {
		t.Run(a.name, func(t *testing.T) {
			env := newGuardEnv(t)
			env.withMail(t)
			c := env.completeRepair(t, "s-unproven")
			env.returnToTrusted(t, c)
			env.clock.advance(time.Hour)
			code := a.fire(t, env, c)
			assert.GreaterOrEqual(t, code, 400, "the attempt is refused")
			env.requireNotContested(t, c.rs.id, business.StewardStatusActive)
			env.server.crossingNotifyWG.Wait()
			assert.Empty(t, env.smtp.Messages(), "no admin notice")
			assert.NotEmpty(t, refreshRejections(t, env), "the refusal is audited")
		})
	}
}

// refreshRejections returns the refresh_rejected audit entries of any tenant.
func refreshRejections(t *testing.T, env *guardEnv) []*business.AuditEntry {
	t.Helper()
	require.NoError(t, env.server.auditManager.Flush(context.Background()))
	entries, err := env.server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{})
	require.NoError(t, err)
	var out []*business.AuditEntry
	for _, e := range entries {
		if e.Action == "refresh_rejected" {
			out = append(out, e)
		}
	}
	return out
}

// The repair-contested notice uses the owning MSP's sender when it is complete and
// the controller-wide sender otherwise. cloneTenant is a seam tenant, so it is its
// own owning MSP.
func TestRepairGuard_ContestedNoticeSenderFollowsOwningMSP(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mspPassword string
		wantMSP     int
		wantPlat    int
	}{
		{"complete MSP sender carries the notice", testSMTPPassword, 1, 0},
		{"MSP sender without a password falls back to platform", "", 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newGuardEnv(t)
			env.withMail(t)
			mspSMTP := newEmailTestSMTPServer(t)
			attachMSPSender(t, env.server, cloneTenant, mspSMTP, tc.mspPassword)
			c := env.completeRepair(t, "s-sender")
			env.server.ObserveAdmittedPeer(context.Background(), c.rs.id, c.newSerial)
			env.server.ObserveRevokedPeer(context.Background(), c.rs.id, c.oldSerial)
			env.requireContested(t, c.rs.id, repairContestRevokedSerial)
			env.server.crossingNotifyWG.Wait()

			assert.Len(t, mspSMTP.Messages(), tc.wantMSP)
			assert.Len(t, env.smtp.Messages(), tc.wantPlat)
		})
	}
}
