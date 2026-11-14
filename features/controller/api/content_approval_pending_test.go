// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/session"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	pendingScriptID = "nightly"
	pendingRunTen   = "msp-a"
	pendingOwnerTo  = "owner-admin@acme-corp.example"
	pendingRunTo    = "run-admin@acme-corp.example"
	pendingCanary   = "CANARY-SECRET-hunter2-9f3a"
	pendingHeader   = "#!/bin/bash\n# cfgms-preapproved: automation\n"
)

// pendingFixture is a real owner-tenant script library in approve mode, a real
// evaluator over the same store, and an in-process SMTP sink behind the notifier.
type pendingFixture struct {
	*scriptApprovalFixture
	smtp  *emailTestSMTPServer
	eval  *ContentApprovalEvaluator
	minor int
}

func newPendingFixture(t *testing.T) *pendingFixture {
	t.Helper()
	f := &pendingFixture{scriptApprovalFixture: newScriptApprovalFixture(t)}
	seedTenantTree(t, f.server)
	f.smtp = newEmailTestSMTPServer(t)
	attachEmail(t, f.server, f.smtp)
	setTenantContacts(t, f.server, f.owner, pendingOwnerTo)
	setTenantContacts(t, f.server, pendingRunTen, pendingRunTo)
	require.NoError(t, f.store.SetMode(context.Background(), f.owner, LibraryKindScript, ApprovalModeApprove, "admin"))

	var err error
	f.eval, err = NewContentApprovalEvaluator(f.store,
		func(context.Context, string) ([]script.TrustedKeyEntry, error) { return nil, nil },
		f.store.store)
	require.NoError(t, err)
	return f
}

func setTenantContacts(t *testing.T, server *Server, tenantID string, addrs ...string) {
	t.Helper()
	_, err := server.tenantManager.SetAdminContacts(context.Background(), tenantID, addrs)
	require.NoError(t, err)
}

// publish stores the next version of the nightly script with body as content and
// returns it as resolved. The first call creates the script; later calls add a version.
func (f *pendingFixture) publish(t *testing.T, body string) *script.VersionedScript {
	t.Helper()
	gr, err := f.repo.ForTenant(f.owner)
	require.NoError(t, err)
	vs := &script.VersionedScript{
		Metadata: &script.ScriptMetadata{ID: pendingScriptID, Name: pendingScriptID, Version: &script.Version{Major: 1, Minor: f.minor},
			Shell: script.ShellBash, Platform: []string{"linux"}},
		Content: pendingHeader + body,
	}
	if f.minor == 0 {
		require.NoError(t, gr.Create(vs))
	} else {
		require.NoError(t, gr.Update(vs))
	}
	f.minor++
	got, err := f.repo.GetForTenant(f.owner, pendingScriptID, vs.Metadata.Version.String())
	require.NoError(t, err)
	return got
}

func (f *pendingFixture) approveStored(t *testing.T, vs *script.VersionedScript) {
	t.Helper()
	require.NoError(t, f.store.PutApproval(context.Background(), ContentApproval{
		TenantID: f.owner, Kind: LibraryKindScript, ContentID: vs.Metadata.ID, Version: vs.Metadata.Version.String(),
		ContentHash: script.ScriptApprovalHash(f.owner, vs), ApprovedBy: "admin", Method: ApprovalMethodApproveTap,
	}))
}

func (f *pendingFixture) evaluate(t *testing.T, vs *script.VersionedScript) Decision {
	t.Helper()
	d, err := f.eval.Evaluate(context.Background(), pendingRunTen, vs, f.owner)
	require.NoError(t, err)
	return d
}

// recordOn evaluates vs and hands the decision to server's RecordPendingAndNotify,
// then waits for the notification goroutine.
func (f *pendingFixture) recordOn(t *testing.T, server *Server, vs *script.VersionedScript) Decision {
	t.Helper()
	d := f.evaluate(t, vs)
	require.NoError(t, server.RecordPendingAndNotify(context.Background(), f.owner, vs, d))
	server.crossingNotifyWG.Wait()
	return d
}

// mailText returns a delivered message with its quoted-printable body decoded, so
// assertions read what the recipient reads and not soft line breaks.
func mailText(t *testing.T, raw string) string {
	t.Helper()
	header, body, ok := strings.Cut(raw, "\r\n\r\n")
	require.True(t, ok, "message has a header block")
	dec, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	require.NoError(t, err)
	return header + "\r\n\r\n" + string(dec)
}

func (f *pendingFixture) mails(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, m := range f.smtp.Messages() {
		out = append(out, mailText(t, m))
	}
	return out
}

func (f *pendingFixture) record(t *testing.T, vs *script.VersionedScript) Decision {
	t.Helper()
	return f.recordOn(t, f.server, vs)
}

func (f *pendingFixture) pending(t *testing.T) []*PendingChange {
	t.Helper()
	out, err := f.store.ListPending(context.Background(), f.owner)
	require.NoError(t, err)
	return out
}

func (f *pendingFixture) tapApprove(t *testing.T, vs *script.VersionedScript) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(ApproveScriptRequest{ScriptID: vs.Metadata.ID, Version: vs.Metadata.Version.String(),
		ApprovalHash: script.ScriptApprovalHash(f.owner, vs)})
	return f.tappedApprove(t, string(b), string(b))
}

func (f *pendingFixture) callList(t *testing.T, tenantID string) []PendingScriptChange {
	t.Helper()
	p := &Principal{Channel: AuthChannelMTLS, ID: "admin-of-" + tenantID, TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	req := withPrincipal(httptest.NewRequest(http.MethodGet, pendingPath, nil), p)
	rec := httptest.NewRecorder()
	f.server.handleListPendingScriptChanges(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data PendingScriptChangeList `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data.Changes
}

const pendingPath = approvalsPath + "/pending"

// seedChanged approves 1.0.0 and publishes a changed 1.1.0, returning both.
func (f *pendingFixture) seedChanged(t *testing.T) (old, changed *script.VersionedScript) {
	t.Helper()
	old = f.publish(t, "echo one\n")
	f.approveStored(t, old)
	changed = f.publish(t, "echo two\n")
	return old, changed
}

// [AC] First evaluation of a changed hash creates exactly one record and one email,
// however many times it is evaluated; the run stays refused.
func TestRecordPending_ChangedHashOneRecordOneEmail(t *testing.T) {
	f := newPendingFixture(t)
	old, changed := f.seedChanged(t)

	for i := 0; i < 4; i++ {
		d := f.record(t, changed)
		assert.Equal(t, ContentDecisionPending, d.State)
		assert.True(t, d.AwaitingApproval)
	}

	recs := f.pending(t)
	require.Len(t, recs, 1)
	assert.Equal(t, f.owner, recs[0].TenantID)
	assert.Equal(t, pendingScriptID, recs[0].ScriptID)
	assert.Equal(t, "1.1.0", recs[0].Version)
	assert.Equal(t, script.ScriptApprovalHash(f.owner, changed), recs[0].ApprovalHash)
	assert.Equal(t, "1.0.0", recs[0].PreviousVersion)
	assert.Equal(t, script.ScriptApprovalHash(f.owner, old), recs[0].PreviousApprovalHash)
	assert.False(t, recs[0].FirstSeen.IsZero())

	msgs := f.mails(t)
	require.Len(t, msgs, 1, "one new hash is announced exactly once")
	assert.Contains(t, msgs[0], pendingScriptID)
	assert.Contains(t, msgs[0], recs[0].ApprovalHash)
	assert.Contains(t, msgs[0], recs[0].PreviousApprovalHash)
	assert.Contains(t, msgs[0], "https://localhost:8080/")

	assert.Equal(t, ContentDecisionPending, f.evaluate(t, changed).State, "the run stays refused until approved")
}

// A version with no earlier approval is a first approval, not a change.
func TestRecordPending_NoPriorApprovalCreatesNothing(t *testing.T) {
	f := newPendingFixture(t)
	first := f.publish(t, "echo one\n")
	f.record(t, first)
	assert.Empty(t, f.pending(t))
	assert.Empty(t, f.smtp.Messages())
}

// A decision that is not an approve-logic pending, or does not match the version, is not recorded.
func TestRecordPending_RejectsUnsuitableDecisions(t *testing.T) {
	f := newPendingFixture(t)
	_, changed := f.seedChanged(t)
	ctx := context.Background()
	good := f.evaluate(t, changed)

	approved := good
	approved.State = ContentDecisionApproved
	denied := good
	denied.State = ContentDecisionDenied
	notAwaiting := good
	notAwaiting.AwaitingApproval = false
	for name, d := range map[string]Decision{"approved": approved, "denied": denied, "not awaiting approval": notAwaiting} {
		assert.NoError(t, f.server.RecordPendingAndNotify(ctx, f.owner, changed, d), name)
	}
	f.server.crossingNotifyWG.Wait()
	assert.Empty(t, f.pending(t))
	assert.Empty(t, f.smtp.Messages())

	wrongOwner := good
	wrongOwner.OwnerTenant = "someone-else"
	assert.Error(t, f.server.RecordPendingAndNotify(ctx, f.owner, changed, wrongOwner))
	wrongHash := good
	wrongHash.ApprovalHash = "not-the-hash"
	assert.Error(t, f.server.RecordPendingAndNotify(ctx, f.owner, changed, wrongHash))
	assert.Error(t, f.server.RecordPendingAndNotify(ctx, "", changed, good))
	assert.Error(t, f.server.RecordPendingAndNotify(ctx, f.owner, nil, good))
	assert.Empty(t, f.pending(t))

	// A decision that went stale because the version was approved meanwhile records nothing.
	f.approveStored(t, changed)
	assert.NoError(t, f.server.RecordPendingAndNotify(ctx, f.owner, changed, good))
	f.server.crossingNotifyWG.Wait()
	assert.Empty(t, f.pending(t))
	assert.Empty(t, f.smtp.Messages())

	f.server.contentApprovalStore = nil
	assert.Error(t, f.server.RecordPendingAndNotify(ctx, f.owner, changed, good), "unwired store fails closed")
}

// [REQUIRED TEST] After the #5839 approval of the new hash the evaluator returns
// approved and the pending record is cleared.
func TestApproveScript_ClearsPendingAndEvaluatorApproves(t *testing.T) {
	f := newPendingFixture(t)
	_, changed := f.seedChanged(t)
	f.record(t, changed)
	require.Len(t, f.pending(t), 1)

	rec := f.tapApprove(t, changed)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	d := f.evaluate(t, changed)
	assert.Equal(t, ContentDecisionApproved, d.State)
	assert.Empty(t, f.pending(t), "approval clears the pending record")

	// A second record call after approval changes nothing.
	f.record(t, changed)
	assert.Empty(t, f.pending(t))
	assert.Len(t, f.smtp.Messages(), 1)
}

// [REQUIRED TEST] The previous approval does not carry over to changed content, and
// approving the new hash does not carry over to the next change.
func TestPending_PreviousApprovalDoesNotCarryOver(t *testing.T) {
	f := newPendingFixture(t)
	old, changed := f.seedChanged(t)

	assert.Equal(t, ContentDecisionApproved, f.evaluate(t, old).State, "the old approval stands for the old content")
	d := f.evaluate(t, changed)
	assert.Equal(t, ContentDecisionPending, d.State, "the old approval does not approve the changed content")
	assert.NotEqual(t, script.ScriptApprovalHash(f.owner, old), d.ApprovalHash)

	got, err := f.store.GetApproval(context.Background(), f.owner, LibraryKindScript, pendingScriptID, "1.1.0", script.ScriptApprovalHash(f.owner, old))
	require.NoError(t, err)
	assert.Nil(t, got, "the old hash is not an approval of the new version")

	require.Equal(t, http.StatusCreated, f.tapApprove(t, changed).Code)
	next := f.publish(t, "echo three\n")
	assert.Equal(t, ContentDecisionPending, f.evaluate(t, next).State, "approving 1.1.0 does not approve 1.2.0")
	assert.Equal(t, ContentDecisionApproved, f.evaluate(t, old).State, "pinning the previous version still runs it")
}

// [AC] A delivery failure, or no notifier at all, leaves the record and the refusal.
func TestRecordPending_DeliveryFailureStillRefusesAndRecords(t *testing.T) {
	t.Run("recipient rejected", func(t *testing.T) {
		f := newPendingFixture(t)
		f.smtp.rejectRcpt = true
		_, changed := f.seedChanged(t)
		d := f.record(t, changed)
		assert.Equal(t, ContentDecisionPending, d.State)
		assert.Len(t, f.pending(t), 1)
		assert.Equal(t, ContentDecisionPending, f.evaluate(t, changed).State)
		assert.Empty(t, f.smtp.Messages())
	})
	t.Run("no notifier", func(t *testing.T) {
		f := newPendingFixture(t)
		f.server.emailMu.Lock()
		f.server.emailNotifier = nil
		f.server.emailMu.Unlock()
		_, changed := f.seedChanged(t)
		f.record(t, changed)
		assert.Len(t, f.pending(t), 1)
		assert.Equal(t, ContentDecisionPending, f.evaluate(t, changed).State)
	})
	t.Run("no contacts", func(t *testing.T) {
		f := newPendingFixture(t)
		setTenantContacts(t, f.server, f.owner)
		_, changed := f.seedChanged(t)
		f.record(t, changed)
		assert.Len(t, f.pending(t), 1)
		assert.Empty(t, f.smtp.Messages())
	})
}

// [AC] The owner tenant's admins are mailed, not the run tenant's.
func TestRecordPending_MailsOwnerAdminsNotRunTenantAdmins(t *testing.T) {
	f := newPendingFixture(t)
	_, changed := f.seedChanged(t)
	d := f.record(t, changed)
	require.Equal(t, f.owner, d.OwnerTenant)
	require.NotEqual(t, f.owner, pendingRunTen)

	msgs := f.mails(t)
	require.Len(t, msgs, 1)
	assert.Contains(t, msgs[0], pendingOwnerTo)
	assert.NotContains(t, msgs[0], pendingRunTo, "a run-tenant-only admin is not mailed")
}

// [REQUIRED TEST] The composed email contains none of the script content.
func TestRecordPending_EmailCarriesNoScriptContent(t *testing.T) {
	f := newPendingFixture(t)
	old := f.publish(t, "export TOKEN="+pendingCanary+"-old\necho one\n")
	f.approveStored(t, old)
	changed := f.publish(t, "export TOKEN="+pendingCanary+"-new\necho two\n")
	f.record(t, changed)

	msgs := f.mails(t)
	require.Len(t, msgs, 1)
	assert.NotContains(t, msgs[0], pendingCanary)
	assert.NotContains(t, msgs[0], "echo two")
	assert.NotContains(t, msgs[0], "echo one")
	assert.NotContains(t, msgs[0], "cfgms-preapproved")

	// The composer itself, called directly, with the script text as the only variable.
	changes := f.pending(t)
	require.Len(t, changes, 1)
	msg := f.server.composePendingChangeEmail(changes[0], []string{pendingOwnerTo})
	assert.NotContains(t, msg.Subject+msg.Body, pendingCanary)
	assert.NotContains(t, msg.Subject+msg.Body, "echo")
}

// [REQUIRED TEST] CRLF in a script id cannot inject a header or a body line break.
func TestRecordPending_CRLFInIdentifiersCannotInjectHeader(t *testing.T) {
	evil := "x\r\nBcc: attacker@evil.example\r\nX-Injected: 1"
	f := newPendingFixture(t)
	pc := &PendingChange{TenantID: f.owner, ScriptID: evil, Version: "1.0.0\r\nBcc: v@evil.example",
		ApprovalHash: "h1\nX-H: 1", PreviousVersion: "0.9.0\r\nX-P: 1", PreviousApprovalHash: "h0\rX-Q: 1", FirstSeen: time.Now()}

	msg := f.server.composePendingChangeEmail(pc, []string{pendingOwnerTo})
	assert.NotContains(t, msg.Subject, "\r")
	assert.NotContains(t, msg.Subject, "\n")
	for _, line := range strings.Split(msg.Body, "\n") {
		assert.False(t, strings.HasPrefix(line, "Bcc:"), "body line %q injects a header-like line", line)
		assert.False(t, strings.HasPrefix(line, "X-"), "body line %q injects a header-like line", line)
	}
	assert.NotContains(t, msg.Body, "\r")

	// And over the wire: no header line of the delivered message was injected.
	require.NoError(t, f.store.PutApproval(context.Background(), ContentApproval{TenantID: f.owner, Kind: LibraryKindScript,
		ContentID: evil, Version: "0.9.0", ContentHash: "prior-hash", ApprovedBy: "admin", Method: ApprovalMethodApproveTap}))
	vs := &script.VersionedScript{
		Metadata: &script.ScriptMetadata{ID: evil, Version: &script.Version{Major: 1}, Shell: script.ShellBash},
		Content:  "echo x\n", Hash: "irrelevant",
	}
	d := Decision{State: ContentDecisionPending, AwaitingApproval: true, OwnerTenant: f.owner, ApprovalHash: script.ScriptApprovalHash(f.owner, vs)}
	require.NoError(t, f.server.RecordPendingAndNotify(context.Background(), f.owner, vs, d))
	f.server.crossingNotifyWG.Wait()
	msgs := f.mails(t)
	require.Len(t, msgs, 1)
	header, _, _ := strings.Cut(msgs[0], "\r\n\r\n")
	for _, line := range strings.Split(header, "\r\n") {
		assert.False(t, strings.HasPrefix(strings.ToLower(line), "bcc:"), "injected header %q", line)
		assert.False(t, strings.HasPrefix(strings.ToLower(line), "x-injected:"), "injected header %q", line)
	}
}

// [REQUIRED TEST] Many new hashes produce at most the capped number of records and
// emails per window, then one summary notice; a later window starts afresh.
func TestRecordPending_FloodIsBoundedAndSummarised(t *testing.T) {
	f := newPendingFixture(t)
	old := f.publish(t, "echo base\n")
	f.approveStored(t, old)

	total := pendingChangeCap + 4
	for i := 0; i < total; i++ {
		vs := f.publish(t, fmt.Sprintf("echo change %d\n", i))
		f.record(t, vs)
		f.record(t, vs)
	}
	assert.Len(t, f.pending(t), pendingChangeCap)
	msgs := f.mails(t)
	require.Len(t, msgs, pendingChangeCap+1, "the capped notices plus exactly one summary")
	summaries := 0
	for _, m := range msgs {
		if strings.Contains(m, "summary") {
			summaries++
			assert.NotContains(t, m, pendingScriptID, "the summary names no script")
		}
	}
	assert.Equal(t, 1, summaries)

	// Refused either way.
	last := f.publish(t, "echo last\n")
	assert.Equal(t, ContentDecisionPending, f.evaluate(t, last).State)

	// A new window counts again.
	base := time.Now().UTC()
	f.store.now = func() time.Time { return base.Add(pendingChangeWindow + time.Minute) }
	f.record(t, last)
	assert.Len(t, f.pending(t), pendingChangeCap+1)
	assert.Len(t, f.smtp.Messages(), pendingChangeCap+2)
}

// [REQUIRED TEST] Two server instances on one store send exactly one email for one
// new hash.
func TestRecordPending_TwoServersOneStoreSendOneEmail(t *testing.T) {
	f := newPendingFixture(t)
	second := setupTestServer(t)
	seedTenantTree(t, second)
	second.SetScriptRepository(f.repo)
	second.SetContentApprovalStore(f.store)
	attachEmail(t, second, f.smtp)
	setTenantContacts(t, second, f.owner, pendingOwnerTo)

	_, changed := f.seedChanged(t)
	d := f.evaluate(t, changed)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		srv := f.server
		if i%2 == 1 {
			srv = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, srv.RecordPendingAndNotify(context.Background(), f.owner, changed, d))
		}()
	}
	wg.Wait()
	f.server.crossingNotifyWG.Wait()
	second.crossingNotifyWG.Wait()

	assert.Len(t, f.pending(t), 1)
	assert.Len(t, f.smtp.Messages(), 1, "the durable record decides which caller mails")
}

// [AC] The pending list returns only the caller tenant's records, and the diff only
// to a caller of the owner tenant.
func TestListPending_OwnerTenantOnlyWithDiff(t *testing.T) {
	f := newPendingFixture(t)
	_, changed := f.seedChanged(t)
	f.record(t, changed)

	got := f.callList(t, f.owner)
	require.Len(t, got, 1)
	assert.Equal(t, pendingScriptID, got[0].ScriptID)
	assert.Equal(t, "1.1.0", got[0].Version)
	assert.Equal(t, "1.0.0", got[0].PreviousVersion)
	assert.Contains(t, got[0].Diff, "-echo one")
	assert.Contains(t, got[0].Diff, "+echo two")
	assert.Contains(t, got[0].Diff, "--- "+pendingScriptID+" 1.0.0")
	assert.Contains(t, got[0].Diff, "+++ "+pendingScriptID+" 1.1.0")

	for _, other := range []string{pendingRunTen, "client-1", "msp-b"} {
		assert.Empty(t, f.callList(t, other), "tenant %s must see none of the owner's records or diffs", other)
	}
}

// The diff is only given for previous content that still matches what was approved.
func TestListPending_DiffWithheldWhenPreviousContentNoLongerMatchesApproval(t *testing.T) {
	f := newPendingFixture(t)
	_, changed := f.seedChanged(t)
	f.record(t, changed)

	recs := f.pending(t)
	require.Len(t, recs, 1)
	recs[0].PreviousApprovalHash = "approval-hash-of-other-content"
	data, err := json.Marshal(recs[0])
	require.NoError(t, err)
	require.NoError(t, f.store.store.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key:  pendingKey(f.owner, recs[0].ScriptID, recs[0].Version, recs[0].ApprovalHash),
		Data: data, Format: cfgconfig.ConfigFormatJSON,
	}))

	got := f.callList(t, f.owner)
	require.Len(t, got, 1)
	assert.Empty(t, got[0].Diff)
	assert.NotEmpty(t, got[0].DiffUnavailable)
}

// The list hides a record whose hash has since been approved, even if clearing failed.
func TestListPending_HidesAlreadyApprovedRecord(t *testing.T) {
	f := newPendingFixture(t)
	_, changed := f.seedChanged(t)
	f.record(t, changed)
	f.approveStored(t, changed)
	assert.Len(t, f.pending(t), 1, "the record is still stored")
	assert.Empty(t, f.callList(t, f.owner))
}

// [REQUIRED TEST] Listing pending changes and evaluating a script never create a
// record or send mail.
func TestListPendingAndEvaluate_NeverRecordOrMail(t *testing.T) {
	f := newPendingFixture(t)
	_, changed := f.seedChanged(t)

	for i := 0; i < 3; i++ {
		d := f.evaluate(t, changed)
		assert.Equal(t, ContentDecisionPending, d.State)
		assert.True(t, d.AwaitingApproval)
		assert.Empty(t, f.callList(t, f.owner))
		rec := f.serve(f.adminRequest(t, http.MethodGet, approvalsPath, ""))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		rec = f.serve(f.adminRequest(t, http.MethodGet, pendingPath, ""))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	}
	f.server.crossingNotifyWG.Wait()
	assert.Empty(t, f.pending(t))
	assert.Empty(t, f.smtp.Messages())
}

func TestListPendingRoute_RequiresReadPermission(t *testing.T) {
	f := newPendingFixture(t)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, pendingPath, nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "an unauthenticated caller is refused")

	key := NewEphemeralTestKey(t, f.server, []string{"tenant:read"}, f.owner, 5*time.Minute)
	req := httptest.NewRequest(http.MethodGet, pendingPath, nil)
	req.Header.Set("X-API-Key", key)
	rec = httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "without automation-approval:read")
}

func TestListPending_UnavailableWithoutStore(t *testing.T) {
	f := newPendingFixture(t)
	f.server.contentApprovalStore = nil
	req := withPrincipal(httptest.NewRequest(http.MethodGet, pendingPath, nil),
		&Principal{Channel: AuthChannelMTLS, ID: "a", TenantID: f.owner, ImplicitAdmin: true})
	rec := httptest.NewRecorder()
	f.server.handleListPendingScriptChanges(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestUnifiedDiff(t *testing.T) {
	cases := []struct {
		name, a, b string
		want       []string
		notWant    []string
	}{
		{"identical", "a\nb\n", "a\nb\n", nil, []string{"@@"}},
		{"line changed", "a\nb\nc\n", "a\nX\nc\n", []string{"--- old", "+++ new", "@@ -1,3 +1,3 @@", " a", "-b", "+X", " c"}, nil},
		{"line added", "a\nc\n", "a\nb\nc\n", []string{"+b", " a", " c"}, []string{"-a", "-c"}},
		{"line removed", "a\nb\nc\n", "a\nc\n", []string{"-b"}, []string{"\n+a", "\n+c"}},
		{"from empty", "", "a\n", []string{"+a"}, nil},
		{"to empty", "a\n", "", []string{"-a"}, nil},
		{"crlf normalised", "a\r\nb\r\n", "a\nb\n", nil, []string{"@@"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := unifiedDiff("old", "new", c.a, c.b)
			for _, w := range c.want {
				assert.Contains(t, got, w)
			}
			for _, n := range c.notWant {
				assert.NotContains(t, got, n)
			}
		})
	}
}

func TestUnifiedDiff_FarApartChangesMakeSeparateHunks(t *testing.T) {
	var a, b []string
	for i := 0; i < 40; i++ {
		a = append(a, fmt.Sprintf("line %d", i))
		b = append(b, fmt.Sprintf("line %d", i))
	}
	b[2], b[37] = "changed early", "changed late"
	got := unifiedDiff("o", "n", strings.Join(a, "\n")+"\n", strings.Join(b, "\n")+"\n")
	assert.Equal(t, 2, strings.Count(got, "@@ -"), got)
	assert.NotContains(t, got, " line 20\n", "distant unchanged lines are not shown")
}

func TestUnifiedDiff_HugeInputStillProducesBoundedDiff(t *testing.T) {
	a := strings.Repeat("alpha\n", 6000)
	b := strings.Repeat("beta\n", 6000)
	got := unifiedDiff("o", "n", a, b)
	assert.Contains(t, got, "-alpha")
	assert.Contains(t, got, "+beta")
}

// A script whose header does not request pre-approval is pending for another
// reason; it is not an approval awaiting a tap and records nothing.
func TestRecordPending_ScriptNotRequestingPreapprovalRecordsNothing(t *testing.T) {
	f := newPendingFixture(t)
	old := f.publish(t, "echo one\n")
	f.approveStored(t, old)

	gr, err := f.repo.ForTenant(f.owner)
	require.NoError(t, err)
	require.NoError(t, gr.Update(&script.VersionedScript{
		Metadata: &script.ScriptMetadata{ID: pendingScriptID, Name: pendingScriptID, Version: &script.Version{Major: 1, Minor: 1},
			Shell: script.ShellBash, Platform: []string{"linux"}},
		Content: "#!/bin/bash\necho no request\n",
	}))
	silent, err := f.repo.GetForTenant(f.owner, pendingScriptID, "1.1.0")
	require.NoError(t, err)

	d := f.record(t, silent)
	assert.Equal(t, ContentDecisionPending, d.State)
	assert.False(t, d.AwaitingApproval)
	assert.Empty(t, f.pending(t))
	assert.Empty(t, f.smtp.Messages())
}

// [AC] The pending-script-change notice uses the owning MSP's sender when it is
// complete and the controller-wide sender otherwise.
func TestRecordPending_NoticeSenderFollowsOwningMSP(t *testing.T) {
	const ownerUnderMSP = "client-1" // owned by msp-a
	cases := []struct {
		name        string
		mspPassword string // "" leaves the MSP sender without a password
		wantMSP     int
		wantPlat    int
	}{
		{"complete MSP sender carries the notice", testSMTPPassword, 1, 0},
		{"MSP sender without a password falls back to platform", "", 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPendingFixture(t)
			f.owner = ownerUnderMSP
			require.NoError(t, f.store.SetMode(context.Background(), f.owner, LibraryKindScript, ApprovalModeApprove, "admin"))
			setTenantContacts(t, f.server, f.owner, pendingOwnerTo)
			mspSMTP := newEmailTestSMTPServer(t)
			attachMSPSender(t, f.server, pendingRunTen, mspSMTP, tc.mspPassword)

			_, changed := f.seedChanged(t)
			f.record(t, changed)

			assert.Len(t, mspSMTP.Messages(), tc.wantMSP)
			assert.Len(t, f.smtp.Messages(), tc.wantPlat)
		})
	}
}
