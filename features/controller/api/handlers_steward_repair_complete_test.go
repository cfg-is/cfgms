// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

const repairTestID = "s-repair"

// repairSteward is a tampered steward with a real file-backed device key, a
// requested repair, and a second key store standing in for the key it makes.
type repairSteward struct {
	env      *repairEnv
	id       string
	oldKS    *identity.FileKeyStore
	newKS    *identity.FileKeyStore
	repairID string
	preCerts []string
}

func newRepairSteward(t *testing.T, env *repairEnv, id, level string) *repairSteward {
	t.Helper()
	old := newDeviceKey(t)
	env.addTamperedWithKey(t, id, old, level)
	rs := &repairSteward{env: env, id: id, oldKS: old, newKS: newDeviceKey(t), preCerts: env.issueClientCerts(t, id, 2)}
	_, _, err := rs.newKS.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	rs.repairID = env.requestRepair(t, id, nil).RepairID
	return rs
}

func pubBytes(t *testing.T, ks *identity.FileKeyStore) []byte {
	t.Helper()
	raw, err := identity.EncodePublicKeyBytes(ks.Algorithm(), ks.PublicKey())
	require.NoError(t, err)
	return raw
}

// request builds a completion request with both proofs over (steward ID,
// repair_id, new public key, CSR). mutate may break it.
func (rs *repairSteward) request(t *testing.T, newKS *identity.FileKeyStore, mutate func(*RefreshCompleteRequest)) RefreshCompleteRequest {
	t.Helper()
	newPub := pubBytes(t, newKS)
	digest := controlplaneTypes.RepairRotationProofDigest(rs.id, rs.repairID, newPub, testValidCSRPEM)
	oldSig, err := rs.oldKS.Sign(digest)
	require.NoError(t, err)
	newSig, err := newKS.Sign(digest)
	require.NoError(t, err)
	req := RefreshCompleteRequest{
		RepairID:            rs.repairID,
		CSRPEM:              testValidCSRPEM,
		NewIdentityKeyPub:   base64.RawURLEncoding.EncodeToString(newPub),
		NewIdentityKeyAlg:   string(newKS.Algorithm()),
		NewIdentityKeyLevel: "file",
		OldKeyProof:         base64.RawURLEncoding.EncodeToString(oldSig),
		NewKeyProof:         base64.RawURLEncoding.EncodeToString(newSig),
	}
	if mutate != nil {
		mutate(&req)
	}
	return req
}

func (rs *repairSteward) complete(req RefreshCompleteRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+rs.oldKS.DeviceID()+"/refresh/complete", bytes.NewReader(body))
	r.RemoteAddr = "192.0.2.77:40001"
	r = mux.SetURLVars(r, map[string]string{"device_id": rs.oldKS.DeviceID()})
	rec := httptest.NewRecorder()
	rs.env.server.handleRefreshComplete(rec, r)
	return rec
}

func (rs *repairSteward) record(t *testing.T) *business.StewardRecord {
	t.Helper()
	rec, err := rs.env.steward.GetSteward(context.Background(), rs.id)
	require.NoError(t, err)
	return rec
}

// requireUnchanged asserts a refused completion changed nothing.
func (rs *repairSteward) requireUnchanged(t *testing.T) {
	t.Helper()
	rec := rs.record(t)
	assert.Equal(t, business.StewardStatusTampered, rec.Status)
	assert.Equal(t, rs.oldKS.DeviceID(), rec.DeviceID, "the identity is untouched")
	assert.Equal(t, pubBytes(t, rs.oldKS), rec.IdentityKeyPub)
	for _, s := range rs.preCerts {
		revoked, err := rs.env.certMgr.IsRevoked(s)
		require.NoError(t, err)
		assert.False(t, revoked, "no serial is revoked by a refused completion")
	}
}

func TestRepairComplete_EndToEnd(t *testing.T) {
	env := newRepairEnv(t)
	rs := newRepairSteward(t, env, repairTestID, "file")
	before := rs.record(t)

	// Live old stream and a refresh queued under the old device id.
	evicted := make(chan error, 1)
	require.NoError(t, env.server.registry.Register(&registry.StewardConnection{
		StewardID: repairTestID, Sender: nopSender{}, Evict: func(err error) { evicted <- err },
	}))
	require.NoError(t, env.server.pendingRefreshStore.AddPendingRefresh(context.Background(), &business.PendingRefreshEntry{
		PendingID: "refresh-queued-old", DeviceID: rs.oldKS.DeviceID(), TenantID: cloneTenant,
		Status: business.PendingRefreshStatusPending, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}))

	rec := rs.complete(rs.request(t, rs.newKS, nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Wire struct: certificate and issuer chain only.
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	for k := range raw {
		assert.Contains(t, []string{"status", "client_cert", "issuer_chain"}, k, "unexpected response field %q", k)
	}
	for _, absent := range []string{"signing_cert", "server_cert", "ca_cert", "transport_address", "steward_id", "tenant_id", "client_key"} {
		assert.NotContains(t, raw, absent)
	}
	assert.NotEmpty(t, raw["client_cert"])

	// Identity rotated; steward ID and tenant unchanged; still tampered.
	after := rs.record(t)
	assert.Equal(t, pubBytes(t, rs.newKS), after.IdentityKeyPub)
	assert.Equal(t, rs.newKS.DeviceID(), after.DeviceID)
	assert.NotEqual(t, before.DeviceID, after.DeviceID)
	assert.Equal(t, before.ID, after.ID)
	assert.Equal(t, before.TenantID, after.TenantID)
	assert.Equal(t, business.StewardStatusTampered, after.Status, "returning to trusted is a later step")

	// Every pre-repair serial is revoked; the new one is not.
	for _, s := range rs.preCerts {
		revoked, err := env.certMgr.IsRevoked(s)
		require.NoError(t, err)
		assert.True(t, revoked, "pre-repair serial %s", s)
	}
	infos, err := env.certMgr.GetCertificateByCommonName(repairTestID)
	require.NoError(t, err)
	var fresh []string
	for _, info := range infos {
		if info.Type != cert.CertificateTypeClient {
			continue
		}
		isPre := false
		for _, s := range rs.preCerts {
			isPre = isPre || s == info.SerialNumber
		}
		if !isPre {
			fresh = append(fresh, info.SerialNumber)
		}
	}
	require.Len(t, fresh, 1, "exactly the new certificate")
	revoked, err := env.certMgr.IsRevoked(fresh[0])
	require.NoError(t, err)
	assert.False(t, revoked)

	// The live old stream is closed at once.
	select {
	case err := <-evicted:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("the live control stream was not evicted")
	}

	// A refresh queued under the old device id cannot complete: the old identity no longer resolves.
	queued, err := env.server.pendingRefreshStore.GetPendingRefreshByID(context.Background(), "refresh-queued-old")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusExpired, queued.Status)
	_, err = env.steward.GetStewardByDeviceID(context.Background(), rs.oldKS.DeviceID())
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
	body, _ := json.Marshal(RefreshChallengeRequest{TenantID: cloneTenant})
	cr := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
	cr = mux.SetURLVars(cr, map[string]string{"device_id": rs.oldKS.DeviceID()})
	cw := httptest.NewRecorder()
	env.server.handleRefreshChallenge(cw, cr)
	assert.Equal(t, http.StatusNotFound, cw.Code, "the old identity key can no longer start a refresh")

	// Tombstone for N7.
	tomb, found, err := env.server.nonceStore.GetAndConsumeNonce(context.Background(), repairRetiredKeyPrefix+rs.oldKS.DeviceID())
	require.NoError(t, err)
	require.True(t, found, "the retired-device tombstone is written")
	var entry repairRetiredEntry
	require.NoError(t, json.Unmarshal(tomb, &entry))
	assert.Equal(t, repairTestID, entry.StewardID)
	assert.Equal(t, rs.oldKS.DeviceID(), entry.OldDeviceID)
	assert.WithinDuration(t, time.Now(), entry.CompletedAt, 10*time.Second)

	// GET shows the completion and where it came from.
	st := env.repairStatus(t, repairTestID)
	assert.Equal(t, repairStateCompleted, st.State)
	assert.Equal(t, "192.0.2.77", st.CompletedFrom)
	assert.Contains(t, st.OutcomeCodes, controlplaneTypes.ReasonCodeRepairCompleted)
	assert.Len(t, env.auditActions(t, auditActionTamperRepairCompleted), 1)

	// The request cannot be used again.
	assert.False(t, env.nonceLive(t, repairTestID, rs.repairID))
}

func TestRepairComplete_Race_ExactlyOneWins(t *testing.T) {
	env := newRepairEnv(t)
	rs := newRepairSteward(t, env, repairTestID, "file")
	thief := newDeviceKey(t)
	_, _, err := thief.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	reqs := []RefreshCompleteRequest{rs.request(t, rs.newKS, nil), rs.request(t, thief, nil)}
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = rs.complete(reqs[i]).Code
		}(i)
	}
	wg.Wait()

	wins := 0
	winner := -1
	for i, c := range codes {
		if c == http.StatusOK {
			wins++
			winner = i
		}
	}
	require.Equal(t, 1, wins, "exactly one completion succeeds: %v", codes)
	keys := []*identity.FileKeyStore{rs.newKS, thief}
	rec := rs.record(t)
	assert.Equal(t, keys[winner].DeviceID(), rec.DeviceID, "the record holds the winner's key")
	assert.Equal(t, business.StewardStatusTampered, rec.Status)

	// The loser's later refresh with the old identity key is refused.
	body, _ := json.Marshal(RefreshChallengeRequest{TenantID: cloneTenant})
	cr := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
	cr = mux.SetURLVars(cr, map[string]string{"device_id": rs.oldKS.DeviceID()})
	cw := httptest.NewRecorder()
	env.server.handleRefreshChallenge(cw, cr)
	assert.Equal(t, http.StatusNotFound, cw.Code)

	// And a late completion by the loser with its own key is refused, changing nothing.
	loser := keys[1-winner]
	late := rs.complete(rs.request(t, loser, nil))
	assert.NotEqual(t, http.StatusOK, late.Code)
	assert.Equal(t, keys[winner].DeviceID(), rs.record(t).DeviceID)
}

func TestRepairComplete_GarbageProofsDoNotConsumeTheNonce(t *testing.T) {
	env := newRepairEnv(t)
	rs := newRepairSteward(t, env, repairTestID, "file")

	garbage := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64))
	for name, mutate := range map[string]func(*RefreshCompleteRequest){
		"garbage old proof": func(r *RefreshCompleteRequest) { r.OldKeyProof = garbage },
		"garbage new proof": func(r *RefreshCompleteRequest) { r.NewKeyProof = garbage },
		"both garbage":      func(r *RefreshCompleteRequest) { r.OldKeyProof, r.NewKeyProof = garbage, garbage },
	} {
		rec := rs.complete(rs.request(t, rs.newKS, mutate))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, name+": "+rec.Body.String())
		assert.True(t, env.nonceLive(t, repairTestID, rs.repairID), name+": the nonce is not burned")
		rs.requireUnchanged(t)
	}
	rec := rs.complete(rs.request(t, rs.newKS, nil))
	require.Equal(t, http.StatusOK, rec.Code, "a later valid completion still works: "+rec.Body.String())
}

func TestRepairComplete_RefusalsChangeNothing(t *testing.T) {
	stranger := newDeviceKey(t)
	_, _, err := stranger.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	cases := map[string]struct {
		level  string
		mutate func(t *testing.T, rs *repairSteward, req *RefreshCompleteRequest)
		want   int
	}{
		"missing nonce": {"file", func(_ *testing.T, rs *repairSteward, r *RefreshCompleteRequest) {
			r.RepairID = "00000000000000000000000000000000"
			rs.repairID = r.RepairID // proofs must cover the id used so only the nonce is missing
		}, http.StatusUnauthorized},
		"missing new-key proof": {"file", func(_ *testing.T, _ *repairSteward, r *RefreshCompleteRequest) { r.NewKeyProof = "" }, http.StatusBadRequest},
		"missing old-key proof": {"file", func(_ *testing.T, _ *repairSteward, r *RefreshCompleteRequest) { r.OldKeyProof = "" }, http.StatusBadRequest},
		"bad old-key proof (another key signed)": {"file", func(t *testing.T, rs *repairSteward, r *RefreshCompleteRequest) {
			digest := controlplaneTypes.RepairRotationProofDigest(rs.id, rs.repairID, pubBytes(t, rs.newKS), testValidCSRPEM)
			sig, err := stranger.Sign(digest)
			require.NoError(t, err)
			r.OldKeyProof = base64.RawURLEncoding.EncodeToString(sig)
		}, http.StatusUnauthorized},
		"proof over another CSR":       {"file", func(_ *testing.T, _ *repairSteward, r *RefreshCompleteRequest) { r.CSRPEM = testValidCSRPEM + "\n" }, http.StatusUnauthorized},
		"lower key protection level":   {"tpm", func(_ *testing.T, _ *repairSteward, r *RefreshCompleteRequest) { r.NewIdentityKeyLevel = "file" }, http.StatusBadRequest},
		"unknown key protection level": {"file", func(_ *testing.T, _ *repairSteward, r *RefreshCompleteRequest) { r.NewIdentityKeyLevel = "cloud" }, http.StatusBadRequest},
		"key not rotated": {"file", func(t *testing.T, rs *repairSteward, r *RefreshCompleteRequest) {
			*r = rs.request(t, rs.oldKS, nil)
		}, http.StatusBadRequest},
		"no CSR": {"file", func(_ *testing.T, _ *repairSteward, r *RefreshCompleteRequest) { r.CSRPEM = "" }, http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := newRepairEnv(t)
			rs := newRepairSteward(t, env, repairTestID, tc.level)
			req := rs.request(t, rs.newKS, nil)
			tc.mutate(t, rs, &req)
			rec := rs.complete(req)
			assert.Equal(t, tc.want, rec.Code, rec.Body.String())
			rs.requireUnchanged(t)
			if name != "missing nonce" {
				assert.True(t, env.nonceLive(t, repairTestID, rs.repairID), "a refused completion does not consume the nonce")
			}
		})
	}

	t.Run("a repair id issued to another steward", func(t *testing.T) {
		env := newRepairEnv(t)
		rs := newRepairSteward(t, env, repairTestID, "file")
		other := newRepairSteward(t, env, "s-repair-other", "file")
		// The proofs cover the swapped id so only the nonce ownership is wrong.
		rs.repairID = other.repairID
		rec := rs.complete(rs.request(t, rs.newKS, nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		rs.requireUnchanged(t)
		assert.True(t, env.nonceLive(t, "s-repair-other", other.repairID), "the other steward's request is untouched")
	})

	t.Run("a steward that is not tampered", func(t *testing.T) {
		env := newRepairEnv(t)
		rs := newRepairSteward(t, env, repairTestID, "file")
		ok, err := env.steward.TransitionStewardStatus(context.Background(), repairTestID, business.StewardStatusActive, business.StewardStatusTampered)
		require.NoError(t, err)
		require.True(t, ok)
		rec := rs.complete(rs.request(t, rs.newKS, nil))
		assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
		assert.Equal(t, rs.oldKS.DeviceID(), rs.record(t).DeviceID)
		assert.True(t, env.nonceLive(t, repairTestID, rs.repairID))
	})

	t.Run("a cancelled request cannot complete", func(t *testing.T) {
		env := newRepairEnv(t)
		rs := newRepairSteward(t, env, repairTestID, "file")
		env.requestRepair(t, repairTestID, nil) // cancels the first
		rec := rs.complete(rs.request(t, rs.newKS, nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		rs.requireUnchanged(t)
	})

	t.Run("an expired request cannot complete", func(t *testing.T) {
		env := newRepairEnv(t)
		rs := newRepairSteward(t, env, repairTestID, "file")
		_, _, err := env.server.nonceStore.GetAndConsumeNonce(context.Background(), repairRequestKey(repairTestID, rs.repairID))
		require.NoError(t, err)
		expired, _ := json.Marshal(repairRequestEntry{ExpiresAtUnix: time.Now().Add(-time.Minute).Unix()})
		require.NoError(t, env.server.nonceStore.PutNonce(context.Background(), repairRequestKey(repairTestID, rs.repairID), expired, time.Hour))
		rec := rs.complete(rs.request(t, rs.newKS, nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		rs.requireUnchanged(t)
	})
}

// countingPoP counts verifications so a test can prove none ran.
type countingPoP struct{ calls atomic.Int32 }

func (c *countingPoP) Verify(alg KeyAlgorithm, pub crypto.PublicKey, digest, sig []byte) bool {
	c.calls.Add(1)
	return defaultPoPVerifier{}.Verify(alg, pub, digest, sig)
}

func TestRepairComplete_RevokedStewardRefusedBeforeAnyProof(t *testing.T) {
	env := newRepairEnv(t)
	rs := newRepairSteward(t, env, repairTestID, "file")
	pop := &countingPoP{}
	env.server.popVerifier = pop
	require.Equal(t, http.StatusOK, env.post(env.server.handleBanTamperedSteward, "ban", repairTestID, cloneTenant, nil).Code)

	rec := rs.complete(rs.request(t, rs.newKS, nil))
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Zero(t, pop.calls.Load(), "no proof is verified for a revoked steward")
	assert.Equal(t, rs.oldKS.DeviceID(), rs.record(t).DeviceID)
}

func TestRepairComplete_RevokeFailureLeavesOldKeyAndTampered(t *testing.T) {
	env := newRepairEnv(t)
	rs := newRepairSteward(t, env, repairTestID, "file")

	// A directory where the revocation list is written makes every revoke fail.
	revPath := filepath.Join(env.certDir, "revocation.json")
	require.NoError(t, os.RemoveAll(revPath))
	require.NoError(t, os.Mkdir(revPath, 0o700))

	rec := rs.complete(rs.request(t, rs.newKS, nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	rec2 := rs.record(t)
	assert.Equal(t, business.StewardStatusTampered, rec2.Status, "never active")
	assert.Equal(t, rs.oldKS.DeviceID(), rec2.DeviceID, "the old key is back in place")
	assert.Equal(t, pubBytes(t, rs.oldKS), rec2.IdentityKeyPub)

	st := env.repairStatus(t, repairTestID)
	assert.Equal(t, repairStateFailed, st.State, "the repair failed and the operator asks again")
	assert.Len(t, env.auditActions(t, auditActionTamperRepairFailed), 1)
	assert.Empty(t, env.auditActions(t, auditActionTamperRepairCompleted))
}

func TestRepairComplete_RetryOfLostResponse(t *testing.T) {
	env := newRepairEnv(t)
	rs := newRepairSteward(t, env, repairTestID, "file")

	first := rs.complete(rs.request(t, rs.newKS, nil))
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())

	// Same nonce, same new key: the same result.
	retry := rs.complete(rs.request(t, rs.newKS, nil))
	require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
	assert.JSONEq(t, first.Body.String(), retry.Body.String())
	// And again: reading the stored result does not consume it.
	again := rs.complete(rs.request(t, rs.newKS, nil))
	require.Equal(t, http.StatusOK, again.Code)
	assert.JSONEq(t, first.Body.String(), again.Body.String())

	// A different new key with the same nonce is refused, changing nothing.
	other := newDeviceKey(t)
	_, _, err := other.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	refused := rs.complete(rs.request(t, other, nil))
	assert.NotEqual(t, http.StatusOK, refused.Code, refused.Body.String())
	assert.Equal(t, rs.newKS.DeviceID(), rs.record(t).DeviceID)
	// The retry still works afterwards.
	assert.Equal(t, http.StatusOK, rs.complete(rs.request(t, rs.newKS, nil)).Code)

	// Only one certificate was issued and only one completion audited.
	assert.Len(t, env.auditActions(t, auditActionTamperRepairCompleted), 1)

	// A retry whose proof is not by the recorded old key gets nothing.
	forged := rs.request(t, rs.newKS, func(r *RefreshCompleteRequest) {
		r.OldKeyProof = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 64))
	})
	assert.Equal(t, http.StatusUnauthorized, rs.complete(forged).Code)
}

func TestRepairComplete_RetryIsRefusedForRevokedSteward(t *testing.T) {
	env := newRepairEnv(t)
	rs := newRepairSteward(t, env, repairTestID, "file")
	require.Equal(t, http.StatusOK, rs.complete(rs.request(t, rs.newKS, nil)).Code)
	require.Equal(t, http.StatusOK, env.post(env.server.handleBanTamperedSteward, "ban", repairTestID, cloneTenant, nil).Code)
	rec := rs.complete(rs.request(t, rs.newKS, nil))
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRepairComplete_HardwareKeyMayStayHardware(t *testing.T) {
	env := newRepairEnv(t)
	rs := newRepairSteward(t, env, repairTestID, "tpm")
	rec := rs.complete(rs.request(t, rs.newKS, func(r *RefreshCompleteRequest) {
		r.NewIdentityKeyLevel = "secure-enclave"
		// The proofs do not cover the level.
	}))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "secure-enclave", rs.record(t).KeyProtectionLevel)
}
