// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// Version-skew coverage (Issue #6263). Every case runs the real controller signing
// path (cpTypes.SignCommand), the wire encode/decode the gRPC transport uses, and a
// real Handler with a real verifier. An older steward is simulated by overwriting
// the proto command type with an enum value this build has no mapping for.

// unmappedWireType is a never-assigned enum value, so the receive side has no
// protoToCommandType entry for it.
const unmappedWireType = transportpb.CommandType(9999)

// unknownSigningVersion is a payload version this build does not know.
const unknownSigningVersion uint32 = 99

type skewFx struct {
	signer   signature.Signer
	h        *Handler
	store    *memCommandStore
	dispatch *atomic.Int32
}

func newSkewFx(t *testing.T) *skewFx {
	t.Helper()
	signer, verifier := newTestSignerVerifier(t)
	store := newMemCommandStore()
	h := newTestHandlerWithVerifier(t, store, verifier)
	var n atomic.Int32
	h.RegisterHandler(cpTypes.CommandSyncConfig, func(context.Context, *cpTypes.Command) error {
		n.Add(1)
		return nil
	})
	t.Cleanup(h.Wait)
	return &skewFx{signer: signer, h: h, store: store, dispatch: &n}
}

func skewCommand(id string, params map[string]interface{}) *cpTypes.Command {
	return &cpTypes.Command{
		ID:        id,
		Type:      cpTypes.CommandSyncConfig,
		StewardID: "steward-test",
		Timestamp: time.Now(),
		Params:    params,
	}
}

// wire signs cmd as the controller does, encodes it, lets mutate change the proto
// (as an older or newer peer would present it) and decodes it as the steward does.
func (fx *skewFx) wire(t *testing.T, cmd *cpTypes.Command, mutate func(pb *transportpb.Command)) *cpTypes.SignedCommand {
	t.Helper()
	sc, err := cpTypes.SignCommand(cmd, fx.signer)
	require.NoError(t, err)
	pb := grpc.SignedCommandToProto(sc)
	require.NotNil(t, pb)
	if mutate != nil {
		mutate(pb)
	}
	got := grpc.SignedCommandFromProto(pb)
	require.NotNil(t, got)
	return got
}

// requireInert asserts the refused command ran nothing, left no command record and
// did not enter the replay cache: the same ID with a supported type is accepted.
func (fx *skewFx) requireInert(t *testing.T, id string) {
	t.Helper()
	fx.h.Wait()
	assert.Zero(t, fx.dispatch.Load(), "a refused command must not be dispatched")
	_, err := fx.store.GetCommandRecord(context.Background(), id)
	assert.Error(t, err, "a refused command must leave no command record")

	retry := fx.wire(t, skewCommand(id, nil), nil)
	require.NoError(t, fx.h.HandleCommand(context.Background(), retry),
		"the refused ID must not be in the replay cache")
	fx.h.Wait()
	assert.EqualValues(t, 1, fx.dispatch.Load())
}

func TestVersionSkew_UnknownWireTypeRefusedAsUnsupported(t *testing.T) {
	fx := newSkewFx(t)
	sc := fx.wire(t, skewCommand("skew-type", nil), func(pb *transportpb.Command) { pb.Type = unmappedWireType })

	err := fx.h.HandleCommand(context.Background(), sc)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedCommandType)
	assert.NotErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.NotErrorIs(t, err, signature.ErrSignatureMismatch)

	fx.requireInert(t, "skew-type")
}

func TestVersionSkew_UnspecifiedWireTypeRefusedAsUnsupported(t *testing.T) {
	fx := newSkewFx(t)
	sc := fx.wire(t, skewCommand("skew-unspec", nil), func(pb *transportpb.Command) {
		pb.Type = transportpb.CommandType_COMMAND_TYPE_UNSPECIFIED
	})
	err := fx.h.HandleCommand(context.Background(), sc)
	assert.ErrorIs(t, err, ErrUnsupportedCommandType)
	assert.NotErrorIs(t, err, ErrUnauthenticatedCommand)
	fx.requireInert(t, "skew-unspec")
}

func TestVersionSkew_SupportedTypeWithExtraParamVerifies(t *testing.T) {
	fx := newSkewFx(t)
	sc := fx.wire(t, skewCommand("skew-extra", map[string]interface{}{"field_from_newer_controller": "1.0"}), nil)

	require.NoError(t, fx.h.HandleCommand(context.Background(), sc))
	fx.h.Wait()
	assert.EqualValues(t, 1, fx.dispatch.Load())
}

func TestVersionSkew_TamperedSupportedTypeStillSignatureMismatch(t *testing.T) {
	fx := newSkewFx(t)
	sc := fx.wire(t, skewCommand("skew-tamper", map[string]interface{}{"k": "v"}), nil)
	sc.RawParams["k"] = "changed"

	err := fx.h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.ErrorIs(t, err, signature.ErrSignatureMismatch)
	assert.NotErrorIs(t, err, ErrUnsupportedCommandType)
	fx.h.Wait()
	assert.Zero(t, fx.dispatch.Load())
}

func TestVersionSkew_StampedV1StillRefusedFirst(t *testing.T) {
	fx := newSkewFx(t)
	cmd := skewCommand("skew-v1", nil)
	cmd.Term = 3
	sc, err := cpTypes.SignCommand(cmd, fx.signer)
	require.NoError(t, err)
	// Re-sign over the v1 payload and name no version, as a pre-term-coverage controller did.
	sc.Command.SigningPayloadVersion = 0
	b, err := cpTypes.CommandSigningBytesVersion(&sc.Command, nil, cpTypes.SigningPayloadV1)
	require.NoError(t, err)
	sc.Signature, err = fx.signer.Sign(b)
	require.NoError(t, err)
	pb := grpc.SignedCommandToProto(sc)
	// An unmapped type must not change which refusal wins: the v1 check runs first.
	pb.Type = unmappedWireType
	got := grpc.SignedCommandFromProto(pb)

	err = fx.h.HandleCommand(context.Background(), got)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.NotErrorIs(t, err, ErrUnsupportedCommandType)

	// And the supported-type form is refused the same way.
	pb.Type = transportpb.CommandType_COMMAND_TYPE_SYNC_CONFIG
	err = fx.h.HandleCommand(context.Background(), grpc.SignedCommandFromProto(pb))
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	fx.h.Wait()
	assert.Zero(t, fx.dispatch.Load())
}

func TestVersionSkew_UnknownSigningPayloadVersionIsNotUnauthenticated(t *testing.T) {
	fx := newSkewFx(t)
	sc := fx.wire(t, skewCommand("skew-version", nil), func(pb *transportpb.Command) {
		pb.SigningPayloadVersion = unknownSigningVersion
	})

	err := fx.h.HandleCommand(context.Background(), sc)
	require.Error(t, err)
	assert.ErrorIs(t, err, cpTypes.ErrUnknownSigningPayloadVersion)
	assert.NotErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.NotErrorIs(t, err, signature.ErrSignatureMismatch)

	fx.requireInert(t, "skew-version")
}

// TestVersionSkew_LockedPathRefusesUnmappedTypeBeforeSignature pins that the locked
// path already refuses an unmapped wire type in stepType, before its signature step.
func TestVersionSkew_LockedPathRefusesUnmappedTypeBeforeSignature(t *testing.T) {
	fx := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{})

	sc := fx.sign(t, lockedCmd("locked-skew", cpTypes.CommandExecuteScript, map[string]interface{}{"shell": platformShell()}))
	pb := grpc.SignedCommandToProto(sc)
	pb.Type = unmappedWireType
	got := grpc.SignedCommandFromProto(pb)

	err := lh.refuseAndAssertInert(t, got)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.EqualValues(t, 1, lh.trust.RefusalCount("type_not_allowed:"),
		"refused by the type step, which precedes the signature step")
	assert.EqualValues(t, 0, lh.trust.RefusalCount("unsigned"))
}
