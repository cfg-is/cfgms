// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func publishSample() *VersionedWorkflow {
	return &VersionedWorkflow{
		Workflow:        Workflow{Name: "wf", Version: "1.0.0", Steps: []Step{{Name: "s1", Type: StepTypeTask}}},
		SemanticVersion: SemanticVersion{Major: 1},
	}
}

func noAccount(context.Context, string) (PublicationSigner, error) { return nil, nil }

func allowAll(context.Context, string, string, string) bool { return true }

func TestPublicationEnvelope_BindsTenantVersionAndContent(t *testing.T) {
	exp := time.Unix(1_800_000_000, 0).UTC()
	vw := publishSample()
	base, hash, err := PublicationEnvelope("tenant-a", vw, "n", exp)
	require.NoError(t, err)
	assert.Equal(t, []string{"tenant-a"}, base.Targets)

	again, hash2, err := PublicationEnvelope("tenant-a", vw, "n", exp)
	require.NoError(t, err)
	assert.Equal(t, base, again)
	assert.Equal(t, hash, hash2)

	other, _, err := PublicationEnvelope("tenant-b", vw, "n", exp)
	require.NoError(t, err)
	assert.NotEqual(t, base.Targets, other.Targets)
	assert.NotEqual(t, base.Content, other.Content)

	vw.Steps[0].Name = "edited"
	edited, hash3, err := PublicationEnvelope("tenant-a", vw, "n", exp)
	require.NoError(t, err)
	assert.NotEqual(t, hash, hash3)
	assert.NotEqual(t, base.Content, edited.Content)
}

func TestVerifyPublication_Refusals(t *testing.T) {
	ctx := context.Background()
	vw := publishSample()

	err := VerifyPublication(ctx, "tenant-a", vw, noAccount, allowAll)
	assert.ErrorIs(t, err, ErrPublicationInvalid, "an unpublished version is refused")

	exp := time.Unix(1_800_000_000, 0).UTC()
	_, hash, err := PublicationEnvelope("tenant-a", vw, "n", exp)
	require.NoError(t, err)
	vw.Publication = &Publication{ContentHash: hash, Nonce: "n", ExpiresAt: exp, SignerAccountID: "acct"}

	err = VerifyPublication(ctx, "tenant-a", vw, noAccount, allowAll)
	assert.ErrorIs(t, err, ErrPublicationInvalid, "a signer account that no longer exists is refused")

	err = VerifyPublication(ctx, "tenant-a", vw, nil, nil)
	assert.ErrorIs(t, err, ErrPublicationInvalid, "an unwired verifier fails closed")

	vw.Steps[0].Name = "edited"
	err = VerifyPublication(ctx, "tenant-a", vw, noAccount, allowAll)
	assert.ErrorIs(t, err, ErrPublicationInvalid, "an edited version is refused")
}

func TestPublication_SurvivesStorageRoundTripAndDoesNotChangeTheHash(t *testing.T) {
	vw := publishSample()
	before, err := CanonicalWorkflowHash(vw)
	require.NoError(t, err)

	vw.Publication = &Publication{
		ContentHash: before, Nonce: "n", ExpiresAt: time.Unix(1_800_000_000, 0).UTC(),
		CredentialID: "c", AuthenticatorData: "a", ClientDataJSON: "d", Signature: "s",
		SignerAccountID: "acct", SignedAt: time.Unix(1_800_000_100, 0).UTC(),
	}
	after, err := CanonicalWorkflowHash(vw)
	require.NoError(t, err)
	assert.Equal(t, before, after, "the Publication is not part of the form it signs")

	data, err := yaml.Marshal(vw)
	require.NoError(t, err)
	var back VersionedWorkflow
	require.NoError(t, yaml.Unmarshal(data, &back))
	require.NotNil(t, back.Publication)
	assert.True(t, vw.Publication.ExpiresAt.Equal(back.Publication.ExpiresAt))
	assert.Equal(t, vw.Publication.Signature, back.Publication.Signature)
}
