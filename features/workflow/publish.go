// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// PublishPermission is the permission a signer must hold, in the workflow's tenant, for a
// stored Publication to verify.
const PublishPermission = "workflow:publish"

// ErrPublicationInvalid is returned, wrapped, whenever a workflow version has no
// Publication or its Publication does not verify. Callers must treat every cause alike.
var ErrPublicationInvalid = errors.New("workflow publication is not valid")

// PublicationSigner is the signer account as the controller holds it right now. It
// verifies a stored assertion using only the credential registered to that account.
type PublicationSigner interface {
	// Enabled reports whether the account exists and is not disabled.
	Enabled() bool
	// VerifyAssertion checks the stored assertion against envelope under the account's
	// registered credential key, including origin, rpIdHash, user presence and user
	// verification. It fails when the credential is no longer registered to the account.
	VerifyAssertion(envelope operatorpayload.Envelope, p *Publication) error
}

// PublicationAccountLookup resolves the signer account by ID. It returns (nil, nil) when
// the account no longer exists.
type PublicationAccountLookup func(ctx context.Context, accountID string) (PublicationSigner, error)

// PublicationPermissionCheck reports whether the account holds permissionID in tenantID.
type PublicationPermissionCheck func(ctx context.Context, accountID, permissionID, tenantID string) bool

// PublicationEnvelope builds the envelope an admin signs to publish vw in tenantID: the
// tenant, name, version and the CURRENT canonical hash of the version, with the given
// nonce and ceremony expiry. It returns the hash alongside.
func PublicationEnvelope(tenantID string, vw *VersionedWorkflow, nonce string, expiresAt time.Time) (operatorpayload.Envelope, string, error) {
	hash, err := CanonicalWorkflowHash(vw)
	if err != nil {
		return operatorpayload.Envelope{}, "", fmt.Errorf("canonical workflow hash: %w", err)
	}
	env, err := operatorpayload.WorkflowEnvelope(operatorpayload.WorkflowVersion{
		TenantID:    tenantID,
		Name:        vw.Name,
		Version:     vw.SemanticVersion.String(),
		ContentHash: hash,
	}, nonce, expiresAt)
	if err != nil {
		return operatorpayload.Envelope{}, "", err
	}
	return env, hash, nil
}

// VerifyPublication re-verifies vw's stored Publication. It rebuilds the envelope from
// the stored nonce and expiry and the current canonical hash of vw in tenantID, then
// verifies the assertion under the signer account's registered credential. It runs at
// every evaluation, caches nothing, and applies no maximum age. It fails when the version
// has no Publication, was edited or moved to another tenant since it was signed, or the
// signer's credential, account or workflow:publish permission in tenantID is gone.
func VerifyPublication(ctx context.Context, tenantID string, vw *VersionedWorkflow, accountLookup PublicationAccountLookup, permissionCheck PublicationPermissionCheck) error {
	if vw == nil || vw.Publication == nil {
		return fmt.Errorf("%w: version is not published", ErrPublicationInvalid)
	}
	if accountLookup == nil || permissionCheck == nil {
		return fmt.Errorf("%w: verifier is not wired", ErrPublicationInvalid)
	}
	env, err := publishedEnvelope(tenantID, vw)
	if err != nil {
		return err
	}
	return verifyPublicationSigner(ctx, tenantID, env, vw.Publication, accountLookup, permissionCheck)
}

// publishedEnvelope rebuilds the envelope vw's Publication signed, from the stored nonce
// and expiry and the CURRENT canonical hash of vw in tenantID. It fails, wrapping
// ErrPublicationInvalid, when the version changed since it was published.
func publishedEnvelope(tenantID string, vw *VersionedWorkflow) (operatorpayload.Envelope, error) {
	p := vw.Publication
	env, hash, err := PublicationEnvelope(tenantID, vw, p.Nonce, p.ExpiresAt)
	if err != nil {
		return operatorpayload.Envelope{}, fmt.Errorf("%w: %v", ErrPublicationInvalid, err)
	}
	if p.ContentHash != hash {
		return operatorpayload.Envelope{}, fmt.Errorf("%w: version changed since it was published", ErrPublicationInvalid)
	}
	return env, nil
}

// verifyPublicationSigner checks the signer side of p against env: the signer account
// exists and is enabled, the stored assertion verifies under its registered credential,
// and it still holds workflow:publish in tenantID. Every failure wraps ErrPublicationInvalid.
func verifyPublicationSigner(ctx context.Context, tenantID string, env operatorpayload.Envelope, p *Publication, accountLookup PublicationAccountLookup, permissionCheck PublicationPermissionCheck) error {
	if p.SignerAccountID == "" {
		return fmt.Errorf("%w: no signer account", ErrPublicationInvalid)
	}
	signer, err := accountLookup(ctx, p.SignerAccountID)
	if err != nil {
		return fmt.Errorf("%w: signer lookup failed: %v", ErrPublicationInvalid, err)
	}
	if signer == nil || !signer.Enabled() {
		return fmt.Errorf("%w: signer account is unavailable", ErrPublicationInvalid)
	}
	if err := signer.VerifyAssertion(env, p); err != nil {
		return fmt.Errorf("%w: %v", ErrPublicationInvalid, err)
	}
	if !permissionCheck(ctx, p.SignerAccountID, PublishPermission, tenantID) {
		return fmt.Errorf("%w: signer no longer holds %s in the workflow's tenant", ErrPublicationInvalid, PublishPermission)
	}
	return nil
}
