// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ContentDecisionState is the outcome of a content approval evaluation.
type ContentDecisionState string

const (
	// ContentDecisionApproved means the version may run under a grant.
	ContentDecisionApproved ContentDecisionState = "approved"
	// ContentDecisionPending means the version may run once an approval exists.
	ContentDecisionPending ContentDecisionState = "pending"
	// ContentDecisionDenied means the version must not run, whatever approvals
	// exist: the evidence is bad or the decision could not be made.
	ContentDecisionDenied ContentDecisionState = "denied"
)

// ApprovalMethodComment is the Method of a decision made by the comment mode.
// It is not a stored approval method: no record carries it, so it is
// deliberately absent from ApprovalMethod.Valid.
const ApprovalMethodComment ApprovalMethod = "comment"

// privilegeNamespace is where handlers_scripts.go keeps ScriptPrivilegeMetadata.
const privilegeNamespace = "script-privilege"

// Decision is the result of ContentApprovalEvaluator.Evaluate. ApprovalHash is
// the value to bind a queue pin to; it is set whenever it could be computed.
type Decision struct {
	State        ContentDecisionState
	Reason       string
	ContentHash  string
	ApprovalHash string
	Method       ApprovalMethod
	OwnerTenant  string
}

// ScriptTrustedKeyResolver returns the trusted signing keys in effect for a
// tenant: the entries of its effective script_signing.trusted_keys that name a
// thumbprint, or none when the tenant does not trust keys. An error means the
// keys could not be determined.
type ScriptTrustedKeyResolver func(ctx context.Context, tenantID string) ([]script.TrustedKeyEntry, error)

// NewConfigServiceTrustedKeyResolver resolves a tenant's trusted keys through
// the configuration service's inheritance cascade, the same one that builds the
// configuration a steward enforces. The read is controller-internal work (the
// decision needs the owner tenant's keys whoever asked), so it runs in a system
// context; the keys never leave the evaluator.
func NewConfigServiceTrustedKeyResolver(cs *service.ConfigurationServiceV2) ScriptTrustedKeyResolver {
	return func(ctx context.Context, tenantID string) ([]script.TrustedKeyEntry, error) {
		if cs == nil {
			return nil, errors.New("configuration service is not available")
		}
		effective, err := cs.GetEffectiveConfiguration(ctxkeys.WithSystem(ctx), tenantID, "")
		if err != nil {
			return nil, fmt.Errorf("resolve effective configuration: %w", err)
		}
		if effective == nil || effective.Config == nil {
			return nil, nil
		}
		return trustedKeyEntries(effective.Config.Steward.ScriptSigning), nil
	}
}

// trustedKeyEntries converts a tenant's script_signing into the allowlist the
// verifier consults. A tenant has trusted keys only in trusted_keys and
// trusted_keys_and_public mode, and only entries that name a thumbprint count.
// any_valid, an unset mode and an unknown mode yield none, and AllowPublicCA is
// ignored: neither can approve anything here.
func trustedKeyEntries(cfg stewardtypes.ScriptSigningConfig) []script.TrustedKeyEntry {
	if cfg.TrustMode != stewardtypes.TrustModeTrustedKeys && cfg.TrustMode != stewardtypes.TrustModeTrustedKeysAndPublic {
		return nil
	}
	var out []script.TrustedKeyEntry
	for _, k := range cfg.TrustedKeys {
		if k.Thumbprint == "" {
			continue
		}
		out = append(out, script.TrustedKeyEntry{Name: k.Name, Thumbprint: k.Thumbprint})
	}
	return out
}

// ContentApprovalEvaluator decides whether one resolved script version may run
// under a grant. Evaluate is side-effect free.
type ContentApprovalEvaluator struct {
	store     *ContentApprovalStore
	keys      ScriptTrustedKeyResolver
	privilege cfgconfig.ConfigStore
}

// NewContentApprovalEvaluator builds an evaluator over the approval store, a
// trusted key resolver and the store that holds script privilege metadata.
func NewContentApprovalEvaluator(store *ContentApprovalStore, keys ScriptTrustedKeyResolver, privilege cfgconfig.ConfigStore) (*ContentApprovalEvaluator, error) {
	if store == nil || keys == nil || privilege == nil {
		return nil, errors.New("content approval evaluator: approval store, key resolver and privilege store are required")
	}
	return &ContentApprovalEvaluator{store: store, keys: keys, privilege: privilege}, nil
}

// Evaluate decides whether vs, resolved from ownerTenant's library, may run for
// runTenant. The mode, approvals and trusted keys are the owner's. It never
// resolves a version itself and never writes or sends anything.
//
// Every infrastructure failure returns a denied Decision together with the
// error; a caller must treat either as "do not run".
func (e *ContentApprovalEvaluator) Evaluate(ctx context.Context, runTenant string, vs *script.VersionedScript, ownerTenant string) (Decision, error) {
	d := Decision{State: ContentDecisionDenied, OwnerTenant: ownerTenant}
	if reason := checkEvaluationInput(runTenant, vs, ownerTenant); reason != "" {
		d.Reason = reason
		return d, errors.New("content approval evaluator: " + reason)
	}
	d.ContentHash = vs.Hash
	d.ApprovalHash = script.ScriptApprovalHash(ownerTenant, vs)

	sum := sha256.Sum256([]byte(vs.Content))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(strings.ToLower(vs.Hash))) != 1 {
		d.Reason = "stored content hash does not match the content"
		return d, nil
	}
	if denied, err := e.checkPrivilege(ctx, &d, ownerTenant, vs.Metadata.ID); denied {
		return d, err
	}
	mode, err := e.store.GetMode(ctx, ownerTenant, LibraryKindScript)
	if err != nil {
		return failClosed(d, "library approval mode could not be read", err)
	}
	requested, perr := script.ParsePreapprovalRequest(vs.Content, vs.Metadata.Shell)
	if perr != nil {
		d.Reason = "script header is not valid: " + perr.Error()
		return d, nil
	}
	if !requested {
		d.State, d.Reason = ContentDecisionPending, "script header does not request pre-approval for automation"
		return d, nil
	}

	switch mode {
	case ApprovalModeComment:
		d.State, d.Method, d.Reason = ContentDecisionApproved, ApprovalMethodComment, "script header requests pre-approval and the library mode is comment"
		return d, nil
	case ApprovalModeApprove:
		return e.evaluateApprove(ctx, d, vs)
	case ApprovalModeSigned:
		return e.evaluateSigned(ctx, d, runTenant, vs)
	}
	d.Reason = "library approval mode is not recognised"
	return d, nil
}

// checkEvaluationInput returns why the call cannot be evaluated, or "".
func checkEvaluationInput(runTenant string, vs *script.VersionedScript, ownerTenant string) string {
	switch {
	case runTenant == "":
		return "run tenant is required"
	case ownerTenant == "":
		return "owner tenant is required"
	case vs == nil || vs.Metadata == nil || vs.Metadata.Version == nil || vs.Metadata.ID == "":
		return "a resolved script version is required"
	}
	return ""
}

// failClosed returns d denied with a reason and the cause as an error. The
// error text is for the caller's logs; the reason carries no backend detail.
func failClosed(d Decision, reason string, cause error) (Decision, error) {
	d.State, d.Reason = ContentDecisionDenied, reason
	return d, fmt.Errorf("content approval evaluator: %s: %w", reason, cause)
}

// checkPrivilege denies a script whose privilege metadata names API scopes:
// automation never runs such a script. It reports whether d is now final.
func (e *ContentApprovalEvaluator) checkPrivilege(ctx context.Context, d *Decision, ownerTenant, scriptID string) (bool, error) {
	entry, err := e.privilege.GetConfig(ctx, &cfgconfig.ConfigKey{TenantID: ownerTenant, Namespace: privilegeNamespace, Name: scriptID})
	if errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return false, nil
	}
	if err != nil {
		*d, err = failClosed(*d, "script privilege metadata could not be read", err)
		return true, err
	}
	var meta ScriptPrivilegeMetadata
	if err := json.Unmarshal(entry.Data, &meta); err != nil {
		*d, err = failClosed(*d, "script privilege metadata could not be decoded", err)
		return true, err
	}
	if len(meta.RequiredAPIScope) > 0 {
		d.Reason = "script requires API scopes and is not available to automation"
		return true, nil
	}
	return false, nil
}

// evaluateApprove approves only on an approval record bound to the approval hash.
func (e *ContentApprovalEvaluator) evaluateApprove(ctx context.Context, d Decision, vs *script.VersionedScript) (Decision, error) {
	state, rec, hash, err := e.store.evaluateScriptApproval(ctx, d.OwnerTenant, vs)
	if err != nil {
		return failClosed(d, "approval record could not be read", err)
	}
	d.ApprovalHash = hash
	if state != ScriptApprovalApproved {
		d.State, d.Reason = ContentDecisionPending, "no approval exists for this exact version and content"
		return d, nil
	}
	d.State, d.Method, d.Reason = ContentDecisionApproved, rec.Method, "an approval is recorded for this exact version and content"
	return d, nil
}

// evaluateSigned approves a verified signature by a trusted key. A tenant with
// no trusted keys, or a version with no detached signature, falls back to the
// approve logic. A signature that is present and does not verify is denied.
func (e *ContentApprovalEvaluator) evaluateSigned(ctx context.Context, d Decision, runTenant string, vs *script.VersionedScript) (Decision, error) {
	ownerKeys, err := e.keys(ctx, d.OwnerTenant)
	if err != nil {
		return failClosed(d, "trusted keys of the owner tenant could not be resolved", err)
	}
	if len(ownerKeys) == 0 || !hasDetachedMaterial(vs.Signature) {
		return e.evaluateApprove(ctx, d, vs)
	}
	if err := verifyUnderKeys(vs, ownerKeys); err != nil {
		d.Reason = "signature does not verify under the trusted keys of the owner tenant"
		return d, nil
	}
	if runTenant != d.OwnerTenant {
		runKeys, err := e.keys(ctx, runTenant)
		if err != nil {
			return failClosed(d, "trusted keys of the run tenant could not be resolved", err)
		}
		if len(runKeys) > 0 {
			if err := verifyUnderKeys(vs, runKeys); err != nil {
				d.Reason = "signature does not verify under the trusted keys of the run tenant"
				return d, nil
			}
		}
	}
	d.State, d.Method, d.Reason = ContentDecisionApproved, ApprovalMethodSignature, "signature verifies under the trusted keys"
	return d, nil
}

// hasDetachedMaterial reports whether sig carries the algorithm, signature and
// public key a detached signature needs. A signature without them is unsigned.
func hasDetachedMaterial(sig *script.ScriptSignature) bool {
	return sig != nil && sig.Algorithm != "" && sig.Signature != "" && sig.PublicKey != ""
}

// verifyUnderKeys verifies the script's signature over its content against a
// trusted key allowlist. Trust mode is always trusted_keys, never any_valid.
// Only detached material reaches the verifier, so the Authenticode path of a
// Windows controller is never taken. Nothing is cached.
func verifyUnderKeys(vs *script.VersionedScript, keys []script.TrustedKeyEntry) error {
	return script.VerifyScriptSignature([]byte(vs.Content), vs.Signature, vs.Metadata.Shell, script.ModuleSigningConfig{
		TrustMode:   script.TrustModeTrustedKeys,
		TrustedKeys: keys,
	})
}
