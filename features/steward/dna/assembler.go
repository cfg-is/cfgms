// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ConfidenceReporter is an optional interface that ConfigState implementations
// may implement to declare the confidence level of their Get output.
// If a ConfigState does not implement this interface, the assembler defaults
// to "high" confidence per ADR-017.
type ConfidenceReporter interface {
	Confidence() string
}

// Assembler builds the DNA fragment set for a steward by resolving module authority
// and merging observe-only host-fact fragments. It implements ADR-017 §2's authority
// resolver algorithm with the Option-1 substitution and ADR-020 §3's required-fields
// union check at assembly time.
type Assembler struct {
	logger logging.Logger
}

// NewAssembler creates a new DNA assembler.
func NewAssembler(logger logging.Logger) *Assembler {
	return &Assembler{logger: logger}
}

// Assemble builds the complete DNA fragment set by:
//
//  1. Resolving module authority per ADR-017 §2: for each kind in ownership whose
//     module is active, the module's Get is called to produce the fragment.
//  2. Detecting authority conflicts (ADR-016 clause 5): two modules declaring the
//     same kind is a configuration error — that kind is logged and skipped, never
//     merged or silently resolved.
//  3. Applying ADR-020 §3's required-fields check: a module Get output missing a
//     declared required field causes fail-closed rejection of that fragment.
//  4. Merging hostFactFragments (already canonicalized/hashed by #2910) for any
//     kind not claimed by an active module. Module authority always preempts
//     observe-only data, including for conflicted kinds.
//
// Self-authority only: this method has no parameter through which a caller could
// name a foreign host or entity as authority — a structural exclusion per Issue #2905
// (ADR-016 clause 5, "self-authority only — a hard PO ruling").
//
// The returned envelopes cover only module-owned fragments; the caller is responsible
// for merging host-fact envelopes produced by PartitionHostFacts.
func (a *Assembler) Assemble(
	ctx context.Context,
	activeModules map[string]modules.Module,
	ownership map[string][]modules.OwnershipDeclaration,
	hostFactFragments []*commonpb.Fragment,
) ([]*commonpb.Fragment, map[string]*commonpb.FragmentEnvelope, error) {
	observedAt := time.Now()

	// Phase 1: Resolve kind→module assignment, detecting authority conflicts.
	//
	// ADR-016 clause 5: if two modules claim the same kind, that is a configuration
	// error. The kind is logged and skipped — never merged or silently resolved.
	kindToModule := make(map[string]string)                     // kind → owning module name
	conflictKinds := make(map[string]bool)                      // kinds with ≥2 claimants
	kindToDecl := make(map[string]modules.OwnershipDeclaration) // kind → its decl (for required fields)

	for moduleName, decls := range ownership {
		for _, decl := range decls {
			if conflictKinds[decl.Kind] {
				a.logger.Error("authority conflict: additional module also claims this kind",
					"kind", decl.Kind, "module", moduleName)
				continue
			}
			if existing, claimed := kindToModule[decl.Kind]; claimed {
				a.logger.Error("authority conflict: two modules own the same kind — kind will be skipped",
					"kind", decl.Kind, "module_1", existing, "module_2", moduleName)
				conflictKinds[decl.Kind] = true
				delete(kindToModule, decl.Kind)
				delete(kindToDecl, decl.Kind)
				continue
			}
			kindToModule[decl.Kind] = moduleName
			kindToDecl[decl.Kind] = decl
		}
	}

	// Phase 2: Assemble one fragment per non-conflicted, active-module-owned kind.
	var fragments []*commonpb.Fragment
	envelopes := make(map[string]*commonpb.FragmentEnvelope)

	for kind, moduleName := range kindToModule {
		mod, ok := activeModules[moduleName]
		if !ok {
			a.logger.Warn("ownership declared for module not found in active set",
				"module", moduleName, "kind", kind)
			continue
		}

		frag, env, built := a.buildModuleFragment(ctx, moduleName, kindToDecl[kind], mod, observedAt)
		if !built {
			continue
		}
		fragments = append(fragments, frag)
		envelopes[kind] = env
	}

	// Phase 3: Merge observe-only host-fact fragments for kinds no module claims.
	//
	// Both conflicted and successfully-resolved module-owned kinds preempt gather data
	// (ADR-016 clause 5 atomicity: a claimed kind is NEVER dual-sourced, even on conflict).
	ownedKinds := make(map[string]bool, len(kindToModule)+len(conflictKinds))
	for kind := range kindToModule {
		ownedKinds[kind] = true
	}
	for kind := range conflictKinds {
		ownedKinds[kind] = true
	}

	for _, frag := range hostFactFragments {
		if ownedKinds[frag.FragmentId] {
			a.logger.Debug("dropping host-fact fragment: kind is claimed by a module",
				"kind", frag.FragmentId)
			continue
		}
		fragments = append(fragments, frag)
	}

	return fragments, envelopes, nil
}

// buildModuleFragment calls Get on the module, applies ADR-020 §3 required-fields
// validation, canonicalizes (S2), and hashes (S3). Returns (nil, nil, false) on any
// failure; the failure is already logged.
func (a *Assembler) buildModuleFragment(
	ctx context.Context,
	moduleName string,
	decl modules.OwnershipDeclaration,
	mod modules.Module,
	observedAt time.Time,
) (*commonpb.Fragment, *commonpb.FragmentEnvelope, bool) {
	state, err := mod.Get(ctx, decl.Kind)
	if err != nil {
		// Log a bounded, taint-free error category rather than the module's raw
		// error string. mod.Get is a polymorphic call across out-of-process
		// module binaries; CodeQL go/clear-text-logging (CWE-312) unions every
		// Module.Get implementation and treats their returned errors as
		// potentially carrying a sensitive-named field value (heuristic
		// naming / field-insensitivity FPs — see moduleGetErrorCategory). The
		// raw error string is not the assembler's to surface across that trust
		// boundary anyway; each module logs its own error detail via its
		// injected logger.
		a.logger.Error("module Get returned error — fragment skipped",
			"module", moduleName, "kind", decl.Kind, "error_category", moduleGetErrorCategory(err))
		return nil, nil, false
	}

	if !a.checkRequiredFields(moduleName, decl, state) {
		return nil, nil, false
	}

	canonical, err := CanonicalizeFragment(decl.Kind, moduleName, state)
	if err != nil {
		a.logger.Error("CanonicalizeFragment failed — fragment skipped",
			"module", moduleName, "kind", decl.Kind, "error", err)
		return nil, nil, false
	}

	hash := FragmentHash(canonical)

	confidence := "high"
	if cr, ok := state.(ConfidenceReporter); ok {
		if c := cr.Confidence(); c != "" {
			confidence = c
		}
	}

	frag := &commonpb.Fragment{
		FragmentId:     decl.Kind,
		Authority:      moduleName,
		CanonicalBytes: canonical,
		FragmentHash:   hash,
	}
	env := &commonpb.FragmentEnvelope{
		Source:     "module:" + moduleName,
		ObservedAt: timestamppb.New(observedAt),
		Confidence: confidence,
	}
	return frag, env, true
}

// moduleGetErrorCategory maps a Module.Get error onto a bounded, taint-free
// category label for logging. It exists to satisfy two constraints at once:
//
//  1. Diagnosability: ops needs to know why a fragment was skipped without
//     grepping every module's own logs.
//  2. No clear-text logging (CWE-312): Module.Get is a polymorphic boundary
//     across out-of-process module binaries. CodeQL's go/clear-text-logging
//     unions every Module.Get implementation and treats their returned errors
//     as potentially carrying a sensitive-named field value — e.g. the linux
//     user executor formats its /etc/passwd path (field passwdFile) into read
//     errors, and the hyperv module carries *SecretKey handle references. Those
//     are naming / field-insensitivity false positives, but the raw error text
//     is still not the assembler's to surface across that trust boundary. This
//     function returns only string constants selected by errors.Is checks, so
//     no data flows from the error's message text into the log sink.
func moduleGetErrorCategory(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline-exceeded"
	case errors.Is(err, modules.ErrNotImplemented):
		return "not-implemented"
	case errors.Is(err, modules.ErrUnsupportedPlatform):
		return "unsupported-platform"
	case errors.Is(err, modules.ErrInvalidResourceID):
		return "invalid-resource-id"
	case errors.Is(err, modules.ErrInvalidInput):
		return "invalid-input"
	default:
		return "module-error"
	}
}

// checkRequiredFields verifies that every key in decl.RequiredFields is present
// and non-empty in state.AsMap(). Returns false and logs on the first violation
// (ADR-020 §3 fail-closed: the entire fragment is rejected, not just the field).
func (a *Assembler) checkRequiredFields(
	moduleName string,
	decl modules.OwnershipDeclaration,
	state modules.ConfigState,
) bool {
	if len(decl.RequiredFields) == 0 {
		return true
	}
	stateMap := state.AsMap()
	for _, field := range decl.RequiredFields {
		v, present := stateMap[field]
		if !present || v == nil {
			a.logger.Error("required field absent in module Get output — fragment rejected (ADR-020 §3)",
				"module", moduleName, "kind", decl.Kind, "field", field)
			return false
		}
		if s, ok := v.(string); ok && s == "" {
			a.logger.Error("required field empty in module Get output — fragment rejected (ADR-020 §3)",
				"module", moduleName, "kind", decl.Kind, "field", field)
			return false
		}
	}
	return true
}
