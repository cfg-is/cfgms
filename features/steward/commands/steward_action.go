// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// Result codes carried in the completion event's Details["result_code"].
const (
	ActionResultOK          = "ok"
	ActionResultSelfProtect = "self_protect"
	ActionResultUnsupported = "unsupported"
	ActionResultNotFound    = "not_found"
	ActionResultFailed      = "failed"
)

// actionTargetKindService is the target kind of the service verbs.
const actionTargetKindService = "service"

// actionTargetNamePattern bounds a target name before it reaches any OS API.
var actionTargetNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,256}$`)

// actionVerb describes one entry of the closed verb allowlist.
type actionVerb struct {
	targetKind string
	serviceOp  ServiceOp
}

// stewardActionVerbs is the closed allowlist. Anything else is rejected outright.
var stewardActionVerbs = map[string]actionVerb{
	"service.start":   {targetKind: actionTargetKindService, serviceOp: ServiceOpStart},
	"service.stop":    {targetKind: actionTargetKindService, serviceOp: ServiceOpStop},
	"service.restart": {targetKind: actionTargetKindService, serviceOp: ServiceOpRestart},
}

// stewardActionParamKeys are the only keys a steward_action command may carry: the
// action itself plus the operator envelope proof. Any other key rejects the command.
var stewardActionParamKeys = map[string]bool{
	"execution_id": true, "verb": true, "target": true, "parameters": true,
	"targets": true, "nonce": true, "expires_at": true,
	"signature_algorithm": true, "signature_value": true, "signature_public_key": true,
	"webauthn_authenticator_data": true, "webauthn_client_data_json": true,
	"webauthn_signature": true, "webauthn_credential_id": true, "webauthn_manifest": true,
}

// RegisterStewardActionHandler registers the steward_action command handler on h,
// backed by the platform's in-process service controller.
func (h *Handler) RegisterStewardActionHandler() {
	h.registerStewardAction(newPlatformServiceController())
}

func (h *Handler) registerStewardAction(ctrl ServiceController) {
	h.RegisterHandler(cpTypes.CommandStewardAction, func(ctx context.Context, cmd *cpTypes.Command) error {
		return h.handleStewardAction(ctx, cmd, ctrl)
	})
}

// handleStewardAction authenticates, validates and performs one structured action.
//
// Order is fixed: the operator envelope is rebuilt from the command's own verb, target
// and parameters and verified with exactly operatorpayload.ActionShell before anything
// else; then the params are decoded strictly and checked against the allowlist; then
// the self-protect guard runs; only then is an OS call made. Rejections before the OS
// call return an error and perform nothing. Outcomes (ok, self_protect, unsupported,
// not_found, failed) are reported through EventScriptCompleted.
func (h *Handler) handleStewardAction(ctx context.Context, cmd *cpTypes.Command, ctrl ServiceController) error {
	verb, _ := cmd.Params["verb"].(string)
	kind, name, targetErr := decodeActionTarget(cmd.Params["target"])
	parameters, paramsErr := decodeActionParameters(cmd.Params["parameters"])

	// Content the operator signed is rebuilt from what this command claims. A mismatch
	// with the signed bytes fails verification.
	content, err := operatorpayload.ActionContent(operatorpayload.Action{
		Verb: verb, TargetKind: kind, TargetName: name, Parameters: parameters,
	})
	if err != nil {
		return fmt.Errorf("%w: malformed steward_action: %v", ErrUnauthenticatedCommand, err)
	}
	// The shared verifier checks expiry but not a ceiling; an action envelope may not be
	// valid for longer than ActionEnvelopeMaxTTL. Checked first so a refused envelope
	// does not consume its nonce.
	if expiresAt, perr := time.Parse(time.RFC3339, fmt.Sprint(cmd.Params["expires_at"])); perr == nil &&
		expiresAt.After(time.Now().Add(operatorpayload.ActionEnvelopeMaxTTL)) {
		return fmt.Errorf("%w: action envelope validity exceeds the maximum", ErrUnauthenticatedCommand)
	}
	if err := h.verifyOperatorEnvelope(cmd, content, operatorpayload.ActionShell); err != nil {
		h.logger.Warn("steward_action: operator envelope rejected",
			"command_id", cmd.ID,
			"error", logging.SanitizeLogValue(err.Error()))
		return err
	}

	if targetErr != nil {
		return rejectAction(h, cmd, "invalid target", targetErr)
	}
	if paramsErr != nil {
		return rejectAction(h, cmd, "invalid parameters", paramsErr)
	}
	for key := range cmd.Params {
		if !stewardActionParamKeys[key] {
			return rejectAction(h, cmd, "unexpected param", fmt.Errorf("unexpected param key %q", logging.SanitizeLogValue(key)))
		}
	}
	spec, ok := stewardActionVerbs[verb]
	if !ok {
		return rejectAction(h, cmd, "unknown verb", fmt.Errorf("verb %q is not allowed", logging.SanitizeLogValue(verb)))
	}
	if kind != spec.targetKind {
		return rejectAction(h, cmd, "wrong target kind", fmt.Errorf("verb requires target kind %s", spec.targetKind))
	}
	if !actionTargetNamePattern.MatchString(name) {
		return rejectAction(h, cmd, "invalid target name", errors.New("target name does not match the allowed pattern"))
	}
	if len(parameters) != 0 {
		return rejectAction(h, cmd, "unexpected param", errors.New("verb takes no parameters"))
	}

	executionID, _ := cmd.Params["execution_id"].(string)

	if spec.serviceOp == ServiceOpStop || spec.serviceOp == ServiceOpRestart {
		self, err := ctrl.IsStewardService(ctx, name)
		if err != nil {
			// Fail closed: if the steward cannot tell whether this is its own service it
			// must not stop it.
			h.logger.Error("steward_action: self-protect check failed",
				"command_id", cmd.ID,
				"target", logging.SanitizeLogValue(name),
				"error", logging.SanitizeLogValue(err.Error()))
			h.sendActionResult(ctx, cmd, executionID, ActionResultFailed)
			return nil
		}
		if self {
			h.logger.Warn("steward_action: refused to act on the steward's own service",
				"command_id", cmd.ID,
				"verb", logging.SanitizeLogValue(verb),
				"target", logging.SanitizeLogValue(name))
			h.sendActionResult(ctx, cmd, executionID, ActionResultSelfProtect)
			return nil
		}
	}

	code := ActionResultOK
	if err := ctrl.Control(ctx, spec.serviceOp, name); err != nil {
		switch {
		case errors.Is(err, ErrServiceUnsupported):
			code = ActionResultUnsupported
		case errors.Is(err, ErrServiceNotFound):
			code = ActionResultNotFound
		default:
			code = ActionResultFailed
		}
		h.logger.Warn("steward_action: service operation did not complete",
			"command_id", cmd.ID,
			"verb", logging.SanitizeLogValue(verb),
			"target", logging.SanitizeLogValue(name),
			"result_code", code,
			"error", logging.SanitizeLogValue(err.Error()))
	} else {
		h.logger.Info("steward_action: completed",
			"command_id", cmd.ID,
			"verb", logging.SanitizeLogValue(verb),
			"target", logging.SanitizeLogValue(name))
	}
	h.sendActionResult(ctx, cmd, executionID, code)
	return nil
}

func rejectAction(h *Handler, cmd *cpTypes.Command, reason string, err error) error {
	h.logger.Warn("steward_action: rejected",
		"command_id", cmd.ID,
		"reason", reason)
	return fmt.Errorf("steward_action: %s: %w", reason, err)
}

// sendActionResult reports the outcome through the existing EventScriptCompleted
// event, as execute_script does: exit_code is 0 for ok and 1 otherwise.
func (h *Handler) sendActionResult(ctx context.Context, cmd *cpTypes.Command, executionID, resultCode string) {
	exitCode := 1
	if resultCode == ActionResultOK {
		exitCode = 0
	}
	h.sendStatus(ctx, &cpTypes.Event{
		ID:        newEventID(),
		Type:      cpTypes.EventScriptCompleted,
		StewardID: h.stewardID,
		CommandID: cmd.ID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": executionID,
			"exit_code":    exitCode,
			"result_code":  resultCode,
		},
	})
}

// decodeActionTarget strictly decodes the target param: an object (or its JSON text)
// with exactly the string keys "kind" and "name".
func decodeActionTarget(v interface{}) (kind, name string, err error) {
	m, err := decodeStringObject(v)
	if err != nil {
		return "", "", fmt.Errorf("target: %w", err)
	}
	if len(m) != 2 {
		return "", "", errors.New("target must have exactly kind and name")
	}
	kind, okK := m["kind"]
	name, okN := m["name"]
	if !okK || !okN {
		return "", "", errors.New("target must have exactly kind and name")
	}
	return kind, name, nil
}

// decodeActionParameters strictly decodes the parameters param: an object (or its JSON
// text) whose values are all strings. Absent or empty means no parameters.
func decodeActionParameters(v interface{}) (map[string]string, error) {
	if v == nil {
		return map[string]string{}, nil
	}
	if s, ok := v.(string); ok && s == "" {
		return map[string]string{}, nil
	}
	m, err := decodeStringObject(v)
	if err != nil {
		return map[string]string{}, fmt.Errorf("parameters: %w", err)
	}
	return m, nil
}

func decodeStringObject(v interface{}) (map[string]string, error) {
	switch t := v.(type) {
	case map[string]string:
		return t, nil
	case map[string]interface{}:
		out := make(map[string]string, len(t))
		for k, val := range t {
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("value for %q is not a string", logging.SanitizeLogValue(k))
			}
			out[k] = s
		}
		return out, nil
	case string:
		var out map[string]string
		if err := json.Unmarshal([]byte(t), &out); err != nil || out == nil {
			return nil, errors.New("not a JSON object of strings")
		}
		return out, nil
	default:
		return nil, errors.New("not an object")
	}
}
