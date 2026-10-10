// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	notifif "github.com/cfgis/cfgms/pkg/notification/interfaces"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

const (
	// emailCredentialTenantID is the sentinel tenant the controller-wide SMTP
	// password is stored under; email delivery is one controller-wide capability.
	emailCredentialTenantID = "system"

	// maxEmailCredentialBody bounds the PUT credential body.
	maxEmailCredentialBody = 4 << 10

	// emailTestSendTimeout bounds one test send.
	emailTestSendTimeout = 30 * time.Second

	emailTestSubject = "CFGMS email delivery test"
	emailTestBody    = "This is a test message from your CFGMS controller. Email delivery is configured correctly."
)

// emailConfig returns the configured notifications.email block, or nil.
func (s *Server) emailConfig() *config.EmailConfig {
	if s.cfg == nil || s.cfg.Notifications == nil {
		return nil
	}
	return s.cfg.Notifications.Email
}

// readEmailCredential reads the stored SMTP password. It addresses the secret by
// its explicit (tenant, key) pair when the store supports it, so a key containing
// "/" is never ambiguous and a change made on another controller node is seen.
func (s *Server) readEmailCredential(ctx context.Context, key string) (*secretsif.Secret, error) {
	if ta, ok := s.secretStore.(secretsif.TenantSecretAccessor); ok {
		return ta.GetTenantSecret(ctx, emailCredentialTenantID, key)
	}
	return s.secretStore.GetSecret(ctx, emailCredentialTenantID+"/"+key)
}

// emailCredentialPresent reports whether a password is stored under the
// configured password_secret_key.
func (s *Server) emailCredentialPresent(ctx context.Context, ec *config.EmailConfig) bool {
	if ec == nil || ec.PasswordSecretKey == "" || s.secretStore == nil {
		return false
	}
	sec, err := s.readEmailCredential(ctx, ec.PasswordSecretKey)
	return err == nil && sec != nil && sec.Value != ""
}

// buildEmailNotifier creates the notifier from config plus the stored
// credential. It returns (nil, nil) when email is not configured or the
// credential is absent.
func (s *Server) buildEmailNotifier(ctx context.Context) (notifif.Notifier, error) {
	ec := s.emailConfig()
	if !ec.Configured() || s.secretStore == nil {
		return nil, nil
	}
	sec, err := s.readEmailCredential(ctx, ec.PasswordSecretKey)
	if err != nil || sec == nil || sec.Value == "" {
		return nil, nil
	}
	pcfg := map[string]interface{}{
		"host":     ec.Host,
		"security": ec.EffectiveTLSMode(),
		"from":     ec.From,
	}
	if ec.Port != 0 {
		pcfg["port"] = ec.Port
	}
	if ec.Username != "" {
		pcfg["username"] = ec.Username
		// The provider rejects a password without a username.
		pcfg["password"] = sec.Value
	}
	s.emailMu.RLock()
	for k, v := range s.emailExtra {
		pcfg[k] = v
	}
	s.emailMu.RUnlock()
	return notifif.CreateNotifierFromConfig(ec.EmailProvider(), pcfg)
}

// initEmailNotifier builds the notifier at startup and logs once at INFO when
// email delivery is disabled.
func (s *Server) initEmailNotifier(ctx context.Context) {
	n, err := s.buildEmailNotifier(ctx)
	if err != nil {
		s.logger.Warn("Email delivery disabled: notifier could not be built",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	if n == nil {
		s.logger.Info("Email delivery is disabled: notifications.email is not configured or its credential has not been stored")
		return
	}
	s.emailMu.Lock()
	s.emailNotifier = n
	s.emailMu.Unlock()
	s.logger.Info("Email delivery enabled", "provider", n.Name())
}

// rebuildEmailNotifier replaces the held notifier after the credential changes.
func (s *Server) rebuildEmailNotifier(ctx context.Context) error {
	n, err := s.buildEmailNotifier(ctx)
	if err != nil {
		return err
	}
	s.emailMu.Lock()
	s.emailNotifier = n
	s.emailMu.Unlock()
	return nil
}

// emailScopeAllowed reports whether the caller is root-scoped. Email delivery is
// one controller-wide capability, so a tenant-scoped caller is refused.
func emailScopeAllowed(r *http.Request) bool {
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	return scope.IsRoot() //architecture:allow-root-scope -- email delivery is one controller-wide capability with no resource tenant
}

type emailSettingsResponse struct {
	Provider          string `json:"provider"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	From              string `json:"from"`
	Username          string `json:"username"`
	TLSMode           string `json:"tls_mode"`
	PasswordSecretKey string `json:"password_secret_key"`
	Configured        bool   `json:"configured"`
	CredentialPresent bool   `json:"credential_present"`
}

// handleGetEmailSettings handles GET /api/v1/notifications/email. It returns the
// non-secret settings and never the password.
func (s *Server) handleGetEmailSettings(w http.ResponseWriter, r *http.Request) {
	if !emailScopeAllowed(r) {
		s.writeErrorResponse(w, http.StatusForbidden, "email settings require a root-scoped principal", "FORBIDDEN")
		return
	}
	ec := s.emailConfig()
	resp := emailSettingsResponse{
		Provider:          ec.EmailProvider(),
		TLSMode:           ec.EffectiveTLSMode(),
		Configured:        ec.Configured(),
		CredentialPresent: s.emailCredentialPresent(r.Context(), ec),
	}
	if ec != nil {
		resp.Host, resp.Port, resp.From = ec.Host, ec.Port, ec.From
		resp.Username, resp.PasswordSecretKey = ec.Username, ec.PasswordSecretKey
	}
	s.writeSuccessResponse(w, resp)
}

// handlePutEmailCredential handles PUT /api/v1/notifications/email/credential.
// The password is stored through the secret store and never returned or logged.
func (s *Server) handlePutEmailCredential(w http.ResponseWriter, r *http.Request) {
	if !emailScopeAllowed(r) {
		s.writeErrorResponse(w, http.StatusForbidden, "email settings require a root-scoped principal", "FORBIDDEN")
		return
	}
	ec := s.emailConfig()
	if !ec.Configured() {
		s.writeErrorResponse(w, http.StatusConflict, "email delivery is not configured", "EMAIL_NOT_CONFIGURED")
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "secret store unavailable", "SERVICE_UNAVAILABLE")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEmailCredentialBody))
	defer clear(body) // discard the raw password bytes once the store call is done
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Password == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "password is required", "INVALID_REQUEST")
		return
	}

	createdBy := "api-admin"
	if p, _ := r.Context().Value(principalContextKey).(*Principal); p != nil && p.ID != "" {
		createdBy = p.ID
	}
	err = s.secretStore.StoreSecret(r.Context(), &secretsif.SecretRequest{
		Key:         ec.PasswordSecretKey,
		Value:       req.Password,
		TenantID:    emailCredentialTenantID,
		CreatedBy:   createdBy,
		Description: "SMTP password for controller email delivery",
		Tags:        []string{"notification", "smtp"},
		Metadata:    map[string]string{secretsif.MetadataKeySecretType: string(secretsif.SecretTypePassword)},
	})
	req.Password = ""
	if err != nil {
		s.logger.Error("Failed to store email credential", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to store credential", "STORE_ERROR")
		return
	}

	if err := s.rebuildEmailNotifier(r.Context()); err != nil {
		s.logger.Error("Email credential stored but notifier could not be built",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "credential stored but email delivery could not be enabled", "NOTIFIER_ERROR")
		return
	}
	s.logger.Info("Email credential stored", "user", logging.SanitizeLogValue(createdBy))
	s.writeSuccessResponse(w, map[string]interface{}{"credential_present": true, "configured": true})
}

type emailTestRequest struct {
	To string `json:"to"`
}

type emailTestRecipient struct {
	Address  string `json:"address"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

type emailTestResponse struct {
	Delivered     bool                 `json:"delivered"`
	Recipients    []emailTestRecipient `json:"recipients"`
	FailureReason string               `json:"failure_reason,omitempty"`
}

// handleTestEmail handles POST /api/v1/notifications/email/test. It sends a
// fixed message to one validated address; the address is not stored.
func (s *Server) handleTestEmail(w http.ResponseWriter, r *http.Request) {
	if !emailScopeAllowed(r) {
		s.writeErrorResponse(w, http.StatusForbidden, "email settings require a root-scoped principal", "FORBIDDEN")
		return
	}
	var req emailTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEmailCredentialBody)).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	to := strings.TrimSpace(req.To)
	addr, err := mail.ParseAddress(to)
	if err != nil || addr.Address != to {
		s.writeErrorResponse(w, http.StatusBadRequest, "to must be a single valid email address", "INVALID_REQUEST")
		return
	}

	n := s.EmailNotifier()
	if n == nil {
		s.writeErrorResponse(w, http.StatusConflict, "email delivery is not configured or its credential has not been stored", "EMAIL_NOT_CONFIGURED")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), emailTestSendTimeout)
	defer cancel()
	res, err := n.Send(ctx, notifif.Message{To: []string{addr.Address}, Subject: emailTestSubject, Body: emailTestBody})
	resp := emailTestResponse{Recipients: []emailTestRecipient{}}
	if err != nil {
		s.logger.Warn("Email test send failed", "error", logging.SanitizeLogValue(err.Error()))
		reason := "delivery failed"
		if errors.Is(err, context.DeadlineExceeded) {
			reason = "delivery timed out"
		} else if msg := logging.SanitizeLogValue(err.Error()); msg != "" {
			reason = msg
		}
		resp.FailureReason = reason
		s.writeSuccessResponse(w, resp)
		return
	}
	for _, rr := range res.Recipients {
		resp.Recipients = append(resp.Recipients, emailTestRecipient{Address: rr.Address, Accepted: rr.Accepted, Reason: rr.Reason})
	}
	resp.Delivered = len(res.Failed()) == 0 && len(res.Recipients) > 0
	if !resp.Delivered {
		resp.FailureReason = "recipient not accepted"
	}
	s.writeSuccessResponse(w, resp)
}
