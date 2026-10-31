// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package credentials

import (
	"context"
	"errors"
	"time"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// issueAttempts bounds the read/decide/write loop when concurrent issuers keep
// changing the record under it.
const issueAttempts = 5

// BindingNamespace is the config-store namespace in which the account-creation
// path records that a resource's directory account exists (its GUID binding).
const BindingNamespace = "credential-bindings"

// BindingChecker reports whether a resource has a GUID binding, i.e. whether
// the account the password was issued for exists.
type BindingChecker interface {
	HasBinding(ctx context.Context, key Key) (bool, error)
}

// ConfigBindingChecker reads bindings from the config store: one entry per
// (steward, resource) under BindingNamespace, written by the account-creation
// path once the directory account has a GUID.
type ConfigBindingChecker struct{ Store cfgconfig.ConfigStore }

// HasBinding implements BindingChecker. Any read error other than "not found"
// is returned so the caller fails closed.
func (c ConfigBindingChecker) HasBinding(ctx context.Context, key Key) (bool, error) {
	if c.Store == nil {
		return false, errors.New("binding store unavailable")
	}
	_, err := c.Store.GetConfig(ctx, &cfgconfig.ConfigKey{TenantID: key.TenantID, Namespace: BindingNamespace, Name: nameFor(key)})
	if err == nil {
		return true, nil
	}
	if errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return false, nil
	}
	return false, errors.New("binding read failed")
}

// BindingConfigKey returns the config key a binding for key is stored under, for
// the account-creation path to write.
func BindingConfigKey(key Key) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: key.TenantID, Namespace: BindingNamespace, Name: nameFor(key)}
}

// AuditRecorder records audit events. *audit.Manager satisfies it.
type AuditRecorder interface {
	RecordEvent(ctx context.Context, event *audit.AuditEventBuilder) error
}

// Service issues and expires initial credentials over a CredentialStore.
type Service struct {
	store    CredentialStore
	bindings BindingChecker
	audit    AuditRecorder
	logger   logging.Logger
	ttl      time.Duration
	now      func() time.Time
}

// ServiceOption customises NewService.
type ServiceOption func(*Service)

// WithTTL sets the credential lifetime (default DefaultTTL).
func WithTTL(ttl time.Duration) ServiceOption {
	return func(s *Service) {
		if ttl > 0 {
			s.ttl = ttl
		}
	}
}

// WithServiceClock overrides the clock (tests).
func WithServiceClock(now func() time.Time) ServiceOption { return func(s *Service) { s.now = now } }

// WithAudit sets the audit recorder.
func WithAudit(a AuditRecorder) ServiceOption { return func(s *Service) { s.audit = a } }

// NewService constructs the service. bindings is required: without it the
// service cannot tell a created account from a failed create and would refuse
// every re-issue or, worse, allow one.
func NewService(store CredentialStore, bindings BindingChecker, logger logging.Logger, opts ...ServiceOption) (*Service, error) {
	if store == nil || bindings == nil || logger == nil {
		return nil, errors.New("credential service requires a store, a binding checker and a logger")
	}
	s := &Service{store: store, bindings: bindings, logger: logger, ttl: DefaultTTL, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Store returns the CredentialStore the service issues from, for the reveal API.
func (s *Service) Store() CredentialStore { return s.store }

// Issue returns the initial password for key, generating it the first time.
//
//   - none yet, or expired: a new password is issued;
//   - pending: the same password is returned again;
//   - revealed (or being revealed) with a GUID binding: ErrAlreadyIssued;
//   - revealed without a binding (the create failed after reveal): the old record
//     is voided, a new password is issued and the re-issue is audited.
//
// The caller has already authenticated the steward and checked that the
// resource is declared in that steward's own configuration.
func (s *Service) Issue(ctx context.Context, key Key) (string, error) {
	if err := key.Validate(); err != nil {
		return "", err
	}
	for attempt := 0; attempt < issueAttempts; attempt++ {
		cred, err := s.store.Get(ctx, key)
		var replaces *Record
		reissue := false
		switch {
		case errors.Is(err, ErrNotFound):
		case err != nil:
			return "", err
		case cred.StewardID != key.StewardID || cred.TenantID != key.TenantID:
			return "", errors.New("credential record owner mismatch")
		default:
			now := s.now()
			switch cred.State {
			case StateRevealing:
				return "", ErrAlreadyIssued
			case StateRevealed:
				bound, berr := s.bindings.HasBinding(ctx, key)
				if berr != nil {
					return "", berr
				}
				if bound {
					return "", ErrAlreadyIssued
				}
				reissue = true
			case StatePending:
				if now.Before(cred.ExpiresAt) && cred.Password != "" {
					return cred.Password, nil
				}
				if !now.Before(cred.ExpiresAt) {
					s.auditUnrevealedExpiry(ctx, &cred.Record)
				}
			}
			replaces = &cred.Record
		}

		if err := s.checkCaps(ctx, key, replaces); err != nil {
			return "", err
		}
		password, err := GeneratePassword()
		if err != nil {
			return "", err
		}
		id, err := NewRecordID()
		if err != nil {
			return "", err
		}
		now := s.now()
		rec := &Record{
			ID: id, TenantID: key.TenantID, StewardID: key.StewardID, ResourceID: key.ResourceID,
			CreatedAt: now, ExpiresAt: now.Add(s.ttl), State: StatePending,
		}
		err = s.store.Put(ctx, rec, password, replaces)
		if errors.Is(err, ErrExists) || errors.Is(err, ErrConflict) {
			continue // a concurrent issuer won; read its record
		}
		if err != nil {
			return "", err
		}
		if reissue {
			s.auditEvent(ctx, key, "credential_reissued", replaces.ID, rec.ID,
				"initial credential re-issued: previous record was revealed but the account has no GUID binding")
		}
		return password, nil
	}
	return "", errors.New("credential issue contended too long")
}

// Discard removes key's record and password. The account-creation path calls it
// when the directory definitely rejected the create, so no account exists with
// that password.
func (s *Service) Discard(ctx context.Context, key Key) error {
	if err := key.Validate(); err != nil {
		return err
	}
	return s.store.Delete(ctx, key)
}

// checkCaps rejects the issue when it would exceed the pending caps. Replacing a
// pending record does not add to the count.
func (s *Service) checkCaps(ctx context.Context, key Key, replaces *Record) error {
	pending, err := s.store.List(ctx, Filter{TenantID: key.TenantID, State: StatePending})
	if err != nil {
		return err
	}
	tenantN, stewardN := 0, 0
	for _, r := range pending {
		if replaces != nil && r.ID == replaces.ID {
			continue
		}
		tenantN++
		if r.StewardID == key.StewardID {
			stewardN++
		}
	}
	if tenantN >= MaxPendingPerTenant || stewardN >= MaxPendingPerSteward {
		return ErrCapExceeded
	}
	return nil
}

// Sweep expires records past their expiry and deletes their secrets. A pending
// or revealing record that expires un-revealed is audited: its account may then
// exist with a password nobody knows. A revealed record keeps its record (it is
// what refuses a second issue) and loses only its secret.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	records, err := s.store.List(ctx, Filter{})
	if err != nil {
		return 0, err
	}
	now := s.now()
	expired := 0
	var firstErr error
	for _, rec := range records {
		if now.Before(rec.ExpiresAt) || rec.State == StateExpired {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		switch rec.State {
		case StatePending, StateRevealing:
			if _, err := s.store.Claim(ctx, rec.Key(), rec.ID, rec.State, StateExpired); err != nil {
				if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) && firstErr == nil {
					firstErr = err
				}
				continue
			}
			if err := s.store.DeleteSecret(ctx, rec); err != nil && firstErr == nil {
				firstErr = err
			}
			s.auditUnrevealedExpiry(ctx, rec)
			expired++
		case StateRevealed:
			if err := s.store.DeleteSecret(ctx, rec); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return expired, firstErr
}

func (s *Service) auditUnrevealedExpiry(ctx context.Context, rec *Record) {
	s.auditEvent(ctx, rec.Key(), "credential_expired_unrevealed", rec.ID, "",
		"initial credential expired without being revealed; the account may exist with an unknown password")
}

// auditEvent records ids and the reason only — never a password.
func (s *Service) auditEvent(ctx context.Context, key Key, action, recordID, newID, description string) {
	if s.audit == nil {
		return
	}
	ev := audit.NewEventBuilder().
		Tenant(key.TenantID).
		Type(business.AuditEventSecurityEvent).
		Action(action).
		User(key.StewardID, business.AuditUserTypeSystem).
		Resource("initial_credential", key.ResourceID, "").
		Detail("description", description).
		Detail("steward_id", key.StewardID).
		Detail("credential_id", recordID).
		Severity(business.AuditSeverityMedium)
	if newID != "" {
		ev = ev.Detail("new_credential_id", newID)
	}
	if err := s.audit.RecordEvent(ctx, ev); err != nil {
		s.logger.Warn("credential audit event not recorded",
			"action", action, "error", logging.SanitizeLogValue(err.Error()))
	}
}
