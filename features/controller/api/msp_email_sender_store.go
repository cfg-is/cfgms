// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/config"
	notifif "github.com/cfgis/cfgms/pkg/notification/interfaces"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// Config-store location and secret key owned by the MSP email sender. The record
// lives under the MSP tenant id in the msp-email-sender namespace; the password
// lives in the secret store under the same tenant. MSPEmailSenderStore is the only
// writer of the namespace: no route and no sync path may store into it, so no
// generic config path can replace the host while keeping the stored password (see
// TestMSPEmailSenderNamespaceOnlyStoreWrites).
const (
	mspEmailSenderNamespace = "msp-email-sender"
	mspEmailSenderName      = "sender"

	// mspEmailPasswordKey is the secret key of the MSP sender's SMTP password.
	mspEmailPasswordKey = "notifications.email.password"

	mspEmailMaxFromLen     = 254
	mspEmailMaxUsernameLen = 256
	mspEmailMaxPasswordLen = 1024
)

// mspEmailAllowedPorts are the only SMTP ports an MSP-supplied host may be dialled
// on, so a writable host cannot be aimed at arbitrary services. This is narrower
// than the controller-wide sender on purpose. It is a variable only so a test can
// point it at an in-process SMTP server; production code never assigns it.
var mspEmailAllowedPorts = []int{465, 587}

// MSPEmailSender is the non-secret part of an MSP tenant's email sender. The
// password is never part of it.
type MSPEmailSender struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	TLSMode  string `json:"tls_mode"`
	From     string `json:"from"`
	Username string `json:"username"`
}

// mspEmailSenderRecord is the stored form of the sender.
type mspEmailSenderRecord struct {
	MSPEmailSender
	UpdatedAt time.Time `json:"updated_at"`
}

// MSPEmailSenderStore persists one email sender per MSP tenant over a durable
// config store. It holds only the non-secret settings; the password is kept in
// the secret store by the password methods in this file.
type MSPEmailSenderStore struct {
	store cfgconfig.ConfigStore
	now   func() time.Time
}

// NewMSPEmailSenderStore builds a store over cs, which must be a durable provider.
func NewMSPEmailSenderStore(cs cfgconfig.ConfigStore) (*MSPEmailSenderStore, error) {
	if cs == nil {
		return nil, errors.New("msp email sender store: config store is required")
	}
	return &MSPEmailSenderStore{store: cs, now: func() time.Time { return time.Now().UTC() }}, nil
}

func mspEmailSenderKey(mspID string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: mspID, Namespace: mspEmailSenderNamespace, Name: mspEmailSenderName}
}

// Get returns the MSP's sender, or nil when none is stored. A read error or an
// undecodable record is an error and never reads as "no sender".
func (s *MSPEmailSenderStore) Get(ctx context.Context, mspID string) (*MSPEmailSender, error) {
	if mspID == "" {
		return nil, errors.New("msp email sender store: msp tenant id is required")
	}
	entry, err := s.store.GetConfig(ctx, mspEmailSenderKey(mspID))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("msp email sender store: read sender: %w", err)
	}
	var rec mspEmailSenderRecord
	if err := json.Unmarshal(entry.Data, &rec); err != nil {
		return nil, fmt.Errorf("msp email sender store: decode sender: %w", err)
	}
	sender := rec.MSPEmailSender
	return &sender, nil
}

// Put validates and stores the sender, replacing any earlier one, and returns the
// stored value (an empty TLS mode is stored as starttls). It does not touch the
// password. It is the only writer of the namespace.
func (s *MSPEmailSenderStore) Put(ctx context.Context, mspID string, sender MSPEmailSender, actor string) (*MSPEmailSender, error) {
	if mspID == "" {
		return nil, errors.New("msp email sender store: msp tenant id is required")
	}
	if actor == "" {
		return nil, errors.New("msp email sender store: actor is required")
	}
	if sender.TLSMode == "" {
		sender.TLSMode = config.EmailTLSModeStartTLS
	}
	if err := sender.validate(); err != nil {
		return nil, err
	}
	rec := mspEmailSenderRecord{MSPEmailSender: sender, UpdatedAt: s.now()}
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("msp email sender store: encode sender: %w", err)
	}
	err = s.store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:       mspEmailSenderKey(mspID),
		Data:      data,
		Format:    cfgconfig.ConfigFormatJSON,
		Checksum:  fmt.Sprintf("%x", sha256.Sum256(data)),
		UpdatedAt: rec.UpdatedAt,
		UpdatedBy: actor,
		Source:    "msp-email-sender",
	})
	if err != nil {
		return nil, fmt.Errorf("msp email sender store: write sender: %w", err)
	}
	return &sender, nil
}

// Delete removes the MSP's record. Removing an absent record is not an error. The
// caller removes the password with Server.deleteMSPEmailPassword.
func (s *MSPEmailSenderStore) Delete(ctx context.Context, mspID string) error {
	if mspID == "" {
		return errors.New("msp email sender store: msp tenant id is required")
	}
	if err := s.store.DeleteConfig(ctx, mspEmailSenderKey(mspID)); err != nil && !errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return fmt.Errorf("msp email sender store: delete sender: %w", err)
	}
	return nil
}

// ValidateMSPEmailSender checks a sender and its password against the MSP sender
// contract. Neither the sender nor the password is echoed in the error.
func ValidateMSPEmailSender(sender MSPEmailSender, password string) error {
	if sender.TLSMode == "" {
		sender.TLSMode = config.EmailTLSModeStartTLS
	}
	if err := sender.validate(); err != nil {
		return err
	}
	return validateMSPEmailPassword(password)
}

func (m MSPEmailSender) validate() error {
	if m.Host == "" || strings.ContainsAny(m.Host, "/\r\n") || strings.IndexFunc(m.Host, isSpaceOrControl) >= 0 {
		return errors.New("msp email sender: host is required and must not contain whitespace or '/'")
	}
	switch m.TLSMode {
	case config.EmailTLSModeStartTLS, config.EmailTLSModeImplicitTLS:
	default:
		return fmt.Errorf("msp email sender: tls_mode must be %q or %q", config.EmailTLSModeStartTLS, config.EmailTLSModeImplicitTLS)
	}
	if m.Port != 0 && !mspEmailPortAllowed(m.Port) {
		return fmt.Errorf("msp email sender: port must be empty or one of %v", mspEmailAllowedPorts)
	}
	if err := validateMSPEmailFrom(m.From); err != nil {
		return err
	}
	if len(m.Username) > mspEmailMaxUsernameLen || strings.IndexFunc(m.Username, isControl) >= 0 {
		return fmt.Errorf("msp email sender: username must be at most %d bytes with no control characters", mspEmailMaxUsernameLen)
	}
	return nil
}

func mspEmailPortAllowed(port int) bool {
	for _, p := range mspEmailAllowedPorts {
		if p == port {
			return true
		}
	}
	return false
}

func validateMSPEmailFrom(from string) error {
	if from == "" || len(from) > mspEmailMaxFromLen || strings.ContainsAny(from, "\r\n") {
		return errors.New("msp email sender: from is required and must be a bare address of at most 254 bytes")
	}
	addr, err := mail.ParseAddress(from)
	if err != nil || addr.Name != "" || addr.Address != from {
		return errors.New("msp email sender: from must be a bare address without a display name")
	}
	return nil
}

func validateMSPEmailPassword(password string) error {
	if password == "" || len(password) > mspEmailMaxPasswordLen || strings.IndexFunc(password, isControl) >= 0 {
		return fmt.Errorf("msp email sender: password is required, at most %d bytes, with no control characters", mspEmailMaxPasswordLen)
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

func isSpaceOrControl(r rune) bool { return isControl(r) || r == ' ' || r == 0x85 || r == 0xa0 }

// storeMSPEmailPassword writes the MSP's SMTP password under the MSP tenant.
func (s *Server) storeMSPEmailPassword(ctx context.Context, mspID, password, actor string) error {
	if s.secretStore == nil {
		return errors.New("msp email sender: secret store unavailable")
	}
	if mspID == "" {
		return errors.New("msp email sender: msp tenant id is required")
	}
	if err := validateMSPEmailPassword(password); err != nil {
		return err
	}
	err := s.secretStore.StoreSecret(ctx, &secretsif.SecretRequest{
		Key:         mspEmailPasswordKey,
		Value:       password,
		TenantID:    mspID,
		CreatedBy:   actor,
		Description: "SMTP password for the MSP email sender",
		Tags:        []string{"notification", "smtp"},
		Metadata:    map[string]string{secretsif.MetadataKeySecretType: string(secretsif.SecretTypePassword)},
	})
	if err != nil {
		return fmt.Errorf("msp email sender: store password: %w", err)
	}
	return nil
}

// readMSPEmailPassword reads the MSP's SMTP password. It returns "" with no error
// when none is stored.
func (s *Server) readMSPEmailPassword(ctx context.Context, mspID string) (string, error) {
	if s.secretStore == nil || mspID == "" {
		return "", nil
	}
	sec, err := s.readEmailCredential(ctx, mspID, mspEmailPasswordKey)
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("msp email sender: read password: %w", err)
	}
	if sec == nil {
		return "", nil
	}
	return sec.Value, nil
}

// deleteMSPEmailPassword removes the MSP's SMTP password. A missing secret is not
// an error.
func (s *Server) deleteMSPEmailPassword(ctx context.Context, mspID string) error {
	if s.secretStore == nil {
		return errors.New("msp email sender: secret store unavailable")
	}
	if mspID == "" {
		return errors.New("msp email sender: msp tenant id is required")
	}
	var err error
	if ta, ok := s.secretStore.(secretsif.TenantSecretAccessor); ok {
		err = ta.DeleteTenantSecret(ctx, mspID, mspEmailPasswordKey)
	} else {
		err = s.secretStore.DeleteSecret(ctx, mspID+"/"+mspEmailPasswordKey)
	}
	if err != nil && !errors.Is(err, secretsif.ErrSecretNotFound) {
		return fmt.Errorf("msp email sender: delete password: %w", err)
	}
	return nil
}

// buildMSPEmailNotifier builds the SMTP notifier for an MSP from its stored
// sender and password. It returns (nil, nil) when either is absent, so a
// half-written sender never delivers. The provider's address guard is always on:
// the host is supplied by a tenant, so loopback, private and link-local targets
// are refused at connect time.
func (s *Server) buildMSPEmailNotifier(ctx context.Context, mspID string) (notifif.Notifier, error) {
	st := s.MSPEmailSenderStore()
	if st == nil || s.secretStore == nil || mspID == "" {
		return nil, nil
	}
	sender, err := st.Get(ctx, mspID)
	if err != nil {
		return nil, err
	}
	if sender == nil {
		return nil, nil
	}
	password, err := s.readMSPEmailPassword(ctx, mspID)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, nil
	}
	pcfg := emailProviderConfig(sender.Host, sender.TLSMode, sender.From, sender.Port, sender.Username, password)
	s.emailMu.RLock()
	for k, v := range s.mspEmailExtra {
		pcfg[k] = v
	}
	s.emailMu.RUnlock()
	// Set after the extras so a test extra cannot switch the guard off.
	pcfg["guard_addresses"] = true
	return notifif.CreateNotifierFromConfig("smtp", pcfg)
}
