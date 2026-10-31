// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package credentials holds the controller-issued one-time initial password
// store (Issue #5555). The password itself lives in the secrets provider; the
// credential record (id, owner, state, expiry) lives in the config store. The
// RPC handler (#5555), the reveal API (#5559) and the in-process account path
// (#5563) all use CredentialStore and GeneratePassword from here, without
// importing the RPC handler.
package credentials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	// Namespace is the config-store namespace holding credential records.
	Namespace = "credentials"

	// secretNamePrefix starts every secret name. The secret is stored under the
	// record's tenant with the name
	//   credentials-initial_<steward>_<resource>_<record id>
	// (the config-signing/ precedent folds its directory into the name for the same
	// reason: the single-node secret backend rejects "/" in a secret name). The
	// record id is part of the name so a replacement never overwrites the password
	// a concurrent reader of the old record is about to fetch.
	secretNamePrefix = "credentials-initial"

	secretCreatedBy = "cfgms-controller-credentials"
	recordCreatedBy = "cfgms-controller-credentials"

	// DefaultTTL is how long an issued password stays retrievable.
	DefaultTTL = 72 * time.Hour

	// MaxPendingPerSteward and MaxPendingPerTenant bound un-revealed records.
	MaxPendingPerSteward = 1000
	MaxPendingPerTenant  = 1000
)

// State is the lifecycle state of a credential record.
type State string

const (
	StatePending   State = "pending"
	StateRevealing State = "revealing"
	StateRevealed  State = "revealed"
	StateExpired   State = "expired"
)

var (
	// ErrNotFound means no record exists for the key.
	ErrNotFound = errors.New("credential not found")
	// ErrExists means Put found a record already present.
	ErrExists = errors.New("credential record already exists")
	// ErrConflict means the record changed (id or state) since the caller read it.
	ErrConflict = errors.New("credential record changed concurrently")
	// ErrAlreadyIssued means the password was already revealed and the account
	// exists, or a reveal is in progress.
	ErrAlreadyIssued = errors.New("already issued")
	// ErrCapExceeded means the per-steward or per-tenant pending cap is reached.
	ErrCapExceeded = errors.New("pending credential cap reached")
	// ErrNotClusterAtomic is returned, with nothing written, when the controller
	// is a multi-node cluster and the config store cannot make a read-modify-write
	// atomic across nodes.
	ErrNotClusterAtomic = cfgconfig.ErrNotClusterAtomic
	// ErrInvalidKey means a key component is empty or not path-safe.
	ErrInvalidKey = errors.New("invalid credential key")
)

// idPattern restricts steward and resource ids to characters that are safe as
// one segment of a secret key.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidID reports whether s is usable as a steward or resource id segment.
func ValidID(s string) bool { return idPattern.MatchString(s) }

// Key identifies the one credential for a resource on a steward.
type Key struct {
	TenantID   string
	StewardID  string
	ResourceID string
}

// Validate rejects keys whose components could escape their key segment.
func (k Key) Validate() error {
	if k.TenantID == "" || len(k.TenantID) > 256 || !ValidID(k.StewardID) || !ValidID(k.ResourceID) {
		return ErrInvalidKey
	}
	return nil
}

// Record is the credential record kept in the config store. It never holds the
// password.
type Record struct {
	ID         string    `json:"id"` // random 128-bit, hex
	TenantID   string    `json:"tenant_id"`
	StewardID  string    `json:"steward_id"`
	ResourceID string    `json:"resource_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	State      State     `json:"state"`
}

// Key returns the record's identity.
func (r *Record) Key() Key {
	return Key{TenantID: r.TenantID, StewardID: r.StewardID, ResourceID: r.ResourceID}
}

// Credential is a Record plus its password, when the secret is still present.
// Every formatting verb prints a redacted form, so an accidental %v or %+v in a
// log line cannot expose the password.
type Credential struct {
	Record
	Password string `json:"-"`
}

// String implements fmt.Stringer with the password redacted.
func (c Credential) String() string {
	return fmt.Sprintf("credential{id=%s state=%s password=[redacted]}", c.ID, c.State)
}

// GoString implements fmt.GoStringer with the password redacted.
func (c Credential) GoString() string { return c.String() }

// Filter selects records for List; empty fields match everything.
type Filter struct {
	TenantID  string
	StewardID string
	State     State
}

// CredentialStore persists credential records and their passwords.
type CredentialStore interface {
	// Put stores password under rec (state pending) and makes rec the current
	// record for its key. With replaces == nil no record may exist (ErrExists);
	// otherwise the current record must still be replaces, same id and state
	// (ErrConflict), and replaces' password is deleted. Nothing is left behind on
	// failure.
	Put(ctx context.Context, rec *Record, password string, replaces *Record) error
	// Get returns the record and, when the secret still exists, its password.
	// ErrNotFound when there is no record.
	Get(ctx context.Context, key Key) (*Credential, error)
	// List returns records matching filter, without passwords.
	List(ctx context.Context, filter Filter) ([]*Record, error)
	// Claim atomically moves the record id from one state to another; exactly one
	// of several concurrent callers wins and the rest get ErrConflict.
	Claim(ctx context.Context, key Key, id string, from, to State) (*Record, error)
	// Delete removes the record and its password.
	Delete(ctx context.Context, key Key) error
	// DeleteSecret removes only rec's password, keeping the record (a revealed
	// record must outlive its secret: it is what refuses a second issue).
	DeleteSecret(ctx context.Context, rec *Record) error
}

var allowedTransitions = map[State][]State{
	StatePending:   {StateRevealing, StateExpired},
	StateRevealing: {StateRevealed, StatePending, StateExpired},
}

// StoreOption customises NewStore.
type StoreOption func(*store)

// WithClock overrides the clock (tests).
func WithClock(now func() time.Time) StoreOption { return func(s *store) { s.now = now } }

type store struct {
	cfg     cfgconfig.ConfigStore
	secrets secretsif.SecretStore
	now     func() time.Time
}

// NewStore returns a CredentialStore over the shared config and secrets stores.
func NewStore(cfg cfgconfig.ConfigStore, secrets secretsif.SecretStore, opts ...StoreOption) (CredentialStore, error) {
	if cfg == nil || secrets == nil {
		return nil, errors.New("credential store requires a config store and a secret store")
	}
	s := &store{cfg: cfg, secrets: secrets, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// NewRecordID returns a random 128-bit id, hex encoded.
func NewRecordID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("record id generation failed: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func nameFor(k Key) string {
	sum := sha256.Sum256([]byte(k.StewardID + "\x00" + k.ResourceID))
	return hex.EncodeToString(sum[:])
}

func recordKey(k Key) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: k.TenantID, Namespace: Namespace, Name: nameFor(k)}
}

func secretName(k Key, id string) string {
	return secretNamePrefix + "_" + k.StewardID + "_" + k.ResourceID + "_" + id
}

// getSecret reads a password, addressing it by explicit (tenant, name) when the
// store offers it so a hierarchical tenant id cannot be mis-split.
func (s *store) getSecret(ctx context.Context, k Key, id string) (*secretsif.Secret, error) {
	name := secretName(k, id)
	if acc, ok := s.secrets.(secretsif.TenantSecretAccessor); ok {
		return acc.GetTenantSecret(ctx, k.TenantID, name)
	}
	return s.secrets.GetSecret(ctx, k.TenantID+"/"+name)
}

func (s *store) deleteSecret(ctx context.Context, k Key, id string) error {
	name := secretName(k, id)
	if acc, ok := s.secrets.(secretsif.TenantSecretAccessor); ok {
		return acc.DeleteTenantSecret(ctx, k.TenantID, name)
	}
	return s.secrets.DeleteSecret(ctx, k.TenantID+"/"+name)
}

// checkCluster fails closed before any write when the controller is clustered
// and the config store cannot make the state moves atomic across nodes.
func (s *store) checkCluster() error {
	if cfgconfig.ClusterConfigured() && !cfgconfig.ClusterAtomic(s.cfg) {
		return ErrNotClusterAtomic
	}
	return nil
}

func encode(rec *Record) (*cfgconfig.ConfigEntry, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("encode credential record: %w", err)
	}
	return &cfgconfig.ConfigEntry{
		Key:       recordKey(rec.Key()),
		Data:      data,
		Format:    cfgconfig.ConfigFormatJSON,
		CreatedBy: recordCreatedBy,
		UpdatedBy: recordCreatedBy,
		Source:    "credentials",
	}, nil
}

func decode(e *cfgconfig.ConfigEntry) (*Record, error) {
	var rec Record
	if err := json.Unmarshal(e.Data, &rec); err != nil {
		return nil, errors.New("credential record is unreadable")
	}
	return &rec, nil
}

func (s *store) Put(ctx context.Context, rec *Record, password string, replaces *Record) error {
	if rec == nil || password == "" || rec.ID == "" || rec.State != StatePending {
		return errors.New("credential put requires a pending record with an id and a password")
	}
	if err := rec.Key().Validate(); err != nil {
		return err
	}
	if err := s.checkCluster(); err != nil {
		return err
	}
	ttl := rec.ExpiresAt.Sub(s.now())
	if ttl < time.Second {
		ttl = time.Second
	}
	if err := s.secrets.StoreSecret(ctx, &secretsif.SecretRequest{
		Key:       secretName(rec.Key(), rec.ID),
		Value:     password,
		TTL:       ttl,
		CreatedBy: secretCreatedBy,
		TenantID:  rec.TenantID,
	}); err != nil {
		return errors.New("credential secret write failed")
	}
	entry, err := encode(rec)
	if err != nil {
		s.dropSecret(ctx, rec)
		return err
	}
	if replaces == nil {
		err = cfgconfig.CreateIfAbsent(ctx, s.cfg, entry)
		if errors.Is(err, cfgconfig.ErrAlreadyExists) {
			err = ErrExists
		}
	} else {
		err = cfgconfig.AtomicUpdate(ctx, s.cfg, entry.Key, func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
			if cur == nil {
				return nil, ErrConflict
			}
			curRec, derr := decode(cur)
			if derr != nil {
				return nil, derr
			}
			if curRec.ID != replaces.ID || curRec.State != replaces.State {
				return nil, ErrConflict
			}
			return entry, nil
		})
	}
	if err != nil {
		s.dropSecret(ctx, rec)
		return err
	}
	if replaces != nil {
		s.dropSecret(ctx, replaces)
	}
	return nil
}

// dropSecret removes a password best-effort; the secret's own TTL bounds any
// leftover.
func (s *store) dropSecret(ctx context.Context, rec *Record) {
	_ = s.deleteSecret(ctx, rec.Key(), rec.ID)
}

func (s *store) Get(ctx context.Context, key Key) (*Credential, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if err := s.checkCluster(); err != nil {
		return nil, err
	}
	entry, err := s.cfg.GetConfig(ctx, recordKey(key))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return nil, ErrNotFound
		}
		return nil, errors.New("credential record read failed")
	}
	rec, err := decode(entry)
	if err != nil {
		return nil, err
	}
	cred := &Credential{Record: *rec}
	sec, err := s.getSecret(ctx, key, rec.ID)
	switch {
	case err == nil:
		cred.Password = sec.Value
	case errors.Is(err, secretsif.ErrSecretNotFound), errors.Is(err, secretsif.ErrSecretExpired):
		// A missing secret is a state the caller handles (replace the record).
	default:
		return nil, errors.New("credential secret read failed")
	}
	return cred, nil
}

func (s *store) List(ctx context.Context, filter Filter) ([]*Record, error) {
	entries, err := s.cfg.ListConfigs(ctx, &cfgconfig.ConfigFilter{TenantID: filter.TenantID, Namespace: Namespace})
	if err != nil {
		return nil, errors.New("credential record list failed")
	}
	out := make([]*Record, 0, len(entries))
	for _, e := range entries {
		rec, err := decode(e)
		if err != nil {
			continue
		}
		if filter.StewardID != "" && rec.StewardID != filter.StewardID {
			continue
		}
		if filter.State != "" && rec.State != filter.State {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

func (s *store) Claim(ctx context.Context, key Key, id string, from, to State) (*Record, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	allowed := false
	for _, t := range allowedTransitions[from] {
		if t == to {
			allowed = true
		}
	}
	if !allowed {
		return nil, fmt.Errorf("credential transition %s -> %s is not allowed", from, to)
	}
	var updated *Record
	err := cfgconfig.AtomicUpdate(ctx, s.cfg, recordKey(key), func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		if cur == nil {
			return nil, ErrNotFound
		}
		rec, err := decode(cur)
		if err != nil {
			return nil, err
		}
		if rec.ID != id || rec.State != from {
			return nil, ErrConflict
		}
		rec.State = to
		updated = rec
		return encode(rec)
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *store) Delete(ctx context.Context, key Key) error {
	if err := key.Validate(); err != nil {
		return err
	}
	if err := s.checkCluster(); err != nil {
		return err
	}
	cred, err := s.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	s.dropSecret(ctx, &cred.Record)
	if err := s.cfg.DeleteConfig(ctx, recordKey(key)); err != nil && !errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return errors.New("credential record delete failed")
	}
	return nil
}

func (s *store) DeleteSecret(ctx context.Context, rec *Record) error {
	if rec == nil {
		return nil
	}
	if err := rec.Key().Validate(); err != nil {
		return err
	}
	err := s.deleteSecret(ctx, rec.Key(), rec.ID)
	if err != nil && !errors.Is(err, secretsif.ErrSecretNotFound) {
		return errors.New("credential secret delete failed")
	}
	return nil
}

// KindActiveDirectoryUser is the only resource kind an initial credential is
// issued for: the module name of the declared resource.
const KindActiveDirectoryUser = "activedirectory.user"
