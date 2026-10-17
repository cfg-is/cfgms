// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TenantAdmission enforces a per-tenant concurrency limit on the steward
// connect (Register) and heartbeat (ControlChannel) ingest paths, composing with
// the same admission mechanism the DNA sync path already uses
// (features/controller/transport.TenantQueue) so one tenant cannot exhaust a
// shared cell's connect/heartbeat capacity (Issue #3759, ADR-031 Decision 6).
//
// The interface is declared here rather than importing TenantQueue directly:
// pkg/controlplane is a central provider (CLAUDE.md Central Provider System) and
// must never depend on a features/ package. *TenantQueue already exposes exactly
// this Acquire/Release shape for the DNA path, so it satisfies TenantAdmission
// without any change — server.go wires a *TenantQueue in here.
//
// "Composing with" means the same type, the same per-tenant limit and the same
// acquire/release discipline — not the same instance. server.go deliberately
// gives connect/heartbeat a queue of their own, because the DNA path's bucket
// key is wire data while every key produced here is server-verified; see
// features/controller/server/ingest_admission.go.
type TenantAdmission interface {
	// Acquire attempts to take an admission slot for tenantID, returning a
	// non-nil error immediately (never blocking) once the tenant's concurrency
	// limit is reached.
	Acquire(tenantID string) error
	// Release returns a slot previously obtained by Acquire.
	Release(tenantID string)
}

// WithTenantAdmission injects the per-tenant admission gate used by Register
// (connect) and the ControlChannel heartbeat path. Optional — a nil gate (the
// default) disables admission control, matching pre-#3759 behavior.
//
// The gate a caller passes here must key its buckets on server-verified state
// only. This provider guarantees that for the keys it produces (see
// admissionBucket); an instance shared with a path that keys buckets on wire
// data would hand that path's caller-controlled key space to connect and
// heartbeat, so callers keep such paths on a separate instance.
func WithTenantAdmission(admission TenantAdmission) option {
	return func(p *Provider) {
		p.tenantAdmission = admission
	}
}

// WithEventAdmission injects the per-tenant admission gate for steward events on
// the ControlChannel. It must be a different instance from the one passed to
// WithTenantAdmission so a flood of slow event handlers from one tenant cannot
// use up that tenant's connect or heartbeat slots (Issue #5120). Optional — nil
// disables the tenant gate; the per-stream in-flight limit still applies.
func WithEventAdmission(admission TenantAdmission) option {
	return func(p *Provider) {
		p.eventAdmission = admission
	}
}

// maxInFlightEventsPerStream bounds event handlers in flight at the same time
// for one ControlChannel stream: a quarter of the per-tenant limit (32), so one
// steward cannot fill its tenant's event slots. It bounds concurrency, not the
// event rate. Events past the cap are dropped and counted, never queued.
const maxInFlightEventsPerStream = 8

// maxInFlightHeartbeatsPerStream is the number of heartbeats a stream may have
// being handled at once.
const maxInFlightHeartbeatsPerStream = 1

// dropLogInterval is the minimum time between drop warnings on one stream.
const dropLogInterval = 30 * time.Second

// dropLogLimiter rate-limits a stream's drop warnings: the first drop is
// logged, then at most one line per interval carrying the drops since the last.
type dropLogLimiter struct {
	mu      sync.Mutex
	last    time.Time
	pending int64
}

// record notes one drop and reports whether to log now, with the number of
// drops since the last logged line.
func (d *dropLogLimiter) record(now time.Time) (bool, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pending++
	if !d.last.IsZero() && now.Sub(d.last) < dropLogInterval {
		return false, 0
	}
	n := d.pending
	d.pending = 0
	d.last = now
	return true, n
}

// streamIngest is the per-ControlChannel-stream in-flight state. One is created
// per stream, so no counter is shared across streams.
type streamIngest struct {
	events         atomic.Int32
	heartbeats     atomic.Int32
	eventDrops     *dropLogLimiter
	heartbeatDrops *dropLogLimiter
}

func newStreamIngest() *streamIngest {
	return &streamIngest{eventDrops: &dropLogLimiter{}, heartbeatDrops: &dropLogLimiter{}}
}

func tryAcquireCounter(c *atomic.Int32, limit int32) bool {
	if c.Add(1) > limit {
		c.Add(-1)
		return false
	}
	return true
}

func (s *streamIngest) tryEvent() bool {
	return tryAcquireCounter(&s.events, maxInFlightEventsPerStream)
}
func (s *streamIngest) releaseEvent() { s.events.Add(-1) }
func (s *streamIngest) tryHeartbeat() bool {
	return tryAcquireCounter(&s.heartbeats, maxInFlightHeartbeatsPerStream)
}
func (s *streamIngest) releaseHeartbeat() { s.heartbeats.Add(-1) }

// dropMessage counts a shed steward message and logs it, rate-limited per
// stream.
func (p *Provider) dropMessage(limiter *dropLogLimiter, counter *atomic.Int64, kind, reason, stewardID, bucket string) {
	counter.Add(1)
	if ok, n := limiter.record(time.Now()); ok {
		p.logger.Warn("controlchannel "+kind+" dropped — "+reason,
			"steward_id", logging.SanitizeLogValue(stewardID),
			"admission_bucket", logging.SanitizeLogValue(bucket),
			"dropped_since_last_log", n)
	}
}

// TenantAdmission returns the per-tenant admission gate wired into this
// provider, or nil when admission control is disabled. It exists so wiring can
// be asserted from outside the package — notably that the connect/heartbeat gate
// is a different instance from the one the wire-keyed DNA and bulk paths use.
func (p *Provider) TenantAdmission() TenantAdmission {
	return p.tenantAdmission
}

// EventAdmission returns the steward-event admission gate wired into this
// provider, or nil when the tenant event gate is disabled.
func (p *Provider) EventAdmission() TenantAdmission {
	return p.eventAdmission
}

// StewardTenantResolver maps an mTLS-verified steward identity to the tenant
// that owns it, using the controller's own fleet records.
//
// Admission buckets must never be selected by a value the caller put on the
// wire: creds.tenant_id and heartbeat.tenant_id are steward-supplied and
// forgeable, so keying a shared semaphore on them lets any steward holding a
// valid certificate saturate another tenant's slots (cross-tenant denial of
// service) and lets it mint unbounded, never-evicted map keys. This resolver is
// the server-side answer used instead.
type StewardTenantResolver interface {
	// TenantForSteward returns the tenant owning stewardID. It returns
	// ("", nil) when no record exists yet — a determinate "unknown", not a
	// failure — and a non-nil error only when the lookup itself could not be
	// completed.
	TenantForSteward(ctx context.Context, stewardID string) (string, error)
}

// WithStewardTenantResolver injects the server-side steward→tenant lookup used
// to key admission buckets on the ControlChannel (heartbeat) path, and on
// Register when no registration token store is wired.
//
// Optional. Without it the provider keys admission on the mTLS-verified steward
// identity instead: still server-verified and still bounded (a key can only
// exist for a CN this controller's CA issued), but a tenant's stewards are not
// pooled into one bucket.
func WithStewardTenantResolver(resolver StewardTenantResolver) option {
	return func(p *Provider) {
		p.stewardTenantResolver = resolver
	}
}

type stewardStoreTenantResolver struct {
	store business.StewardStore
}

// NewStewardStoreTenantResolver builds the production steward→tenant resolver
// over the fleet registry (business.StewardStore) — the same store the
// ControlChannel approval checker reads.
func NewStewardStoreTenantResolver(store business.StewardStore) StewardTenantResolver {
	return &stewardStoreTenantResolver{store: store}
}

func (r *stewardStoreTenantResolver) TenantForSteward(ctx context.Context, stewardID string) (string, error) {
	if r.store == nil {
		return "", fmt.Errorf("steward store is unavailable")
	}
	record, err := r.store.GetSteward(ctx, stewardID)
	if err != nil {
		// "No such steward" is a determinate answer, not a lookup failure: the
		// steward simply has no tenant on record yet, and the caller falls back
		// to a per-steward bucket. Reporting it as an error would log at WARN on
		// every heartbeat stream opened before the fleet record lands.
		if errors.Is(err, business.ErrStewardNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("load steward tenant: %w", err)
	}
	if record == nil {
		return "", nil
	}
	return record.TenantID, nil
}

// maxAdmissionTenantIDLen bounds the length of a tenant ID accepted as an
// admission bucket key. Tenant IDs are hierarchical paths ("root/msp-a/client-1"),
// so this is generous for real deployments while keeping a single key's retained
// bytes small.
const maxAdmissionTenantIDLen = 128

// stewardBucketPrefix namespaces the per-steward fallback bucket. ':' is not an
// accepted tenant-ID character (see validAdmissionTenantID), so a prefixed
// steward key can never collide with a tenant key — including the tenant keys
// the DNA and bulk-transfer paths share with this queue.
const stewardBucketPrefix = "steward-cn:"

// validAdmissionTenantID reports whether id is safe to use as a TenantQueue key.
//
// TenantQueue entries are created lazily and never evicted; its documented bound
// ("number of active tenants") holds only while the key space is server-
// controlled and bounded. Every key this provider produces is already derived
// from server-side state rather than the wire, so this is defence in depth: a
// corrupted or over-long record value is rejected here instead of permanently
// allocating a sync.Map entry plus a channel.
func validAdmissionTenantID(id string) bool {
	if id == "" || len(id) > maxAdmissionTenantIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == '/':
		default:
			return false
		}
	}
	return true
}

// admissionBucket returns the TenantQueue key for a steward's ingest traffic.
//
// verifiedTenantID is a tenant the caller has already proven server-side (the
// RegistrationTokenStore lookup in Register); pass "" when there is none. When
// it is empty the tenant is resolved from the fleet record for the mTLS-verified
// stewardID. If neither yields a usable tenant, the bucket falls back to the
// steward's own certificate CN, which is still a server-verified, CA-bounded key.
//
// The caller-supplied tenant fields on the wire (creds.tenant_id,
// heartbeat.tenant_id) are never an input here.
func (p *Provider) admissionBucket(ctx context.Context, stewardID, verifiedTenantID string) string {
	if verifiedTenantID == "" && p.stewardTenantResolver != nil {
		resolved, err := p.stewardTenantResolver.TenantForSteward(ctx, stewardID)
		if err != nil {
			// Admission is a fairness control, not an authorization decision, so a
			// resolver outage degrades to per-steward buckets rather than refusing
			// traffic: every steward stays rate-bounded and no steward can reach
			// another tenant's bucket.
			p.logger.Warn("steward tenant lookup failed, admission falls back to a per-steward bucket",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
		} else {
			verifiedTenantID = resolved
		}
	}

	if validAdmissionTenantID(verifiedTenantID) {
		return verifiedTenantID
	}
	if verifiedTenantID != "" {
		p.logger.Warn("server-side tenant ID is not usable as an admission key, falling back to a per-steward bucket",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"tenant_id", logging.SanitizeLogValue(verifiedTenantID))
	}
	return stewardBucketPrefix + stewardID
}
