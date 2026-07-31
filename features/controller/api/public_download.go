// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	publicDownloadRequestsPerWindow = 120
	publicDownloadMaxPerSource      = 2
	publicDownloadMaxGlobal         = 8
	publicDownloadMaxTrackedSources = 10_000
	publicDownloadCacheMaxEntries   = 32
	publicDownloadCacheMaxBytes     = 128 * 1024 * 1024
	publicDownloadCacheMaxItemBytes = 66 * 1024 * 1024
	publicDownloadMaxBuilders       = 2
)

var errPublicDownloadTooLarge = errors.New("public download exceeds cache item limit")

type publicDownloadGuardConfig struct {
	requestsPerWindow int
	window            time.Duration
	maxPerSource      int
	maxGlobal         int
	maxTrackedSources int
	now               func() time.Time
}

func defaultPublicDownloadGuardConfig() publicDownloadGuardConfig {
	return publicDownloadGuardConfig{
		requestsPerWindow: publicDownloadRequestsPerWindow,
		window:            time.Minute,
		maxPerSource:      publicDownloadMaxPerSource,
		maxGlobal:         publicDownloadMaxGlobal,
		maxTrackedSources: publicDownloadMaxTrackedSources,
		now:               time.Now,
	}
}

type publicDownloadSourceState struct {
	windowStart time.Time
	lastSeen    time.Time
	requests    int
	inflight    int
}

// publicDownloadGuard applies a successful-request budget to the anonymous
// installer and steward-binary routes. Auth-defense rate limiting is deliberately
// failure-oriented, so it cannot bound valid anonymous downloads on its own.
type publicDownloadGuard struct {
	mu       sync.Mutex
	cfg      publicDownloadGuardConfig
	sources  map[string]*publicDownloadSourceState
	inflight int
}

func newPublicDownloadGuard(cfg publicDownloadGuardConfig) *publicDownloadGuard {
	return &publicDownloadGuard{
		cfg:     cfg,
		sources: make(map[string]*publicDownloadSourceState),
	}
}

func (g *publicDownloadGuard) middleware(
	trustedProxies []net.IPNet,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := extractSourceIP(r, trustedProxies)
		release, status, retryAfter := g.acquire(source)
		if release == nil {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			http.Error(w, http.StatusText(status), status)
			return
		}
		defer release()
		next.ServeHTTP(w, r)
	})
}

func (g *publicDownloadGuard) acquire(source string) (func(), int, int) {
	now := g.cfg.now()
	if source == "" {
		source = "unknown"
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	state, exists := g.sources[source]
	if !exists {
		g.pruneLocked(now)
		if len(g.sources) >= g.cfg.maxTrackedSources {
			return nil, http.StatusTooManyRequests, max(1, int(g.cfg.window/time.Second))
		}
		state = &publicDownloadSourceState{windowStart: now}
		g.sources[source] = state
	}

	if now.Sub(state.windowStart) >= g.cfg.window {
		state.windowStart = now
		state.requests = 0
	}
	state.lastSeen = now
	if state.requests >= g.cfg.requestsPerWindow {
		remaining := state.windowStart.Add(g.cfg.window).Sub(now)
		retry := int((remaining + time.Second - 1) / time.Second)
		return nil, http.StatusTooManyRequests, max(1, retry)
	}
	// Concurrency refusals consume the request budget too, preventing a source
	// from spinning on a saturated slot without limit.
	state.requests++

	if state.inflight >= g.cfg.maxPerSource || g.inflight >= g.cfg.maxGlobal {
		return nil, http.StatusTooManyRequests, 1
	}
	state.inflight++
	g.inflight++

	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			state.inflight--
			g.inflight--
			state.lastSeen = g.cfg.now()
			g.mu.Unlock()
		})
	}, 0, 0
}

func (g *publicDownloadGuard) pruneLocked(now time.Time) {
	for source, state := range g.sources {
		if state.inflight == 0 && now.Sub(state.lastSeen) >= g.cfg.window {
			delete(g.sources, source)
		}
	}
}

type publicDownloadAsset struct {
	body               []byte
	contentType        string
	contentDisposition string
	etag               string
	cacheControl       string
	headers            map[string]string
}

func newPublicDownloadAsset(body []byte, contentType, disposition, cacheControl string) *publicDownloadAsset {
	sum := sha256.Sum256(body)
	return &publicDownloadAsset{
		body:               body,
		contentType:        contentType,
		contentDisposition: disposition,
		etag:               `"` + hex.EncodeToString(sum[:]) + `"`,
		cacheControl:       cacheControl,
	}
}

type publicDownloadCacheEntry struct {
	asset      *publicDownloadAsset
	expiresAt  time.Time
	accessSeq  uint64
	storedSize int
}

// publicDownloadCache coalesces concurrent cache misses and bounds both entry
// count and resident bytes. Large-object construction is separately limited so
// distinct cache misses cannot multiply memory use up to the HTTP connection cap.
type publicDownloadCache struct {
	mu          sync.Mutex
	entries     map[string]*publicDownloadCacheEntry
	building    map[string]chan struct{}
	generations map[string]uint64
	buildTokens chan struct{}
	ttl         time.Duration
	maxEntries  int
	maxBytes    int
	maxItem     int
	totalBytes  int
	accessSeq   uint64
	now         func() time.Time
}

func newPublicDownloadCache() *publicDownloadCache {
	return &publicDownloadCache{
		entries:     make(map[string]*publicDownloadCacheEntry),
		building:    make(map[string]chan struct{}),
		generations: make(map[string]uint64),
		buildTokens: make(chan struct{}, publicDownloadMaxBuilders),
		ttl:         5 * time.Minute,
		maxEntries:  publicDownloadCacheMaxEntries,
		maxBytes:    publicDownloadCacheMaxBytes,
		maxItem:     publicDownloadCacheMaxItemBytes,
		now:         time.Now,
	}
}

func (c *publicDownloadCache) getOrBuild(
	ctx context.Context,
	key string,
	build func() (*publicDownloadAsset, error),
) (*publicDownloadAsset, error) {
	for {
		now := c.now()
		c.mu.Lock()
		if entry, ok := c.entries[key]; ok {
			if now.Before(entry.expiresAt) {
				c.accessSeq++
				entry.accessSeq = c.accessSeq
				asset := entry.asset
				c.mu.Unlock()
				return asset, nil
			}
			c.deleteLocked(key)
		}
		if ready, ok := c.building[key]; ok {
			c.mu.Unlock()
			select {
			case <-ready:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		ready := make(chan struct{})
		c.building[key] = ready
		generation := c.generations[key]
		c.mu.Unlock()

		select {
		case c.buildTokens <- struct{}{}:
		case <-ctx.Done():
			c.finishBuild(key, ready, generation, nil)
			return nil, ctx.Err()
		}
		asset, err := build()
		<-c.buildTokens
		if err == nil && asset == nil {
			err = errors.New("public download builder returned no asset")
		}
		if err == nil && len(asset.body) > c.maxItem {
			err = errPublicDownloadTooLarge
		}
		cacheable := asset
		if err != nil {
			cacheable = nil
		}
		c.finishBuild(key, ready, generation, cacheable)
		if err != nil {
			return nil, err
		}
		return asset, nil
	}
}

func (c *publicDownloadCache) finishBuild(
	key string,
	ready chan struct{},
	generation uint64,
	asset *publicDownloadAsset,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.building, key)
	if asset != nil && len(asset.body) <= c.maxItem && c.generations[key] == generation {
		c.evictLocked(len(asset.body))
		c.accessSeq++
		c.entries[key] = &publicDownloadCacheEntry{
			asset:      asset,
			expiresAt:  c.now().Add(c.ttl),
			accessSeq:  c.accessSeq,
			storedSize: len(asset.body),
		}
		c.totalBytes += len(asset.body)
	}
	close(ready)
}

func (c *publicDownloadCache) evictLocked(incoming int) {
	for len(c.entries) >= c.maxEntries || c.totalBytes+incoming > c.maxBytes {
		var oldestKey string
		var oldestSeq uint64
		for key, entry := range c.entries {
			if oldestKey == "" || entry.accessSeq < oldestSeq {
				oldestKey = key
				oldestSeq = entry.accessSeq
			}
		}
		if oldestKey == "" {
			return
		}
		c.deleteLocked(oldestKey)
	}
}

func (c *publicDownloadCache) deleteLocked(key string) {
	if entry, ok := c.entries[key]; ok {
		c.totalBytes -= entry.storedSize
		delete(c.entries, key)
	}
}

func (c *publicDownloadCache) invalidate(key string) {
	c.mu.Lock()
	c.generations[key]++
	c.deleteLocked(key)
	c.mu.Unlock()
}

func servePublicDownload(w http.ResponseWriter, r *http.Request, name string, asset *publicDownloadAsset) {
	w.Header().Set("Content-Type", asset.contentType)
	w.Header().Set("Cache-Control", asset.cacheControl)
	w.Header().Set("ETag", asset.etag)
	w.Header().Set("Accept-Ranges", "bytes")
	if asset.contentDisposition != "" {
		w.Header().Set("Content-Disposition", asset.contentDisposition)
	}
	for key, value := range asset.headers {
		w.Header().Set(key, value)
	}

	ranges := r.Header.Values("Range")
	if len(ranges) > 1 || (len(ranges) == 1 && strings.Contains(ranges[0], ",")) {
		w.Header().Set("Content-Range", "bytes */"+strconv.Itoa(len(asset.body)))
		http.Error(w, "multiple ranges are not supported", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	// ETag is the authoritative validator. A zero modtime avoids producing a
	// weaker Last-Modified validator for generated archives.
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(asset.body))
}
