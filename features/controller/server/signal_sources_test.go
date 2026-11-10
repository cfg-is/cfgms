// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/pkg/logging"
)

// withSignalSources replaces the init()-time source list for one test.
func withSignalSources(t *testing.T, sources ...signalSource) {
	t.Helper()
	saved := signalSources
	signalSources = sources
	t.Cleanup(func() { signalSources = saved })
}

func newSignalSourceTestServer(t *testing.T) *Server {
	t.Helper()
	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)
	collector := health.NewCollector(
		health.NewDefaultTransportCollector(&health.MockTransportProviderStats{}),
		health.NewDefaultStorageCollector(NewUnimplementedStorageStats("flatfile")),
		health.NewDefaultApplicationCollector(&NoOpApplicationQueueStats{}),
		systemCollector,
	)
	return &Server{logger: logging.NewNoopLogger(), healthCollector: collector}
}

// TestSignalSourcesRunBeforeCollectorStart proves startHealthServices runs every
// source before healthCollector.Start: a sampler a source registers is already
// in place for the collector's initial collection, and the source itself sees a
// collector that has produced no snapshot.
func TestSignalSourcesRunBeforeCollectorStart(t *testing.T) {
	srv := newSignalSourceTestServer(t)

	var ranFirst, ranSecond atomic.Bool
	var snapshotBeforeStart atomic.Bool
	var sampled atomic.Int64
	withSignalSources(t,
		func(s *Server) error {
			ranFirst.Store(true)
			if _, err := s.healthCollector.GetCurrentMetrics(); err == nil {
				snapshotBeforeStart.Store(true)
			}
			gauge, err := s.healthCollector.Signals().RegisterGauge("cfgms_source_test_depth", "Source test depth.", nil)
			if err != nil {
				return err
			}
			s.healthCollector.RegisterSampler(func(context.Context) {
				sampled.Add(1)
				_ = gauge.Set(1, nil)
			})
			return nil
		},
		func(*Server) error { ranSecond.Store(true); return nil },
	)

	srv.startHealthServices()
	t.Cleanup(srv.stopHealthServices)

	assert.True(t, ranFirst.Load())
	assert.True(t, ranSecond.Load())
	assert.False(t, snapshotBeforeStart.Load(), "a source ran after the collector had collected")
	require.Eventually(t, func() bool { return sampled.Load() >= 1 }, 5*time.Second, 5*time.Millisecond,
		"the sampler registered by a source must run on the collector's initial collection")

	var sb strings.Builder
	require.NoError(t, srv.healthCollector.Signals().WriteText(&sb))
	assert.Contains(t, sb.String(), "cfgms_source_test_depth 1")
}

func TestSignalSourceFailureDoesNotBlockStartup(t *testing.T) {
	srv := newSignalSourceTestServer(t)

	var ranAfter atomic.Bool
	withSignalSources(t,
		func(*Server) error { return errors.New("registration failed") },
		func(*Server) error { panic("source bug") },
		func(*Server) error { ranAfter.Store(true); return nil },
	)

	assert.Equal(t, 2, srv.runSignalSources())
	assert.True(t, ranAfter.Load(), "sources after a failing one must still run")

	srv.startHealthServices()
	t.Cleanup(srv.stopHealthServices)
	require.Eventually(t, func() bool {
		_, err := srv.healthCollector.GetCurrentMetrics()
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "collector must still start")
}

func TestSignalSourcesSkippedWithoutCollector(t *testing.T) {
	var ran atomic.Bool
	withSignalSources(t, func(*Server) error { ran.Store(true); return nil })

	(&Server{logger: logging.NewNoopLogger()}).startHealthServices()

	assert.False(t, ran.Load(), "sources need a collector to register against")
}

func TestRegisterSignalSourceAppendsInOrder(t *testing.T) {
	withSignalSources(t)

	var order []int
	registerSignalSource(func(*Server) error { order = append(order, 1); return nil })
	registerSignalSource(func(*Server) error { order = append(order, 2); return nil })
	require.Len(t, signalSources, 2)

	assert.Equal(t, 0, newSignalSourceTestServer(t).runSignalSources())
	assert.Equal(t, []int{1, 2}, order)
}
