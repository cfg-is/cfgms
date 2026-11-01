// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package dna

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// staticPDCResolver is a PDCEmulatorResolver test implementation that returns
// fixed values.
type staticPDCResolver struct {
	localHost, pdcHost string
	isDC               bool
	err                error
}

func (r staticPDCResolver) ResolvePDCEmulator(_ context.Context) (string, string, bool, error) {
	return r.localHost, r.pdcHost, r.isDC, r.err
}

// blockingPDCResolver never answers until its context ends, standing in for a
// lookup against an unreachable role holder.
type blockingPDCResolver struct{}

func (blockingPDCResolver) ResolvePDCEmulator(ctx context.Context) (string, string, bool, error) {
	<-ctx.Done()
	return "", "", true, ctx.Err()
}

func TestIsPDCEmulator_Table(t *testing.T) {
	tests := []struct {
		name      string
		localHost string
		pdcHost   string
		isDC      bool
		want      bool
	}{
		{"match fqdn", "dc01.corp.example.com", "dc01.corp.example.com", true, true},
		{"match unc prefix from DsGetDcName", "dc01.corp.example.com", `\\dc01.corp.example.com`, true, true},
		{"different host", "dc02.corp.example.com", `\\dc01.corp.example.com`, true, false},
		{"not a DC", "dc01.corp.example.com", "dc01.corp.example.com", false, false},
		{"unresolved pdc", "dc01.corp.example.com", "", true, false},
		{"unresolved local", "", "dc01.corp.example.com", true, false},
		{"case variant", "DC01.Corp.Example.COM", `\\dc01.corp.example.com`, true, true},
		{"trailing root dot", "dc01.corp.example.com.", "dc01.corp.example.com", true, true},
		{"local bare label", "DC01", `\\dc01.corp.example.com`, true, true},
		{"pdc bare label", "dc01.corp.example.com", "DC01", true, true},
		{"bare label different host", "dc02", "dc01.corp.example.com", true, false},
		{"same label different domains", "dc01.a.example.com", "dc01.b.example.com", true, false},
		{"label prefix is not a match", "dc0", "dc01.corp.example.com", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsPDCEmulator(tt.localHost, tt.pdcHost, tt.isDC))
		})
	}
}

func TestCollectPDCEmulator_ResolverErrorYieldsFalse(t *testing.T) {
	attrs := map[string]string{}
	resolver := staticPDCResolver{
		localHost: "dc01.corp.example.com",
		pdcHost:   "dc01.corp.example.com", // ignored: the error wins
		isDC:      true,
		err:       errors.New("ERROR_NO_SUCH_DOMAIN"),
	}

	err := collectPDCEmulator(context.Background(), resolver, attrs)
	require.Error(t, err)
	assert.Equal(t, "false", attrs[pdcEmulatorAttr])
}

func TestCollectPDCEmulator_LookupTimeoutYieldsFalse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // an already-expired caller context ends the lookup immediately

	attrs := map[string]string{}
	err := collectPDCEmulator(ctx, blockingPDCResolver{}, attrs)
	require.Error(t, err)
	assert.Equal(t, "false", attrs[pdcEmulatorAttr])
}

func TestCollectPDCEmulator_NilResolverEmitsNothing(t *testing.T) {
	attrs := map[string]string{}
	require.NoError(t, collectPDCEmulator(context.Background(), nil, attrs))
	_, ok := attrs[pdcEmulatorAttr]
	assert.False(t, ok, "platforms without a resolver must not emit %s", pdcEmulatorAttr)
}

func TestCollectPDCEmulator_Values(t *testing.T) {
	tests := []struct {
		name     string
		resolver staticPDCResolver
		want     string
	}{
		{"role holder", staticPDCResolver{localHost: "dc01.corp.example.com", pdcHost: `\\dc01.corp.example.com`, isDC: true}, "true"},
		{"other DC", staticPDCResolver{localHost: "dc02.corp.example.com", pdcHost: `\\dc01.corp.example.com`, isDC: true}, "false"},
		{"member server", staticPDCResolver{localHost: "app01.corp.example.com"}, "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := map[string]string{}
			require.NoError(t, collectPDCEmulator(context.Background(), tt.resolver, attrs))
			assert.Equal(t, tt.want, attrs[pdcEmulatorAttr])
		})
	}
}

func TestBaselineAttributes_IncludesPDCEmulator(t *testing.T) {
	logger := logging.NewLogger("debug")
	ctx := context.Background()

	t.Run("role holder reports true", func(t *testing.T) {
		c := newSnapshotCollector(t, logger, WithPDCEmulatorResolver(staticPDCResolver{
			localHost: "dc01.corp.example.com",
			pdcHost:   `\\dc01.corp.example.com`,
			isDC:      true,
		}))
		attrs := c.RawAttributes(ctx)
		assert.Equal(t, "true", attrs[pdcEmulatorAttr])
	})

	t.Run("unresolved role holder reports false", func(t *testing.T) {
		c := newSnapshotCollector(t, logger, WithPDCEmulatorResolver(staticPDCResolver{
			localHost: "dc01.corp.example.com",
			isDC:      true,
			err:       errors.New("role holder unreachable"),
		}))
		attrs := c.RawAttributes(ctx)
		assert.Equal(t, "false", attrs[pdcEmulatorAttr])
	})

	t.Run("no resolver omits the attribute", func(t *testing.T) {
		c := newSnapshotCollector(t, logger, WithPDCEmulatorResolver(nil))
		attrs := c.RawAttributes(ctx)
		_, ok := attrs[pdcEmulatorAttr]
		assert.False(t, ok)
	})

	t.Run("fast path without background collection", func(t *testing.T) {
		// RawAttributes does not start background collection, so a value here
		// proves the attribute is on the fast path, not the slow set.
		c := newSnapshotCollector(t, logger, WithPDCEmulatorResolver(staticPDCResolver{
			localHost: "dc02.corp.example.com",
			pdcHost:   `\\dc01.corp.example.com`,
			isDC:      true,
		}))
		attrs := c.RawAttributes(ctx)
		select {
		case <-c.bgDone:
			t.Fatal("background collection must not have run")
		default:
		}
		assert.Equal(t, "false", attrs[pdcEmulatorAttr])
	})
}
