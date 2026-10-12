// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package contract

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModuleEnv_OnlyBaselineDeclaredAndContract(t *testing.T) {
	parent := []string{
		"CFGMS_SECRET_KEY_FILE=/etc/cfgms/secret.key",
		"CFGMS_STORAGE_DSN=postgres://u:p@h/db",
		"VENDOR_A_API_REGION=eu-1",
		"VENDOR_A_UNSET_ELSEWHERE=x",
		SocketEnvVar + "=/parent/value",
	}
	want := map[string]string{
		"VENDOR_A_API_REGION": "eu-1",
		SocketEnvVar:          "/run/mod.sock",
	}
	for _, name := range baselineEnvNames {
		parent = append(parent, name+"=baseline-"+name)
		want[name] = "baseline-" + name
	}

	res, err := BuildModuleEnv(parent, []string{"VENDOR_A_API_REGION", "VENDOR_A_NOT_SET"}, "/run/mod.sock")
	require.NoError(t, err)

	got := map[string]string{}
	for _, e := range res.Env {
		i := strings.IndexByte(e, '=')
		got[e[:i]] = e[i+1:]
	}
	assert.Equal(t, want, got)
	assert.Equal(t, []string{"VENDOR_A_NOT_SET"}, res.MissingDeclared)
	assert.Len(t, res.PassedNames, len(want))
	assert.NotContains(t, res.PassedNames, "CFGMS_SECRET_KEY_FILE")
	assert.NotContains(t, res.PassedNames, "VENDOR_A_NOT_SET")
}

func TestModuleEnv_UnsetBaselineNotPassedEmpty(t *testing.T) {
	res, err := BuildModuleEnv(nil, nil, "/s")
	require.NoError(t, err)
	assert.Equal(t, []string{SocketEnvVar + "=/s"}, res.Env)
}

func TestModuleEnv_InvalidDeclaredNameErrors(t *testing.T) {
	tooMany := make([]string, MaxDeclaredEnvNames+1)
	for i := range tooMany {
		tooMany[i] = "VAR_" + strings.Repeat("A", i+1)
	}
	cases := map[string][]string{
		"wildcard":  {"*"},
		"prefix":    {"CFGMS_*"},
		"question":  {"A?"},
		"empty":     {""},
		"equals":    {"A=B"},
		"digit":     {"1ABC"},
		"duplicate": {"A", "B", "A"},
		"reserved":  {SocketEnvVar},
		"too many":  tooMany,
	}
	for name, declared := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := BuildModuleEnv([]string{"A=1"}, declared, "/s")
			require.Error(t, err)
			assert.Nil(t, res)
		})
	}
}

func TestValidateEnvNames_ErrorNamesIndex(t *testing.T) {
	err := ValidateEnvNames([]string{"OK", "A=B"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "env[1]")
	assert.NoError(t, ValidateEnvNames(nil))
	assert.NoError(t, ValidateEnvNames([]string{"HTTP_PROXY", "_x1"}))
}

func TestValidateEnvNames_ReservedNamesRejected(t *testing.T) {
	groups := map[string][]string{
		"cfgms prefix":    {"CFGMS_SECRET_KEY_FILE", "cfgms_x", "Cfgms_Mixed", SocketEnvVar},
		"dynamic loader":  {"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "ld_preload"},
		"go runtime":      {"GODEBUG", "GOTRACEBACK", "godebug"},
		"interpreters":    {"PYTHONPATH", "PYTHONSTARTUP", "NODE_OPTIONS", "PERL5OPT", "RUBYOPT"},
		"shell startup":   {"BASH_ENV", "ENV", "env"},
		"powershell path": {"PSModulePath", "PSMODULEPATH"},
	}
	for group, names := range groups {
		for _, name := range names {
			t.Run(group+"/"+name, func(t *testing.T) {
				err := ValidateEnvNames([]string{"HTTPS_PROXY", name})
				require.Error(t, err)
				assert.Contains(t, err.Error(), "env[1]")
				assert.Contains(t, err.Error(), "reserved")
			})
		}
	}
	assert.NoError(t, ValidateEnvNames([]string{"HTTPS_PROXY", "NO_PROXY", "CFGM_X", "ENVIRON"}))
}

func TestModuleEnv_ReservedDeclaredNameErrors(t *testing.T) {
	res, err := BuildModuleEnv([]string{"LD_PRELOAD=/x.so"}, []string{"LD_PRELOAD"}, "/s")
	require.Error(t, err)
	assert.Nil(t, res)
}
