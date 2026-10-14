// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package git

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// [REQUIRED TEST] the git environment and arguments the resolver builds.
func TestGitEnv_LockedDown(t *testing.T) {
	env := gitEnv([]string{
		"PATH=/usr/bin",
		"GIT_SSL_NO_VERIFY=1",
		"GIT_EXTERNAL_DIFF=evil",
		"GIT_TEMPLATE_DIR=/tmp/t",
		"GIT_SSL_CAINFO=/etc/ca.pem",
		"GIT_SSH_COMMAND=ssh -i /keys/id",
	})
	joined := "\n" + strings.Join(env, "\n") + "\n"

	assert.Contains(t, joined, "\nGIT_TERMINAL_PROMPT=0\n")
	assert.Contains(t, joined, "\nGIT_ALLOW_PROTOCOL=https:ssh\n")
	assert.Contains(t, joined, "\nGIT_CONFIG_NOSYSTEM=1\n")
	assert.Contains(t, joined, "\nGIT_SSL_CAINFO=/etc/ca.pem\n", "operator CA passes through")
	assert.Contains(t, joined, "\nPATH=/usr/bin\n")
	assert.Contains(t, joined, "\nGIT_SSH_COMMAND=ssh -i /keys/id -o BatchMode=yes\n")
	assert.NotContains(t, joined, "GIT_SSL_NO_VERIFY")
	assert.NotContains(t, joined, "GIT_EXTERNAL_DIFF")
	assert.NotContains(t, joined, "GIT_TEMPLATE_DIR")
	assert.NotContains(t, joined, "StrictHostKeyChecking")

	assert.Contains(t, gitEnv(nil), "GIT_SSH_COMMAND=ssh -o BatchMode=yes")
}

func TestGitConfigArgs_LockedDown(t *testing.T) {
	args := strings.Join(gitConfigArgs("/empty"), " ")
	assert.Contains(t, args, "http.sslVerify=true")
	assert.Contains(t, args, "http.schannelUseSSLCAInfo=true")
	assert.Contains(t, args, "core.hooksPath=/empty")
	assert.Contains(t, args, "submodule.recurse=false")
	assert.NotContains(t, args, "sslVerify=false")
	assert.NotContains(t, args, "StrictHostKeyChecking")
}
