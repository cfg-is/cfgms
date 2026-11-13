// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build linux && cgo

package controller

// Issue #6227: the TPM-held credential key a root agent account registers with. It is
// the real client library pkg/softauthn/tpmkey on a software TPM provisioned with an
// endorsement certificate from a CA generated at test time; the controller under test
// trusts only that CA (SetRootAgentTPMRoots).

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/softauthn/tpmkey"
	"github.com/cfgis/cfgms/pkg/softauthn/tpmkey/tpmkeytest"
)

// swaTPM is the software TPM of one test controller.
type swaTPM struct {
	tpm      *tpmkeytest.TPM
	prepared *tpmkey.Prepared
}

// swaTPMKeyImpl is one credential key held in the TPM. One authenticator both registers
// and signs the later assertions: it learns the account's user handle from the creation
// options, which a discoverable login needs, so the attestation is answered through
// the late attester it was built with.
type swaTPMKeyImpl struct {
	e        *swaEnv
	tpm      *swaTPM
	blobs    tpmkey.Blobs
	credID   []byte
	auth     *softauthn.Authenticator
	attester *swaLateAttester
}

// swaLateAttester is the attester an authenticator was built with, whose inner attester
// exists once the controller's TPM challenge has been answered.
type swaLateAttester struct{ inner softauthn.Attester }

func (l *swaLateAttester) AttestTPM(authData, clientDataHash []byte) (*softauthn.TPMStatement, error) {
	if l.inner == nil {
		return nil, errors.New("the TPM challenge has not been answered")
	}
	return l.inner.AttestTPM(authData, clientDataHash)
}

// newTPMKey makes a credential key in the test controller's software TPM, starting the
// TPM and installing its CA as the controller's only trusted TPM root on first use.
func (e *swaEnv) newTPMKey() swaTPMKey {
	t := e.t
	tpm, _ := e.tpmEnv.(*swaTPM)
	if tpm == nil {
		hw := tpmkeytest.Start(t, tpmkeytest.Options{})
		pool := x509.NewCertPool()
		pool.AddCert(hw.CA)
		e.api.SetRootAgentTPMRoots(pool)
		prepared, err := tpmkey.Prepare(hw)
		require.NoError(t, err)
		tpm = &swaTPM{tpm: hw, prepared: prepared}
		e.tpmEnv = tpm
	}

	blobs, _, err := tpmkey.Create(tpm.tpm)
	require.NoError(t, err)
	signer, err := tpmkey.Open(tpm.tpm, blobs)
	require.NoError(t, err)
	credID := make([]byte, 32)
	_, err = rand.Read(credID)
	require.NoError(t, err)
	late := &swaLateAttester{}
	auth, err := softauthn.New(softauthn.Config{
		Signer: signer, RPID: swaRPID, Origin: e.origin, CredentialID: credID, Attester: late,
	})
	require.NoError(t, err)
	return &swaTPMKeyImpl{e: e, tpm: tpm, blobs: blobs, credID: credID, auth: auth, attester: late}
}

func (k *swaTPMKeyImpl) authenticator() *softauthn.Authenticator { return k.auth }

func (k *swaTPMKeyImpl) beginBody() []byte {
	body, err := json.Marshal(map[string]any{"tpm": map[string]any{
		"ek_cert_chain": k.tpm.prepared.EKCertChain, "ak_public": k.tpm.prepared.AKPublic,
	}})
	require.NoError(k.e.t, err)
	return body
}

func (k *swaTPMKeyImpl) register(options []byte) ([]byte, error) {
	var extra struct {
		CfgmsTpm *struct {
			CredentialBlob  []byte `json:"credential_blob"`
			EncryptedSecret []byte `json:"encrypted_secret"`
		} `json:"cfgmsTpm"`
	}
	if err := json.Unmarshal(options, &extra); err != nil {
		return nil, err
	}
	if extra.CfgmsTpm == nil {
		return nil, errors.New("the creation options carry no TPM challenge")
	}
	secret, err := tpmkey.Activate(k.tpm.tpm, k.tpm.prepared, extra.CfgmsTpm.CredentialBlob, extra.CfgmsTpm.EncryptedSecret)
	if err != nil {
		return nil, err
	}
	k.attester.inner = tpmkey.NewAttester(k.tpm.tpm, k.blobs, secret)
	return k.auth.Register(options)
}
