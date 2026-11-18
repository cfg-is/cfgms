// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package compat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// selfSignedBundle generates a throwaway CA-and-client credential bundle at test
// time; no key material is committed.
func selfSignedBundle(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "compat-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	out, err := yaml.Marshal(adminBundle{
		CertPEM: certPEM,
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		CAPEM:   certPEM,
	})
	require.NoError(t, err)
	return string(out)
}

func TestNewMTLSClient(t *testing.T) {
	client, err := newMTLSClient(selfSignedBundle(t))
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestNewMTLSClientRejectsBadBundles(t *testing.T) {
	tests := map[string]string{
		"not yaml":   "cert_pem: [",
		"empty":      "{}",
		"no key":     "cert_pem: a\nca_pem: b\n",
		"bad pair":   "cert_pem: a\nkey_pem: b\nca_pem: c\n",
		"only a key": "key_pem: b\n",
	}
	for name, bundle := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := newMTLSClient(bundle)
			require.Error(t, err)
			assert.Nil(t, client)
		})
	}
}

func TestValidContainer(t *testing.T) {
	assert.NoError(t, validContainer(controllerContainer))
	assert.NoError(t, validContainer(floorContainer))
	for _, bad := range []string{"", "fleet-controller", "compat-controller; rm -rf /", "--privileged"} {
		assert.Error(t, validContainer(bad), "%q", bad)
	}
	_, err := dockerExec("fleet-controller", "true")
	assert.Error(t, err, "dockerExec must refuse a non-compat container before running docker")
}

func TestSameVersion(t *testing.T) {
	assert.True(t, sameVersion("v0.10.5", "v0.10.5"))
	assert.True(t, sameVersion("0.10.5", "v0.10.5"))
	assert.True(t, sameVersion("v0.10.5", "0.10.5"))
	assert.False(t, sameVersion("0.5.0-dev", "v0.10.5"), "an unstamped build reports the source default")
	assert.False(t, sameVersion("", "v0.10.5"))
	assert.False(t, sameVersion("v0.10.50", "v0.10.5"))
	assert.False(t, sameVersion("", ""))
}

func TestDecodeStewardList(t *testing.T) {
	list, err := decodeStewardList([]byte(`{"data":[{"id":"s-1","version":"v0.10.5","status":"active"}],"timestamp":"x"}`))
	require.NoError(t, err)
	assert.Equal(t, []stewardEntry{{ID: "s-1", Version: "v0.10.5"}}, list)

	list, err = decodeStewardList([]byte(`{"data":[]}`))
	require.NoError(t, err)
	assert.Empty(t, list)

	_, err = decodeStewardList([]byte(`{"data":{"stewards":[]}}`))
	require.Error(t, err, "the paginated object shape is not the list shape")
	_, err = decodeStewardList([]byte(`not json`))
	require.Error(t, err)
}

func TestDecodeCommandID(t *testing.T) {
	id, err := decodeCommandID([]byte(`{"data":{"steward_id":"s-1","command_id":"cfg-update-s-1-9","delivery_status":"delivered"}}`))
	require.NoError(t, err)
	assert.Equal(t, "cfg-update-s-1-9", id)

	_, err = decodeCommandID([]byte(`{"data":{"steward_id":"s-1","status":"stored"}}`))
	require.Error(t, err, "a plain storage acknowledgement has no delivery record to watch")
	_, err = decodeCommandID([]byte(`{`))
	require.Error(t, err)
}

func TestDecodeCommandRecord(t *testing.T) {
	// The fixture is the controller's real wire shape: handleGetCommandRecord
	// writes a bare CommandRecordResponse object with no data envelope.
	body, err := json.Marshal(api.CommandRecordResponse{
		ID:             "c1",
		Type:           "sync_config",
		StewardID:      "s-1",
		DeliveryStatus: "rejected",
		DeliveryDetail: "signature mismatch",
	})
	require.NoError(t, err)

	rec, err := decodeCommandRecord(body)
	require.NoError(t, err)
	assert.Equal(t, "c1", rec.ID)
	assert.Equal(t, "sync_config", rec.Type)
	assert.Equal(t, "s-1", rec.StewardID)
	assert.Equal(t, "rejected", rec.DeliveryStatus)
	assert.Equal(t, "signature mismatch", rec.DeliveryDetail)

	_, err = decodeCommandRecord([]byte(`[]`))
	require.Error(t, err)
}

func TestDeliveryOutcome(t *testing.T) {
	tests := []struct {
		status          string
		settled, wantOK bool
	}{
		{"delivered", true, true},
		{"acknowledged", true, true},
		{"rejected", true, false},
		{"failed", true, false},
		{"pending", false, false},
		{"", false, false},
		{"unknown", false, false},
	}
	for _, tc := range tests {
		settled, ok := deliveryOutcome(tc.status)
		assert.Equal(t, tc.settled, settled, tc.status)
		assert.Equal(t, tc.wantOK, ok, tc.status)
	}
}
