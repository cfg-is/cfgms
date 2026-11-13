// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6227: server-verified TPM attestation for a root agent account's software
// authenticator (ADR-021 Amendment 12). These tests need no TPM, so they run on every
// OS leg: EK chain verification against a CA generated at test time, the attestation key
// template, the activation challenge, the attestation statement checks, the credential
// record's persistence and the begin request body. The ceremonies with a genuine
// producer (the software TPM) are in tpm_attestation_sim_linux_test.go.

package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/softauthn"
)

var (
	tpmtOIDEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	tpmtOIDManufacturer  = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	tpmtOIDModel         = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	tpmtOIDFirmware      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	tpmtOIDSAN           = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// tpmtPKI is a manufacturer root, an intermediate below it and their keys.
type tpmtPKI struct {
	root, inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
}

func tpmtSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	require.NoError(t, err)
	return n
}

func tpmtCA(t *testing.T, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          tpmtSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	signer, issuer := key, tmpl
	if parent != nil {
		signer, issuer = parentKey, parent
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func newTPMTestPKI(t *testing.T) *tpmtPKI {
	t.Helper()
	root, rootKey := tpmtCA(t, "acme-corp tpm root", nil, nil)
	inter, interKey := tpmtCA(t, "acme-corp tpm intermediate", root, rootKey)
	return &tpmtPKI{root: root, inter: inter, rootKey: rootKey, interKey: interKey}
}

// tpmtDeviceSAN is the critical subject alternative name of an EK certificate: a lone
// directoryName with the TCG manufacturer, model and firmware attributes.
func tpmtDeviceSAN(t *testing.T) pkix.Extension {
	t.Helper()
	dn, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: tpmtOIDManufacturer, Value: "id:41434D45"}},
		{{Type: tpmtOIDModel, Value: "ACME-TPM-2"}},
		{{Type: tpmtOIDFirmware, Value: "id:00070002"}},
	})
	require.NoError(t, err)
	name, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: dn})
	require.NoError(t, err)
	seq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: name})
	require.NoError(t, err)
	return pkix.Extension{Id: tpmtOIDSAN, Critical: true, Value: seq}
}

// ekCert issues an endorsement certificate for pub below the intermediate: empty
// subject, critical directoryName SAN (when attrs) and the TCG EK extended key usage.
func (p *tpmtPKI) ekCert(t *testing.T, pub crypto.PublicKey, attrs bool, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:       tpmtSerial(t),
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           notAfter,
		KeyUsage:           x509.KeyUsageKeyEncipherment,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{tpmtOIDEKCertificate},
	}
	if attrs {
		tmpl.ExtraExtensions = []pkix.Extension{tpmtDeviceSAN(t)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.inter, pub, p.interKey)
	require.NoError(t, err)
	return der
}

func (p *tpmtPKI) rootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	return pool
}

func tpmtECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

// tpmtAKPublic marshals a TPMT_PUBLIC with the attestation key template around key's
// point; mutate may change it to a template the controller must refuse.
func tpmtAKPublic(t *testing.T, key *ecdsa.PublicKey, mutate func(*tpm2.TPMTPublic)) []byte {
	t.Helper()
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, Restricted: true, SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: key.X.FillBytes(make([]byte, 32))},
			Y: tpm2.TPM2BECCParameter{Buffer: key.Y.FillBytes(make([]byte, 32))},
		}),
	}
	if mutate != nil {
		mutate(&pub)
	}
	return tpm2.Marshal(pub)
}

func TestVerifyEKChain(t *testing.T) {
	pki := newTPMTestPKI(t)
	ek := tpmtECKey(t)
	leaf := pki.ekCert(t, &ek.PublicKey, true, time.Now().Add(24*time.Hour))
	now := time.Now()

	t.Run("accepts a chain to a configured root", func(t *testing.T) {
		got, err := verifyEKChain([][]byte{leaf, pki.inter.Raw}, pki.rootPool(), now)
		require.NoError(t, err)
		assert.True(t, got.PublicKey.(*ecdsa.PublicKey).Equal(&ek.PublicKey))
	})

	t.Run("an intermediate in the roots is a trust anchor", func(t *testing.T) {
		pool := x509.NewCertPool()
		pool.AddCert(pki.inter)
		_, err := verifyEKChain([][]byte{leaf}, pool, now)
		require.NoError(t, err)
	})

	t.Run("refuses an unknown root", func(t *testing.T) {
		other := newTPMTestPKI(t)
		_, err := verifyEKChain([][]byte{leaf, pki.inter.Raw}, other.rootPool(), now)
		require.Error(t, err)
	})

	t.Run("refuses a missing intermediate", func(t *testing.T) {
		_, err := verifyEKChain([][]byte{leaf}, pki.rootPool(), now)
		require.Error(t, err)
	})

	t.Run("refuses an expired certificate", func(t *testing.T) {
		expired := pki.ekCert(t, &ek.PublicKey, true, time.Now().Add(2*time.Hour))
		_, err := verifyEKChain([][]byte{expired, pki.inter.Raw}, pki.rootPool(), now.Add(72*time.Hour))
		require.Error(t, err)
	})

	t.Run("refuses a certificate that is not yet valid", func(t *testing.T) {
		_, err := verifyEKChain([][]byte{leaf, pki.inter.Raw}, pki.rootPool(), now.Add(-72*time.Hour))
		require.Error(t, err)
	})

	t.Run("refuses no roots, an empty chain, a long chain and garbage", func(t *testing.T) {
		_, err := verifyEKChain([][]byte{leaf, pki.inter.Raw}, nil, now)
		require.Error(t, err, "no roots")
		_, err = verifyEKChain(nil, pki.rootPool(), now)
		require.Error(t, err, "empty chain")
		long := make([][]byte, tpmMaxEKChain+1)
		for i := range long {
			long[i] = leaf
		}
		_, err = verifyEKChain(long, pki.rootPool(), now)
		require.Error(t, err, "chain over the cap")
		_, err = verifyEKChain([][]byte{[]byte("not a certificate")}, pki.rootPool(), now)
		require.Error(t, err, "garbage leaf")
		_, err = verifyEKChain([][]byte{leaf, []byte("not a certificate")}, pki.rootPool(), now)
		require.Error(t, err, "garbage intermediate")
	})

	t.Run("another critical extension still fails the chain", func(t *testing.T) {
		tmpl := &x509.Certificate{
			SerialNumber: tpmtSerial(t), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{tpmtDeviceSAN(t), {Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0}}},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.inter, &ek.PublicKey, pki.interKey)
		require.NoError(t, err)
		_, err = verifyEKChain([][]byte{der, pki.inter.Raw}, pki.rootPool(), now)
		require.Error(t, err)
	})
}

func TestParseAttestationKey(t *testing.T) {
	key := tpmtECKey(t)

	t.Run("accepts the attestation key template", func(t *testing.T) {
		pub, got, err := parseAttestationKey(tpmtAKPublic(t, &key.PublicKey, nil))
		require.NoError(t, err)
		assert.True(t, got.Equal(&key.PublicKey))
		assert.Equal(t, tpm2.TPMAlgECC, pub.Type)
	})

	refused := map[string]func(*tpm2.TPMTPublic){
		"a key that is not restricted": func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = false },
		"a key without fixedTPM":       func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false },
		"a key without fixedParent":    func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedParent = false },
		"a key the TPM did not create": func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SensitiveDataOrigin = false },
		"a key that cannot sign":       func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SignEncrypt = false },
		"a key that also decrypts":     func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Decrypt = true },
		"a key with a SHA-1 name":      func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgSHA1 },
		"a key on another curve": func(p *tpm2.TPMTPublic) {
			parms, err := p.Parameters.ECCDetail()
			require.NoError(t, err)
			parms.CurveID = tpm2.TPMECCNistP384
		},
		"a key signing with SHA-384": func(p *tpm2.TPMTPublic) {
			parms, err := p.Parameters.ECCDetail()
			require.NoError(t, err)
			parms.Scheme.Details = tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA384})
		},
		"a key with another scheme": func(p *tpm2.TPMTPublic) {
			parms, err := p.Parameters.ECCDetail()
			require.NoError(t, err)
			parms.Scheme = tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDH,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDH, &tpm2.TPMSKeySchemeECDH{HashAlg: tpm2.TPMAlgSHA256}),
			}
		},
	}
	for name, mutate := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			_, _, err := parseAttestationKey(tpmtAKPublic(t, &key.PublicKey, mutate))
			require.Error(t, err)
		})
	}

	t.Run("refuses a key that is not ECC", func(t *testing.T) {
		raw := tpmtAKPublic(t, &key.PublicKey, nil)
		raw[0], raw[1] = 0x00, 0x01 // TPM_ALG_RSA: the rest no longer parses as an RSA public area
		_, _, err := parseAttestationKey(raw)
		require.Error(t, err)
	})

	t.Run("refuses garbage, trailing bytes and a point off the curve", func(t *testing.T) {
		_, _, err := parseAttestationKey([]byte("garbage"))
		require.Error(t, err)
		_, _, err = parseAttestationKey(nil)
		require.Error(t, err)
		valid := tpmtAKPublic(t, &key.PublicKey, nil)
		_, _, err = parseAttestationKey(append(append([]byte(nil), valid...), 0x00))
		require.Error(t, err, "bytes after the public area are not canonical")

		off := tpmtAKPublic(t, &key.PublicKey, func(p *tpm2.TPMTPublic) {
			p.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: bytes.Repeat([]byte{1}, 32)},
				Y: tpm2.TPM2BECCParameter{Buffer: bytes.Repeat([]byte{2}, 32)},
			})
		})
		_, _, err = parseAttestationKey(off)
		require.Error(t, err)
	})
}

// activationChallenge builds the credactivation input from the AK's TPM name and the EK
// public key. The name is the SHA-256 name algorithm identifier followed by the digest
// of the marshalled public area.
func TestActivationChallenge(t *testing.T) {
	ak, _, err := parseAttestationKey(tpmtAKPublic(t, &tpmtECKey(t).PublicKey, nil))
	require.NoError(t, err)

	name, err := tpm2.ObjectName(ak)
	require.NoError(t, err)
	digest := sha256.Sum256(tpm2.Marshal(*ak))
	assert.Equal(t, append([]byte{0x00, 0x0b}, digest[:]...), name.Buffer, "the AK name is 0x000b || SHA-256(TPMT_PUBLIC)")

	rsaEK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for label, ek := range map[string]crypto.PublicKey{
		"ecc ek": &tpmtECKey(t).PublicKey,
		"rsa ek": &rsaEK.PublicKey,
	} {
		t.Run(label, func(t *testing.T) {
			secret := bytes.Repeat([]byte{7}, tpmSecretLen)
			ch, err := activationChallenge(ak, ek, secret)
			require.NoError(t, err)
			// Both are marshalled TPM2B structures: a 2-byte size, then that many bytes.
			require.Greater(t, len(ch.CredentialBlob), 2)
			require.Greater(t, len(ch.EncryptedSecret), 2)
			assert.Equal(t, len(ch.CredentialBlob)-2, int(ch.CredentialBlob[0])<<8|int(ch.CredentialBlob[1]))
			assert.Equal(t, len(ch.EncryptedSecret)-2, int(ch.EncryptedSecret[0])<<8|int(ch.EncryptedSecret[1]))
			assert.False(t, bytes.Contains(ch.CredentialBlob, secret), "the secret is not in the clear")

			again, err := activationChallenge(ak, ek, secret)
			require.NoError(t, err)
			assert.NotEqual(t, ch.CredentialBlob, again.CredentialBlob, "every challenge uses a fresh seed")
		})
	}

	t.Run("refuses a key type a TPM does not hold as an endorsement key", func(t *testing.T) {
		edPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, err = activationChallenge(ak, edPub, bytes.Repeat([]byte{7}, tpmSecretLen))
		require.Error(t, err)
	})
}

func TestEKIdentity(t *testing.T) {
	pki := newTPMTestPKI(t)
	ek := tpmtECKey(t)

	parse := func(der []byte) *x509.Certificate {
		c, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return c
	}

	t.Run("reads the TCG device attributes, issuer, serial and key hash", func(t *testing.T) {
		cert := parse(pki.ekCert(t, &ek.PublicKey, true, time.Now().Add(time.Hour)))
		rec, err := ekIdentity(cert)
		require.NoError(t, err)
		assert.Equal(t, "id:41434D45", rec.EKManufacturer)
		assert.Equal(t, "ACME-TPM-2", rec.EKModel)
		assert.Equal(t, "id:00070002", rec.EKFirmware)
		assert.Equal(t, pki.inter.Subject.String(), rec.EKIssuer)
		assert.Equal(t, cert.SerialNumber.Text(16), rec.EKSerial)
		der, err := x509.MarshalPKIXPublicKey(&ek.PublicKey)
		require.NoError(t, err)
		sum := sha256.Sum256(der)
		assert.Equal(t, hex.EncodeToString(sum[:]), rec.EKPublicSHA256)
	})

	t.Run("a certificate without attributes still records issuer, serial and key hash", func(t *testing.T) {
		cert := parse(pki.ekCert(t, &ek.PublicKey, false, time.Now().Add(time.Hour)))
		rec, err := ekIdentity(cert)
		require.NoError(t, err)
		assert.Empty(t, rec.EKManufacturer)
		assert.Empty(t, rec.EKModel)
		assert.Empty(t, rec.EKFirmware)
		assert.NotEmpty(t, rec.EKIssuer)
		assert.NotEmpty(t, rec.EKSerial)
		assert.Len(t, rec.EKPublicSHA256, 64)
	})
}

func tpmtBeginRequest(t *testing.T, chain [][]byte, ak []byte) *tpmBeginRequest {
	t.Helper()
	var req tpmBeginRequest
	body, err := json.Marshal(map[string]any{"tpm": map[string]any{"ek_cert_chain": chain, "ak_public": ak}})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &req))
	return &req
}

func TestNewTPMRegistration(t *testing.T) {
	pki := newTPMTestPKI(t)
	ek := tpmtECKey(t)
	leaf := pki.ekCert(t, &ek.PublicKey, true, time.Now().Add(24*time.Hour))
	ak := tpmtAKPublic(t, &tpmtECKey(t).PublicKey, nil)
	chain := [][]byte{leaf, pki.inter.Raw}
	now := time.Now()

	t.Run("builds the challenge and the session state", func(t *testing.T) {
		reg, reason := newTPMRegistration(tpmtBeginRequest(t, chain, ak), pki.rootPool(), now)
		require.Empty(t, reason)
		assert.NotEmpty(t, reg.challenge.CredentialBlob)
		assert.NotEmpty(t, reg.challenge.EncryptedSecret)
		assert.Len(t, reg.state.SecretSHA256, sha256.Size)
		assert.Equal(t, ak, reg.state.AKPublic)
		assert.Equal(t, "ACME-TPM-2", reg.state.EK.EKModel)
		assert.True(t, reg.state.EK.VerifiedAt.IsZero(), "verification time is set at finish")

		other, _ := newTPMRegistration(tpmtBeginRequest(t, chain, ak), pki.rootPool(), now)
		assert.NotEqual(t, reg.state.SecretSHA256, other.state.SecretSHA256, "a fresh secret per begin")
	})

	refusals := []struct {
		name  string
		req   *tpmBeginRequest
		roots *x509.CertPool
		want  string
	}{
		{"no trusted roots", tpmtBeginRequest(t, chain, ak), nil, reasonTPMNoTrustedRoots},
		{"an EK chain to an unknown root", tpmtBeginRequest(t, chain, ak), newTPMTestPKI(t).rootPool(), reasonTPMEKChain},
		{"a missing intermediate", tpmtBeginRequest(t, [][]byte{leaf}, ak), pki.rootPool(), reasonTPMEKChain},
		{"an invalid attestation key", tpmtBeginRequest(t, chain, tpmtAKPublic(t, &tpmtECKey(t).PublicKey, func(p *tpm2.TPMTPublic) {
			p.ObjectAttributes.FixedTPM = false
		})), pki.rootPool(), reasonTPMAKTemplate},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			reg, reason := newTPMRegistration(tt.req, tt.roots, now)
			assert.Nil(t, reg)
			assert.Equal(t, tt.want, reason)
		})
	}
}

func TestReadTPMBeginRequest(t *testing.T) {
	read := func(body string) (*tpmBeginRequest, error) {
		req := httptest.NewRequest(http.MethodPost, "/begin", strings.NewReader(body))
		return readTPMBeginRequest(httptest.NewRecorder(), req)
	}
	good := `{"tpm":{"ek_cert_chain":["AQID"],"ak_public":"BAUG"}}`

	req, err := read(good)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{{1, 2, 3}}, req.TPM.EKCertChain, "standard base64")
	assert.Equal(t, []byte{4, 5, 6}, req.TPM.AKPublic)

	for name, body := range map[string]string{
		"an empty body":              "",
		"not JSON":                   "not json",
		"no tpm member":              `{}`,
		"no chain":                   `{"tpm":{"ak_public":"BAUG"}}`,
		"no attestation key":         `{"tpm":{"ek_cert_chain":["AQID"]}}`,
		"an empty chain":             `{"tpm":{"ek_cert_chain":[],"ak_public":"BAUG"}}`,
		"invalid base64":             `{"tpm":{"ek_cert_chain":["!!"],"ak_public":"BAUG"}}`,
		"a body over the 64 KiB cap": `{"tpm":{"ek_cert_chain":["` + strings.Repeat("A", tpmBeginBodyLimit) + `"],"ak_public":"BAUG"}}`,
	} {
		_, err := read(body)
		assert.Error(t, err, name)
	}

	noBody := httptest.NewRequest(http.MethodPost, "/begin", nil)
	noBody.Body = nil
	_, err = readTPMBeginRequest(httptest.NewRecorder(), noBody)
	assert.Error(t, err, "a nil body")
}

// tpmtStatement is a registration built by the software authenticator with a
// hand-made "tpm" statement, so checkTPMAttestation can be driven through every
// refusal without a TPM. The library's own verification is not run: it is what the
// real ceremonies in the simulator-backed tests exercise.
type tpmtStatement struct {
	akKey      *ecdsa.PublicKey // key in x5c[0]
	activation []byte
	pubArea    *tpm2.TPMTPublic
}

type tpmtFakeAttester struct{ stmt *softauthn.TPMStatement }

func (f tpmtFakeAttester) AttestTPM(_, _ []byte) (*softauthn.TPMStatement, error) {
	s := *f.stmt
	return &s, nil
}

func tpmtCredentialArea(mutate func(*tpm2.TPMTPublic)) *tpm2.TPMTPublic {
	area := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, SignEncrypt: true,
		},
	}
	if mutate != nil {
		mutate(area)
	}
	return area
}

// tpmtCredential registers with the statement in st and returns the credential the
// library would hand the controller.
func tpmtCredential(t *testing.T, st tpmtStatement) *webauthn.Credential {
	t.Helper()
	carrierKey := tpmtECKey(t)
	carrierTmpl := &x509.Certificate{SerialNumber: tpmtSerial(t), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	carrier, err := x509.CreateCertificate(rand.Reader, carrierTmpl, carrierTmpl, st.akKey, carrierKey)
	require.NoError(t, err)

	credKey := tpmtECKey(t)
	credID := make([]byte, 32)
	_, err = rand.Read(credID)
	require.NoError(t, err)
	a, err := softauthn.New(softauthn.Config{
		Signer: credKey, RPID: aaguidRPID, Origin: aaguidOrigin, CredentialID: credID,
		Attester: tpmtFakeAttester{stmt: &softauthn.TPMStatement{
			X5C: [][]byte{carrier}, Sig: []byte{1}, CertInfo: []byte{2},
			PubArea: tpm2.Marshal(*st.pubArea), Activation: st.activation,
		}},
	})
	require.NoError(t, err)

	wa, err := NewWebAuthnFromConfig(aaguidRPID, aaguidRPID, []string{aaguidOrigin})
	require.NoError(t, err)
	creation, _, err := wa.BeginRegistration(&webauthnUser{id: []byte("agent"), name: "agent", displayName: "agent"})
	require.NoError(t, err)
	opts, err := json.Marshal(creation)
	require.NoError(t, err)
	resp, err := a.Register(opts)
	require.NoError(t, err)
	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	require.NoError(t, err)
	return &webauthn.Credential{
		AttestationFormat: parsed.Response.AttestationObject.Format,
		Attestation:       webauthn.CredentialAttestation{Object: parsed.Raw.AttestationResponse.AttestationObject},
	}
}

func TestCheckTPMAttestation(t *testing.T) {
	akKey := tpmtECKey(t)
	secret := bytes.Repeat([]byte{9}, tpmSecretLen)
	digest := sha256.Sum256(secret)
	now := time.Now().UTC()
	state := &tpmActivationState{
		SecretSHA256: digest[:],
		AKPublic:     tpmtAKPublic(t, &akKey.PublicKey, nil),
		EK:           TPMAttestationRecord{EKManufacturer: "id:41434D45", EKIssuer: "CN=acme-corp", EKSerial: "ab", EKPublicSHA256: "cd"},
	}
	good := tpmtStatement{akKey: &akKey.PublicKey, activation: secret, pubArea: tpmtCredentialArea(nil)}

	t.Run("accepts a statement that meets every requirement and records the EK identity", func(t *testing.T) {
		rec, reason := checkTPMAttestation(tpmtCredential(t, good), state, now)
		require.Empty(t, reason)
		require.NotNil(t, rec)
		assert.Equal(t, "id:41434D45", rec.EKManufacturer)
		assert.Equal(t, "CN=acme-corp", rec.EKIssuer)
		assert.Equal(t, now, rec.VerifiedAt)
		assert.True(t, state.EK.VerifiedAt.IsZero(), "the session state is not modified")
	})

	t.Run("refuses a statement whose x5c[0] holds another key than the begin AK", func(t *testing.T) {
		bad := good
		bad.akKey = &tpmtECKey(t).PublicKey
		rec, reason := checkTPMAttestation(tpmtCredential(t, bad), state, now)
		assert.Nil(t, rec)
		assert.Equal(t, reasonTPMAKMismatch, reason)
	})

	t.Run("refuses a wrong, truncated or missing activation secret", func(t *testing.T) {
		for name, activation := range map[string][]byte{
			"wrong":     bytes.Repeat([]byte{8}, tpmSecretLen),
			"truncated": secret[:tpmSecretLen-1],
			"one bit":   append([]byte{secret[0] ^ 1}, secret[1:]...),
		} {
			bad := good
			bad.activation = activation
			_, reason := checkTPMAttestation(tpmtCredential(t, bad), state, now)
			assert.Equal(t, reasonTPMActivationFailed, reason, name)
		}
	})

	t.Run("refuses a certified key that is not fixed to the TPM, its parent, TPM-generated and sign-only", func(t *testing.T) {
		for name, mutate := range map[string]func(*tpm2.TPMTPublic){
			"no fixedTPM":            func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false },
			"no fixedParent":         func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedParent = false },
			"no sensitiveDataOrigin": func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SensitiveDataOrigin = false },
			"cannot sign":            func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SignEncrypt = false },
			"can also decrypt":       func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Decrypt = true },
		} {
			bad := good
			bad.pubArea = tpmtCredentialArea(mutate)
			rec, reason := checkTPMAttestation(tpmtCredential(t, bad), state, now)
			assert.Nil(t, rec, name)
			assert.Equal(t, reasonTPMKeyNotFixed, reason, name)
		}
	})

	t.Run("refuses another attestation format", func(t *testing.T) {
		cred := tpmtCredential(t, good)
		cred.AttestationFormat = "none"
		_, reason := checkTPMAttestation(cred, state, now)
		assert.Equal(t, reasonTPMAttestationFormat, reason)
	})

	t.Run("refuses an attestation object that does not decode", func(t *testing.T) {
		cred := tpmtCredential(t, good)
		cred.Attestation.Object = []byte{0xff, 0x00}
		_, reason := checkTPMAttestation(cred, state, now)
		assert.Equal(t, reasonTPMAttestationInvalid, reason)
	})

	t.Run("refuses a session state it cannot read", func(t *testing.T) {
		broken := *state
		broken.AKPublic = []byte("garbage")
		_, reason := checkTPMAttestation(tpmtCredential(t, good), &broken, now)
		assert.Equal(t, reasonTPMAttestationInvalid, reason)
	})
}

func TestSetRootAgentTPMRoots(t *testing.T) {
	server := setupTestServer(t)
	assert.Nil(t, server.getRootAgentTPMRoots(), "no roots until configured")

	pki := newTPMTestPKI(t)
	server.SetRootAgentTPMRoots(pki.rootPool())
	assert.NotNil(t, server.getRootAgentTPMRoots())

	server.SetRootAgentTPMRoots(x509.NewCertPool())
	assert.Nil(t, server.getRootAgentTPMRoots(), "an empty pool is no roots")

	server.SetRootAgentTPMRoots(pki.rootPool())
	server.SetRootAgentTPMRoots(nil)
	assert.Nil(t, server.getRootAgentTPMRoots(), "nil clears the roots")
}

// The record is written by the server and read back from the real account store: the
// credential list is stored in the account record, so the new field must survive the
// encode and decode in handlers_accounts.go.
func TestTPMAttestationRecord_PersistsThroughTheAccountStore(t *testing.T) {
	server := setupTestServer(t)
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: "tpm-persist", RootScope: true})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	ctx := context.Background()
	acct, err := server.loadAccountFromStore(ctx, "tpm-persist", "")
	require.NoError(t, err)
	require.NotNil(t, acct)
	verified := time.Now().UTC().Truncate(time.Second)
	attested := WebAuthnCredential{
		ID: []byte("attested"), PublicKey: []byte("pk"), RegisteredAt: verified,
		AAGUID: append([]byte(nil), softauthn.AAGUID[:]...), AttestationFormat: "tpm",
		TPMAttestation: &TPMAttestationRecord{
			EKManufacturer: "id:41434D45", EKModel: "ACME-TPM-2", EKFirmware: "id:00070002",
			EKIssuer: "CN=acme-corp tpm intermediate", EKSerial: "1f2e3d", EKPublicSHA256: strings.Repeat("ab", 32),
			VerifiedAt: verified,
		},
	}
	plain := WebAuthnCredential{ID: []byte("plain"), PublicKey: []byte("pk2"), RegisteredAt: verified}
	acct.Credentials = []WebAuthnCredential{attested, plain}
	require.NoError(t, server.persistAccount(ctx, acct, "test"))
	dropAccountCache(server)

	got, err := server.loadAccountFromStore(ctx, "tpm-persist", "")
	require.NoError(t, err)
	require.Len(t, got.Credentials, 2)
	assert.True(t, got.Credentials[0].tpmAttested())
	assert.Equal(t, attested.TPMAttestation, got.Credentials[0].TPMAttestation)
	assert.False(t, got.Credentials[1].tpmAttested(), "absent record means not attested")
	assert.Nil(t, got.Credentials[1].TPMAttestation)
}

func TestWebAuthnPendingSession_TPMActivationSurvivesTheClusterWireForm(t *testing.T) {
	pending := &webAuthnPendingSession{
		data:    webauthn.SessionData{Challenge: "c"},
		expires: time.Now().Add(webAuthnSessionTTL).UTC(),
		binding: "actor",
		tpmActivation: &tpmActivationState{
			SecretSHA256: bytes.Repeat([]byte{3}, sha256.Size),
			AKPublic:     []byte{1, 2, 3},
			EK:           TPMAttestationRecord{EKIssuer: "CN=acme-corp", EKSerial: "1", EKPublicSHA256: "ff"},
		},
	}
	raw, err := json.Marshal(pending.toWire())
	require.NoError(t, err)
	var wire webAuthnPendingWire
	require.NoError(t, json.Unmarshal(raw, &wire))
	back := wire.toSession()
	assert.Equal(t, pending.tpmActivation, back.tpmActivation, "a ceremony survives a node change")

	plain := (&webAuthnPendingSession{data: webauthn.SessionData{Challenge: "c"}}).toWire()
	raw, err = json.Marshal(plain)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "tpm_activation", "an ordinary session carries no TPM state")
	assert.Nil(t, plain.toSession().tpmActivation)
}

func TestRegistrationAuditDetails_CarryTheEKIdentityOfAnAttestedCredential(t *testing.T) {
	rec := &TPMAttestationRecord{
		EKManufacturer: "id:41434D45", EKModel: "ACME-TPM-2", EKFirmware: "id:00070002",
		EKIssuer: "CN=acme-corp", EKSerial: "1f", EKPublicSHA256: "ab",
	}
	got := registrationAuditDetails(map[string]interface{}{}, &WebAuthnCredential{TPMAttestation: rec})
	assert.Equal(t, true, got["tpm_attested"])
	assert.Equal(t, "id:41434D45", got["ek_manufacturer"])
	assert.Equal(t, "ACME-TPM-2", got["ek_model"])
	assert.Equal(t, "id:00070002", got["ek_firmware"])
	assert.Equal(t, "CN=acme-corp", got["ek_issuer"])
	assert.Equal(t, "1f", got["ek_serial"])
	assert.Equal(t, "ab", got["ek_public_sha256"])

	plain := registrationAuditDetails(map[string]interface{}{}, &WebAuthnCredential{})
	assert.NotContains(t, plain, "tpm_attested", "an unattested credential carries no TPM facts")
	assert.NotContains(t, plain, "ek_serial")
}

func TestTPMRegistrationOptions_RequestDirectAttestation(t *testing.T) {
	wa, err := NewWebAuthnFromConfig(aaguidRPID, aaguidRPID, []string{aaguidOrigin})
	require.NoError(t, err)
	user := &webauthnUser{id: []byte("a"), name: "a", displayName: "a"}

	direct, _, err := wa.BeginRegistration(user, tpmRegistrationOptions()...)
	require.NoError(t, err)
	assert.Equal(t, protocol.PreferDirectAttestation, direct.Response.Attestation)

	plain, _, err := wa.BeginRegistration(user)
	require.NoError(t, err)
	assert.NotEqual(t, protocol.PreferDirectAttestation, plain.Response.Attestation, "the library default is unchanged")
}

func TestTPMRegistrationResponseBody_AddsOnlyTheCfgmsTpmMember(t *testing.T) {
	wa, err := NewWebAuthnFromConfig(aaguidRPID, aaguidRPID, []string{aaguidOrigin})
	require.NoError(t, err)
	creation, _, err := wa.BeginRegistration(&webauthnUser{id: []byte("a"), name: "a", displayName: "a"}, tpmRegistrationOptions()...)
	require.NoError(t, err)

	reg := &tpmRegistration{challenge: tpmChallenge{CredentialBlob: []byte{1, 2}, EncryptedSecret: []byte{3, 4}}}
	body, err := reg.responseBody(creation)
	require.NoError(t, err)

	raw, err := json.Marshal(body)
	require.NoError(t, err)
	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Contains(t, decoded, "publicKey", "the creation options are unchanged")
	require.Contains(t, decoded, "cfgmsTpm")
	assert.JSONEq(t, `{"credential_blob":"AQI=","encrypted_secret":"AwQ="}`, string(decoded["cfgmsTpm"]))

	var opts struct {
		PublicKey struct {
			Attestation string `json:"attestation"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(raw, &opts))
	assert.Equal(t, "direct", opts.PublicKey.Attestation)
}
