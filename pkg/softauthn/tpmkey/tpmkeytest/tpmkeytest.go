// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux && cgo

// Package tpmkeytest starts a software TPM 2.0 for tests of code that uses
// pkg/softauthn/tpmkey. It is imported from _test.go files only.
//
// Start provisions the TPM the way a platform vendor does: it derives the
// endorsement key, issues an EK certificate for it from a test CA generated at
// test time, and writes that certificate to the TCG EK certificate NV index.
// The CA certificate is returned so a test verifier can trust it. Nothing here
// is committed key material.
//
// The wrong-output helpers (KeyWithoutFixedTPM, TamperedActivation,
// OtherKeyAttester) exist so a verifier's negative tests can produce
// attestations a correct client never would. The production tpmkey API has no
// such options.
package tpmkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/softauthn/tpmkey"
)

// Manufacturer is the TPM_PT_MANUFACTURER string the software TPM reports, in the
// "id:" form of a TCG device attribute ("MSFT").
const Manufacturer = "id:4D534654"

const (
	ekRSACertIndex tpm2.TPMHandle = 0x01C00002
	ekECCCertIndex tpm2.TPMHandle = 0x01C0000A
	nvWriteChunk                  = 256
	simulatorSeed                 = 1
)

var (
	oidEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	oidManufacturer  = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidModel         = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidVersion       = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	oidSAN           = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// Options selects how the software TPM is provisioned. The zero value gives an
// ECC P-256 endorsement key whose certificate carries TCG device attributes.
type Options struct {
	// RSAEK provisions an RSA 2048 endorsement key and certificate instead of
	// ECC P-256. Creating it takes noticeably longer.
	RSAEK bool
	// NoEKCertificate leaves the EK certificate NV index undefined.
	NoEKCertificate bool
	// NoEKAttributes issues an EK certificate with no TCG device attributes, so
	// the carrier certificate must take them from the TPM's own properties.
	NoEKAttributes bool
}

// TPM is a running software TPM. It is a transport.TPMCloser whose Close does
// nothing, so state survives between operations as it does on a real device;
// the simulator itself stops when the test ends.
type TPM struct {
	sim *simulator.Simulator
	// CA is the test CA that issued the EK certificate.
	CA *x509.Certificate
	// EKCertificate is the DER EK certificate written to NV, or nil.
	EKCertificate []byte
}

var _ transport.TPMCloser = (*TPM)(nil)

// Send implements transport.TPM.
func (s *TPM) Send(in []byte) ([]byte, error) { return tpmutil.RunCommandRaw(s.sim, in) }

// Close implements io.Closer and does nothing.
func (s *TPM) Close() error { return nil }

func (s *TPM) shutdown() {
	if !s.sim.IsClosed() {
		_ = s.sim.Close()
	}
}

// Start starts a software TPM with a fixed seed. Only one software TPM exists
// at a time; a second Start blocks until the first test's TPM has stopped.
func Start(tb testing.TB, opts Options) *TPM {
	tb.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(simulatorSeed)
	require.NoError(tb, err)
	s := &TPM{sim: sim}
	tb.Cleanup(s.shutdown)
	s.provision(tb, opts)
	return s
}

func (s *TPM) provision(tb testing.TB, opts Options) {
	tb.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	// Test-only EK CA for the simulator, not a TLS certificate: pkg/cert.Manager
	// cannot issue the TPM endorsement certificate profile.
	var caTemplate x509.Certificate
	caTemplate.SerialNumber = serial(tb)
	caTemplate.Subject = pkix.Name{CommonName: "tpmkeytest EK CA"}
	caTemplate.NotBefore = time.Now().Add(-time.Hour)
	caTemplate.NotAfter = time.Now().Add(24 * time.Hour)
	caTemplate.IsCA = true
	caTemplate.BasicConstraintsValid = true
	caTemplate.KeyUsage = x509.KeyUsageCertSign
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	require.NoError(tb, err)
	s.CA, err = x509.ParseCertificate(caDER)
	require.NoError(tb, err)
	if opts.NoEKCertificate {
		return
	}

	template, index := tpm2.ECCEKTemplate, ekECCCertIndex
	if opts.RSAEK {
		template, index = tpm2.RSAEKTemplate, ekRSACertIndex
	}
	ek, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHEndorsement, InPublic: tpm2.New2B(template)}.Execute(s)
	require.NoError(tb, err)
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: ek.ObjectHandle}.Execute(s) }()
	pt, err := ek.OutPublic.Contents()
	require.NoError(tb, err)

	var ekPub any
	if opts.RSAEK {
		parms, pErr := pt.Parameters.RSADetail()
		require.NoError(tb, pErr)
		mod, mErr := pt.Unique.RSA()
		require.NoError(tb, mErr)
		ekPub, err = tpm2.RSAPub(parms, mod)
	} else {
		parms, pErr := pt.Parameters.ECCDetail()
		require.NoError(tb, pErr)
		point, uErr := pt.Unique.ECC()
		require.NoError(tb, uErr)
		ekPub, err = tpm2.ECDSAPub(parms, point)
	}
	require.NoError(tb, err)

	var ekTemplate x509.Certificate
	ekTemplate.SerialNumber = serial(tb)
	ekTemplate.NotBefore = time.Now().Add(-time.Hour)
	ekTemplate.NotAfter = time.Now().Add(24 * time.Hour)
	ekTemplate.KeyUsage = x509.KeyUsageKeyEncipherment
	ekTemplate.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidEKCertificate}
	if !opts.NoEKAttributes {
		ekTemplate.ExtraExtensions = []pkix.Extension{attributesExtension(tb)}
	}
	s.EKCertificate, err = x509.CreateCertificate(rand.Reader, &ekTemplate, s.CA, ekPub, caKey)
	require.NoError(tb, err)
	s.writeNV(tb, index, s.EKCertificate)
}

func serial(tb testing.TB) *big.Int {
	tb.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	require.NoError(tb, err)
	return n
}

// attributesExtension is the EK certificate's subject alternative name with the
// TCG manufacturer, model and version attributes.
func attributesExtension(tb testing.TB) pkix.Extension {
	tb.Helper()
	dn, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: oidManufacturer, Value: Manufacturer}},
		{{Type: oidModel, Value: "id:00000000"}},
		{{Type: oidVersion, Value: "id:20260101"}},
	})
	require.NoError(tb, err)
	name, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: dn})
	require.NoError(tb, err)
	value, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: name})
	require.NoError(tb, err)
	return pkix.Extension{Id: oidSAN, Critical: true, Value: value}
}

// writeNV defines an owner-writable, owner- and auth-readable index and fills it.
func (s *TPM) writeNV(tb testing.TB, index tpm2.TPMHandle, data []byte) {
	tb.Helper()
	_, err := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    index,
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, AuthRead: true, NoDA: true, NT: tpm2.TPMNTOrdinary},
			DataSize:   uint16(len(data)), //#nosec G115 -- a certificate is a few hundred bytes
		}),
	}.Execute(s)
	require.NoError(tb, err)
	pub, err := tpm2.NVReadPublic{NVIndex: index}.Execute(s)
	require.NoError(tb, err)
	for off := 0; off < len(data); off += nvWriteChunk {
		end := min(off+nvWriteChunk, len(data))
		_, err = tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: index, Name: pub.NVName},
			Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data[off:end]},
			Offset:     uint16(off), //#nosec G115 -- off is below the certificate length
		}.Execute(s)
		require.NoError(tb, err)
	}
}

// UndefineEKCertificate removes the EK certificate from NV storage, as if the
// TPM had never been provisioned with one.
func (s *TPM) UndefineEKCertificate(tb testing.TB) {
	tb.Helper()
	for _, index := range []tpm2.TPMHandle{ekRSACertIndex, ekECCCertIndex} {
		pub, err := tpm2.NVReadPublic{NVIndex: index}.Execute(s)
		if err != nil {
			continue
		}
		_, err = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.TPMRHOwner,
			NVIndex:    tpm2.NamedHandle{Handle: index, Name: pub.NVName},
		}.Execute(s)
		require.NoError(tb, err)
	}
	s.EKCertificate = nil
}

// KeyWithoutFixedTPM makes a credential key under the same storage primary
// tpmkey uses, but without fixedTPM and fixedParent, so a TPM could duplicate
// it. tpmkey.Open and tpmkey.Attest accept its blobs; a verifier must not.
func KeyWithoutFixedTPM(t transport.TPM) (tpmkey.Blobs, error) {
	prim, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(t)
	if err != nil {
		return tpmkey.Blobs{}, err
	}
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: prim.ObjectHandle}.Execute(t) }()
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: prim.ObjectHandle, Name: prim.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				NoDA:                true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
				},
				CurveID: tpm2.TPMECCNistP256,
			}),
		}),
	}.Execute(t)
	if err != nil {
		return tpmkey.Blobs{}, err
	}
	return tpmkey.Blobs{Public: tpm2.Marshal(rsp.OutPublic), Private: tpm2.Marshal(rsp.OutPrivate)}, nil
}

// tamperedActivation wraps an Attester and flips a bit of the activation secret.
type tamperedActivation struct{ inner softauthn.Attester }

// TamperedActivation returns an Attester that produces the inner attester's
// statement with the activation secret altered by one bit.
func TamperedActivation(inner softauthn.Attester) softauthn.Attester {
	return &tamperedActivation{inner: inner}
}

func (a *tamperedActivation) AttestTPM(authData, clientDataHash []byte) (*softauthn.TPMStatement, error) {
	stmt, err := a.inner.AttestTPM(authData, clientDataHash)
	if err != nil {
		return nil, err
	}
	if len(stmt.Activation) == 0 {
		return nil, errors.New("tpmkeytest: no activation secret to tamper with")
	}
	stmt.Activation = append([]byte(nil), stmt.Activation...)
	stmt.Activation[0] ^= 0x01
	return stmt, nil
}

// OtherKeyAttester returns an Attester that certifies the key in other instead
// of the credential key the authenticator registers, so the statement's
// certInfo and pubArea describe a different key than the one in authData.
func OtherKeyAttester(t transport.TPM, other tpmkey.Blobs, secret []byte) softauthn.Attester {
	return tpmkey.NewAttester(t, other, secret)
}
