// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package tpmkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/cfgis/cfgms/pkg/softauthn"
)

var (
	// TCG object identifiers used in an AIK certificate (TPMv2-EK-Profile 3.2.9
	// for the SAN attributes, WebAuthn 8.3.1 for the EKU).
	oidTCGAIKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
	oidTCGManufacturer   = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTCGModel          = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTCGVersion        = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	oidSubjectAltName    = asn1.ObjectIdentifier{2, 5, 29, 17}

	// carrierValidityBefore and carrierValidityAfter bracket "now" so the
	// carrier certificate is valid despite small clock differences.
	carrierValidityBefore = 10 * time.Minute
	carrierValidityAfter  = time.Hour
)

// attestationKeyTemplate is the attestation key: an ECC NIST P-256 restricted
// signing key, fixedTPM, fixedParent and sensitiveDataOrigin. It is created as
// an endorsement-hierarchy primary, so the same template always yields the same
// key on a given TPM and nothing needs to be persisted.
func attestationKeyTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			SignEncrypt:         true,
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
	}
}

// withAttestationKey derives the attestation key, runs fn with its handle and
// public area, and flushes it.
func withAttestationKey(t transport.TPM, fn func(ak tpm2.AuthHandle, pub *tpm2.TPMTPublic) error) error {
	prim, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(attestationKeyTemplate()),
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("create attestation key: %w", err)
	}
	defer flush(t, prim.ObjectHandle)
	pub, err := prim.OutPublic.Contents()
	if err != nil {
		return fmt.Errorf("decode attestation key: %w", err)
	}
	return fn(passwordAuth(prim.ObjectHandle, prim.Name), pub)
}

// Attest certifies the credential key in b for one registration. The TPM
// signs, with the attestation key, a TPM2_Certify structure over the credential
// key whose qualifying data is SHA-256(authData || clientDataHash). The
// returned statement carries a carrier certificate for the attestation key (see
// carrierCertificate) and the activation secret recovered by Activate.
func Attest(t transport.TPM, b Blobs, authData, clientDataHash, secret []byte) (*softauthn.TPMStatement, error) {
	if len(authData) == 0 || len(clientDataHash) == 0 || len(secret) == 0 {
		return nil, errors.New("attest needs authenticator data, a client data hash and the activation secret")
	}
	pubArea, err := publicArea(b.Public)
	if err != nil {
		return nil, err
	}
	qualifying := sha256.Sum256(append(append([]byte(nil), authData...), clientDataHash...))

	var stmt *softauthn.TPMStatement
	err = withLoadedKey(t, b, func(key tpm2.AuthHandle) error {
		return withAttestationKey(t, func(ak tpm2.AuthHandle, akPub *tpm2.TPMTPublic) error {
			rsp, cErr := tpm2.Certify{
				ObjectHandle:   key,
				SignHandle:     ak,
				QualifyingData: tpm2.TPM2BData{Buffer: qualifying[:]},
				InScheme: tpm2.TPMTSigScheme{
					Scheme:  tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
				},
			}.Execute(t)
			if cErr != nil {
				return fmt.Errorf("certify credential key: %w", cErr)
			}
			sig, dErr := ecdsaDER(rsp.Signature)
			if dErr != nil {
				return dErr
			}
			akKey, kErr := eccPublicKey(akPub, tpm2.TPMECCNistP256)
			if kErr != nil {
				return kErr
			}
			carrier, cErr := carrierCertificate(akKey, deviceAttributes(t))
			if cErr != nil {
				return cErr
			}
			stmt = &softauthn.TPMStatement{
				X5C:        [][]byte{carrier},
				Sig:        sig,
				CertInfo:   append([]byte(nil), rsp.CertifyInfo.Bytes()...),
				PubArea:    pubArea,
				Activation: append([]byte(nil), secret...),
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return stmt, nil
}

// publicArea returns the marshalled TPMT_PUBLIC inside a marshalled TPM2B_PUBLIC,
// byte for byte as the TPM produced it (its Name is hashed from these bytes).
func publicArea(publicBlob []byte) ([]byte, error) {
	p2b, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return nil, fmt.Errorf("decode key public area: %w", err)
	}
	return append([]byte(nil), p2b.Bytes()...), nil
}

// attester adapts Attest to softauthn.Attester for one registration.
type attester struct {
	t      transport.TPM
	blobs  Blobs
	secret []byte
}

// NewAttester returns the softauthn.Attester for a registration whose
// activation secret was recovered by Activate. The caller keeps t open until
// Register returns.
func NewAttester(t transport.TPM, b Blobs, secret []byte) softauthn.Attester {
	return &attester{t: t, blobs: b, secret: append([]byte(nil), secret...)}
}

// AttestTPM implements softauthn.Attester.
func (a *attester) AttestTPM(authData, clientDataHash []byte) (*softauthn.TPMStatement, error) {
	return Attest(a.t, a.blobs, authData, clientDataHash, a.secret)
}

// tcgAttributes are the TCG device attributes an AIK certificate carries in its
// subject alternative name: strings such as "id:4D534654".
type tcgAttributes struct {
	manufacturer, model, version string
}

// deviceAttributes returns the attributes for the carrier certificate:
// manufacturer, model and version from the EK certificate when it carries them,
// otherwise derived from the TPM's fixed properties.
func deviceAttributes(t transport.TPM) tcgAttributes {
	var attrs tcgAttributes
	if der, _, err := readEKCertificate(t); err == nil {
		if cert, pErr := x509.ParseCertificate(der); pErr == nil {
			attrs = ekAttributes(cert)
		}
	}
	if attrs.manufacturer == "" {
		attrs.manufacturer = tpmPropertyID(t, tpm2.TPMPTManufacturer)
	}
	if attrs.model == "" {
		attrs.model = tpmPropertyID(t, tpm2.TPMPTVendorTPMType)
	}
	if attrs.version == "" {
		attrs.version = tpmPropertyID(t, tpm2.TPMPTFirmwareVersion1)
	}
	return attrs
}

// tpmPropertyID renders a TPM fixed property as the "id:XXXXXXXX" form TCG uses.
func tpmPropertyID(t transport.TPM, prop tpm2.TPMPT) string {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(prop),
		PropertyCount: 1,
	}.Execute(t)
	if err == nil {
		if props, pErr := rsp.CapabilityData.Data.TPMProperties(); pErr == nil &&
			len(props.TPMProperty) > 0 && props.TPMProperty[0].Property == prop {
			return fmt.Sprintf("id:%08X", props.TPMProperty[0].Value)
		}
	}
	return "id:00000000"
}

// ekAttributes reads the TCG device attributes from the directoryName in an EK
// certificate's subject alternative name. Missing attributes stay empty.
func ekAttributes(cert *x509.Certificate) tcgAttributes {
	var attrs tcgAttributes
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		for _, dn := range directoryNames(ext.Value) {
			attrs.merge(dn)
		}
	}
	return attrs
}

// directoryNames returns the directoryName entries of a subject alternative name
// extension value.
func directoryNames(san []byte) []pkix.RDNSequence {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(san, &seq); err != nil {
		return nil
	}
	var out []pkix.RDNSequence
	rest := seq.Bytes
	for len(rest) > 0 {
		var name asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &name); err != nil {
			break
		}
		if name.Class != asn1.ClassContextSpecific || name.Tag != 4 {
			continue
		}
		var rdns pkix.RDNSequence
		if _, err := asn1.Unmarshal(name.Bytes, &rdns); err == nil {
			out = append(out, rdns)
		}
	}
	return out
}

// merge takes the manufacturer, model and version string attributes from rdns.
func (a *tcgAttributes) merge(rdns pkix.RDNSequence) {
	for _, rdn := range rdns {
		for _, atv := range rdn {
			v, ok := atv.Value.(string)
			if !ok {
				continue
			}
			switch {
			case atv.Type.Equal(oidTCGManufacturer):
				a.manufacturer = v
			case atv.Type.Equal(oidTCGModel):
				a.model = v
			case atv.Type.Equal(oidTCGVersion):
				a.version = v
			}
		}
	}
}

// carrierCertificate builds the certificate that carries the attestation key's
// public key in x5c[0]. WebAuthn requires x5c[0] to have the AIK certificate
// profile (version 3, empty subject, a subject alternative name with the TCG
// device attributes, the AIK extended key usage, CA=false) and to verify the
// statement signature, so the profile is built here.
//
// It is signed by a throwaway key generated for this call and discarded, so it
// vouches for nothing: the verifier takes only the public key from it and
// establishes trust in that key through the activation challenge against the
// endorsement key certificate. Its validity brackets the present time only so
// that it parses as valid.
func carrierCertificate(ak *ecdsa.PublicKey, attrs tcgAttributes) ([]byte, error) {
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate carrier signing key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("generate carrier serial: %w", err)
	}
	san, err := deviceAttributesExtension(attrs)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	// Not a TLS or PKI certificate, so pkg/cert.Manager does not apply: the
	// WebAuthn tpm format needs this exact AIK profile around the AK public key.
	var template x509.Certificate
	template.SerialNumber = serial
	template.NotBefore = now.Add(-carrierValidityBefore)
	template.NotAfter = now.Add(carrierValidityAfter)
	template.BasicConstraintsValid = true
	template.IsCA = false
	template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidTCGAIKCertificate}
	template.ExtraExtensions = []pkix.Extension{san}
	var issuer x509.Certificate
	issuer.Subject = pkix.Name{CommonName: "cfgms tpm attestation carrier"}
	der, err := x509.CreateCertificate(rand.Reader, &template, &issuer, ak, throwaway)
	if err != nil {
		return nil, fmt.Errorf("build carrier certificate: %w", err)
	}
	return der, nil
}

// deviceAttributesExtension encodes the critical subject alternative name with
// a directoryName holding the TCG manufacturer, model and version attributes.
func deviceAttributesExtension(attrs tcgAttributes) (pkix.Extension, error) {
	dn, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: oidTCGManufacturer, Value: attrs.manufacturer}},
		{{Type: oidTCGModel, Value: attrs.model}},
		{{Type: oidTCGVersion, Value: attrs.version}},
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode device attributes: %w", err)
	}
	name, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: dn})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode device attributes: %w", err)
	}
	value, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: name})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode device attributes: %w", err)
	}
	// An empty subject requires the subject alternative name to be critical.
	return pkix.Extension{Id: oidSubjectAltName, Critical: true, Value: value}, nil
}
