// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package tpmkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ErrNoEKCertificate means the TPM holds no readable endorsement key
// certificate in NV storage, which this package requires.
var ErrNoEKCertificate = errors.New("the TPM has no readable endorsement key certificate in NV storage " +
	"(RSA 2048 at 0x01C00002 or ECC P-256 at 0x01C0000A)")

// TCG EK credential profile NV indices of the endorsement key certificate.
const (
	ekRSACertIndex tpm2.TPMHandle = 0x01C00002
	ekECCCertIndex tpm2.TPMHandle = 0x01C0000A

	// maxEKCertBytes bounds the NV read; real certificates are under 2 KiB.
	maxEKCertBytes = 8192
	// defaultNVBuffer is the NV transfer size when the TPM does not report one.
	// TPM_PT_NV_BUFFER_MAX is at least 512 on every platform TPM.
	defaultNVBuffer = 512
)

// ekSource describes one place an EK certificate may live and the template that
// re-derives the key the certificate was issued for.
type ekSource struct {
	index    tpm2.TPMHandle
	template tpm2.TPMTPublic
}

// ekSources lists the sources in the order they are tried.
func ekSources() []ekSource {
	return []ekSource{
		{index: ekRSACertIndex, template: tpm2.RSAEKTemplate},
		{index: ekECCCertIndex, template: tpm2.ECCEKTemplate},
	}
}

// Prepared is what the begin request carries and what Activate needs: the EK
// certificate chain and the attestation key's public area.
type Prepared struct {
	// EKCertChain is the DER EK certificate read from NV, then any intermediates.
	// The TPM stores only the EK certificate itself; intermediates are not
	// fetched, so the verifier is expected to hold them.
	EKCertChain [][]byte
	// AKPublic is the marshalled TPMT_PUBLIC of the attestation key.
	AKPublic []byte

	ek ekSource
}

// Prepare reads the EK certificate and derives the attestation key's public
// area. It returns ErrNoEKCertificate (wrapped) when the TPM has no readable EK
// certificate.
func Prepare(t transport.TPM) (*Prepared, error) {
	cert, src, err := readEKCertificate(t)
	if err != nil {
		return nil, err
	}
	var akPublic []byte
	err = withAttestationKey(t, func(_ tpm2.AuthHandle, pub *tpm2.TPMTPublic) error {
		akPublic = tpm2.Marshal(*pub)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Prepared{EKCertChain: [][]byte{cert}, AKPublic: akPublic, ek: src}, nil
}

// HasEKCertificate reports whether the TPM holds a readable EK certificate. It
// reads NV storage only, so it is cheap and creates no key.
func HasEKCertificate(t transport.TPM) error {
	_, _, err := readEKCertificate(t)
	return err
}

// readEKCertificate returns the DER EK certificate and its source.
func readEKCertificate(t transport.TPM) ([]byte, ekSource, error) {
	for _, src := range ekSources() {
		der, err := readNVCertificate(t, src.index)
		if err == nil {
			return der, src, nil
		}
		if !errors.Is(err, errNVAbsent) {
			return nil, ekSource{}, err
		}
	}
	return nil, ekSource{}, ErrNoEKCertificate
}

var errNVAbsent = errors.New("NV index is not defined")

// readNVCertificate reads the DER certificate stored at index. The index may be
// padded; only the leading DER element is returned, and it must parse.
func readNVCertificate(t transport.TPM, index tpm2.TPMHandle) ([]byte, error) {
	pubRsp, err := tpm2.NVReadPublic{NVIndex: index}.Execute(t)
	if err != nil {
		if errors.Is(err, tpm2.TPMRCHandle) {
			return nil, errNVAbsent
		}
		return nil, fmt.Errorf("read EK certificate index: %w", err)
	}
	nvPub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("decode EK certificate index: %w", err)
	}
	size := int(nvPub.DataSize)
	if size == 0 || size > maxEKCertBytes {
		return nil, ErrNoEKCertificate
	}
	data, err := readNV(t, index, pubRsp.NVName, size)
	if err != nil {
		return nil, err
	}
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(data, &first); err != nil {
		return nil, ErrNoEKCertificate
	}
	if _, err := x509.ParseCertificate(first.FullBytes); err != nil {
		return nil, ErrNoEKCertificate
	}
	return first.FullBytes, nil
}

// readNV reads size bytes from an NV index. The first chunk is tried with owner
// authorization and then with the index's own (empty) authorization, because
// which one a TPM accepts depends on how the platform provisioned the index.
func readNV(t transport.TPM, index tpm2.TPMHandle, name tpm2.TPM2BName, size int) ([]byte, error) {
	chunk := nvBufferMax(t)
	auths := []tpm2.AuthHandle{
		{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		{Handle: index, Name: name, Auth: tpm2.PasswordAuth(nil)},
	}
	var lastErr error
	for _, auth := range auths {
		out := make([]byte, 0, size)
		for len(out) < size {
			n := min(chunk, size-len(out))
			rsp, err := tpm2.NVRead{
				AuthHandle: auth,
				NVIndex:    tpm2.NamedHandle{Handle: index, Name: name},
				Size:       uint16(n),        //#nosec G115 -- n is bounded by the TPM's NV buffer size, a uint16-sized value
				Offset:     uint16(len(out)), //#nosec G115 -- len(out) < size <= maxEKCertBytes
			}.Execute(t)
			if err != nil {
				lastErr = err
				break
			}
			out = append(out, rsp.Data.Buffer...)
			if len(rsp.Data.Buffer) == 0 {
				lastErr = errors.New("TPM returned no NV data")
				break
			}
		}
		if len(out) >= size {
			return out[:size], nil
		}
	}
	return nil, fmt.Errorf("read EK certificate: %w", lastErr)
}

// nvBufferMax returns the TPM's NV transfer size, bounded to a sane range.
func nvBufferMax(t transport.TPM) int {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}.Execute(t)
	if err != nil {
		return defaultNVBuffer
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil || len(props.TPMProperty) == 0 || props.TPMProperty[0].Property != tpm2.TPMPTNVBufferMax {
		return defaultNVBuffer
	}
	v := int(props.TPMProperty[0].Value)
	if v < 64 || v > 1024 {
		return defaultNVBuffer
	}
	return v
}

// Activate runs TPM2_ActivateCredential for the controller's credential
// challenge and returns the recovered secret. The attestation key is the
// activated object and the endorsement key decrypts the challenge, authorized
// by PolicySecret(endorsement). credentialBlob and encryptedSecret are the
// marshalled TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET, each with its 2-byte
// size prefix. A challenge made for a different AK or EK fails in the TPM.
func Activate(t transport.TPM, p *Prepared, credentialBlob, encryptedSecret []byte) ([]byte, error) {
	if p == nil || len(p.EKCertChain) == 0 {
		return nil, errors.New("activate needs the result of Prepare")
	}
	idObject, err := tpm2.Unmarshal[tpm2.TPM2BIDObject](credentialBlob)
	if err != nil {
		return nil, errors.New("the credential blob is not a TPM2B_ID_OBJECT")
	}
	secret, err := tpm2.Unmarshal[tpm2.TPM2BEncryptedSecret](encryptedSecret)
	if err != nil {
		return nil, errors.New("the encrypted secret is not a TPM2B_ENCRYPTED_SECRET")
	}

	var recovered []byte
	err = withEndorsementKey(t, p, func(ek tpm2.AuthHandle) error {
		return withAttestationKey(t, func(ak tpm2.AuthHandle, _ *tpm2.TPMTPublic) error {
			rsp, aErr := tpm2.ActivateCredential{
				ActivateHandle: ak,
				KeyHandle: tpm2.AuthHandle{
					Handle: ek.Handle,
					Name:   ek.Name,
					Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, endorsementPolicy),
				},
				CredentialBlob: *idObject,
				Secret:         *secret,
			}.Execute(t)
			if aErr != nil {
				return fmt.Errorf("activate credential: %w", aErr)
			}
			recovered = append([]byte(nil), rsp.CertInfo.Buffer...)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if len(recovered) == 0 {
		return nil, errors.New("the TPM recovered an empty secret")
	}
	return recovered, nil
}

// withEndorsementKey derives the endorsement key from the template p names,
// checks it is the key the EK certificate was issued for, runs fn with its
// handle and flushes it.
func withEndorsementKey(t transport.TPM, p *Prepared, fn func(ek tpm2.AuthHandle) error) error {
	ekCert, err := x509.ParseCertificate(p.EKCertChain[0])
	if err != nil {
		return errors.New("the endorsement key certificate is not valid")
	}
	ek, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(p.ek.template),
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("create endorsement key: %w", err)
	}
	defer flush(t, ek.ObjectHandle)
	if err := checkEKMatchesCertificate(ek, ekCert); err != nil {
		return err
	}
	return fn(tpm2.AuthHandle{Handle: ek.ObjectHandle, Name: ek.Name})
}

// endorsementPolicy satisfies the EK's authorization policy: PolicySecret
// against the endorsement hierarchy (empty authorization).
func endorsementPolicy(t transport.TPM, session tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	_, err := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: session,
		NonceTPM:      nonceTPM,
	}.Execute(t)
	return err
}

var errEKCertMismatch = errors.New("the endorsement key certificate does not belong to this TPM's endorsement key")

// checkEKMatchesCertificate refuses an EK certificate that was not issued for
// the key this TPM derives from the template.
func checkEKMatchesCertificate(ek *tpm2.CreatePrimaryResponse, cert *x509.Certificate) error {
	pt, err := ek.OutPublic.Contents()
	if err != nil {
		return fmt.Errorf("decode endorsement key: %w", err)
	}
	var tpmKey interface{ Equal(crypto.PublicKey) bool }
	switch pt.Type {
	case tpm2.TPMAlgRSA:
		tpmKey, err = rsaEndorsementKey(pt)
	case tpm2.TPMAlgECC:
		tpmKey, err = eccEndorsementKey(pt)
	default:
		return errEKCertMismatch
	}
	if err != nil {
		return err
	}
	if !tpmKey.Equal(cert.PublicKey) {
		return errEKCertMismatch
	}
	return nil
}

func rsaEndorsementKey(pt *tpm2.TPMTPublic) (*rsa.PublicKey, error) {
	parms, pErr := pt.Parameters.RSADetail()
	mod, mErr := pt.Unique.RSA()
	if pErr != nil || mErr != nil {
		return nil, errors.New("decode endorsement key: malformed RSA key")
	}
	key, err := tpm2.RSAPub(parms, mod)
	if err != nil {
		return nil, fmt.Errorf("decode endorsement key: %w", err)
	}
	return key, nil
}

func eccEndorsementKey(pt *tpm2.TPMTPublic) (*ecdsa.PublicKey, error) {
	parms, pErr := pt.Parameters.ECCDetail()
	point, uErr := pt.Unique.ECC()
	if pErr != nil || uErr != nil {
		return nil, errors.New("decode endorsement key: malformed ECC key")
	}
	key, err := tpm2.ECDSAPub(parms, point)
	if err != nil {
		return nil, fmt.Errorf("decode endorsement key: %w", err)
	}
	return key, nil
}
