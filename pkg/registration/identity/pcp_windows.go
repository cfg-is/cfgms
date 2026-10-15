// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/logging"
)

// CNG key storage providers. The Platform Crypto Provider keeps keys in the TPM;
// the Software Key Storage Provider runs the same API in software and exists so
// the code path is proven on hosts without a TPM.
const (
	platformCryptoProvider     = "Microsoft Platform Crypto Provider"
	softwareKeyStorageProvider = "Microsoft Software Key Storage Provider"
)

// cngKeyNamePrefix namespaces the persisted CNG key. The full name appends a hash
// of the identity directory, so each identity directory owns exactly one key and
// removing the keys for one directory never touches another's.
const cngKeyNamePrefix = "cfgms-steward-device-identity-"

// cngAltSlotSuffix names the second key slot. CNG cannot rename a key, so
// Regenerate creates the replacement in whichever slot is free and deletes the
// old one; the current key is whichever slot exists.
const cngAltSlotSuffix = "-alt"

// CNG constants (ncrypt.h, bcrypt.h, winerror.h).
const (
	ncryptMachineKeyFlag  = 0x00000020 // NCRYPT_MACHINE_KEY_FLAG
	ncryptSilentFlag      = 0x00000040 // NCRYPT_SILENT_FLAG
	ncryptAllowSigning    = 0x00000002 // NCRYPT_ALLOW_SIGNING_FLAG
	ecdsaP256PublicMagic  = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC ("ECS1")
	p256CoordinateSize    = 32
	nteBadKeyset          = 0x80090016 // NTE_BAD_KEYSET: no key by that name
	nteDeviceNotReady     = 0x80090030 // NTE_DEVICE_NOT_READY
	nteDeviceNotFound     = 0x80090035 // NTE_DEVICE_NOT_FOUND
	tbsETPMNotFound       = 0x8028400F // TBS_E_TPM_NOT_FOUND
	tbsEServiceNotRunning = 0x80284008 // TBS_E_SERVICE_NOT_RUNNING
	tbsEServiceDisabled   = 0x80284010 // TBS_E_SERVICE_DISABLED
)

var (
	modncrypt                     = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = modncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = modncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty         = modncrypt.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey         = modncrypt.NewProc("NCryptFinalizeKey")
	procNCryptOpenKey             = modncrypt.NewProc("NCryptOpenKey")
	procNCryptExportKey           = modncrypt.NewProc("NCryptExportKey")
	procNCryptSignHash            = modncrypt.NewProc("NCryptSignHash")
	procNCryptDeleteKey           = modncrypt.NewProc("NCryptDeleteKey")
	procNCryptFreeObject          = modncrypt.NewProc("NCryptFreeObject")
)

// cngStatusError is a failed CNG call and its SECURITY_STATUS.
type cngStatusError struct {
	op     string
	status uint32
}

func (e *cngStatusError) Error() string {
	return fmt.Sprintf("%s failed: SECURITY_STATUS 0x%08X", e.op, e.status)
}

func cngStatus(err error) uint32 {
	var ce *cngStatusError
	if errors.As(err, &ce) {
		return ce.status
	}
	return 0
}

func isKeyNotFound(err error) bool { return cngStatus(err) == nteBadKeyset }

// keyCannotExist reports statuses meaning the provider cannot hold any key on
// this host, so there is nothing to remove.
func keyCannotExist(err error) bool {
	switch cngStatus(err) {
	case nteBadKeyset, nteDeviceNotReady, nteDeviceNotFound,
		tbsETPMNotFound, tbsEServiceNotRunning, tbsEServiceDisabled:
		return true
	}
	return false
}

// loadNCrypt resolves every ncrypt.dll procedure so a missing export is an
// error rather than a panic inside Call.
func loadNCrypt() error {
	for _, p := range []*windows.LazyProc{
		procNCryptOpenStorageProvider, procNCryptCreatePersistedKey, procNCryptSetProperty,
		procNCryptFinalizeKey, procNCryptOpenKey, procNCryptExportKey, procNCryptSignHash,
		procNCryptDeleteKey, procNCryptFreeObject,
	} {
		if err := p.Find(); err != nil {
			return fmt.Errorf("load ncrypt.dll: %w", err)
		}
	}
	return nil
}

// cngResult converts a CNG call's return value to an error. Each call site
// invokes LazyProc.Call directly, with its pointer arguments converted inline,
// so the Go memory they point to is kept alive for the duration of the call.
func cngResult(op string, r uintptr) error {
	if status := uint32(r); status != 0 { //#nosec G115 -- SECURITY_STATUS is a 32-bit LONG in the low bits of the return register
		return &cngStatusError{op: op, status: status}
	}
	return nil
}

func utf16(s string) (*uint16, error) {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid CNG name %q: %w", s, err)
	}
	return p, nil
}

func freeObject(h uintptr) {
	if h != 0 {
		_, _, _ = procNCryptFreeObject.Call(h)
	}
}

func openProvider(name string) (uintptr, error) {
	if err := loadNCrypt(); err != nil {
		return 0, err
	}
	pname, err := utf16(name)
	if err != nil {
		return 0, err
	}
	var h uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(pname)), 0)
	if err := cngResult("NCryptOpenStorageProvider", r); err != nil {
		return 0, err
	}
	return h, nil
}

// cngKeyConfig selects where the device key lives.
type cngKeyConfig struct {
	// provider is the CNG key storage provider name.
	provider string
	// keyPrefix is prepended to the per-directory hash to name the key.
	keyPrefix string
	// machine stores the key in the machine key store (NCRYPT_MACHINE_KEY_FLAG)
	// rather than the calling account's. The steward runs as LocalSystem and
	// prepare-image runs elevated, so both reach a machine key.
	machine bool
}

// defaultCNGKeyConfig is read when the registered backend is probed. Tests point
// it at a test key prefix and, when not elevated, the per-user key store.
var defaultCNGKeyConfig = cngKeyConfig{provider: platformCryptoProvider, keyPrefix: cngKeyNamePrefix, machine: true}

func (c cngKeyConfig) flags() uintptr {
	f := uintptr(ncryptSilentFlag)
	if c.machine {
		f |= ncryptMachineKeyFlag
	}
	return f
}

// slots returns the two key names for identity directory dir: the primary slot
// first, then the alternate.
func (c cngKeyConfig) slots(dir string) [2]string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	h := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(abs))))
	name := c.keyPrefix + hex.EncodeToString(h[:8])
	return [2]string{name, name + cngAltSlotSuffix}
}

func otherSlot(slots [2]string, name string) string {
	if name == slots[0] {
		return slots[1]
	}
	return slots[0]
}

func (c cngKeyConfig) openKey(prov uintptr, name string) (uintptr, error) {
	pname, err := utf16(name)
	if err != nil {
		return 0, err
	}
	var h uintptr
	r, _, _ := procNCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(pname)), 0, c.flags())
	if err := cngResult("NCryptOpenKey", r); err != nil {
		return 0, err
	}
	return h, nil
}

func setDWORDProperty(key uintptr, prop string, v uint32) error {
	pprop, err := utf16(prop)
	if err != nil {
		return err
	}
	r, _, _ := procNCryptSetProperty.Call(key, uintptr(unsafe.Pointer(pprop)), uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v), 0)
	return cngResult("NCryptSetProperty("+prop+")", r)
}

// createKey creates and finalizes a persisted, non-exportable, sign-only P-256
// key. On failure nothing is left persisted.
func (c cngKeyConfig) createKey(prov uintptr, name string) (uintptr, error) {
	alg, err := utf16("ECDSA_P256")
	if err != nil {
		return 0, err
	}
	pname, err := utf16(name)
	if err != nil {
		return 0, err
	}
	var h uintptr
	r, _, _ := procNCryptCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(alg)), uintptr(unsafe.Pointer(pname)), 0, c.flags())
	if err := cngResult("NCryptCreatePersistedKey", r); err != nil {
		return 0, err
	}
	err = setDWORDProperty(h, "Export Policy", 0)
	if err == nil {
		err = setDWORDProperty(h, "Key Usage", ncryptAllowSigning)
	}
	if err == nil {
		r, _, _ = procNCryptFinalizeKey.Call(h, ncryptSilentFlag)
		err = cngResult("NCryptFinalizeKey", r)
	}
	if err != nil {
		// Before finalize nothing is persisted and freeing discards the key.
		// If finalize persisted it, deleting it releases the handle too.
		if dErr := deleteKeyHandle(h); dErr != nil {
			freeObject(h)
		}
		return 0, err
	}
	return h, nil
}

// exportBlob exports key as blobType.
func exportBlob(key uintptr, blobType string) ([]byte, error) {
	pblob, err := utf16(blobType)
	if err != nil {
		return nil, err
	}
	var n uint32
	r, _, _ := procNCryptExportKey.Call(key, 0, uintptr(unsafe.Pointer(pblob)), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	if err := cngResult("NCryptExportKey", r); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("NCryptExportKey returned an empty blob")
	}
	buf := make([]byte, n)
	r, _, _ = procNCryptExportKey.Call(key, 0, uintptr(unsafe.Pointer(pblob)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), 0)
	if err := cngResult("NCryptExportKey", r); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// parseECCPublicBlob converts a BCRYPT_ECCKEY_BLOB ("ECS1", cbKey, X, Y) to a
// P-256 public key.
func parseECCPublicBlob(blob []byte) (*ecdsa.PublicKey, error) {
	if len(blob) < 8 {
		return nil, errors.New("ECC public blob truncated")
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	cb := binary.LittleEndian.Uint32(blob[4:8])
	if magic != ecdsaP256PublicMagic || cb != p256CoordinateSize {
		return nil, fmt.Errorf("ECC public blob is not an ECDSA P-256 public key (magic 0x%08X, size %d)", magic, cb)
	}
	if len(blob) != 8+2*p256CoordinateSize {
		return nil, fmt.Errorf("ECC public blob has length %d, want %d", len(blob), 8+2*p256CoordinateSize)
	}
	point := make([]byte, 0, 1+2*p256CoordinateSize)
	point = append(point, 0x04)
	point = append(point, blob[8:]...)
	return parseX963P256(point)
}

func publicKeyOf(key uintptr) (*ecdsa.PublicKey, error) {
	blob, err := exportBlob(key, "ECCPUBLICBLOB")
	if err != nil {
		return nil, err
	}
	return parseECCPublicBlob(blob)
}

// p1363ToDER converts a raw r||s ECDSA signature to ASN.1 DER.
func p1363ToDER(sig []byte) ([]byte, error) {
	if len(sig) != 2*p256CoordinateSize {
		return nil, fmt.Errorf("ECDSA signature has length %d, want %d", len(sig), 2*p256CoordinateSize)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(sig[:p256CoordinateSize]),
		new(big.Int).SetBytes(sig[p256CoordinateSize:]),
	})
}

// signDigest signs digest as the hash input directly and returns ASN.1 DER.
func signDigest(key uintptr, digest []byte) ([]byte, error) {
	sig := make([]byte, 2*p256CoordinateSize)
	var n uint32
	r, _, _ := procNCryptSignHash.Call(key, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)), uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
	if err := cngResult("NCryptSignHash", r); err != nil {
		return nil, err
	}
	return p1363ToDER(sig[:n])
}

// deleteKeyHandle deletes the persisted key; on success CNG frees the handle.
func deleteKeyHandle(key uintptr) error {
	// The Platform Crypto Provider rejects NCRYPT_SILENT_FLAG here (NTE_BAD_FLAGS).
	r, _, _ := procNCryptDeleteKey.Call(key, 0)
	return cngResult("NCryptDeleteKey", r)
}

// deleteKey deletes the key named name; an absent key is not an error.
func (c cngKeyConfig) deleteKey(prov uintptr, name string) error {
	h, err := c.openKey(prov, name)
	if isKeyNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := deleteKeyHandle(h); err != nil {
		freeObject(h)
		return err
	}
	return nil
}

// removeCNGKeys deletes both key slots for dir. A host whose provider cannot
// load, or cannot hold a key at all, has nothing to remove.
func removeCNGKeys(c cngKeyConfig, dir string) error {
	prov, err := openProvider(c.provider)
	if err != nil {
		return nil
	}
	defer freeObject(prov)
	var errs []error
	for _, name := range c.slots(dir) {
		if dErr := c.deleteKey(prov, name); dErr != nil && !keyCannotExist(dErr) {
			errs = append(errs, dErr)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("remove CNG device key: %w", err)
	}
	return nil
}

func init() {
	registerBackend(backend{
		level: ProtectionTPM,
		open: func(_ context.Context, dir string, logger logging.Logger) (KeyStore, error) {
			// A recorded TPM identity must reload its key; it must never mint a
			// replacement (which would change the DeviceID).
			mustExist := recordedProtectionLevel(dir) == ProtectionTPM
			return newCNGKeyStore(defaultCNGKeyConfig, dir, mustExist, logger), nil
		},
		remove: func(dir string) error { return removeCNGKeys(defaultCNGKeyConfig, dir) },
	})
}

// cngKeyStore keeps the device key as a persisted, non-exportable NIST P-256
// signing key in a CNG key storage provider: the TPM through the Platform
// Crypto Provider in production. Nothing is written to the identity directory;
// the provider persists the key under a name derived from that directory.
// Provider and key handles are opened per operation and freed before it returns.
type cngKeyStore struct {
	cfg       cngKeyConfig
	slots     [2]string
	mustExist bool
	logger    logging.Logger

	mu       sync.Mutex
	current  string // slot holding the loaded key, "" before GenerateOrLoad
	pub      *ecdsa.PublicKey
	deviceID string
}

var _ KeyStore = (*cngKeyStore)(nil)

func newCNGKeyStore(cfg cngKeyConfig, dir string, mustExist bool, logger logging.Logger) *cngKeyStore {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &cngKeyStore{cfg: cfg, slots: cfg.slots(dir), mustExist: mustExist, logger: logger}
}

func (ks *cngKeyStore) openProvider() (uintptr, error) {
	prov, err := openProvider(ks.cfg.provider)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", ks.cfg.provider, err)
	}
	return prov, nil
}

// findExisting returns the slot and an open handle of the stored key, preferring
// the primary slot, or ("", 0, nil) when neither slot holds a key. Both slots
// exist only after an interrupted Regenerate; either one is a valid key.
func (ks *cngKeyStore) findExisting(prov uintptr) (string, uintptr, error) {
	for _, name := range ks.slots {
		h, err := ks.cfg.openKey(prov, name)
		if isKeyNotFound(err) {
			continue
		}
		if err != nil {
			return "", 0, err
		}
		return name, h, nil
	}
	return "", 0, nil
}

func (ks *cngKeyStore) adoptLocked(slot string, pub *ecdsa.PublicKey) error {
	id, err := ComputeDeviceID(AlgorithmECDSAP256, pub)
	if err != nil {
		return err
	}
	ks.current, ks.pub, ks.deviceID = slot, pub, id
	return nil
}

// selfTest proves a freshly created key is usable the way the steward will use
// it: it reopens by name with the same public key, signs a digest, and the
// signature verifies.
func (ks *cngKeyStore) selfTest(prov uintptr, name string, pub *ecdsa.PublicKey) error {
	h, err := ks.cfg.openKey(prov, name)
	if err != nil {
		return fmt.Errorf("self-test reopen: %w", err)
	}
	defer freeObject(h)
	rpub, err := publicKeyOf(h)
	if err != nil {
		return fmt.Errorf("self-test reopen: %w", err)
	}
	if !rpub.Equal(pub) {
		return errors.New("self-test reopen: reopened key differs from created key")
	}
	var probe [32]byte
	if _, err := rand.Read(probe[:]); err != nil {
		return fmt.Errorf("self-test digest: %w", err)
	}
	digest := sha256.Sum256(probe[:])
	sig, err := signDigest(h, digest[:])
	if err != nil {
		return fmt.Errorf("self-test sign: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("self-test: signature did not verify")
	}
	return nil
}

// createLocked creates a key in slot name, self-tests it and adopts it. On any
// failure the key just created is deleted, so no unusable key is left behind.
func (ks *cngKeyStore) createLocked(prov uintptr, name string) (*ecdsa.PublicKey, error) {
	h, err := ks.cfg.createKey(prov, name)
	if err != nil {
		return nil, err
	}
	pub, err := publicKeyOf(h)
	freeObject(h)
	if err == nil {
		if stErr := ks.selfTest(prov, name, pub); stErr != nil {
			err = fmt.Errorf("CNG key self-test: %w", stErr)
		}
	}
	if err == nil {
		err = ks.adoptLocked(name, pub)
	}
	if err != nil {
		if dErr := ks.cfg.deleteKey(prov, name); dErr != nil {
			err = errors.Join(err, dErr)
		}
		return nil, err
	}
	return pub, nil
}

// GenerateOrLoad loads the stored key. A key that exists but cannot be opened or
// used is an error; it is never replaced, which would change the DeviceID. A new
// key is created only on first enrollment and adopted only after it self-tests.
func (ks *cngKeyStore) GenerateOrLoad(_ context.Context) (crypto.PublicKey, Algorithm, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	prov, err := ks.openProvider()
	if err != nil {
		return nil, "", err
	}
	defer freeObject(prov)

	slot, h, err := ks.findExisting(prov)
	if err != nil {
		return nil, "", fmt.Errorf("open CNG device key: %w", err)
	}
	if h != 0 {
		pub, pErr := publicKeyOf(h)
		freeObject(h)
		if pErr == nil {
			pErr = ks.adoptLocked(slot, pub)
		}
		if pErr != nil {
			return nil, "", fmt.Errorf("load CNG device key: %w", pErr)
		}
		return pub, AlgorithmECDSAP256, nil
	}
	if ks.mustExist {
		return nil, "", errors.New("recorded TPM device key not found")
	}
	pub, err := ks.createLocked(prov, ks.slots[0])
	if err != nil {
		return nil, "", err
	}
	return pub, AlgorithmECDSAP256, nil
}

// Regenerate replaces the key (ADR-034 §4). The new key is created and
// self-tested in the free slot first; the old key is deleted only once the new
// one works, so an interruption leaves the old key or the new one, never
// neither. If the old key cannot be deleted the new one is dropped and the old
// key stays current.
func (ks *cngKeyStore) Regenerate(_ context.Context) (crypto.PublicKey, Algorithm, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	prov, err := ks.openProvider()
	if err != nil {
		return nil, "", err
	}
	defer freeObject(prov)

	old := ks.current
	if old == "" {
		slot, h, fErr := ks.findExisting(prov)
		if fErr != nil {
			return nil, "", fmt.Errorf("open CNG device key: %w", fErr)
		}
		freeObject(h)
		old = slot
	}
	target := ks.slots[0]
	if old != "" {
		target = otherSlot(ks.slots, old)
	}
	if err := ks.cfg.deleteKey(prov, target); err != nil {
		return nil, "", fmt.Errorf("clear CNG key slot: %w", err)
	}
	oldPub, oldID := ks.pub, ks.deviceID
	pub, err := ks.createLocked(prov, target)
	if err != nil {
		return nil, "", err
	}
	if old != "" {
		if dErr := ks.cfg.deleteKey(prov, old); dErr != nil {
			rmErr := ks.cfg.deleteKey(prov, target)
			ks.current, ks.pub, ks.deviceID = old, oldPub, oldID
			return nil, "", errors.Join(fmt.Errorf("remove replaced device key: %w", dErr), rmErr)
		}
	}
	return pub, AlgorithmECDSAP256, nil
}

// RemoveKey deletes both key slots and forgets the in-memory key.
func (ks *cngKeyStore) RemoveKey() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	prov, err := ks.openProvider()
	if err != nil {
		return err
	}
	defer freeObject(prov)
	var errs []error
	for _, name := range ks.slots {
		errs = append(errs, ks.cfg.deleteKey(prov, name))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("remove CNG device key: %w", err)
	}
	ks.current, ks.pub, ks.deviceID = "", nil, ""
	return nil
}

// Algorithm returns AlgorithmECDSAP256.
func (ks *cngKeyStore) Algorithm() Algorithm { return AlgorithmECDSAP256 }

// ProtectionLevel is tpm for the Platform Crypto Provider. Any other provider is
// used by tests only and is never registered with Open, so it reports a distinct
// level rather than claiming hardware protection.
func (ks *cngKeyStore) ProtectionLevel() ProtectionLevel {
	if ks.cfg.provider == platformCryptoProvider {
		return ProtectionTPM
	}
	return softwareKSPLevel
}

// softwareKSPLevel names the test-only CNG software key storage provider.
const softwareKSPLevel ProtectionLevel = "cng-software"

// DeviceID returns the SHA-256 of the PKIX DER public key, or "" before GenerateOrLoad.
func (ks *cngKeyStore) DeviceID() string {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.deviceID
}

// PublicKey returns the *ecdsa.PublicKey, or nil before GenerateOrLoad.
func (ks *cngKeyStore) PublicKey() crypto.PublicKey {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.pub == nil {
		return nil
	}
	return ks.pub
}

// Sign signs the 32-byte digest in the provider with ECDSA and returns ASN.1
// DER. The digest is the hash input directly; nothing is hashed again (ADR-011
// Amendment 3).
func (ks *cngKeyStore) Sign(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.pub == nil {
		return nil, errors.New("device identity key not loaded: call GenerateOrLoad first")
	}
	prov, err := ks.openProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)
	h, err := ks.cfg.openKey(prov, ks.current)
	if err != nil {
		return nil, fmt.Errorf("open CNG device key: %w", err)
	}
	defer freeObject(h)
	return signDigest(h, digest)
}
