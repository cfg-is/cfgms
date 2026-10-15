// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"

	"github.com/cfgis/cfgms/pkg/logging"
)

// The Security framework is called through purego so the darwin steward keeps
// building with CGO_ENABLED=0 (ADR-011 Amendment 3). Every Core Foundation
// object this file creates or copies is released; framework constants are
// borrowed and never released.

const (
	securityPath       = "/System/Library/Frameworks/Security.framework/Security"
	coreFoundationPath = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

	cfStringEncodingUTF8 = 0x08000100
	cfNumberSInt32Type   = 3
	// kSecAccessControlPrivateKeyUsage allows the Secure Enclave key to sign.
	secAccessControlPrivateKeyUsage = 1 << 30

	// Security framework OSStatus values the backend distinguishes.
	errSecItemNotFound       = -25300
	errSecNotAvailable       = -25291
	errSecNoSuchKeychain     = -25294
	errSecMissingEntitlement = -34018
)

// secureEnclaveTag is the stable application tag the device key is stored
// under; reloading by this tag keeps the DeviceID stable across restarts.
const secureEnclaveTag = "io.cfgms.steward.device-identity"

// pendingSuffix names a replacement key while Regenerate swaps it in.
const pendingSuffix = ".pending"

// keyClass selects the Keychain key class. Production uses the Secure Enclave;
// tests use a Keychain software key through the same code path (token ID omitted).
type keyClass struct {
	secureEnclave bool
	permanent     bool
	tag           string
}

// defaultKeyClass is read when the registered backend is probed.
var defaultKeyClass = keyClass{secureEnclave: true, permanent: true, tag: secureEnclaveTag}

// secAPI holds the resolved framework symbols and constants.
type secAPI struct {
	// Core Foundation
	cfRelease              func(uintptr)
	cfDictionaryCreate     func(alloc uintptr, keys, values *uintptr, n int, keyCb, valCb uintptr) uintptr
	cfDataCreate           func(alloc uintptr, b *byte, n int) uintptr
	cfDataGetLength        func(uintptr) int
	cfDataGetBytePtr       func(uintptr) uintptr
	cfNumberCreate         func(alloc uintptr, typ int, v *int32) uintptr
	cfErrorGetCode         func(uintptr) int
	cfErrorCopyDescription func(uintptr) uintptr
	cfStringGetCString     func(s uintptr, buf *byte, size int, enc uint32) bool
	cfStringGetMaxSize     func(length int, enc uint32) int
	cfStringGetLength      func(s uintptr) int

	// Security
	secKeyCreateRandomKey          func(params uintptr, err *uintptr) uintptr
	secItemCopyMatching            func(query uintptr, result *uintptr) int32
	secItemDelete                  func(query uintptr) int32
	secItemUpdate                  func(query, attrs uintptr) int32
	secKeyCopyPublicKey            func(key uintptr) uintptr
	secKeyCopyExternalRepresenting func(key uintptr, err *uintptr) uintptr
	secKeyCreateSignature          func(key, alg, data uintptr, err *uintptr) uintptr
	secAccessControlCreate         func(alloc, protection uintptr, flags uint, err *uintptr) uintptr

	// borrowed constants
	keyCallbacks, valCallbacks                          uintptr
	cfTrue, cfFalse                                     uintptr
	kClass, kClassKey                                   uintptr
	kKeyClass, kKeyClassPrivate                         uintptr
	kKeyType, kKeyTypeEC                                uintptr
	kKeySize                                            uintptr
	kTokenID, kTokenIDSE                                uintptr
	kIsPermanent, kAppTag                               uintptr
	kPrivateKeyAttrs                                    uintptr
	kAccessControl, kAccessibleAfterFirstUnlockThisOnly uintptr
	kReturnRef, kMatchLimit, kMatchLimitOne             uintptr
	kUseDataProtectionKeychain                          uintptr
	kAlgECDSADigestX962SHA256                           uintptr
}

var (
	secOnce sync.Once
	secAPIv *secAPI
	secErr  error
)

// loadSecAPI resolves the frameworks once. The result is definite: either every
// symbol resolved or an error naming the first that did not.
func loadSecAPI() (*secAPI, error) {
	secOnce.Do(func() { secAPIv, secErr = resolveSecAPI() })
	return secAPIv, secErr
}

func resolveSecAPI() (api *secAPI, err error) {
	defer func() {
		// purego panics on an unresolvable symbol.
		if r := recover(); r != nil {
			api, err = nil, fmt.Errorf("resolve Security framework symbols: %v", r)
		}
	}()
	cf, err := purego.Dlopen(coreFoundationPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("load CoreFoundation: %w", err)
	}
	sec, err := purego.Dlopen(securityPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("load Security framework: %w", err)
	}
	a := &secAPI{}
	purego.RegisterLibFunc(&a.cfRelease, cf, "CFRelease")
	purego.RegisterLibFunc(&a.cfDictionaryCreate, cf, "CFDictionaryCreate")
	purego.RegisterLibFunc(&a.cfDataCreate, cf, "CFDataCreate")
	purego.RegisterLibFunc(&a.cfDataGetLength, cf, "CFDataGetLength")
	purego.RegisterLibFunc(&a.cfDataGetBytePtr, cf, "CFDataGetBytePtr")
	purego.RegisterLibFunc(&a.cfNumberCreate, cf, "CFNumberCreate")
	purego.RegisterLibFunc(&a.cfErrorGetCode, cf, "CFErrorGetCode")
	purego.RegisterLibFunc(&a.cfErrorCopyDescription, cf, "CFErrorCopyDescription")
	purego.RegisterLibFunc(&a.cfStringGetCString, cf, "CFStringGetCString")
	purego.RegisterLibFunc(&a.cfStringGetMaxSize, cf, "CFStringGetMaximumSizeForEncoding")
	purego.RegisterLibFunc(&a.cfStringGetLength, cf, "CFStringGetLength")

	purego.RegisterLibFunc(&a.secKeyCreateRandomKey, sec, "SecKeyCreateRandomKey")
	purego.RegisterLibFunc(&a.secItemCopyMatching, sec, "SecItemCopyMatching")
	purego.RegisterLibFunc(&a.secItemDelete, sec, "SecItemDelete")
	purego.RegisterLibFunc(&a.secItemUpdate, sec, "SecItemUpdate")
	purego.RegisterLibFunc(&a.secKeyCopyPublicKey, sec, "SecKeyCopyPublicKey")
	purego.RegisterLibFunc(&a.secKeyCopyExternalRepresenting, sec, "SecKeyCopyExternalRepresentation")
	purego.RegisterLibFunc(&a.secKeyCreateSignature, sec, "SecKeyCreateSignature")
	purego.RegisterLibFunc(&a.secAccessControlCreate, sec, "SecAccessControlCreateWithFlags")

	// Address-of globals: these are the callback structs themselves.
	for name, dst := range map[string]*uintptr{
		"kCFTypeDictionaryKeyCallBacks":   &a.keyCallbacks,
		"kCFTypeDictionaryValueCallBacks": &a.valCallbacks,
	} {
		if *dst, err = purego.Dlsym(cf, name); err != nil {
			return nil, fmt.Errorf("resolve %s: %w", name, err)
		}
	}
	// Exported CFTypeRef globals: Dlsym yields the variable's address; the
	// value is read through it.
	for _, c := range []struct {
		lib  uintptr
		name string
		dst  *uintptr
	}{
		{cf, "kCFBooleanTrue", &a.cfTrue},
		{cf, "kCFBooleanFalse", &a.cfFalse},
		{sec, "kSecClass", &a.kClass},
		{sec, "kSecClassKey", &a.kClassKey},
		{sec, "kSecAttrKeyClass", &a.kKeyClass},
		{sec, "kSecAttrKeyClassPrivate", &a.kKeyClassPrivate},
		{sec, "kSecAttrKeyType", &a.kKeyType},
		{sec, "kSecAttrKeyTypeECSECPrimeRandom", &a.kKeyTypeEC},
		{sec, "kSecAttrKeySizeInBits", &a.kKeySize},
		{sec, "kSecAttrTokenID", &a.kTokenID},
		{sec, "kSecAttrTokenIDSecureEnclave", &a.kTokenIDSE},
		{sec, "kSecAttrIsPermanent", &a.kIsPermanent},
		{sec, "kSecAttrApplicationTag", &a.kAppTag},
		{sec, "kSecPrivateKeyAttrs", &a.kPrivateKeyAttrs},
		{sec, "kSecAttrAccessControl", &a.kAccessControl},
		{sec, "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", &a.kAccessibleAfterFirstUnlockThisOnly},
		{sec, "kSecReturnRef", &a.kReturnRef},
		{sec, "kSecMatchLimit", &a.kMatchLimit},
		{sec, "kSecMatchLimitOne", &a.kMatchLimitOne},
		{sec, "kSecUseDataProtectionKeychain", &a.kUseDataProtectionKeychain},
		{sec, "kSecKeyAlgorithmECDSASignatureDigestX962SHA256", &a.kAlgECDSADigestX962SHA256},
	} {
		addr, dErr := purego.Dlsym(c.lib, c.name)
		if dErr != nil {
			return nil, fmt.Errorf("resolve %s: %w", c.name, dErr)
		}
		*c.dst = derefUintptr(addr)
	}
	return a, nil
}

// derefUintptr reads the pointer-sized value stored at addr, a symbol address
// returned by Dlsym. The address is reinterpreted, not converted, so no
// uintptr-to-Pointer arithmetic is involved.
func derefUintptr(addr uintptr) uintptr {
	p := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	return *(*uintptr)(p)
}

// bytesAt copies n bytes from a Core Foundation buffer at addr.
func bytesAt(addr uintptr, n int) []byte {
	if n <= 0 {
		return nil
	}
	p := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	return append([]byte(nil), unsafe.Slice((*byte)(p), n)...)
}

// osStatusError carries the OSStatus of a failed Security call.
type osStatusError struct {
	op     string
	status int
	detail string
}

func (e *osStatusError) Error() string {
	if e.detail != "" {
		return fmt.Sprintf("%s failed: OSStatus %d: %s", e.op, e.status, e.detail)
	}
	return fmt.Sprintf("%s failed: OSStatus %d", e.op, e.status)
}

func (a *secAPI) cfErrorToError(op string, cfErr uintptr) error {
	if cfErr == 0 {
		return fmt.Errorf("%s failed: no error reported", op)
	}
	defer a.cfRelease(cfErr)
	e := &osStatusError{op: op, status: a.cfErrorGetCode(cfErr)}
	if d := a.cfErrorCopyDescription(cfErr); d != 0 {
		e.detail = a.goString(d)
		a.cfRelease(d)
	}
	return e
}

func (a *secAPI) goString(s uintptr) string {
	size := a.cfStringGetMaxSize(a.cfStringGetLength(s), cfStringEncodingUTF8) + 1
	if size <= 1 {
		return ""
	}
	buf := make([]byte, size)
	if !a.cfStringGetCString(s, &buf[0], size, cfStringEncodingUTF8) {
		return ""
	}
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// dict builds a CFDictionary from alternating key/value refs. The caller releases it.
func (a *secAPI) dict(kv ...uintptr) uintptr {
	n := len(kv) / 2
	keys := make([]uintptr, n)
	vals := make([]uintptr, n)
	for i := 0; i < n; i++ {
		keys[i], vals[i] = kv[2*i], kv[2*i+1]
	}
	d := a.cfDictionaryCreate(0, &keys[0], &vals[0], n, a.keyCallbacks, a.valCallbacks)
	return d
}

func (a *secAPI) data(b []byte) uintptr {
	if len(b) == 0 {
		return a.cfDataCreate(0, nil, 0)
	}
	return a.cfDataCreate(0, &b[0], len(b))
}

func (a *secAPI) dataBytes(d uintptr) []byte {
	return bytesAt(a.cfDataGetBytePtr(d), a.cfDataGetLength(d))
}

// keyAttrs returns the attributes shared by lookup and delete queries for tag.
// The returned release func frees the CF objects behind them.
func (a *secAPI) queryPairs(c keyClass, tag string) (pairs []uintptr, release func()) {
	tagData := a.data([]byte(tag))
	pairs = []uintptr{
		a.kClass, a.kClassKey,
		a.kKeyClass, a.kKeyClassPrivate,
		a.kKeyType, a.kKeyTypeEC,
		a.kAppTag, tagData,
	}
	if c.secureEnclave {
		pairs = append(pairs, a.kTokenID, a.kTokenIDSE, a.kUseDataProtectionKeychain, a.cfTrue)
	}
	return pairs, func() { a.cfRelease(tagData) }
}

// lookup returns a retained private key ref for tag, or (0, nil) when absent.
func (a *secAPI) lookup(c keyClass, tag string) (uintptr, error) {
	pairs, release := a.queryPairs(c, tag)
	defer release()
	pairs = append(pairs, a.kReturnRef, a.cfTrue, a.kMatchLimit, a.kMatchLimitOne)
	q := a.dict(pairs...)
	defer a.cfRelease(q)
	var res uintptr
	st := a.secItemCopyMatching(q, &res)
	switch st {
	case 0:
		if res == 0 {
			return 0, &osStatusError{op: "SecItemCopyMatching", status: 0, detail: "no key returned"}
		}
		return res, nil
	case errSecItemNotFound:
		return 0, nil
	default:
		return 0, &osStatusError{op: "SecItemCopyMatching", status: int(st)}
	}
}

// remove deletes the key stored under tag; an absent key is not an error.
func (a *secAPI) remove(c keyClass, tag string) error {
	pairs, release := a.queryPairs(c, tag)
	defer release()
	q := a.dict(pairs...)
	defer a.cfRelease(q)
	switch st := a.secItemDelete(q); st {
	case 0, errSecItemNotFound:
		return nil
	default:
		return &osStatusError{op: "SecItemDelete", status: int(st)}
	}
}

// retag moves the key stored under from to the tag to.
func (a *secAPI) retag(c keyClass, from, to string) error {
	pairs, release := a.queryPairs(c, from)
	defer release()
	q := a.dict(pairs...)
	defer a.cfRelease(q)
	toData := a.data([]byte(to))
	defer a.cfRelease(toData)
	attrs := a.dict(a.kAppTag, toData)
	defer a.cfRelease(attrs)
	if st := a.secItemUpdate(q, attrs); st != 0 {
		return &osStatusError{op: "SecItemUpdate", status: int(st)}
	}
	return nil
}

// create generates a new P-256 key under tag. With permanent set it is stored
// in the Keychain and can be reloaded by tag; with secureEnclave set the
// private key is generated in and never leaves the Secure Enclave.
func (a *secAPI) create(c keyClass, tag string) (uintptr, error) {
	tagData := a.data([]byte(tag))
	defer a.cfRelease(tagData)
	size := int32(256)
	sizeNum := a.cfNumberCreate(0, cfNumberSInt32Type, &size)
	defer a.cfRelease(sizeNum)

	perm := a.cfFalse
	if c.permanent {
		perm = a.cfTrue
	}
	privAttrs := []uintptr{a.kIsPermanent, perm, a.kAppTag, tagData}
	top := []uintptr{a.kKeyType, a.kKeyTypeEC, a.kKeySize, sizeNum}
	if c.secureEnclave {
		var cfErr uintptr
		acl := a.secAccessControlCreate(0, a.kAccessibleAfterFirstUnlockThisOnly, secAccessControlPrivateKeyUsage, &cfErr)
		if acl == 0 {
			return 0, a.cfErrorToError("SecAccessControlCreateWithFlags", cfErr)
		}
		defer a.cfRelease(acl)
		privAttrs = append(privAttrs, a.kAccessControl, acl)
		top = append(top, a.kTokenID, a.kTokenIDSE, a.kUseDataProtectionKeychain, a.cfTrue)
	}
	privDict := a.dict(privAttrs...)
	defer a.cfRelease(privDict)
	params := a.dict(append(top, a.kPrivateKeyAttrs, privDict)...)
	defer a.cfRelease(params)

	var cfErr uintptr
	key := a.secKeyCreateRandomKey(params, &cfErr)
	if key == 0 {
		return 0, a.cfErrorToError("SecKeyCreateRandomKey", cfErr)
	}
	return key, nil
}

// publicKey exports the P-256 public key of a private key ref.
func (a *secAPI) publicKey(priv uintptr) (*ecdsa.PublicKey, error) {
	pubRef := a.secKeyCopyPublicKey(priv)
	if pubRef == 0 {
		return nil, errors.New("SecKeyCopyPublicKey failed")
	}
	defer a.cfRelease(pubRef)
	var cfErr uintptr
	d := a.secKeyCopyExternalRepresenting(pubRef, &cfErr)
	if d == 0 {
		return nil, a.cfErrorToError("SecKeyCopyExternalRepresentation", cfErr)
	}
	defer a.cfRelease(d)
	return parseX963P256(a.dataBytes(d))
}

// sign signs digest with priv. The algorithm treats the input as an already
// computed SHA-256 digest, so nothing is hashed again; the result is X9.62 DER.
func (a *secAPI) sign(priv uintptr, digest []byte) ([]byte, error) {
	d := a.data(digest)
	defer a.cfRelease(d)
	var cfErr uintptr
	sig := a.secKeyCreateSignature(priv, a.kAlgECDSADigestX962SHA256, d, &cfErr)
	if sig == 0 {
		return nil, a.cfErrorToError("SecKeyCreateSignature", cfErr)
	}
	defer a.cfRelease(sig)
	return a.dataBytes(sig), nil
}

func init() {
	registerBackend(backend{
		level: ProtectionSecureEnclave,
		open: func(_ context.Context, dir string, logger logging.Logger) (KeyStore, error) {
			api, err := loadSecAPI()
			if err != nil {
				return nil, err
			}
			// A recorded Secure Enclave identity must reload its key; it must
			// never mint a replacement (which would change the DeviceID).
			mustExist := recordedProtectionLevel(dir) == ProtectionSecureEnclave
			return newSecKeyStore(api, defaultKeyClass, mustExist, logger), nil
		},
		remove: func(string) error { return removeSecureEnclaveKey(defaultKeyClass) },
	})
}

// removeSecureEnclaveKey deletes the device key for class c. A host where the
// framework cannot load, or which cannot hold such a key, has nothing to remove.
func removeSecureEnclaveKey(c keyClass) error {
	api, err := loadSecAPI()
	if err != nil {
		return nil
	}
	var firstErr error
	for _, tag := range []string{c.tag, c.tag + pendingSuffix} {
		if rErr := api.remove(c, tag); rErr != nil && !keyCannotExist(rErr) && firstErr == nil {
			firstErr = fmt.Errorf("remove Secure Enclave device key: %w", rErr)
		}
	}
	return firstErr
}

// keyCannotExist reports statuses meaning this host cannot hold the key at all.
func keyCannotExist(err error) bool {
	var se *osStatusError
	if !errors.As(err, &se) {
		return false
	}
	switch se.status {
	case errSecMissingEntitlement, errSecNotAvailable, errSecNoSuchKeychain:
		return true
	}
	return false
}

// secKeyStore keeps the device key as a non-exportable P-256 Keychain key.
type secKeyStore struct {
	api       *secAPI
	class     keyClass
	mustExist bool
	logger    logging.Logger
	// selfTest runs after a key is created and before it is adopted. Tests
	// replace it to inject a failure.
	selfTest func(ks *secKeyStore, tag string, key uintptr, pub *ecdsa.PublicKey) error

	mu       sync.Mutex
	key      uintptr
	pub      *ecdsa.PublicKey
	deviceID string
}

var _ KeyStore = (*secKeyStore)(nil)

func newSecKeyStore(api *secAPI, c keyClass, mustExist bool, logger logging.Logger) *secKeyStore {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &secKeyStore{api: api, class: c, mustExist: mustExist, logger: logger, selfTest: (*secKeyStore).runSelfTest}
}

// runSelfTest proves the freshly created key is usable the way the steward will
// use it: it reloads by tag with the same public key, signs a digest, and the
// signature verifies.
func (ks *secKeyStore) runSelfTest(tag string, key uintptr, pub *ecdsa.PublicKey) error {
	if key == 0 || pub == nil {
		return errors.New("self-test: no key")
	}
	reloaded, err := ks.api.lookup(ks.class, tag)
	if err != nil {
		return fmt.Errorf("self-test reload: %w", err)
	}
	if reloaded == 0 {
		return errors.New("self-test reload: persistent key not found by tag")
	}
	defer ks.api.cfRelease(reloaded)
	rpub, err := ks.api.publicKey(reloaded)
	if err != nil {
		return fmt.Errorf("self-test reload: %w", err)
	}
	if !rpub.Equal(pub) {
		return errors.New("self-test reload: reloaded key differs from created key")
	}
	var probe [32]byte
	if _, err := rand.Read(probe[:]); err != nil {
		return fmt.Errorf("self-test digest: %w", err)
	}
	digest := sha256.Sum256(probe[:])
	sig, err := ks.api.sign(reloaded, digest[:])
	if err != nil {
		return fmt.Errorf("self-test sign: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("self-test: signature did not verify")
	}
	return nil
}

func (ks *secKeyStore) adoptLocked(key uintptr, pub *ecdsa.PublicKey) error {
	id, err := ComputeDeviceID(AlgorithmECDSAP256, pub)
	if err != nil {
		return err
	}
	if ks.key != 0 && ks.key != key {
		ks.api.cfRelease(ks.key)
	}
	ks.key, ks.pub, ks.deviceID = key, pub, id
	return nil
}

func (ks *secKeyStore) forgetLocked() {
	if ks.key != 0 {
		ks.api.cfRelease(ks.key)
	}
	ks.key, ks.pub, ks.deviceID = 0, nil, ""
}

// findExisting returns the stored key, preferring the stable tag over a
// replacement left behind by an interrupted Regenerate.
func (ks *secKeyStore) findExisting() (uintptr, error) {
	for _, tag := range []string{ks.class.tag, ks.class.tag + pendingSuffix} {
		key, err := ks.api.lookup(ks.class, tag)
		if err != nil {
			return 0, err
		}
		if key != 0 {
			return key, nil
		}
	}
	return 0, nil
}

// GenerateOrLoad loads the stored key. A key that exists but cannot be loaded is
// an error; it is never replaced. A new key is created only on first enrollment
// and adopted only after the self-test passes.
func (ks *secKeyStore) GenerateOrLoad(_ context.Context) (crypto.PublicKey, Algorithm, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	key, err := ks.findExisting()
	if err != nil {
		return nil, "", err
	}
	if key != 0 {
		pub, pErr := ks.api.publicKey(key)
		if pErr == nil {
			pErr = ks.adoptLocked(key, pub)
		}
		if pErr != nil {
			ks.api.cfRelease(key)
			return nil, "", fmt.Errorf("load Secure Enclave device key: %w", pErr)
		}
		return pub, AlgorithmECDSAP256, nil
	}
	if ks.mustExist {
		return nil, "", errors.New("recorded Secure Enclave device key not found")
	}
	pub, err := ks.createLocked(ks.class.tag)
	if err != nil {
		return nil, "", err
	}
	return pub, AlgorithmECDSAP256, nil
}

// createLocked creates a key under tag, self-tests it and adopts it. On any
// failure the key just created is deleted, so no unusable key is left behind and
// none is ever used.
func (ks *secKeyStore) createLocked(tag string) (*ecdsa.PublicKey, error) {
	if !ks.class.permanent {
		return nil, errors.New("a non-persistent device key would change DeviceID on every start")
	}
	key, err := ks.api.create(ks.class, tag)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*ecdsa.PublicKey, error) {
		ks.api.cfRelease(key)
		if rErr := ks.api.remove(ks.class, tag); rErr != nil {
			err = errors.Join(err, rErr)
		}
		return nil, err
	}
	pub, err := ks.api.publicKey(key)
	if err != nil {
		return fail(err)
	}
	stErr := ks.selfTest(ks, tag, key, pub)
	if stErr != nil {
		return fail(fmt.Errorf("Secure Enclave key self-test: %w", stErr))
	}
	if err := ks.adoptLocked(key, pub); err != nil {
		return fail(err)
	}
	return pub, nil
}

// Regenerate replaces the key (ADR-034 §4). The new key is created and
// self-tested under a pending tag first; the old key is deleted only once the
// new one works, then the new key takes the stable tag. If the final retag
// fails the pending tag still resolves on the next load.
func (ks *secKeyStore) Regenerate(_ context.Context) (crypto.PublicKey, Algorithm, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	pending := ks.class.tag + pendingSuffix
	if err := ks.api.remove(ks.class, pending); err != nil {
		return nil, "", err
	}
	pub, err := ks.createLocked(pending)
	if err != nil {
		return nil, "", err
	}
	if err := ks.api.remove(ks.class, ks.class.tag); err != nil {
		// The old key still resolves first on load; drop the replacement and
		// go back to the old key rather than run on a key the next start ignores.
		rmErr := ks.api.remove(ks.class, pending)
		ks.forgetLocked()
		if old, fErr := ks.findExisting(); fErr == nil && old != 0 {
			if oldPub, pErr := ks.api.publicKey(old); pErr == nil && ks.adoptLocked(old, oldPub) == nil {
				return nil, "", errors.Join(fmt.Errorf("remove replaced device key: %w", err), rmErr)
			}
			ks.api.cfRelease(old)
		}
		return nil, "", errors.Join(fmt.Errorf("remove replaced device key: %w", err), rmErr)
	}
	if err := ks.api.retag(ks.class, pending, ks.class.tag); err != nil {
		ks.logger.Warn("Secure Enclave device key kept under its pending tag",
			"error", logging.SanitizeLogValue(err.Error()))
	}
	return pub, AlgorithmECDSAP256, nil
}

// RemoveKey deletes the stored key and forgets the in-memory one.
func (ks *secKeyStore) RemoveKey() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var errs []error
	for _, tag := range []string{ks.class.tag, ks.class.tag + pendingSuffix} {
		errs = append(errs, ks.api.remove(ks.class, tag))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("remove Secure Enclave device key: %w", err)
	}
	ks.forgetLocked()
	return nil
}

// Algorithm returns AlgorithmECDSAP256.
func (ks *secKeyStore) Algorithm() Algorithm { return AlgorithmECDSAP256 }

// ProtectionLevel is secure-enclave for the Secure Enclave class. The Keychain
// software class exists for tests only and is never registered with Open, so it
// reports a distinct level rather than claiming hardware protection.
func (ks *secKeyStore) ProtectionLevel() ProtectionLevel {
	if ks.class.secureEnclave {
		return ProtectionSecureEnclave
	}
	return softwareKeychainLevel
}

// softwareKeychainLevel names the test-only Keychain software key class.
const softwareKeychainLevel ProtectionLevel = "keychain-software"

// DeviceID returns the SHA-256 of the PKIX DER public key, or "" before GenerateOrLoad.
func (ks *secKeyStore) DeviceID() string {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.deviceID
}

// PublicKey returns the *ecdsa.PublicKey, or nil before GenerateOrLoad.
func (ks *secKeyStore) PublicKey() crypto.PublicKey {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.pub == nil {
		return nil
	}
	return ks.pub
}

// Sign signs the 32-byte digest with ECDSA and returns ASN.1 DER. The digest is
// the hash input directly; nothing is hashed again (ADR-011 Amendment 3).
func (ks *secKeyStore) Sign(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.key == 0 {
		return nil, errors.New("device identity key not loaded: call GenerateOrLoad first")
	}
	return ks.api.sign(ks.key, digest)
}
