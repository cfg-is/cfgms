//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package acme

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Windows CryptoAPI constants
const (
	certStoreProvSystem        = 10         // CERT_STORE_PROV_SYSTEM_W
	certSystemStoreLocalMachine = 0x00020000 // CERT_SYSTEM_STORE_LOCAL_MACHINE
	certSystemStoreCurrentUser  = 0x00010000 // CERT_SYSTEM_STORE_CURRENT_USER
	certFindSubjectStr         = 0x00080007 // CERT_FIND_SUBJECT_STR_W
	certStoreAddReplaceExisting = 3          // CERT_STORE_ADD_REPLACE_EXISTING
	cryptExportable            = 0x00000001  // CRYPT_EXPORTABLE
	cryptMachineKeyset         = 0x00000020  // CRYPT_MACHINE_KEYSET
	pkcs12AllowOverwriteKey    = 0x00004000  // PKCS12_ALLOW_OVERWRITE_KEY

	x509ASNEncoding = 0x00000001 // X509_ASN_ENCODING
	pkcs7ASNEncoding = 0x00010000 // PKCS_7_ASN_ENCODING
	encodingType     = x509ASNEncoding | pkcs7ASNEncoding
)

// cryptDataBlob is the CRYPT_DATA_BLOB / CRYPTOAPI_BLOB structure for PFX import.
type cryptDataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	modcrypt32 = windows.NewLazySystemDLL("crypt32.dll")

	procCertOpenStore                    = modcrypt32.NewProc("CertOpenStore")
	procCertCloseStore                   = modcrypt32.NewProc("CertCloseStore")
	procCertEnumCertificatesInStore      = modcrypt32.NewProc("CertEnumCertificatesInStore")
	procCertFindCertificateInStore       = modcrypt32.NewProc("CertFindCertificateInStore")
	procCertAddCertificateContextToStore = modcrypt32.NewProc("CertAddCertificateContextToStore")
	procCertDeleteCertificateFromStore   = modcrypt32.NewProc("CertDeleteCertificateFromStore")
	procCertFreeCertificateContext       = modcrypt32.NewProc("CertFreeCertificateContext")
	procPFXImportCertStore               = modcrypt32.NewProc("PFXImportCertStore")
)

// winCertStoreBackend stores certificates in the Windows Certificate Store
// via CryptoAPI. It maintains filesystem PEM backups for ACME renewal operations,
// since extracting private keys from the Windows cert store is complex.
type winCertStoreBackend struct {
	storeLocation uint32         // CERT_SYSTEM_STORE_LOCAL_MACHINE or CERT_SYSTEM_STORE_CURRENT_USER
	storeName     string         // "My", "WebHosting", etc.
	fsBackup      *fsCertBackend // PEM backup for Load/renewal operations
}

// newCertBackend creates the appropriate certificate backend for the given path.
// On Windows, paths starting with "cert:\" use the Windows Certificate Store;
// all other paths use filesystem PEM storage.
func newCertBackend(certStorePath string) (CertBackend, error) {
	if isCertStorePath(certStorePath) {
		location, storeName := parseCertStorePath(certStorePath)
		return newWinCertStoreBackend(location, storeName)
	}
	return newFsCertBackend(filepath.Join(certStorePath, "acme", "certificates"))
}

// newWinCertStoreBackend creates a Windows cert store backend with filesystem backup.
func newWinCertStoreBackend(location, storeName string) (*winCertStoreBackend, error) {
	storeLocation := uint32(certSystemStoreLocalMachine)
	if strings.EqualFold(location, "CurrentUser") {
		storeLocation = certSystemStoreCurrentUser
	}

	// Create backup filesystem backend at the platform default location
	backupDir := filepath.Join(os.Getenv("ProgramData"), "cfgms", "certs", "acme", "certificates")
	fsBackup, err := newFsCertBackend(backupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create backup storage: %w", err)
	}

	return &winCertStoreBackend{
		storeLocation: storeLocation,
		storeName:     storeName,
		fsBackup:      fsBackup,
	}, nil
}

func (w *winCertStoreBackend) StoreCertificate(domain string, certPEM, keyPEM, issuerPEM []byte, meta *CertificateMetadata) error {
	// Save PEM backup to filesystem first (needed for renewals and status checks)
	if err := w.fsBackup.StoreCertificate(domain, certPEM, keyPEM, issuerPEM, meta); err != nil {
		return fmt.Errorf("failed to store PEM backup: %w", err)
	}

	// Import into Windows Certificate Store
	if err := w.importToStore(certPEM, keyPEM, issuerPEM); err != nil {
		return fmt.Errorf("%w: %v", ErrCertStoreImportFailed, err)
	}

	return nil
}

func (w *winCertStoreBackend) LoadCertificate(domain string) (certPEM, keyPEM []byte, err error) {
	return w.fsBackup.LoadCertificate(domain)
}

func (w *winCertStoreBackend) LoadCertificateMetadata(domain string) (*CertificateMetadata, error) {
	return w.fsBackup.LoadCertificateMetadata(domain)
}

func (w *winCertStoreBackend) DeleteCertificate(domain string) error {
	// Load the cert to get the subject name for store lookup
	certPEM, _, err := w.fsBackup.LoadCertificate(domain)
	if err == nil {
		// Best-effort removal from Windows cert store
		_ = w.deleteFromStore(certPEM)
	}

	// Always clean up filesystem backup
	return w.fsBackup.DeleteCertificate(domain)
}

func (w *winCertStoreBackend) CertificateExists(domain string) bool {
	return w.fsBackup.CertificateExists(domain)
}

// importToStore converts PEM cert+key to PFX and imports into the Windows cert store.
func (w *winCertStoreBackend) importToStore(certPEM, keyPEM, issuerPEM []byte) error {
	// Parse PEM certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse private key (supports EC, RSA, PKCS8)
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode key PEM")
	}
	key, err := parsePrivateKeyDER(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Parse optional CA/issuer certificates
	var caCerts []*x509.Certificate
	if len(issuerPEM) > 0 {
		rest := issuerPEM
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			caCert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				caCerts = append(caCerts, caCert)
			}
		}
	}

	// Encode to PFX using LegacyDES for broad Windows compatibility
	pfxData, err := gopkcs12.LegacyDES.Encode(key, cert, caCerts, "")
	if err != nil {
		return fmt.Errorf("failed to encode PFX: %w", err)
	}

	// Import PFX into a temporary in-memory store
	pfxBlob := cryptDataBlob{
		cbData: uint32(len(pfxData)),
		pbData: &pfxData[0],
	}

	passwordPtr, err := windows.UTF16PtrFromString("")
	if err != nil {
		return fmt.Errorf("failed to encode password: %w", err)
	}

	flags := uintptr(cryptExportable | cryptMachineKeyset | pkcs12AllowOverwriteKey)
	tempStore, _, callErr := procPFXImportCertStore.Call(
		uintptr(unsafe.Pointer(&pfxBlob)),
		uintptr(unsafe.Pointer(passwordPtr)),
		flags,
	)
	if tempStore == 0 {
		return fmt.Errorf("PFXImportCertStore failed: %v", callErr)
	}
	defer procCertCloseStore.Call(tempStore, 0) //nolint:errcheck

	// Open the target system store
	targetStore, err := w.openSystemStore()
	if err != nil {
		return err
	}
	defer procCertCloseStore.Call(uintptr(targetStore), 0) //nolint:errcheck

	// Enumerate certificates from the temp store and add to target
	var prevCtx uintptr
	for {
		certCtx, _, _ := procCertEnumCertificatesInStore.Call(tempStore, prevCtx)
		if certCtx == 0 {
			break
		}

		// Add to target store (replaces existing cert with same subject)
		ret, _, callErr := procCertAddCertificateContextToStore.Call(
			uintptr(targetStore),
			certCtx,
			uintptr(certStoreAddReplaceExisting),
			0, // don't need output context
		)
		if ret == 0 {
			procCertFreeCertificateContext.Call(certCtx) //nolint:errcheck
			return fmt.Errorf("CertAddCertificateContextToStore failed: %v", callErr)
		}

		prevCtx = certCtx
	}

	return nil
}

// deleteFromStore removes a certificate from the Windows cert store by subject match.
func (w *winCertStoreBackend) deleteFromStore(certPEM []byte) error {
	// Parse to get the subject common name for lookup
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	store, err := w.openSystemStore()
	if err != nil {
		return err
	}
	defer procCertCloseStore.Call(uintptr(store), 0) //nolint:errcheck

	// Find the certificate by subject CN
	subject := cert.Subject.CommonName
	if subject == "" && len(cert.DNSNames) > 0 {
		subject = cert.DNSNames[0]
	}

	subjectPtr, err := windows.UTF16PtrFromString(subject)
	if err != nil {
		return fmt.Errorf("failed to encode subject: %w", err)
	}

	certCtx, _, _ := procCertFindCertificateInStore.Call(
		uintptr(store),
		uintptr(encodingType),
		0,
		uintptr(certFindSubjectStr),
		uintptr(unsafe.Pointer(subjectPtr)),
		0,
	)
	if certCtx == 0 {
		return nil // Not found — nothing to delete
	}

	// CertDeleteCertificateFromStore frees the context, so we don't call CertFreeCertificateContext
	ret, _, callErr := procCertDeleteCertificateFromStore.Call(certCtx)
	if ret == 0 {
		return fmt.Errorf("CertDeleteCertificateFromStore failed: %v", callErr)
	}

	return nil
}

// openSystemStore opens the configured Windows system certificate store.
func (w *winCertStoreBackend) openSystemStore() (syscall.Handle, error) {
	storeNamePtr, err := windows.UTF16PtrFromString(w.storeName)
	if err != nil {
		return 0, fmt.Errorf("failed to encode store name: %w", err)
	}

	store, _, callErr := procCertOpenStore.Call(
		uintptr(certStoreProvSystem),
		0, // encoding type (unused for system stores)
		0, // hCryptProv (unused)
		uintptr(w.storeLocation),
		uintptr(unsafe.Pointer(storeNamePtr)),
	)
	if store == 0 {
		return 0, fmt.Errorf("%w: %v", ErrCertStoreOpenFailed, callErr)
	}

	return syscall.Handle(store), nil
}

// parsePrivateKeyDER tries to parse a DER-encoded private key as EC, PKCS1 RSA, or PKCS8.
func parsePrivateKeyDER(der []byte) (any, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}
