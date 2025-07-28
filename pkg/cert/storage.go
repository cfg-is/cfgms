package cert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileStore implements CertificateStore using filesystem storage
type FileStore struct {
	mu      sync.RWMutex
	basePath string
	certs   map[string]*CertificateInfo // indexed by serial number
}

// NewFileStore creates a new filesystem-based certificate store
func NewFileStore(basePath string) (*FileStore, error) {
	if basePath == "" {
		return nil, fmt.Errorf("base path is required")
	}
	
	// Create base directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}
	
	store := &FileStore{
		basePath: basePath,
		certs:    make(map[string]*CertificateInfo),
	}
	
	// Load existing certificates
	if err := store.loadCertificates(); err != nil {
		return nil, fmt.Errorf("failed to load existing certificates: %w", err)
	}
	
	return store, nil
}

// StoreCertificate stores a certificate in the filesystem
func (fs *FileStore) StoreCertificate(cert *Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is required")
	}
	
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	// Create certificate-specific directory
	certDir := filepath.Join(fs.basePath, cert.SerialNumber)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}
	
	// Store certificate PEM
	certPath := filepath.Join(certDir, "cert.pem")
	if err := os.WriteFile(certPath, cert.CertificatePEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	
	// Store private key PEM (if available) with restricted permissions
	if cert.PrivateKeyPEM != nil {
		keyPath := filepath.Join(certDir, "key.pem")
		if err := os.WriteFile(keyPath, cert.PrivateKeyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write private key: %w", err)
		}
	}
	
	// Store certificate metadata
	metadata := &CertificateInfo{
		Type:                cert.Type,
		CommonName:          cert.CommonName,
		SerialNumber:        cert.SerialNumber,
		CreatedAt:           cert.CreatedAt,
		ExpiresAt:           cert.ExpiresAt,
		IsValid:             cert.IsValid,
		Fingerprint:         cert.Fingerprint,
		Issuer:              cert.Issuer,
		ClientID:            cert.ClientID,
		DaysUntilExpiration: int(time.Until(cert.ExpiresAt).Hours() / 24),
		NeedsRenewal:        int(time.Until(cert.ExpiresAt).Hours()/24) < 30,
	}
	
	metadataPath := filepath.Join(certDir, "metadata.json")
	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	
	if err := os.WriteFile(metadataPath, metadataJSON, 0644); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}
	
	// Update in-memory cache
	fs.certs[cert.SerialNumber] = metadata
	
	return nil
}

// GetCertificate retrieves a certificate by serial number
func (fs *FileStore) GetCertificate(serialNumber string) (*Certificate, error) {
	if serialNumber == "" {
		return nil, fmt.Errorf("serial number is required")
	}
	
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	certDir := filepath.Join(fs.basePath, serialNumber)
	
	// Check if certificate directory exists
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate not found: %s", serialNumber)
	}
	
	// Load certificate PEM
	certPath := filepath.Join(certDir, "cert.pem")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	
	// Load private key PEM (if exists)
	var keyPEM []byte
	keyPath := filepath.Join(certDir, "key.pem")
	if _, err := os.Stat(keyPath); err == nil {
		keyPEM, err = os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}
	}
	
	// Load metadata
	metadataPath := filepath.Join(certDir, "metadata.json")
	metadataJSON, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}
	
	var metadata CertificateInfo
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}
	
	return &Certificate{
		Type:           metadata.Type,
		CommonName:     metadata.CommonName,
		SerialNumber:   metadata.SerialNumber,
		CreatedAt:      metadata.CreatedAt,
		ExpiresAt:      metadata.ExpiresAt,
		IsValid:        metadata.IsValid,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		Fingerprint:    metadata.Fingerprint,
		Issuer:         metadata.Issuer,
		ClientID:       metadata.ClientID,
	}, nil
}

// GetCertificateByCommonName retrieves certificates by common name
func (fs *FileStore) GetCertificateByCommonName(commonName string) ([]*CertificateInfo, error) {
	if commonName == "" {
		return nil, fmt.Errorf("common name is required")
	}
	
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	var results []*CertificateInfo
	for _, cert := range fs.certs {
		if cert.CommonName == commonName {
			// Create a copy to avoid mutation
			certCopy := *cert
			results = append(results, &certCopy)
		}
	}
	
	// Sort by creation date (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})
	
	return results, nil
}

// GetCertificatesByType retrieves certificates by type
func (fs *FileStore) GetCertificatesByType(certType CertificateType) ([]*CertificateInfo, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	var results []*CertificateInfo
	for _, cert := range fs.certs {
		if cert.Type == certType {
			// Create a copy to avoid mutation
			certCopy := *cert
			results = append(results, &certCopy)
		}
	}
	
	// Sort by creation date (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})
	
	return results, nil
}

// ListCertificates returns all certificates
func (fs *FileStore) ListCertificates() ([]*CertificateInfo, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	var results []*CertificateInfo
	for _, cert := range fs.certs {
		// Skip CA certificates - they are handled separately
		if cert.Type == CertificateTypeCA {
			continue
		}
		
		// Create a copy to avoid mutation
		certCopy := *cert
		// Update dynamic fields
		certCopy.DaysUntilExpiration = int(time.Until(certCopy.ExpiresAt).Hours() / 24)
		certCopy.NeedsRenewal = certCopy.DaysUntilExpiration < 30
		certCopy.IsValid = time.Now().Before(certCopy.ExpiresAt)
		
		results = append(results, &certCopy)
	}
	
	// Sort by creation date (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})
	
	return results, nil
}

// DeleteCertificate removes a certificate from storage
func (fs *FileStore) DeleteCertificate(serialNumber string) error {
	if serialNumber == "" {
		return fmt.Errorf("serial number is required")
	}
	
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	certDir := filepath.Join(fs.basePath, serialNumber)
	
	// Check if certificate directory exists
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		return fmt.Errorf("certificate not found: %s", serialNumber)
	}
	
	// Remove certificate directory and all files
	if err := os.RemoveAll(certDir); err != nil {
		return fmt.Errorf("failed to remove certificate directory: %w", err)
	}
	
	// Remove from in-memory cache
	delete(fs.certs, serialNumber)
	
	return nil
}

// GetExpiringCertificates returns certificates expiring within the specified days
func (fs *FileStore) GetExpiringCertificates(withinDays int) ([]*CertificateInfo, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	cutoffDate := time.Now().Add(time.Duration(withinDays) * 24 * time.Hour)
	
	var results []*CertificateInfo
	for _, cert := range fs.certs {
		if cert.ExpiresAt.Before(cutoffDate) && cert.ExpiresAt.After(time.Now()) {
			// Create a copy to avoid mutation
			certCopy := *cert
			certCopy.DaysUntilExpiration = int(time.Until(certCopy.ExpiresAt).Hours() / 24)
			certCopy.NeedsRenewal = true
			
			results = append(results, &certCopy)
		}
	}
	
	// Sort by expiration date (soonest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].ExpiresAt.Before(results[j].ExpiresAt)
	})
	
	return results, nil
}

// loadCertificates loads all certificates from storage into memory
func (fs *FileStore) loadCertificates() error {
	// Read all directories in base path
	entries, err := os.ReadDir(fs.basePath)
	if err != nil {
		return fmt.Errorf("failed to read storage directory: %w", err)
	}
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		serialNumber := entry.Name()
		
		// Skip if not a valid serial number directory
		if strings.Contains(serialNumber, ".") {
			continue
		}
		
		// Load metadata for this certificate
		metadataPath := filepath.Join(fs.basePath, serialNumber, "metadata.json")
		if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
			continue // Skip directories without metadata
		}
		
		metadataJSON, err := os.ReadFile(metadataPath)
		if err != nil {
			continue // Skip if we can't read metadata
		}
		
		var metadata CertificateInfo
		if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
			continue // Skip if metadata is invalid
		}
		
		// Add to in-memory cache
		fs.certs[serialNumber] = &metadata
	}
	
	return nil
}

// RefreshCache reloads all certificates from storage
func (fs *FileStore) RefreshCache() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	// Clear existing cache
	fs.certs = make(map[string]*CertificateInfo)
	
	// Reload certificates
	return fs.loadCertificates()
}

// GetStoragePath returns the base storage path
func (fs *FileStore) GetStoragePath() string {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.basePath
}

// GetCertificateCount returns the number of certificates in storage
func (fs *FileStore) GetCertificateCount() int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.certs)
}

// GetCertificateCountByType returns the number of certificates by type
func (fs *FileStore) GetCertificateCountByType() map[CertificateType]int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	counts := make(map[CertificateType]int)
	for _, cert := range fs.certs {
		counts[cert.Type]++
	}
	
	return counts
}