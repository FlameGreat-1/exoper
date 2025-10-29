package mtls

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"exoper/backend/internal/common/config"
	"exoper/backend/internal/common/database"
	"exoper/backend/internal/common/errors"
)

type CertificateStatus string
type RevocationReason string

const (
	StatusValid     CertificateStatus = "valid"
	StatusExpired   CertificateStatus = "expired"
	StatusRevoked   CertificateStatus = "revoked"
	StatusInvalid   CertificateStatus = "invalid"
	StatusUnknown   CertificateStatus = "unknown"
	StatusSuspended CertificateStatus = "suspended"

	ReasonUnspecified          RevocationReason = "unspecified"
	ReasonKeyCompromise        RevocationReason = "key_compromise"
	ReasonCACompromise         RevocationReason = "ca_compromise"
	ReasonAffiliationChanged   RevocationReason = "affiliation_changed"
	ReasonSuperseded           RevocationReason = "superseded"
	ReasonCessationOfOperation RevocationReason = "cessation_of_operation"
	ReasonCertificateHold      RevocationReason = "certificate_hold"
	ReasonPrivilegeWithdrawn   RevocationReason = "privilege_withdrawn"
	ReasonAACompromise         RevocationReason = "aa_compromise"
)

type MTLSManager struct {
	config       *config.Config
	db           *database.Database
	logger       *zap.Logger
	rootCAs      *x509.CertPool
	intermediateCAs *x509.CertPool
	crlCache     map[string]*CRLInfo
	ocspCache    map[string]*OCSPResponse
}

type CertificateInfo struct {
	SerialNumber       string            `json:"serial_number"`
	Subject            string            `json:"subject"`
	Issuer             string            `json:"issuer"`
	NotBefore          time.Time         `json:"not_before"`
	NotAfter           time.Time         `json:"not_after"`
	Fingerprint        string            `json:"fingerprint"`
	FingerprintSHA256  string            `json:"fingerprint_sha256"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	KeyUsage           []string          `json:"key_usage"`
	ExtendedKeyUsage   []string          `json:"extended_key_usage"`
	SubjectAltNames    []string          `json:"subject_alt_names"`
	Status             CertificateStatus `json:"status"`
	RevocationReason   string            `json:"revocation_reason,omitempty"`
	RevocationTime     *time.Time        `json:"revocation_time,omitempty"`
	TrustChain         []string          `json:"trust_chain"`
	ValidationErrors   []string          `json:"validation_errors,omitempty"`
}

type CertificateValidationRequest struct {
	Certificate      string   `json:"certificate"`
	CertificateChain []string `json:"certificate_chain,omitempty"`
	CheckRevocation  bool     `json:"check_revocation"`
	CheckExpiration  bool     `json:"check_expiration"`
	RequiredKeyUsage []string `json:"required_key_usage,omitempty"`
	TenantID         string   `json:"tenant_id,omitempty"`
	ClientIP         string   `json:"client_ip,omitempty"`
}

type CertificateValidationResult struct {
	Valid              bool              `json:"valid"`
	CertificateInfo    *CertificateInfo  `json:"certificate_info"`
	ValidationErrors   []ValidationError `json:"validation_errors,omitempty"`
	TrustChainStatus   string            `json:"trust_chain_status"`
	RevocationStatus   string            `json:"revocation_status"`
	RiskScore          float64           `json:"risk_score"`
	RiskFactors        []string          `json:"risk_factors,omitempty"`
	ValidatedAt        time.Time         `json:"validated_at"`
	ValidationDuration time.Duration     `json:"validation_duration"`
}

type ValidationError struct {
	Code     string                `json:"code"`
	Message  string                `json:"message"`
	Severity errors.ErrorSeverity  `json:"severity"`
	Field    string                `json:"field,omitempty"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

type CRLInfo struct {
	URL           string                    `json:"url"`
	LastUpdate    time.Time                 `json:"last_update"`
	NextUpdate    time.Time                 `json:"next_update"`
	RevokedCerts  map[string]*RevokedCert   `json:"revoked_certs"`
	CacheExpiry   time.Time                 `json:"cache_expiry"`
}

type RevokedCert struct {
	SerialNumber     string           `json:"serial_number"`
	RevocationTime   time.Time        `json:"revocation_time"`
	RevocationReason RevocationReason `json:"revocation_reason"`
}

type OCSPResponse struct {
	Status       string    `json:"status"`
	ProducedAt   time.Time `json:"produced_at"`
	ThisUpdate   time.Time `json:"this_update"`
	NextUpdate   time.Time `json:"next_update"`
	CacheExpiry  time.Time `json:"cache_expiry"`
}

type TrustedCertificate struct {
	ID           uuid.UUID         `db:"id"`
	TenantID     uuid.UUID         `db:"tenant_id"`
	Name         string            `db:"name"`
	Certificate  string            `db:"certificate"`
	Fingerprint  string            `db:"fingerprint"`
	Subject      string            `db:"subject"`
	Issuer       string            `db:"issuer"`
	NotBefore    time.Time         `db:"not_before"`
	NotAfter     time.Time         `db:"not_after"`
	KeyUsage     []string          `db:"key_usage"`
	IsActive     bool              `db:"is_active"`
	CreatedAt    time.Time         `db:"created_at"`
	CreatedBy    uuid.UUID         `db:"created_by"`
	RevokedAt    *time.Time        `db:"revoked_at"`
	RevokedBy    *uuid.UUID        `db:"revoked_by"`
	Metadata     map[string]interface{} `db:"metadata"`
}

func NewMTLSManager(cfg *config.Config, db *database.Database, logger *zap.Logger) (*MTLSManager, error) {
	manager := &MTLSManager{
		config:    cfg,
		db:        db,
		logger:    logger,
		crlCache:  make(map[string]*CRLInfo),
		ocspCache: make(map[string]*OCSPResponse),
	}

	if err := manager.loadTrustedCAs(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to load trusted CAs")
	}

	if err := manager.initializeRevocationChecking(); err != nil {
		logger.Warn("Failed to initialize revocation checking", zap.Error(err))
	}

	return manager, nil
}

func (m *MTLSManager) ValidateCertificate(ctx context.Context, req *CertificateValidationRequest) (*CertificateValidationResult, error) {
	startTime := time.Now()
	
	result := &CertificateValidationResult{
		Valid:              false,
		ValidationErrors:   []ValidationError{},
		ValidatedAt:        startTime,
		RiskFactors:        []string{},
	}

	if req.Certificate == "" {
		result.ValidationErrors = append(result.ValidationErrors, ValidationError{
			Code:     "missing_certificate",
			Message:  "certificate is required",
			Severity: errors.SeverityHigh,
		})
		result.ValidationDuration = time.Since(startTime)
		return result, nil
	}

	cert, err := m.parseCertificate(req.Certificate)
	if err != nil {
		result.ValidationErrors = append(result.ValidationErrors, ValidationError{
			Code:     "invalid_certificate_format",
			Message:  fmt.Sprintf("failed to parse certificate: %v", err),
			Severity: errors.SeverityHigh,
		})
		result.ValidationDuration = time.Since(startTime)
		return result, nil
	}

	certInfo := m.extractCertificateInfo(cert)
	result.CertificateInfo = certInfo

	if req.CheckExpiration {
		if err := m.validateExpiration(cert); err != nil {
			result.ValidationErrors = append(result.ValidationErrors, ValidationError{
				Code:     "certificate_expired",
				Message:  err.Error(),
				Severity: errors.SeverityHigh,
			})
		}
	}

	if err := m.validateKeyUsage(cert, req.RequiredKeyUsage); err != nil {
		result.ValidationErrors = append(result.ValidationErrors, ValidationError{
			Code:     "invalid_key_usage",
			Message:  err.Error(),
			Severity: errors.SeverityMedium,
		})
	}

	trustChainResult := m.validateTrustChain(cert, req.CertificateChain)
	result.TrustChainStatus = trustChainResult.Status
	if !trustChainResult.Valid {
		for _, err := range trustChainResult.Errors {
			result.ValidationErrors = append(result.ValidationErrors, err)
		}
	}

	if req.CheckRevocation {
		revocationResult := m.checkRevocationStatus(ctx, cert)
		result.RevocationStatus = revocationResult.Status
		if revocationResult.Revoked {
			result.ValidationErrors = append(result.ValidationErrors, ValidationError{
				Code:     "certificate_revoked",
				Message:  fmt.Sprintf("certificate has been revoked: %s", revocationResult.Reason),
				Severity: errors.SeverityHigh,
			})
		}
	}

	result.RiskScore = m.calculateCertificateRiskScore(cert, req)
	result.RiskFactors = m.assessCertificateRiskFactors(cert, req)

	if len(result.ValidationErrors) == 0 {
		result.Valid = true
	}

	result.ValidationDuration = time.Since(startTime)

	m.logCertificateValidation(req, result)

	return result, nil
}

func (m *MTLSManager) ExtractClientCertificate(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "no TLS connection information")
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New(errors.ErrCodeUnauthorized, "no client certificate provided")
	}

	clientCert := r.TLS.PeerCertificates[0]
	
	if err := m.validateClientCertificateBasics(clientCert); err != nil {
		return nil, err
	}

	return clientCert, nil
}

func (m *MTLSManager) ValidateClientCertificate(ctx context.Context, cert *x509.Certificate, tenantID string) (*CertificateValidationResult, error) {
	req := &CertificateValidationRequest{
		Certificate:     m.encodeCertificate(cert),
		CheckRevocation: true,
		CheckExpiration: true,
		RequiredKeyUsage: []string{"digital_signature", "key_encipherment"},
		TenantID:        tenantID,
	}

	result, err := m.ValidateCertificate(ctx, req)
	if err != nil {
		return nil, err
	}

	if tenantID != "" {
		if err := m.validateTenantCertificateAccess(ctx, cert, tenantID); err != nil {
			result.Valid = false
			result.ValidationErrors = append(result.ValidationErrors, ValidationError{
				Code:     "tenant_access_denied",
				Message:  err.Error(),
				Severity: errors.SeverityHigh,
			})
		}
	}

	return result, nil
}

func (m *MTLSManager) loadTrustedCAs() error {
	m.rootCAs = x509.NewCertPool()
	m.intermediateCAs = x509.NewCertPool()

	if m.config.Security.MTLSRootCAPath != "" {
		rootCAData, err := os.ReadFile(m.config.Security.MTLSRootCAPath)
		if err != nil {
			return fmt.Errorf("failed to read root CA file: %v", err)
		}

		if !m.rootCAs.AppendCertsFromPEM(rootCAData) {
			return fmt.Errorf("failed to parse root CA certificates")
		}
	}

	if m.config.Security.MTLSIntermediateCAPath != "" {
		intermediateCAData, err := os.ReadFile(m.config.Security.MTLSIntermediateCAPath)
		if err != nil {
			return fmt.Errorf("failed to read intermediate CA file: %v", err)
		}

		if !m.intermediateCAs.AppendCertsFromPEM(intermediateCAData) {
			return fmt.Errorf("failed to parse intermediate CA certificates")
		}
	}

	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		m.logger.Warn("Failed to load system cert pool", zap.Error(err))
	} else {
		for _, cert := range systemRoots.Subjects() {
			m.rootCAs.AddCert(&x509.Certificate{Raw: cert})
		}
	}

	return nil
}

func (m *MTLSManager) initializeRevocationChecking() error {
	go m.startCRLUpdateWorker()
	go m.startOCSPCacheWorker()
	return nil
}

func (m *MTLSManager) parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func (m *MTLSManager) extractCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	sha1Hash := sha1.Sum(cert.Raw)
	fingerprint := hex.EncodeToString(sha1Hash[:])
	
	sha256Hash := sha256.Sum256(cert.Raw)
	fingerprintSHA256 := hex.EncodeToString(sha256Hash[:])

	keyUsage := m.extractKeyUsage(cert)
	extKeyUsage := m.extractExtendedKeyUsage(cert)
	subjectAltNames := m.extractSubjectAltNames(cert)

	return &CertificateInfo{
		SerialNumber:       cert.SerialNumber.String(),
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		Fingerprint:        fingerprint,
		FingerprintSHA256:  fingerprintSHA256,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		KeyUsage:           keyUsage,
		ExtendedKeyUsage:   extKeyUsage,
		SubjectAltNames:    subjectAltNames,
		Status:             StatusValid,
		TrustChain:         []string{},
		ValidationErrors:   []string{},
	}
}

func (m *MTLSManager) validateExpiration(cert *x509.Certificate) error {
	now := time.Now()
	
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (valid from %v)", cert.NotBefore)
	}
	
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (expired on %v)", cert.NotAfter)
	}

	timeUntilExpiry := cert.NotAfter.Sub(now)
	if timeUntilExpiry < 30*24*time.Hour {
		m.logger.Warn("Certificate expires soon",
			zap.String("serial", cert.SerialNumber.String()),
			zap.Duration("time_until_expiry", timeUntilExpiry))
	}

	return nil
}

func (m *MTLSManager) validateKeyUsage(cert *x509.Certificate, requiredUsage []string) error {
	if len(requiredUsage) == 0 {
		return nil
	}

	certKeyUsage := m.extractKeyUsage(cert)
	certExtKeyUsage := m.extractExtendedKeyUsage(cert)
	
	allUsage := append(certKeyUsage, certExtKeyUsage...)

	for _, required := range requiredUsage {
		found := false
		for _, usage := range allUsage {
			if strings.EqualFold(usage, required) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("certificate missing required key usage: %s", required)
		}
	}

	return nil
}

func (m *MTLSManager) validateTrustChain(cert *x509.Certificate, chainPEMs []string) *TrustChainResult {
	result := &TrustChainResult{
		Valid:  false,
		Status: "invalid",
		Errors: []ValidationError{},
		Chain:  []string{},
	}

	intermediates := x509.NewCertPool()
	
	for _, chainPEM := range chainPEMs {
		chainCert, err := m.parseCertificate(chainPEM)
		if err != nil {
			result.Errors = append(result.Errors, ValidationError{
				Code:     "invalid_chain_certificate",
				Message:  fmt.Sprintf("failed to parse chain certificate: %v", err),
				Severity: errors.SeverityMedium,
			})
			continue
		}
		intermediates.AddCert(chainCert)
		result.Chain = append(result.Chain, chainCert.Subject.String())
	}

	if m.intermediateCAs != nil {
		for _, cert := range m.intermediateCAs.Subjects() {
			intermediates.AddCert(&x509.Certificate{Raw: cert})
		}
	}

	opts := x509.VerifyOptions{
		Roots:         m.rootCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "trust_chain_verification_failed",
			Message:  fmt.Sprintf("certificate chain verification failed: %v", err),
			Severity: errors.SeverityHigh,
		})
		result.Status = "verification_failed"
		return result
	}

	if len(chains) == 0 {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "no_valid_chain",
			Message:  "no valid certificate chain found",
			Severity: errors.SeverityHigh,
		})
		result.Status = "no_valid_chain"
		return result
	}

	result.Valid = true
	result.Status = "valid"
	
	for _, chain := range chains[0] {
		result.Chain = append(result.Chain, chain.Subject.String())
	}

	return result
}

func (m *MTLSManager) checkRevocationStatus(ctx context.Context, cert *x509.Certificate) *RevocationResult {
	result := &RevocationResult{
		Revoked: false,
		Status:  "not_revoked",
		Reason:  "",
		Method:  "",
	}

	if len(cert.CRLDistributionPoints) > 0 {
		crlResult := m.checkCRLRevocation(ctx, cert)
		if crlResult.Revoked {
			result.Revoked = true
			result.Status = "revoked"
			result.Reason = crlResult.Reason
			result.Method = "CRL"
			return result
		}
	}

	if len(cert.OCSPServer) > 0 {
		ocspResult := m.checkOCSPRevocation(ctx, cert)
		if ocspResult.Revoked {
			result.Revoked = true
			result.Status = "revoked"
			result.Reason = ocspResult.Reason
			result.Method = "OCSP"
			return result
		}
	}

	if len(cert.CRLDistributionPoints) == 0 && len(cert.OCSPServer) == 0 {
		result.Status = "no_revocation_info"
	}

	return result
}

func (m *MTLSManager) checkCRLRevocation(ctx context.Context, cert *x509.Certificate) *RevocationResult {
	result := &RevocationResult{
		Revoked: false,
		Status:  "not_revoked",
		Method:  "CRL",
	}

	for _, crlURL := range cert.CRLDistributionPoints {
		crlInfo, err := m.getCRLInfo(ctx, crlURL)
		if err != nil {
			m.logger.Warn("Failed to get CRL info", zap.String("url", crlURL), zap.Error(err))
			continue
		}

		if revokedCert, exists := crlInfo.RevokedCerts[cert.SerialNumber.String()]; exists {
			result.Revoked = true
			result.Status = "revoked"
			result.Reason = string(revokedCert.RevocationReason)
			result.RevokedAt = &revokedCert.RevocationTime
			return result
		}
	}

	return result
}

func (m *MTLSManager) checkOCSPRevocation(ctx context.Context, cert *x509.Certificate) *RevocationResult {
	result := &RevocationResult{
		Revoked: false,
		Status:  "not_revoked",
		Method:  "OCSP",
	}

	for _, ocspURL := range cert.OCSPServer {
		ocspResp, err := m.getOCSPResponse(ctx, cert, ocspURL)
		if err != nil {
			m.logger.Warn("Failed to get OCSP response", zap.String("url", ocspURL), zap.Error(err))
			continue
		}

		if ocspResp.Status == "revoked" {
			result.Revoked = true
			result.Status = "revoked"
			return result
		}
	}

	return result
}

func (m *MTLSManager) calculateCertificateRiskScore(cert *x509.Certificate, req *CertificateValidationRequest) float64 {
	score := 0.0

	timeUntilExpiry := cert.NotAfter.Sub(time.Now())
	if timeUntilExpiry < 30*24*time.Hour {
		score += 0.3
	} else if timeUntilExpiry < 90*24*time.Hour {
		score += 0.1
	}

	certAge := time.Since(cert.NotBefore)
	if certAge > 2*365*24*time.Hour {
		score += 0.2
	}

	if cert.PublicKeyAlgorithm == x509.RSA {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			if rsaKey.N.BitLen() < 2048 {
				score += 0.4
			}
		}
	}

	if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.MD5WithRSA {
		score += 0.5
	}

	if len(cert.CRLDistributionPoints) == 0 && len(cert.OCSPServer) == 0 {
		score += 0.2
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (m *MTLSManager) assessCertificateRiskFactors(cert *x509.Certificate, req *CertificateValidationRequest) []string {
	factors := []string{}

	timeUntilExpiry := cert.NotAfter.Sub(time.Now())
	if timeUntilExpiry < 30*24*time.Hour {
		factors = append(factors, "expires_soon")
	}

	certAge := time.Since(cert.NotBefore)
	if certAge > 2*365*24*time.Hour {
		factors = append(factors, "old_certificate")
	}

	if cert.PublicKeyAlgorithm == x509.RSA {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			if rsaKey.N.BitLen() < 2048 {
				factors = append(factors, "weak_key_size")
			}
		}
	}

	if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.MD5WithRSA {
		factors = append(factors, "weak_signature_algorithm")
	}

	if len(cert.CRLDistributionPoints) == 0 && len(cert.OCSPServer) == 0 {
		factors = append(factors, "no_revocation_info")
	}

	return factors
}

func (m *MTLSManager) validateClientCertificateBasics(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "certificate is nil")
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return errors.New(errors.ErrCodeUnauthorized, "certificate is not yet valid")
	}

	if now.After(cert.NotAfter) {
		return errors.New(errors.ErrCodeUnauthorized, "certificate has expired")
	}

	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}

	if !hasClientAuth {
		return errors.New(errors.ErrCodeUnauthorized, "certificate not valid for client authentication")
	}

	return nil
}

func (m *MTLSManager) validateTenantCertificateAccess(ctx context.Context, cert *x509.Certificate, tenantID string) error {
	sha256Hash := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(sha256Hash[:])
	
	query := `
		SELECT EXISTS(
			SELECT 1 FROM trusted_certificates 
			WHERE tenant_id = $1 AND fingerprint = $2 AND is_active = true
		)`

	var exists bool
	err := m.db.Get(ctx, &exists, query, tenantID, fingerprint)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to check certificate access")
	}

	if !exists {
		return errors.New(errors.ErrCodeForbidden, "certificate not authorized for tenant")
	}

	return nil
}

func (m *MTLSManager) encodeCertificate(cert *x509.Certificate) string {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return string(certPEM)
}

func (m *MTLSManager) extractKeyUsage(cert *x509.Certificate) []string {
	var usage []string

	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		usage = append(usage, "digital_signature")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		usage = append(usage, "content_commitment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usage = append(usage, "key_encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		usage = append(usage, "data_encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		usage = append(usage, "key_agreement")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		usage = append(usage, "cert_sign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		usage = append(usage, "crl_sign")
	}
	if cert.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		usage = append(usage, "encipher_only")
	}
	if cert.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		usage = append(usage, "decipher_only")
	}

	return usage
}

func (m *MTLSManager) extractExtendedKeyUsage(cert *x509.Certificate) []string {
	var usage []string

	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			usage = append(usage, "server_auth")
		case x509.ExtKeyUsageClientAuth:
			usage = append(usage, "client_auth")
		case x509.ExtKeyUsageCodeSigning:
			usage = append(usage, "code_signing")
		case x509.ExtKeyUsageEmailProtection:
			usage = append(usage, "email_protection")
		case x509.ExtKeyUsageTimeStamping:
			usage = append(usage, "time_stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usage = append(usage, "ocsp_signing")
		}
	}

	return usage
}

func (m *MTLSManager) extractSubjectAltNames(cert *x509.Certificate) []string {
	var names []string

	names = append(names, cert.DNSNames...)
	
	for _, email := range cert.EmailAddresses {
		names = append(names, email)
	}

	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}

	for _, uri := range cert.URIs {
		names = append(names, uri.String())
	}

	return names
}

func (m *MTLSManager) logCertificateValidation(req *CertificateValidationRequest, result *CertificateValidationResult) {
	if result.Valid {
		m.logger.Info("Certificate validation successful",
			zap.String("serial_number", result.CertificateInfo.SerialNumber),
			zap.String("subject", result.CertificateInfo.Subject),
			zap.String("issuer", result.CertificateInfo.Issuer),
			zap.Float64("risk_score", result.RiskScore),
			zap.Strings("risk_factors", result.RiskFactors),
			zap.Duration("validation_duration", result.ValidationDuration))
	} else {
		errorCodes := make([]string, len(result.ValidationErrors))
		for i, err := range result.ValidationErrors {
			errorCodes[i] = err.Code
		}

		m.logger.Warn("Certificate validation failed",
			zap.String("serial_number", result.CertificateInfo.SerialNumber),
			zap.String("subject", result.CertificateInfo.Subject),
			zap.Strings("error_codes", errorCodes),
			zap.Duration("validation_duration", result.ValidationDuration))
	}
}
