package mtls

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
)

type TrustedCertificateRequest struct {
	TenantID    uuid.UUID
	Name        string
	Certificate string
	CreatedBy   uuid.UUID
	Metadata    map[string]interface{}
}

func (m *MTLSManager) AddTrustedCertificate(ctx context.Context, req *TrustedCertificateRequest) (*TrustedCertificate, error) {
	if err := m.validateTrustedCertificateRequest(req); err != nil {
		return nil, err
	}

	cert, err := m.parseCertificate(req.Certificate)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRequest, "invalid certificate format")
	}

	if err := m.validateCertificateForTrust(cert); err != nil {
		return nil, err
	}

	fingerprint := utils.CalculateSHA256Fingerprint(cert.Raw)
	
	exists, err := m.certificateExists(ctx, req.TenantID, fingerprint)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New(errors.ErrCodeConflict, "certificate already exists for tenant")
	}

	keyUsage := m.extractKeyUsage(cert)

	trustedCert := &TrustedCertificate{
		ID:          uuid.New(),
		TenantID:    req.TenantID,
		Name:        req.Name,
		Certificate: req.Certificate,
		Fingerprint: fingerprint,
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		KeyUsage:    keyUsage,
		IsActive:    true,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   req.CreatedBy,
		Metadata:    req.Metadata,
	}

	if err := m.storeTrustedCertificate(ctx, trustedCert); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to store trusted certificate")
	}

	m.logger.Info("Trusted certificate added",
		zap.String("cert_id", trustedCert.ID.String()),
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("subject", cert.Subject.String()),
		zap.String("fingerprint", fingerprint))

	return trustedCert, nil
}

func (m *MTLSManager) RevokeTrustedCertificate(ctx context.Context, certID, reason string, revokedBy uuid.UUID) error {
	now := time.Now().UTC()
	
	query := `
		UPDATE trusted_certificates 
		SET is_active = false, revoked_at = $1, revoked_by = $2 
		WHERE id = $3 AND is_active = true`

	result, err := m.db.Exec(ctx, query, now, revokedBy, certID)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to revoke trusted certificate")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New(errors.ErrCodeNotFound, "trusted certificate not found or already revoked")
	}

	m.logger.Info("Trusted certificate revoked",
		zap.String("cert_id", certID),
		zap.String("reason", reason),
		zap.String("revoked_by", revokedBy.String()))

	return nil
}

func (m *MTLSManager) ListTrustedCertificates(ctx context.Context, tenantID uuid.UUID, includeRevoked bool) ([]*TrustedCertificate, error) {
	query := `
		SELECT id, tenant_id, name, certificate, fingerprint, subject, issuer,
		       not_before, not_after, key_usage, is_active, created_at, created_by,
		       revoked_at, revoked_by, metadata
		FROM trusted_certificates 
		WHERE tenant_id = $1`

	if !includeRevoked {
		query += ` AND is_active = true`
	}

	query += ` ORDER BY created_at DESC`

	var certificates []*TrustedCertificate
	err := m.db.Select(ctx, &certificates, query, tenantID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to list trusted certificates")
	}

	return certificates, nil
}

func (m *MTLSManager) GetTrustedCertificate(ctx context.Context, certID string) (*TrustedCertificate, error) {
	query := `
		SELECT id, tenant_id, name, certificate, fingerprint, subject, issuer,
		       not_before, not_after, key_usage, is_active, created_at, created_by,
		       revoked_at, revoked_by, metadata
		FROM trusted_certificates 
		WHERE id = $1`

	var certificate TrustedCertificate
	err := m.db.Get(ctx, &certificate, query, certID)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, errors.New(errors.ErrCodeNotFound, "trusted certificate not found")
		}
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to get trusted certificate")
	}

	return &certificate, nil
}

func (m *MTLSManager) validateTrustedCertificateRequest(req *TrustedCertificateRequest) error {
	if req.TenantID == uuid.Nil {
		return errors.New(errors.ErrCodeInvalidRequest, "tenant ID is required")
	}

	if req.Name == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "certificate name is required")
	}

	if len(req.Name) > 100 {
		return errors.New(errors.ErrCodeInvalidRequest, "certificate name too long")
	}

	if req.Certificate == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "certificate is required")
	}

	if req.CreatedBy == uuid.Nil {
		return errors.New(errors.ErrCodeInvalidRequest, "created_by is required")
	}

	return nil
}

func (m *MTLSManager) validateCertificateForTrust(cert *x509.Certificate) error {
	now := time.Now()
	
	if now.After(cert.NotAfter) {
		return errors.New(errors.ErrCodeInvalidRequest, "certificate has expired")
	}

	if now.Before(cert.NotBefore) {
		return errors.New(errors.ErrCodeInvalidRequest, "certificate is not yet valid")
	}

	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}

	if !hasClientAuth {
		return errors.New(errors.ErrCodeInvalidRequest, "certificate must have client authentication usage")
	}

	if cert.PublicKeyAlgorithm == x509.RSA {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			if rsaKey.N.BitLen() < 2048 {
				return errors.New(errors.ErrCodeInvalidRequest, "RSA key size must be at least 2048 bits")
			}
		}
	}

	return nil
}

func (m *MTLSManager) certificateExists(ctx context.Context, tenantID uuid.UUID, fingerprint string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM trusted_certificates WHERE tenant_id = $1 AND fingerprint = $2)`
	
	var exists bool
	err := m.db.Get(ctx, &exists, query, tenantID, fingerprint)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (m *MTLSManager) storeTrustedCertificate(ctx context.Context, cert *TrustedCertificate) error {
	query := `
		INSERT INTO trusted_certificates (
			id, tenant_id, name, certificate, fingerprint, subject, issuer,
			not_before, not_after, key_usage, is_active, created_at, created_by, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err := m.db.Exec(ctx, query,
		cert.ID,
		cert.TenantID,
		cert.Name,
		cert.Certificate,
		cert.Fingerprint,
		cert.Subject,
		cert.Issuer,
		cert.NotBefore,
		cert.NotAfter,
		cert.KeyUsage,
		cert.IsActive,
		cert.CreatedAt,
		cert.CreatedBy,
		cert.Metadata,
	)

	return err
}
