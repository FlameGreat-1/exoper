package mtls

import (
	"context"
	"time"

	"go.uber.org/zap"

	"exoper/backend/internal/common/errors"
)

type CertificateMonitor struct {
	manager *MTLSManager
	logger  *zap.Logger
}

type ExpirationAlert struct {
	CertificateID   string    `json:"certificate_id"`
	TenantID        string    `json:"tenant_id"`
	Subject         string    `json:"subject"`
	Fingerprint     string    `json:"fingerprint"`
	ExpiresAt       time.Time `json:"expires_at"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	AlertLevel      string    `json:"alert_level"`
}

func NewCertificateMonitor(manager *MTLSManager, logger *zap.Logger) *CertificateMonitor {
	return &CertificateMonitor{
		manager: manager,
		logger:  logger,
	}
}

func (cm *CertificateMonitor) StartMonitoring(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	cm.checkExpiringCertificates(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cm.checkExpiringCertificates(ctx)
		}
	}
}

func (cm *CertificateMonitor) checkExpiringCertificates(ctx context.Context) {
	query := `
		SELECT id, tenant_id, subject, fingerprint, not_after
		FROM trusted_certificates 
		WHERE is_active = true AND not_after <= $1`

	thresholdDate := time.Now().UTC().Add(90 * 24 * time.Hour)

	var expiring []struct {
		ID          string    `db:"id"`
		TenantID    string    `db:"tenant_id"`
		Subject     string    `db:"subject"`
		Fingerprint string    `db:"fingerprint"`
		NotAfter    time.Time `db:"not_after"`
	}

	err := cm.manager.db.Select(ctx, &expiring, query, thresholdDate)
	if err != nil {
		cm.logger.Error("Failed to check expiring certificates", zap.Error(err))
		return
	}

	now := time.Now().UTC()
	for _, cert := range expiring {
		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
		
		alertLevel := "info"
		if daysUntilExpiry <= 7 {
			alertLevel = "critical"
		} else if daysUntilExpiry <= 30 {
			alertLevel = "warning"
		}

		alert := &ExpirationAlert{
			CertificateID:   cert.ID,
			TenantID:        cert.TenantID,
			Subject:         cert.Subject,
			Fingerprint:     cert.Fingerprint,
			ExpiresAt:       cert.NotAfter,
			DaysUntilExpiry: daysUntilExpiry,
			AlertLevel:      alertLevel,
		}

		cm.sendExpirationAlert(alert)
	}

	if len(expiring) > 0 {
		cm.logger.Info("Certificate expiration check completed",
			zap.Int("expiring_count", len(expiring)))
	}
}

func (cm *CertificateMonitor) sendExpirationAlert(alert *ExpirationAlert) {
	cm.logger.Warn("Certificate expiring soon",
		zap.String("certificate_id", alert.CertificateID),
		zap.String("tenant_id", alert.TenantID),
		zap.String("subject", alert.Subject),
		zap.Int("days_until_expiry", alert.DaysUntilExpiry),
		zap.String("alert_level", alert.AlertLevel))
}

func (cm *CertificateMonitor) CleanupExpiredCertificates(ctx context.Context) error {
	query := `
		UPDATE trusted_certificates 
		SET is_active = false 
		WHERE is_active = true AND not_after < $1`

	result, err := cm.manager.db.Exec(ctx, query, time.Now().UTC())
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to cleanup expired certificates")
	}

	if result.RowsAffected > 0 {
		cm.logger.Info("Expired certificates cleaned up", zap.Int64("count", result.RowsAffected))
	}

	return nil
}