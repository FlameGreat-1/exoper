package metrics

import (
	"time"

	"go.uber.org/zap"
)

type AuthMetrics struct {
	metrics *Metrics
	logger  *zap.Logger
}

func NewAuthMetrics(metrics *Metrics, logger *zap.Logger) *AuthMetrics {
	am := &AuthMetrics{
		metrics: metrics,
		logger:  logger,
	}

	if err := am.registerAuthMetrics(); err != nil {
		logger.Error("Failed to register auth metrics", zap.Error(err))
	}

	return am
}

func (am *AuthMetrics) registerAuthMetrics() error {
	definitions := []MetricDefinition{
		{
			Name:   "authentication_requests_total",
			Help:   "Total number of authentication requests",
			Labels: []string{"method", "status", "tenant_id"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "authentication_failures_total",
			Help:   "Total number of authentication failures",
			Labels: []string{"method", "reason", "tenant_id"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "authentication_duration_seconds",
			Help:   "Authentication request duration in seconds",
			Labels: []string{"method", "status"},
			Type:   MetricTypeHistogram,
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		{
			Name:   "authorization_requests_total",
			Help:   "Total number of authorization requests",
			Labels: []string{"resource", "action", "status"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "authorization_denials_total",
			Help:   "Total number of authorization denials",
			Labels: []string{"resource", "action", "reason"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "tokens_issued_total",
			Help:   "Total number of tokens issued",
			Labels: []string{"type", "tenant_id"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "tokens_validated_total",
			Help:   "Total number of token validations",
			Labels: []string{"type", "status"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "tokens_revoked_total",
			Help:   "Total number of tokens revoked",
			Labels: []string{"type", "reason"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "active_sessions_total",
			Help:   "Current number of active sessions",
			Labels: []string{"tenant_id"},
			Type:   MetricTypeGauge,
		},
		{
			Name:   "sessions_created_total",
			Help:   "Total number of sessions created",
			Labels: []string{"tenant_id"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "sessions_expired_total",
			Help:   "Total number of sessions expired",
			Labels: []string{"tenant_id"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "certificates_validated_total",
			Help:   "Total number of certificate validations",
			Labels: []string{"status"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "certificate_validation_failures_total",
			Help:   "Total number of certificate validation failures",
			Labels: []string{"reason"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "api_keys_created_total",
			Help:   "Total number of API keys created",
			Labels: []string{"tenant_id"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "api_keys_revoked_total",
			Help:   "Total number of API keys revoked",
			Labels: []string{"reason"},
			Type:   MetricTypeCounter,
		},
		{
			Name:   "risk_score_distribution",
			Help:   "Distribution of authentication risk scores",
			Labels: []string{"method", "tenant_id"},
			Type:   MetricTypeHistogram,
			Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		},
	}

	return am.metrics.RegisterBulkMetrics(definitions)
}

// Authentication metrics
func (am *AuthMetrics) RecordAuthenticationAttempt(method, status, tenantID string, duration time.Duration) {
	labels := map[string]string{
		"method":    method,
		"status":    status,
		"tenant_id": tenantID,
	}
	
	am.metrics.IncrementCounter("authentication_requests_total", labels)
	am.metrics.RecordHistogram("authentication_duration_seconds", duration.Seconds(), map[string]string{
		"method": method,
		"status": status,
	})
}

func (am *AuthMetrics) RecordAuthenticationFailure(method, reason, tenantID string) {
	am.metrics.IncrementCounter("authentication_failures_total", map[string]string{
		"method":    method,
		"reason":    reason,
		"tenant_id": tenantID,
	})
}

func (am *AuthMetrics) RecordRiskScore(method, tenantID string, score float64) {
	am.metrics.RecordHistogram("risk_score_distribution", score, map[string]string{
		"method":    method,
		"tenant_id": tenantID,
	})
}

// Authorization metrics
func (am *AuthMetrics) RecordAuthorizationAttempt(resource, action, status string) {
	am.metrics.IncrementCounter("authorization_requests_total", map[string]string{
		"resource": resource,
		"action":   action,
		"status":   status,
	})
}

func (am *AuthMetrics) RecordAuthorizationDenial(resource, action, reason string) {
	am.metrics.IncrementCounter("authorization_denials_total", map[string]string{
		"resource": resource,
		"action":   action,
		"reason":   reason,
	})
}

// Token metrics
func (am *AuthMetrics) RecordTokenIssued(tokenType, tenantID string) {
	am.metrics.IncrementCounter("tokens_issued_total", map[string]string{
		"type":      tokenType,
		"tenant_id": tenantID,
	})
}

func (am *AuthMetrics) RecordTokenValidation(tokenType, status string) {
	am.metrics.IncrementCounter("tokens_validated_total", map[string]string{
		"type":   tokenType,
		"status": status,
	})
}

func (am *AuthMetrics) RecordTokenRevocation(tokenType, reason string) {
	am.metrics.IncrementCounter("tokens_revoked_total", map[string]string{
		"type":   tokenType,
		"reason": reason,
	})
}

// Session metrics
func (am *AuthMetrics) RecordSessionCreated(tenantID string) {
	am.metrics.IncrementCounter("sessions_created_total", map[string]string{
		"tenant_id": tenantID,
	})
	am.metrics.IncGauge("active_sessions_total", map[string]string{
		"tenant_id": tenantID,
	})
}

func (am *AuthMetrics) RecordSessionExpired(tenantID string) {
	am.metrics.IncrementCounter("sessions_expired_total", map[string]string{
		"tenant_id": tenantID,
	})
	am.metrics.DecGauge("active_sessions_total", map[string]string{
		"tenant_id": tenantID,
	})
}

// Certificate metrics
func (am *AuthMetrics) RecordCertificateValidation(status string) {
	am.metrics.IncrementCounter("certificates_validated_total", map[string]string{
		"status": status,
	})
}

func (am *AuthMetrics) RecordCertificateValidationFailure(reason string) {
	am.metrics.IncrementCounter("certificate_validation_failures_total", map[string]string{
		"reason": reason,
	})
}

// API Key metrics
func (am *AuthMetrics) RecordAPIKeyCreated(tenantID string) {
	am.metrics.IncrementCounter("api_keys_created_total", map[string]string{
		"tenant_id": tenantID,
	})
}

func (am *AuthMetrics) RecordAPIKeyRevoked(reason string) {
	am.metrics.IncrementCounter("api_keys_revoked_total", map[string]string{
		"reason": reason,
	})
}
