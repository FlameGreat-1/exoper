package service

import (
	"time"

	"exoper/backend/internal/common/errors"
)

type TokenValidationResult struct {
	Valid            bool              `json:"valid"`
	TokenInfo        *TokenInfo        `json:"token_info,omitempty"`
	Principal        *Principal        `json:"principal,omitempty"`
	ValidationErrors []ValidationError `json:"validation_errors,omitempty"`
	RiskScore        float64           `json:"risk_score"`
	ValidatedAt      time.Time         `json:"validated_at"`
}

type TokenRefreshResult struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	TokenInfo    *TokenInfo `json:"token_info"`
	IssuedAt     time.Time  `json:"issued_at"`
}

type SessionResult struct {
	SessionID    string       `json:"session_id"`
	SessionToken string       `json:"session_token"`
	SessionInfo  *SessionInfo `json:"session_info"`
	CreatedAt    time.Time    `json:"created_at"`
}

type SessionValidationResult struct {
	Valid         bool         `json:"valid"`
	SessionInfo   *SessionInfo `json:"session_info,omitempty"`
	Principal     *Principal   `json:"principal,omitempty"`
	ValidatedAt   time.Time    `json:"validated_at"`
	ExtendedUntil *time.Time   `json:"extended_until,omitempty"`
}

type APIKeyResult struct {
	KeyID     string      `json:"key_id"`
	Key       string      `json:"key"`
	Prefix    string      `json:"prefix"`
	KeyInfo   *APIKeyInfo `json:"key_info"`
	CreatedAt time.Time   `json:"created_at"`
}

type APIKeyInfo struct {
	KeyID       string                 `json:"key_id"`
	TenantID    string                 `json:"tenant_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Prefix      string                 `json:"prefix"`
	Permissions []string               `json:"permissions"`
	Scopes      []string               `json:"scopes"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time             `json:"last_used_at,omitempty"`
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
	CreatedBy   string                 `json:"created_by"`
	RevokedAt   *time.Time             `json:"revoked_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type CertificateVerificationResult struct {
	Valid              bool              `json:"valid"`
	CertificateInfo    *CertificateInfo  `json:"certificate_info"`
	ValidationErrors   []string          `json:"validation_errors,omitempty"`
	TrustChainStatus   string            `json:"trust_chain_status"`
	VerifiedAt         time.Time         `json:"verified_at"`
}

type PermissionsResult struct {
	Permissions []string               `json:"permissions"`
	Scopes      []string               `json:"scopes"`
	Roles       []RoleInfo             `json:"roles"`
	EvaluatedAt time.Time              `json:"evaluated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type RoleInfo struct {
	RoleID      string                 `json:"role_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Permissions []string               `json:"permissions"`
	Scopes      []string               `json:"scopes"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type ValidationError struct {
	Code     string                `json:"code"`
	Message  string                `json:"message"`
	Field    string                `json:"field,omitempty"`
	Severity errors.ErrorSeverity  `json:"severity"`
}

type PolicyEvaluationResult struct {
	Authorized  bool               `json:"authorized"`
	Reason      string             `json:"reason"`
	Evaluations []PolicyEvaluation `json:"evaluations"`
}
