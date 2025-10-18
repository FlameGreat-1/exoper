package providers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	authpb "flamo/backend/pkg/api/proto/auth"
)

type APIKeyProvider struct {
	config *config.Config
	db     *database.Database
	logger *zap.Logger
}

type APIKeyData struct {
	ID          uuid.UUID `db:"id"`
	TenantID    uuid.UUID `db:"tenant_id"`
	Name        string    `db:"name"`
	KeyHash     string    `db:"key_hash"`
	Prefix      string    `db:"prefix"`
	Permissions []string  `db:"permissions"`
	Scopes      []string  `db:"scopes"`
	ExpiresAt   *time.Time `db:"expires_at"`
	LastUsedAt  *time.Time `db:"last_used_at"`
	IsActive    bool      `db:"is_active"`
	CreatedAt   time.Time `db:"created_at"`
	CreatedBy   uuid.UUID `db:"created_by"`
	RevokedAt   *time.Time `db:"revoked_at"`
	RevokedBy   *uuid.UUID `db:"revoked_by"`
}

func NewAPIKeyProvider(cfg *config.Config, db *database.Database, logger *zap.Logger) *APIKeyProvider {
	return &APIKeyProvider{
		config: cfg,
		db:     db,
		logger: logger,
	}
}

func (p *APIKeyProvider) Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResult, error) {
	credentials, ok := req.Credentials.(*authpb.APIKeyCredentials)
	if !ok {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "invalid API key credentials")
	}

	if err := p.validateAPIKeyFormat(credentials.Key); err != nil {
		return nil, err
	}

	keyData, err := p.getAPIKeyByPrefix(ctx, credentials.Prefix, req.TenantID)
	if err != nil {
		return nil, err
	}

	if !p.verifyAPIKey(credentials.Key, keyData.KeyHash) {
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid API key")
	}

	if err := p.validateAPIKeyStatus(keyData); err != nil {
		return nil, err
	}

	if err := p.validateAPIKeyExpiration(keyData); err != nil {
		return nil, err
	}

	if err := p.validateSignature(credentials, keyData); err != nil {
		return nil, err
	}

	principal := p.buildPrincipal(keyData)
	riskScore := p.calculateRiskScore(req, keyData)

	if err := p.updateLastUsed(ctx, keyData.ID); err != nil {
		p.logger.Warn("Failed to update API key last used", zap.Error(err))
	}

	return &AuthenticationResult{
		Authenticated: true,
		Principal:     principal,
		Level:         LevelStrong,
		Permissions:   keyData.Permissions,
		Scopes:        keyData.Scopes,
		RiskScore:     riskScore,
		RiskFactors:   p.assessRiskFactors(req, keyData),
		ExpiresAt:     keyData.ExpiresAt,
		Metadata: map[string]interface{}{
			"api_key_id":   keyData.ID.String(),
			"api_key_name": keyData.Name,
			"created_at":   keyData.CreatedAt,
		},
	}, nil
}

func (p *APIKeyProvider) ValidateCredentials(ctx context.Context, credentials interface{}) (*ValidationResult, error) {
	apiKeyCreds, ok := credentials.(*authpb.APIKeyCredentials)
	if !ok {
		return &ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Code:     "invalid_credentials_type",
				Message:  "credentials must be API key credentials",
				Severity: errors.SeverityHigh,
			}},
		}, nil
	}

	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []string{},
		Metadata: make(map[string]interface{}),
	}

	if err := p.validateAPIKeyFormat(apiKeyCreds.Key); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "invalid_key_format",
			Message:  err.Error(),
			Field:    "key",
			Severity: errors.SeverityHigh,
		})
	}

	if apiKeyCreds.Prefix == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "missing_prefix",
			Message:  "API key prefix is required",
			Field:    "prefix",
			Severity: errors.SeverityHigh,
		})
	}

	if apiKeyCreds.Timestamp == nil {
		result.Warnings = append(result.Warnings, "timestamp not provided for replay protection")
	} else {
		age := time.Since(apiKeyCreds.Timestamp.AsTime())
		if age > 5*time.Minute {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Code:     "timestamp_too_old",
				Message:  "request timestamp is too old",
				Field:    "timestamp",
				Severity: errors.SeverityMedium,
			})
		}
	}

	if apiKeyCreds.Nonce == "" {
		result.Warnings = append(result.Warnings, "nonce not provided for replay protection")
	}

	return result, nil
}

func (p *APIKeyProvider) GetSupportedMethods() []AuthenticationMethod {
	return []AuthenticationMethod{MethodAPIKey}
}

func (p *APIKeyProvider) GetAuthenticationLevel() AuthenticationLevel {
	return LevelStrong
}

func (p *APIKeyProvider) IsEnabled() bool {
	return true
}

func (p *APIKeyProvider) validateAPIKeyFormat(key string) error {
	if key == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "API key is required")
	}

	parts := strings.Split(key, "_")
	if len(parts) != 4 {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid API key format")
	}

	if parts[0] != "exo" {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid API key prefix")
	}

	if len(parts[2]) != 8 || len(parts[3]) != 48 {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid API key length")
	}

	if !utils.IsAlphaNumeric(parts[1]) {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid tenant slug in API key")
	}

	return nil
}

func (p *APIKeyProvider) getAPIKeyByPrefix(ctx context.Context, prefix string, tenantID uuid.UUID) (*APIKeyData, error) {
	query := `
		SELECT id, tenant_id, name, key_hash, prefix, permissions, scopes, 
		       expires_at, last_used_at, is_active, created_at, created_by, 
		       revoked_at, revoked_by
		FROM api_keys 
		WHERE prefix = $1 AND tenant_id = $2 AND is_active = true AND revoked_at IS NULL`

	var keyData APIKeyData
	err := p.db.Get(ctx, &keyData, query, prefix, tenantID)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, errors.New(errors.ErrCodeUnauthorized, "invalid API key")
		}
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to retrieve API key")
	}

	return &keyData, nil
}

func (p *APIKeyProvider) verifyAPIKey(providedKey, storedHash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(providedKey))
	return err == nil
}

func (p *APIKeyProvider) validateAPIKeyStatus(keyData *APIKeyData) error {
	if !keyData.IsActive {
		return errors.New(errors.ErrCodeUnauthorized, "API key is inactive")
	}

	if keyData.RevokedAt != nil {
		return errors.New(errors.ErrCodeUnauthorized, "API key has been revoked")
	}

	return nil
}

func (p *APIKeyProvider) validateAPIKeyExpiration(keyData *APIKeyData) error {
	if keyData.ExpiresAt != nil && keyData.ExpiresAt.Before(time.Now().UTC()) {
		return errors.New(errors.ErrCodeUnauthorized, "API key has expired")
	}
	return nil
}

func (p *APIKeyProvider) validateSignature(credentials *authpb.APIKeyCredentials, keyData *APIKeyData) error {
	if credentials.Signature == "" {
		return nil
	}

	if credentials.Timestamp == nil || credentials.Nonce == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "timestamp and nonce required for signature validation")
	}

	message := fmt.Sprintf("%s:%s:%s", 
		credentials.Timestamp.AsTime().Format(time.RFC3339),
		credentials.Nonce,
		credentials.Key)

	
	if !utils.VerifyHMAC(message, credentials.Signature, keyData.KeyHash) {
		return errors.New(errors.ErrCodeUnauthorized, "invalid signature")
	}

	return nil
}

func (p *APIKeyProvider) buildPrincipal(keyData *APIKeyData) *Principal {
	return &Principal{
		ID:             keyData.ID.String(),
		Type:           "api_key",
		Name:           keyData.Name,
		TenantID:       keyData.TenantID.String(),
		Roles:          []string{"api_client"},
		Groups:         []string{},
		Attributes:     map[string]interface{}{
			"key_id": keyData.ID.String(),
			"prefix": keyData.Prefix,
		},
		CreatedAt:      keyData.CreatedAt,
		LastLogin:      keyData.LastUsedAt,
		IsActive:       keyData.IsActive,
		MFAEnabled:     false,
	}
}

func (p *APIKeyProvider) calculateRiskScore(req *AuthenticationRequest, keyData *APIKeyData) float64 {
	score := 0.0

	if keyData.LastUsedAt == nil {
		score += 0.1
	} else {
		daysSinceLastUse := time.Since(*keyData.LastUsedAt).Hours() / 24
		if daysSinceLastUse > 30 {
			score += 0.2
		}
	}

	if req.ClientIP != "" && !utils.IsValidIP(req.ClientIP) {
		score += 0.3
	}

	if len(keyData.Permissions) > 10 {
		score += 0.1
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (p *APIKeyProvider) assessRiskFactors(req *AuthenticationRequest, keyData *APIKeyData) []string {
	factors := []string{}

	if keyData.LastUsedAt == nil {
		factors = append(factors, "first_time_use")
	}

	if keyData.LastUsedAt != nil {
		daysSinceLastUse := time.Since(*keyData.LastUsedAt).Hours() / 24
		if daysSinceLastUse > 30 {
			factors = append(factors, "long_time_since_last_use")
		}
	}

	if len(keyData.Permissions) > 10 {
		factors = append(factors, "high_privilege_key")
	}

	return factors
}

func (p *APIKeyProvider) updateLastUsed(ctx context.Context, keyID uuid.UUID) error {
	query := `UPDATE api_keys SET last_used_at = $1 WHERE id = $2`
	_, err := p.db.Exec(ctx, query, time.Now().UTC(), keyID)
	return err
}
