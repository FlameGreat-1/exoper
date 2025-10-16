package tokens

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
)

type APIKeyManager struct {
	config *config.Config
	db     *database.Database
	logger *zap.Logger
}

type APIKey struct {
	ID          uuid.UUID  `db:"id"`
	TenantID    uuid.UUID  `db:"tenant_id"`
	Name        string     `db:"name"`
	Description string     `db:"description"`
	KeyHash     string     `db:"key_hash"`
	Prefix      string     `db:"prefix"`
	Permissions []string   `db:"permissions"`
	Scopes      []string   `db:"scopes"`
	ExpiresAt   *time.Time `db:"expires_at"`
	LastUsedAt  *time.Time `db:"last_used_at"`
	IsActive    bool       `db:"is_active"`
	CreatedAt   time.Time  `db:"created_at"`
	CreatedBy   uuid.UUID  `db:"created_by"`
	RevokedAt   *time.Time `db:"revoked_at"`
	RevokedBy   *uuid.UUID `db:"revoked_by"`
	Metadata    map[string]interface{} `db:"metadata"`
}

type APIKeyRequest struct {
	TenantID    uuid.UUID
	Name        string
	Description string
	Permissions []string
	Scopes      []string
	ExpiresAt   *time.Time
	CreatedBy   uuid.UUID
	Metadata    map[string]interface{}
}

func NewAPIKeyManager(cfg *config.Config, db *database.Database, logger *zap.Logger) *APIKeyManager {
	return &APIKeyManager{
		config: cfg,
		db:     db,
		logger: logger,
	}
}

func (akm *APIKeyManager) CreateAPIKey(ctx context.Context, req *APIKeyRequest) (*APIKey, string, error) {
	if err := akm.validateAPIKeyRequest(req); err != nil {
		return nil, "", err
	}

	tenantSlug, err := akm.getTenantSlug(ctx, req.TenantID)
	if err != nil {
		return nil, "", err
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", errors.Wrap(err, errors.ErrCodeInternalError, "failed to generate API key")
	}

	keyString := hex.EncodeToString(keyBytes)
	prefix := fmt.Sprintf("exo_%s_%s", tenantSlug, keyString[:8])
	fullKey := fmt.Sprintf("%s_%s", prefix, keyString[8:])

	keyHash, err := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", errors.Wrap(err, errors.ErrCodeInternalError, "failed to hash API key")
	}

	apiKey := &APIKey{
		ID:          uuid.New(),
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		KeyHash:     string(keyHash),
		Prefix:      prefix,
		Permissions: req.Permissions,
		Scopes:      req.Scopes,
		ExpiresAt:   req.ExpiresAt,
		IsActive:    true,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   req.CreatedBy,
		Metadata:    req.Metadata,
	}

	if err := akm.storeAPIKey(ctx, apiKey); err != nil {
		return nil, "", errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to store API key")
	}

	akm.logger.Info("API key created",
		zap.String("key_id", apiKey.ID.String()),
		zap.String("name", apiKey.Name),
		zap.String("tenant_id", req.TenantID.String()))

	return apiKey, fullKey, nil
}

func (akm *APIKeyManager) RevokeAPIKey(ctx context.Context, keyID, reason string, revokedBy uuid.UUID) error {
	now := time.Now().UTC()
	query := `
		UPDATE api_keys 
		SET is_active = false, revoked_at = $1, revoked_by = $2 
		WHERE id = $3 AND is_active = true`

	result, err := akm.db.Exec(ctx, query, now, revokedBy, keyID)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to revoke API key")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New(errors.ErrCodeNotFound, "API key not found or already revoked")
	}

	akm.logger.Info("API key revoked",
		zap.String("key_id", keyID),
		zap.String("reason", reason))

	return nil
}

func (akm *APIKeyManager) validateAPIKeyRequest(req *APIKeyRequest) error {
	if req.TenantID == uuid.Nil {
		return errors.New(errors.ErrCodeInvalidRequest, "tenant ID is required")
	}

	if req.Name == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "API key name is required")
	}

	if len(req.Name) > 100 {
		return errors.New(errors.ErrCodeInvalidRequest, "API key name too long")
	}

	if len(req.Permissions) == 0 {
		return errors.New(errors.ErrCodeInvalidRequest, "at least one permission is required")
	}

	if req.CreatedBy == uuid.Nil {
		return errors.New(errors.ErrCodeInvalidRequest, "created_by is required")
	}

	return nil
}

func (akm *APIKeyManager) getTenantSlug(ctx context.Context, tenantID uuid.UUID) (string, error) {
	query := `SELECT slug FROM tenants WHERE id = $1`
	var slug string
	err := akm.db.Get(ctx, &slug, query, tenantID)
	if err != nil {
		return "", errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to get tenant slug")
	}
	return slug, nil
}

func (akm *APIKeyManager) storeAPIKey(ctx context.Context, apiKey *APIKey) error {
	query := `
		INSERT INTO api_keys (
			id, tenant_id, name, description, key_hash, prefix,
			permissions, scopes, expires_at, is_active, created_at,
			created_by, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	_, err := akm.db.Exec(ctx, query,
		apiKey.ID,
		apiKey.TenantID,
		apiKey.Name,
		apiKey.Description,
		apiKey.KeyHash,
		apiKey.Prefix,
		apiKey.Permissions,
		apiKey.Scopes,
		apiKey.ExpiresAt,
		apiKey.IsActive,
		apiKey.CreatedAt,
		apiKey.CreatedBy,
		apiKey.Metadata,
	)

	return err
}
