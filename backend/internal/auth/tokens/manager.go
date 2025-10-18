package tokens

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
)

type TokenType string

const (
	TypeAccess  TokenType = "access"
	TypeRefresh TokenType = "refresh"
	TypeID      TokenType = "id"
	TypeSession TokenType = "session"
	TypeAPIKey  TokenType = "api_key"
)

type TokenManager struct {
	config     *config.Config
	db         *database.Database
	logger     *zap.Logger
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

type TokenClaims struct {
	jwt.RegisteredClaims
	TenantID     string                 `json:"tenant_id"`
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email"`
	Username     string                 `json:"username"`
	Roles        []string               `json:"roles"`
	Permissions  []string               `json:"permissions"`
	Scopes       []string               `json:"scopes"`
	SessionID    string                 `json:"session_id,omitempty"`
	TokenType    string                 `json:"token_type"`
	AuthLevel    string                 `json:"auth_level"`
	MFAVerified  bool                   `json:"mfa_verified"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	CustomClaims map[string]interface{} `json:"custom_claims,omitempty"`
}

type TokenInfo struct {
	ID           string                 `json:"id"`
	Type         TokenType              `json:"type"`
	Token        string                 `json:"token"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	TenantID     string                 `json:"tenant_id"`
	UserID       string                 `json:"user_id"`
	SessionID    string                 `json:"session_id,omitempty"`
	Scopes       []string               `json:"scopes"`
	Permissions  []string               `json:"permissions"`
	IssuedAt     time.Time              `json:"issued_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	NotBefore    *time.Time             `json:"not_before,omitempty"`
	LastUsedAt   *time.Time             `json:"last_used_at,omitempty"`
	IsActive     bool                   `json:"is_active"`
	RevokedAt    *time.Time             `json:"revoked_at,omitempty"`
	RevokedBy    string                 `json:"revoked_by,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type TokenRequest struct {
	TenantID     uuid.UUID
	UserID       uuid.UUID
	Email        string
	Username     string
	Roles        []string
	Permissions  []string
	Scopes       []string
	SessionID    string
	TokenType    TokenType
	AuthLevel    string
	MFAVerified  bool
	IPAddress    string
	UserAgent    string
	Duration     time.Duration
	CustomClaims map[string]interface{}
}

type ValidationRequest struct {
	Token               string
	TokenType           TokenType
	RequiredScopes      []string
	RequiredPermissions []string
	CheckExpiration     bool
	CheckRevocation     bool
	Context             map[string]interface{}
}

type ValidationResult struct {
	Valid           bool
	Claims          *TokenClaims
	TokenInfo       *TokenInfo
	Errors          []ValidationError
	RiskScore       float64
	ValidatedAt     time.Time
}

type ValidationError struct {
	Code     string
	Message  string
	Field    string
	Severity errors.ErrorSeverity
}

type RevokedToken struct {
	JTI       string    `db:"jti"`
	TenantID  uuid.UUID `db:"tenant_id"`
	UserID    uuid.UUID `db:"user_id"`
	TokenType string    `db:"token_type"`
	RevokedAt time.Time `db:"revoked_at"`
	RevokedBy uuid.UUID `db:"revoked_by"`
	Reason    string    `db:"reason"`
	ExpiresAt time.Time `db:"expires_at"`
}

func NewTokenManager(cfg *config.Config, db *database.Database, logger *zap.Logger) (*TokenManager, error) {
	tm := &TokenManager{
		config: cfg,
		db:     db,
		logger: logger,
	}

	if err := tm.loadKeys(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to load JWT keys")
	}

	return tm, nil
}

func (tm *TokenManager) GenerateToken(ctx context.Context, req *TokenRequest) (*TokenInfo, error) {
	if err := tm.validateTokenRequest(req); err != nil {
		return nil, err
	}

	jti := tm.generateJTI()
	now := time.Now().UTC()
	expiresAt := now.Add(req.Duration)

	claims := &TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   req.UserID.String(),
			Issuer:    tm.config.Security.JWTIssuer,
			Audience:  []string{tm.config.Security.JWTAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
		TenantID:     req.TenantID.String(),
		UserID:       req.UserID.String(),
		Email:        req.Email,
		Username:     req.Username,
		Roles:        req.Roles,
		Permissions:  req.Permissions,
		Scopes:       req.Scopes,
		SessionID:    req.SessionID,
		TokenType:    string(req.TokenType),
		AuthLevel:    req.AuthLevel,
		MFAVerified:  req.MFAVerified,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		CustomClaims: req.CustomClaims,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(tm.privateKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "failed to sign token")
	}

	tokenInfo := &TokenInfo{
		ID:          jti,
		Type:        req.TokenType,
		Token:       tokenString,
		TenantID:    req.TenantID.String(),
		UserID:      req.UserID.String(),
		SessionID:   req.SessionID,
		Scopes:      req.Scopes,
		Permissions: req.Permissions,
		IssuedAt:    now,
		ExpiresAt:   expiresAt,
		NotBefore:   &now,
		IsActive:    true,
		Metadata:    make(map[string]interface{}),
	}

	if req.TokenType == TypeRefresh {
		refreshToken, err := tm.generateRefreshToken(ctx, req, jti)
		if err != nil {
			return nil, err
		}
		tokenInfo.RefreshToken = refreshToken
	}

	if err := tm.storeTokenInfo(ctx, tokenInfo); err != nil {
		tm.logger.Warn("Failed to store token info", zap.Error(err))
	}

	tm.logger.Info("Token generated",
		zap.String("token_id", jti),
		zap.String("token_type", string(req.TokenType)),
		zap.String("user_id", req.UserID.String()),
		zap.String("tenant_id", req.TenantID.String()))

	return tokenInfo, nil
}

func (tm *TokenManager) ValidateToken(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:       false,
		Errors:      []ValidationError{},
		ValidatedAt: time.Now().UTC(),
	}

	if req.Token == "" {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "missing_token",
			Message:  "token is required",
			Severity: errors.SeverityHigh,
		})
		return result, nil
	}

	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(req.Token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.publicKey, nil
	})

	if err != nil {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "invalid_token",
			Message:  fmt.Sprintf("token parsing failed: %v", err),
			Severity: errors.SeverityHigh,
		})
		return result, nil
	}

	if !token.Valid {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "invalid_token",
			Message:  "token is not valid",
			Severity: errors.SeverityHigh,
		})
		return result, nil
	}

	if req.CheckExpiration && claims.ExpiresAt.Before(time.Now()) {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "token_expired",
			Message:  "token has expired",
			Severity: errors.SeverityMedium,
		})
		return result, nil
	}

	if req.CheckRevocation {
		revoked, err := tm.isTokenRevoked(ctx, claims.ID)
		if err != nil {
			result.Errors = append(result.Errors, ValidationError{
				Code:     "revocation_check_failed",
				Message:  "failed to check token revocation status",
				Severity: errors.SeverityMedium,
			})
		} else if revoked {
			result.Errors = append(result.Errors, ValidationError{
				Code:     "token_revoked",
				Message:  "token has been revoked",
				Severity: errors.SeverityHigh,
			})
			return result, nil
		}
	}

	if req.TokenType != "" && claims.TokenType != string(req.TokenType) {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "invalid_token_type",
			Message:  fmt.Sprintf("expected token type %s, got %s", req.TokenType, claims.TokenType),
			Severity: errors.SeverityMedium,
		})
	}

	if err := tm.validateScopes(claims.Scopes, req.RequiredScopes); err != nil {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "insufficient_scope",
			Message:  err.Error(),
			Severity: errors.SeverityMedium,
		})
	}

	if err := tm.validatePermissions(claims.Permissions, req.RequiredPermissions); err != nil {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "insufficient_permissions",
			Message:  err.Error(),
			Severity: errors.SeverityMedium,
		})
	}

	if len(result.Errors) == 0 {
		result.Valid = true
		result.Claims = claims
		result.RiskScore = tm.calculateTokenRiskScore(claims, req)

		tokenInfo, err := tm.getTokenInfo(ctx, claims.ID)
		if err == nil {
			result.TokenInfo = tokenInfo
			tm.updateTokenLastUsed(ctx, claims.ID)
		}
	}

	return result, nil
}

func (tm *TokenManager) RefreshToken(ctx context.Context, refreshToken string, scopes []string, duration time.Duration) (*TokenInfo, error) {
	claims, err := tm.validateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, errors.New(errors.ErrCodeInternalError, "invalid user ID in token")
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		return nil, errors.New(errors.ErrCodeInternalError, "invalid tenant ID in token")
	}

	newScopes := scopes
	if len(newScopes) == 0 {
		newScopes = claims.Scopes
	}

	if duration == 0 {
		duration = time.Hour
	}

	req := &TokenRequest{
		TenantID:     tenantID,
		UserID:       userID,
		Email:        claims.Email,
		Username:     claims.Username,
		Roles:        claims.Roles,
		Permissions:  claims.Permissions,
		Scopes:       newScopes,
		SessionID:    claims.SessionID,
		TokenType:    TypeAccess,
		AuthLevel:    claims.AuthLevel,
		MFAVerified:  claims.MFAVerified,
		IPAddress:    claims.IPAddress,
		UserAgent:    claims.UserAgent,
		Duration:     duration,
		CustomClaims: claims.CustomClaims,
	}

	return tm.GenerateToken(ctx, req)
}

func (tm *TokenManager) RevokeToken(ctx context.Context, tokenID, reason, revokedBy string) error {
	if tokenID == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "token ID is required")
	}

	claims, err := tm.getTokenClaims(ctx, tokenID)
	if err != nil {
		return err
	}

	revokedToken := &RevokedToken{
		JTI:       tokenID,
		TenantID:  uuid.MustParse(claims.TenantID),
		UserID:    uuid.MustParse(claims.UserID),
		TokenType: claims.TokenType,
		RevokedAt: time.Now().UTC(),
		RevokedBy: uuid.MustParse(revokedBy),
		Reason:    reason,
		ExpiresAt: claims.ExpiresAt.Time,
	}

	if err := tm.storeRevokedToken(ctx, revokedToken); err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to revoke token")
	}

	tm.logger.Info("Token revoked",
		zap.String("token_id", tokenID),
		zap.String("reason", reason),
		zap.String("revoked_by", revokedBy))

	return nil
}

func (tm *TokenManager) RevokeAllUserTokens(ctx context.Context, userID, reason, revokedBy string) error {
	query := `
		INSERT INTO revoked_tokens (jti, tenant_id, user_id, token_type, revoked_at, revoked_by, reason, expires_at)
		SELECT token_id, tenant_id, user_id, token_type, $1, $2, $3, expires_at
		FROM token_info 
		WHERE user_id = $4 AND is_active = true AND expires_at > $1`

	_, err := tm.db.Exec(ctx, query, time.Now().UTC(), revokedBy, reason, userID)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to revoke user tokens")
	}

	updateQuery := `UPDATE token_info SET is_active = false WHERE user_id = $1`
	_, err = tm.db.Exec(ctx, updateQuery, userID)
	if err != nil {
		tm.logger.Warn("Failed to update token info status", zap.Error(err))
	}

	tm.logger.Info("All user tokens revoked",
		zap.String("user_id", userID),
		zap.String("reason", reason))

	return nil
}

func (tm *TokenManager) CleanupExpiredTokens(ctx context.Context) error {
	now := time.Now().UTC()
	
	query := `DELETE FROM revoked_tokens WHERE expires_at < $1`
	result, err := tm.db.Exec(ctx, query, now)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to cleanup expired revoked tokens")
	}

	rowsAffected := result.RowsAffected
	
	infoQuery := `DELETE FROM token_info WHERE expires_at < $1`
	infoResult, err := tm.db.Exec(ctx, infoQuery, now)
	if err != nil {
		tm.logger.Warn("Failed to cleanup expired token info", zap.Error(err))
	} else {
		rowsAffected += infoResult.RowsAffected
	}

	tm.logger.Info("Expired tokens cleaned up", zap.Int64("count", rowsAffected))
	return nil
}

func (tm *TokenManager) validateTokenRequest(req *TokenRequest) error {
	if req.TenantID == uuid.Nil {
		return errors.New(errors.ErrCodeInvalidRequest, "tenant ID is required")
	}

	if req.UserID == uuid.Nil {
		return errors.New(errors.ErrCodeInvalidRequest, "user ID is required")
	}

	if req.TokenType == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "token type is required")
	}

	if req.Duration <= 0 {
		return errors.New(errors.ErrCodeInvalidRequest, "token duration must be positive")
	}

	if req.Duration > 24*time.Hour && req.TokenType == TypeAccess {
		return errors.New(errors.ErrCodeInvalidRequest, "access token duration cannot exceed 24 hours")
	}

	if req.Duration > 30*24*time.Hour && req.TokenType == TypeRefresh {
		return errors.New(errors.ErrCodeInvalidRequest, "refresh token duration cannot exceed 30 days")
	}

	return nil
}

func (tm *TokenManager) generateJTI() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (tm *TokenManager) generateRefreshToken(ctx context.Context, req *TokenRequest, accessTokenJTI string) (string, error) {
	refreshReq := &TokenRequest{
		TenantID:     req.TenantID,
		UserID:       req.UserID,
		Email:        req.Email,
		Username:     req.Username,
		Roles:        req.Roles,
		Permissions:  req.Permissions,
		Scopes:       req.Scopes,
		SessionID:    req.SessionID,
		TokenType:    TypeRefresh,
		AuthLevel:    req.AuthLevel,
		MFAVerified:  req.MFAVerified,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		Duration:     30 * 24 * time.Hour,
		CustomClaims: map[string]interface{}{
			"access_token_jti": accessTokenJTI,
		},
	}

	refreshTokenInfo, err := tm.GenerateToken(ctx, refreshReq)
	if err != nil {
		return "", err
	}

	return refreshTokenInfo.Token, nil
}

func (tm *TokenManager) loadKeys() error {
	if tm.config.Security.JWTSecret != "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %v", err)
		}

		tm.privateKey = key
		tm.publicKey = &key.PublicKey
		return nil
	}

	return fmt.Errorf("no JWT key configuration found")
}

func (tm *TokenManager) isTokenRevoked(ctx context.Context, jti string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)`
	var revoked bool
	err := tm.db.Get(ctx, &revoked, query, jti)
	if err != nil {
		return false, err
	}
	return revoked, nil
}

func (tm *TokenManager) validateScopes(tokenScopes, requiredScopes []string) error {
	if len(requiredScopes) == 0 {
		return nil
	}

	for _, required := range requiredScopes {
		found := false
		for _, tokenScope := range tokenScopes {
			if tokenScope == required || tokenScope == "*" {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing required scope: %s", required)
		}
	}

	return nil
}

func (tm *TokenManager) validatePermissions(tokenPermissions, requiredPermissions []string) error {
	if len(requiredPermissions) == 0 {
		return nil
	}

	for _, required := range requiredPermissions {
		found := false
		for _, tokenPerm := range tokenPermissions {
			if tokenPerm == required || tokenPerm == "*" {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing required permission: %s", required)
		}
	}

	return nil
}

func (tm *TokenManager) calculateTokenRiskScore(claims *TokenClaims, req *ValidationRequest) float64 {
	score := 0.0

	tokenAge := time.Since(claims.IssuedAt.Time)
	if tokenAge > 12*time.Hour {
		score += 0.2
	}

	if !claims.MFAVerified && claims.AuthLevel != "basic" {
		score += 0.3
	}

	if claims.IPAddress == "" {
		score += 0.1
	}

	if len(claims.Permissions) > 20 {
		score += 0.2
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (tm *TokenManager) storeTokenInfo(ctx context.Context, tokenInfo *TokenInfo) error {
	query := `
		INSERT INTO token_info (
			token_id, token_type, tenant_id, user_id, session_id, 
			scopes, permissions, issued_at, expires_at, not_before, 
			is_active, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := tm.db.Exec(ctx, query,
		tokenInfo.ID,
		string(tokenInfo.Type),
		tokenInfo.TenantID,
		tokenInfo.UserID,
		tokenInfo.SessionID,
		tokenInfo.Scopes,
		tokenInfo.Permissions,
		tokenInfo.IssuedAt,
		tokenInfo.ExpiresAt,
		tokenInfo.NotBefore,
		tokenInfo.IsActive,
		tokenInfo.Metadata,
	)

	return err
}

func (tm *TokenManager) getTokenInfo(ctx context.Context, tokenID string) (*TokenInfo, error) {
	query := `
		SELECT token_id, token_type, tenant_id, user_id, session_id,
		       scopes, permissions, issued_at, expires_at, not_before,
		       last_used_at, is_active, revoked_at, metadata
		FROM token_info 
		WHERE token_id = $1`

	var tokenInfo TokenInfo
	err := tm.db.Get(ctx, &tokenInfo, query, tokenID)
	if err != nil {
		return nil, err
	}

	return &tokenInfo, nil
}

func (tm *TokenManager) updateTokenLastUsed(ctx context.Context, tokenID string) {
	query := `UPDATE token_info SET last_used_at = $1 WHERE token_id = $2`
	_, err := tm.db.Exec(ctx, query, time.Now().UTC(), tokenID)
	if err != nil {
		tm.logger.Warn("Failed to update token last used", zap.Error(err))
	}
}

func (tm *TokenManager) getTokenClaims(ctx context.Context, tokenID string) (*TokenClaims, error) {
	tokenInfo, err := tm.getTokenInfo(ctx, tokenID)
	if err != nil {
		return nil, err
	}

	if !tokenInfo.IsActive {
		return nil, errors.New(errors.ErrCodeUnauthorized, "token is inactive")
	}

	claims := &TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenInfo.ID,
			Subject:   tokenInfo.UserID,
			ExpiresAt: jwt.NewNumericDate(tokenInfo.ExpiresAt),
		},
		TenantID:    tokenInfo.TenantID,
		UserID:      tokenInfo.UserID,
		TokenType:   string(tokenInfo.Type),
		Scopes:      tokenInfo.Scopes,
		Permissions: tokenInfo.Permissions,
	}

	return claims, nil
}

func (tm *TokenManager) storeRevokedToken(ctx context.Context, revokedToken *RevokedToken) error {
	query := `
		INSERT INTO revoked_tokens (
			jti, tenant_id, user_id, token_type, revoked_at, 
			revoked_by, reason, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := tm.db.Exec(ctx, query,
		revokedToken.JTI,
		revokedToken.TenantID,
		revokedToken.UserID,
		revokedToken.TokenType,
		revokedToken.RevokedAt,
		revokedToken.RevokedBy,
		revokedToken.Reason,
		revokedToken.ExpiresAt,
	)

	return err
}

func (tm *TokenManager) validateRefreshToken(ctx context.Context, refreshToken string) (*TokenClaims, error) {
	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.publicKey, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeUnauthorized, "invalid refresh token")
	}

	if !token.Valid {
		return nil, errors.New(errors.ErrCodeUnauthorized, "refresh token is not valid")
	}

	if claims.TokenType != string(TypeRefresh) {
		return nil, errors.New(errors.ErrCodeUnauthorized, "token is not a refresh token")
	}

	revoked, err := tm.isTokenRevoked(ctx, claims.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to check token revocation")
	}

	if revoked {
		return nil, errors.New(errors.ErrCodeUnauthorized, "refresh token has been revoked")
	}

	return claims, nil
}
