package providers

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	authpb "flamo/backend/pkg/api/proto/auth"
)

type JWTProvider struct {
	config     *config.Config
	db         *database.Database
	logger     *zap.Logger
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

type JWTClaims struct {
	jwt.RegisteredClaims
	TenantID     string                 `json:"tenant_id"`
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email"`
	Roles        []string               `json:"roles"`
	Permissions  []string               `json:"permissions"`
	Scopes       []string               `json:"scopes"`
	SessionID    string                 `json:"session_id,omitempty"`
	AuthLevel    string                 `json:"auth_level"`
	MFAVerified  bool                   `json:"mfa_verified"`
	CustomClaims map[string]interface{} `json:"custom_claims,omitempty"`
}

func NewJWTProvider(cfg *config.Config, db *database.Database, logger *zap.Logger) (*JWTProvider, error) {
	provider := &JWTProvider{
		config: cfg,
		db:     db,
		logger: logger,
	}

	if err := provider.loadKeys(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to load JWT keys")
	}

	return provider, nil
}

func (p *JWTProvider) Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResult, error) {
	credentials, ok := req.Credentials.(*authpb.JWTCredentials)
	if !ok {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "invalid JWT credentials")
	}

	token, claims, err := p.validateToken(credentials.Token)
	if err != nil {
		return nil, err
	}

	if err := p.validateClaims(claims, credentials); err != nil {
		return nil, err
	}

	if err := p.checkTokenRevocation(ctx, claims.ID); err != nil {
		return nil, err
	}

	principal := p.buildPrincipalFromClaims(claims)
	riskScore := p.calculateJWTRiskScore(req, claims)

	tokenInfo := &TokenInfo{
		TokenID:   claims.ID,
		Type:      "access",
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		IssuedAt:  claims.IssuedAt.Time,
		ExpiresAt: claims.ExpiresAt.Time,
		NotBefore: &claims.NotBefore.Time,
		Scopes:    claims.Scopes,
		Claims:    p.extractCustomClaims(claims),
		JTI:       claims.ID,
	}

	return &AuthenticationResult{
		Authenticated: true,
		Principal:     principal,
		Level:         p.getAuthLevelFromClaims(claims),
		Permissions:   claims.Permissions,
		Scopes:        claims.Scopes,
		TokenInfo:     tokenInfo,
		RiskScore:     riskScore,
		RiskFactors:   p.assessJWTRiskFactors(req, claims),
		ExpiresAt:     &claims.ExpiresAt.Time,
		Metadata: map[string]interface{}{
			"token_id":     claims.ID,
			"session_id":   claims.SessionID,
			"mfa_verified": claims.MFAVerified,
		},
	}, nil
}

func (p *JWTProvider) ValidateCredentials(ctx context.Context, credentials interface{}) (*ValidationResult, error) {
	jwtCreds, ok := credentials.(*authpb.JWTCredentials)
	if !ok {
		return &ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Code:     "invalid_credentials_type",
				Message:  "credentials must be JWT credentials",
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

	if jwtCreds.Token == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "missing_token",
			Message:  "JWT token is required",
			Field:    "token",
			Severity: errors.SeverityHigh,
		})
		return result, nil
	}

	_, _, err := p.validateToken(jwtCreds.Token)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "invalid_token",
			Message:  err.Error(),
			Field:    "token",
			Severity: errors.SeverityHigh,
		})
	}

	return result, nil
}

func (p *JWTProvider) GetSupportedMethods() []AuthenticationMethod {
	return []AuthenticationMethod{MethodJWT}
}

func (p *JWTProvider) GetAuthenticationLevel() AuthenticationLevel {
	return LevelStrong
}

func (p *JWTProvider) IsEnabled() bool {
	return p.config.Security.JWTSecret != ""
}

func (p *JWTProvider) loadKeys() error {
	if p.config.Security.JWTSecret == "" {
		return fmt.Errorf("JWT secret not configured")
	}

	return nil
}

func (p *JWTProvider) validateToken(tokenString string) (*jwt.Token, *JWTClaims, error) {
	claims := &JWTClaims{}
	
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(p.config.Security.JWTSecret), nil
	})

	if err != nil {
		return nil, nil, errors.Wrap(err, errors.ErrCodeUnauthorized, "invalid JWT token")
	}

	if !token.Valid {
		return nil, nil, errors.New(errors.ErrCodeUnauthorized, "invalid JWT token")
	}

	return token, claims, nil
}

func (p *JWTProvider) validateClaims(claims *JWTClaims, credentials *authpb.JWTCredentials) error {
	if claims.TenantID == "" {
		return errors.New(errors.ErrCodeUnauthorized, "tenant ID not found in token")
	}

	if credentials.Issuer != "" && claims.Issuer != credentials.Issuer {
		return errors.New(errors.ErrCodeUnauthorized, "token issuer mismatch")
	}

	if len(credentials.Audience) > 0 {
		found := false
		for _, aud := range credentials.Audience {
			for _, claimAud := range claims.Audience {
				if aud == claimAud {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return errors.New(errors.ErrCodeUnauthorized, "token audience mismatch")
		}
	}

	return nil
}

func (p *JWTProvider) checkTokenRevocation(ctx context.Context, jti string) error {
	query := `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)`
	var revoked bool
	err := p.db.Get(ctx, &revoked, query, jti)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to check token revocation")
	}

	if revoked {
		return errors.New(errors.ErrCodeUnauthorized, "token has been revoked")
	}

	return nil
}

func (p *JWTProvider) buildPrincipalFromClaims(claims *JWTClaims) *Principal {
	return &Principal{
		ID:             claims.UserID,
		Type:           "user",
		Name:           claims.Subject,
		Email:          claims.Email,
		TenantID:       claims.TenantID,
		Roles:          claims.Roles,
		Groups:         []string{},
		Attributes: map[string]interface{}{
			"session_id":   claims.SessionID,
			"mfa_verified": claims.MFAVerified,
			"auth_level":   claims.AuthLevel,
		},
		IsActive:   true,
		MFAEnabled: claims.MFAVerified,
	}
}

func (p *JWTProvider) calculateJWTRiskScore(req *AuthenticationRequest, claims *JWTClaims) float64 {
	score := 0.0

	tokenAge := time.Since(claims.IssuedAt.Time)
	if tokenAge > 24*time.Hour {
		score += 0.2
	}

	if !claims.MFAVerified && req.RequireMFA {
		score += 0.3
	}

	if claims.SessionID == "" {
		score += 0.1
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (p *JWTProvider) assessJWTRiskFactors(req *AuthenticationRequest, claims *JWTClaims) []string {
	factors := []string{}

	tokenAge := time.Since(claims.IssuedAt.Time)
	if tokenAge > 24*time.Hour {
		factors = append(factors, "old_token")
	}

	if !claims.MFAVerified && req.RequireMFA {
		factors = append(factors, "mfa_not_verified")
	}

	if claims.SessionID == "" {
		factors = append(factors, "no_session")
	}

	return factors
}

func (p *JWTProvider) getAuthLevelFromClaims(claims *JWTClaims) AuthenticationLevel {
	switch claims.AuthLevel {
	case "multi_factor":
		return LevelMultiFactor
	case "strong":
		return LevelStrong
	case "basic":
		return LevelBasic
	default:
		return LevelBasic
	}
}

func (p *JWTProvider) extractCustomClaims(claims *JWTClaims) map[string]interface{} {
	result := make(map[string]interface{})
	
	if claims.CustomClaims != nil {
		for k, v := range claims.CustomClaims {
			result[k] = v
		}
	}

	result["tenant_id"] = claims.TenantID
	result["user_id"] = claims.UserID
	result["email"] = claims.Email
	result["roles"] = claims.Roles
	result["permissions"] = claims.Permissions
	result["scopes"] = claims.Scopes
	result["mfa_verified"] = claims.MFAVerified

	return result
}
