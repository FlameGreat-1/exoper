package providers

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	commonpb "flamo/backend/pkg/api/proto/common"
	authpb "flamo/backend/pkg/api/proto/auth"
	"flamo/backend/pkg/api/proto/models/tenant"
)

type AuthenticationMethod string

const (
	MethodAPIKey AuthenticationMethod = "api_key"
	MethodJWT    AuthenticationMethod = "jwt"
	MethodMTLS   AuthenticationMethod = "mtls"
	MethodOAuth2 AuthenticationMethod = "oauth2"
	MethodBasic  AuthenticationMethod = "basic"
	MethodSAML   AuthenticationMethod = "saml"
	MethodOIDC   AuthenticationMethod = "oidc"
)

type AuthenticationLevel string

const (
	LevelNone        AuthenticationLevel = "none"
	LevelBasic       AuthenticationLevel = "basic"
	LevelStrong      AuthenticationLevel = "strong"
	LevelMultiFactor AuthenticationLevel = "multi_factor"
)

type Provider interface {
	Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResult, error)
	ValidateCredentials(ctx context.Context, credentials interface{}) (*ValidationResult, error)
	GetSupportedMethods() []AuthenticationMethod
	GetAuthenticationLevel() AuthenticationLevel
	IsEnabled() bool
}

type AuthenticationRequest struct {
	Method              AuthenticationMethod
	Credentials         interface{}
	TenantID           uuid.UUID
	ClientIP           string
	UserAgent          string
	RequiredScopes     []string
	RequiredPermissions []string
	RequireMFA         bool
	Context            map[string]interface{}
}

type AuthenticationResult struct {
	Authenticated      bool
	Principal          *Principal
	Level              AuthenticationLevel
	Permissions        []string
	Scopes             []string
	TokenInfo          *TokenInfo
	SessionInfo        *SessionInfo
	CertificateInfo    *CertificateInfo
	RiskScore          float64
	RiskFactors        []string
	ExpiresAt          *time.Time
	Metadata           map[string]interface{}
}

type ValidationResult struct {
	Valid              bool
	Errors             []ValidationError
	Warnings           []string
	RiskScore          float64
	Metadata           map[string]interface{}
}

type ValidationError struct {
	Code     string
	Message  string
	Field    string
	Severity errors.ErrorSeverity
}

type Principal struct {
	ID             string
	Type           string
	Name           string
	Email          string
	TenantID       string
	OrganizationID string
	Roles          []string
	Groups         []string
	Attributes     map[string]interface{}
	CreatedAt      time.Time
	LastLogin      *time.Time
	IsActive       bool
	MFAEnabled     bool
}

type TokenInfo struct {
	TokenID   string
	Type      string
	Issuer    string
	Subject   string
	Audience  []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	NotBefore *time.Time
	Scopes    []string
	Claims    map[string]interface{}
	JTI       string
}

type SessionInfo struct {
	SessionID    string
	UserID       string
	TenantID     string
	CreatedAt    time.Time
	LastActivity time.Time
	ExpiresAt    time.Time
	IPAddress    string
	UserAgent    string
	IsActive     bool
	Metadata     map[string]interface{}
}

type CertificateInfo struct {
	SerialNumber       string
	Subject            string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	Fingerprint        string
	PublicKeyAlgorithm string
	SignatureAlgorithm string
	KeyUsage           []string
	ExtendedKeyUsage   []string
	SubjectAltNames    []string
	Status             string
	RevocationReason   string
	RevocationTime     *time.Time
}

type ProviderManager struct {
	providers map[AuthenticationMethod]Provider
	config    *config.Config
	db        *database.Database
	logger    *zap.Logger
}

func NewProviderManager(cfg *config.Config, db *database.Database, logger *zap.Logger) *ProviderManager {
	return &ProviderManager{
		providers: make(map[AuthenticationMethod]Provider),
		config:    cfg,
		db:        db,
		logger:    logger,
	}
}

func (pm *ProviderManager) RegisterProvider(method AuthenticationMethod, provider Provider) error {
	if provider == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "provider cannot be nil")
	}

	if !provider.IsEnabled() {
		return errors.New(errors.ErrCodeInvalidRequest, "provider is not enabled")
	}

	pm.providers[method] = provider
	pm.logger.Info("Authentication provider registered",
		zap.String("method", string(method)),
		zap.String("level", string(provider.GetAuthenticationLevel())))

	return nil
}

func (pm *ProviderManager) GetProvider(method AuthenticationMethod) (Provider, error) {
	provider, exists := pm.providers[method]
	if !exists {
		return nil, errors.New(errors.ErrCodeInvalidRequest, 
			fmt.Sprintf("authentication method not supported: %s", method))
	}

	if !provider.IsEnabled() {
		return nil, errors.New(errors.ErrCodeServiceUnavailable,
			fmt.Sprintf("authentication method disabled: %s", method))
	}

	return provider, nil
}

func (pm *ProviderManager) Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResult, error) {
	if req == nil {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "authentication request is required")
	}

	if req.TenantID == uuid.Nil {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "tenant ID is required")
	}

	provider, err := pm.GetProvider(req.Method)
	if err != nil {
		return nil, err
	}

	tenantInfo, err := pm.getTenantInfo(ctx, req.TenantID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "failed to get tenant information")
	}

	if !tenantInfo.CanAccess() {
		return nil, errors.New(errors.ErrCodeForbidden, "tenant access denied")
	}

	if err := pm.validateSecurityConstraints(req, tenantInfo); err != nil {
		return nil, err
	}

	result, err := provider.Authenticate(ctx, req)
	if err != nil {
		pm.logAuthenticationFailure(req, err)
		return nil, err
	}

	if result.Authenticated {
		if err := pm.validatePermissions(result, req); err != nil {
			return nil, err
		}

		if err := pm.updateLastActivity(ctx, result.Principal); err != nil {
			pm.logger.Warn("Failed to update last activity", zap.Error(err))
		}

		pm.logAuthenticationSuccess(req, result)
	}

	return result, nil
}

func (pm *ProviderManager) getTenantInfo(ctx context.Context, tenantID uuid.UUID) (*tenant.Tenant, error) {
	query := `
		SELECT id, name, slug, status, tier, organization_id, 
		       compliance_config, security_config, resource_limits,
		       created_at, updated_at
		FROM tenants 
		WHERE id = $1`

	var t tenant.Tenant
	err := pm.db.Get(ctx, &t, query, tenantID)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, errors.New(errors.ErrCodeNotFound, "tenant not found")
		}
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to retrieve tenant")
	}

	return &t, nil
}

func (pm *ProviderManager) validateSecurityConstraints(req *AuthenticationRequest, tenantInfo *tenant.Tenant) error {
	if len(tenantInfo.SecurityConfig.IPWhitelist) > 0 {
		allowed := false
		for _, allowedIP := range tenantInfo.SecurityConfig.IPWhitelist {
			if utils.IsValidIP(allowedIP) && allowedIP == req.ClientIP {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New(errors.ErrCodeForbidden, "IP address not whitelisted")
		}
	}

	return nil
}

func (pm *ProviderManager) validatePermissions(result *AuthenticationResult, req *AuthenticationRequest) error {
	if len(req.RequiredPermissions) > 0 {
		for _, required := range req.RequiredPermissions {
			found := false
			for _, granted := range result.Permissions {
				if granted == required || granted == "*" {
					found = true
					break
				}
			}
			if !found {
				return errors.New(errors.ErrCodeForbidden, 
					fmt.Sprintf("missing required permission: %s", required))
			}
		}
	}

	if len(req.RequiredScopes) > 0 {
		for _, required := range req.RequiredScopes {
			found := false
			for _, granted := range result.Scopes {
				if granted == required || granted == "*" {
					found = true
					break
				}
			}
			if !found {
				return errors.New(errors.ErrCodeForbidden, 
					fmt.Sprintf("missing required scope: %s", required))
			}
		}
	}

	return nil
}

func (pm *ProviderManager) updateLastActivity(ctx context.Context, principal *Principal) error {
	if principal.Type == "user" {
		query := `UPDATE users SET last_login = $1 WHERE id = $2`
		_, err := pm.db.Exec(ctx, query, time.Now().UTC(), principal.ID)
		return err
	}
	return nil
}

func (pm *ProviderManager) logAuthenticationSuccess(req *AuthenticationRequest, result *AuthenticationResult) {
	pm.logger.Info("Authentication successful",
		zap.String("method", string(req.Method)),
		zap.String("principal_id", result.Principal.ID),
		zap.String("principal_type", result.Principal.Type),
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("client_ip", req.ClientIP),
		zap.Float64("risk_score", result.RiskScore),
		zap.Strings("risk_factors", result.RiskFactors))
}

func (pm *ProviderManager) logAuthenticationFailure(req *AuthenticationRequest, err error) {
	pm.logger.Warn("Authentication failed",
		zap.String("method", string(req.Method)),
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("client_ip", req.ClientIP),
		zap.Error(err))
}

func (pm *ProviderManager) GetSupportedMethods() []AuthenticationMethod {
	methods := []AuthenticationMethod{}
	for method, provider := range pm.providers {
		if provider.IsEnabled() {
			methods = append(methods, method)
		}
	}
	return methods
}

func (pm *ProviderManager) IsMethodSupported(method AuthenticationMethod) bool {
	provider, exists := pm.providers[method]
	return exists && provider.IsEnabled()
}
