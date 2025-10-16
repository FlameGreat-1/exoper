package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"flamo/backend/internal/auth/mtls"
	"flamo/backend/internal/auth/providers"
	"flamo/backend/internal/auth/tokens"
	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	authpb "flamo/backend/pkg/api/proto/auth"
	"flamo/backend/pkg/api/proto/models/tenant"
)

type AuthService struct {
	config          *config.Config
	db              *database.Database
	logger          *zap.Logger
	providerManager *providers.ProviderManager
	tokenManager    *tokens.TokenManager
	sessionManager  *tokens.SessionManager
	apiKeyManager   *tokens.APIKeyManager
	mtlsManager     *mtls.MTLSManager
	tenantCache     map[string]*tenant.Tenant
}

type AuthenticationRequest struct {
	Method              authpb.AuthenticationMethod
	Credentials         interface{}
	TenantID           string
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
	Level              authpb.AuthenticationLevel
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

type AuthorizationRequest struct {
	PrincipalID         string
	Resource            string
	Action              string
	ResourceAttributes  map[string]interface{}
	Context             map[string]interface{}
	RequiredPermissions []string
	EnforceMFA          bool
}

type AuthorizationResult struct {
	Authorized          bool
	Decision            string
	GrantedPermissions  []string
	DeniedPermissions   []string
	PolicyEvaluations   []PolicyEvaluation
	Reason              string
	Obligations         map[string]interface{}
	EvaluatedAt         time.Time
	Metadata            map[string]interface{}
}

type PolicyEvaluation struct {
	PolicyID   string
	PolicyName string
	Decision   string
	Reason     string
	Confidence float64
	Context    map[string]interface{}
}

func NewAuthService(cfg *config.Config, db *database.Database, logger *zap.Logger) (*AuthService, error) {
	providerManager := providers.NewProviderManager(cfg, db, logger)
	
	tokenManager, err := tokens.NewTokenManager(cfg, db, logger)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to create token manager")
	}

	sessionManager := tokens.NewSessionManager(cfg, db, logger)
	apiKeyManager := tokens.NewAPIKeyManager(cfg, db, logger)

	mtlsManager, err := mtls.NewMTLSManager(cfg, db, logger)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to create mTLS manager")
	}

	service := &AuthService{
		config:          cfg,
		db:              db,
		logger:          logger,
		providerManager: providerManager,
		tokenManager:    tokenManager,
		sessionManager:  sessionManager,
		apiKeyManager:   apiKeyManager,
		mtlsManager:     mtlsManager,
		tenantCache:     make(map[string]*tenant.Tenant),
	}

	if err := service.initializeProviders(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to initialize auth providers")
	}

	return service, nil
}

func (s *AuthService) Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResult, error) {
	startTime := time.Now()
	
	if err := s.validateAuthenticationRequest(req); err != nil {
		return nil, err
	}

	tenantInfo, err := s.getTenantInfo(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}

	if !tenantInfo.CanAccess() {
		return nil, errors.New(errors.ErrCodeForbidden, "tenant access denied")
	}

	if err := s.enforceSecurityPolicies(req, tenantInfo); err != nil {
		return nil, err
	}

	providerReq := &providers.AuthenticationRequest{
		Method:              providers.AuthenticationMethod(req.Method.String()),
		Credentials:         req.Credentials,
		TenantID:           uuid.MustParse(req.TenantID),
		ClientIP:           req.ClientIP,
		UserAgent:          req.UserAgent,
		RequiredScopes:     req.RequiredScopes,
		RequiredPermissions: req.RequiredPermissions,
		RequireMFA:         req.RequireMFA,
		Context:            req.Context,
	}

	providerResult, err := s.providerManager.Authenticate(ctx, providerReq)
	if err != nil {
		s.logAuthenticationFailure(req, err, time.Since(startTime))
		return nil, err
	}

	if !providerResult.Authenticated {
		return nil, errors.New(errors.ErrCodeUnauthorized, "authentication failed")
	}

	result := s.convertProviderResult(providerResult)
	
	if err := s.enhanceAuthenticationResult(ctx, result, req, tenantInfo); err != nil {
		s.logger.Warn("Failed to enhance authentication result", zap.Error(err))
	}

	if err := s.recordAuthenticationEvent(ctx, req, result); err != nil {
		s.logger.Warn("Failed to record authentication event", zap.Error(err))
	}

	s.logAuthenticationSuccess(req, result, time.Since(startTime))

	return result, nil
}

func (s *AuthService) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResult, error) {
	startTime := time.Now()

	if err := s.validateAuthorizationRequest(req); err != nil {
		return nil, err
	}

	principal, err := s.getPrincipal(ctx, req.PrincipalID)
	if err != nil {
		return nil, err
	}

	if !principal.IsActive {
		return nil, errors.New(errors.ErrCodeForbidden, "principal is inactive")
	}

	tenantInfo, err := s.getTenantInfo(ctx, principal.TenantID)
	if err != nil {
		return nil, err
	}

	if !tenantInfo.CanAccess() {
		return nil, errors.New(errors.ErrCodeForbidden, "tenant access denied")
	}

	result := &AuthorizationResult{
		Authorized:         false,
		Decision:           "deny",
		GrantedPermissions: []string{},
		DeniedPermissions:  []string{},
		PolicyEvaluations:  []PolicyEvaluation{},
		EvaluatedAt:        time.Now().UTC(),
		Metadata:           make(map[string]interface{}),
	}

	permissions, err := s.getPrincipalPermissions(ctx, principal)
	if err != nil {
		return nil, err
	}

	if req.EnforceMFA && !principal.MFAEnabled {
		result.Reason = "MFA required but not enabled"
		return result, nil
	}

	authorized, grantedPerms, deniedPerms := s.evaluatePermissions(permissions, req.RequiredPermissions)
	result.GrantedPermissions = grantedPerms
	result.DeniedPermissions = deniedPerms

	if authorized {
		policyResult := s.evaluatePolicies(ctx, principal, req)
		result.PolicyEvaluations = policyResult.Evaluations
		
		if policyResult.Authorized {
			result.Authorized = true
			result.Decision = "allow"
			result.Reason = "authorization successful"
		} else {
			result.Reason = policyResult.Reason
		}
	} else {
		result.Reason = "insufficient permissions"
	}

	if err := s.recordAuthorizationEvent(ctx, req, result); err != nil {
		s.logger.Warn("Failed to record authorization event", zap.Error(err))
	}

	s.logAuthorizationResult(req, result, time.Since(startTime))

	return result, nil
}

func (s *AuthService) ValidateToken(ctx context.Context, token string, tokenType authpb.TokenType, requiredScopes, requiredPermissions []string) (*TokenValidationResult, error) {
	validationReq := &tokens.ValidationRequest{
		Token:               token,
		TokenType:           tokens.TokenType(tokenType.String()),
		RequiredScopes:      requiredScopes,
		RequiredPermissions: requiredPermissions,
		CheckExpiration:     true,
		CheckRevocation:     true,
		Context:             make(map[string]interface{}),
	}

	result, err := s.tokenManager.ValidateToken(ctx, validationReq)
	if err != nil {
		return nil, err
	}

	validationResult := &TokenValidationResult{
		Valid:           result.Valid,
		TokenInfo:       s.convertTokenInfo(result.TokenInfo),
		Principal:       s.convertPrincipalFromClaims(result.Claims),
		ValidationErrors: s.convertValidationErrors(result.Errors),
		RiskScore:       result.RiskScore,
		ValidatedAt:     result.ValidatedAt,
	}

	return validationResult, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string, scopes []string, duration time.Duration) (*TokenRefreshResult, error) {
	tokenInfo, err := s.tokenManager.RefreshToken(ctx, refreshToken, scopes, duration)
	if err != nil {
		return nil, err
	}

	result := &TokenRefreshResult{
		AccessToken:  tokenInfo.Token,
		RefreshToken: tokenInfo.RefreshToken,
		TokenInfo:    s.convertTokenInfo(tokenInfo),
		IssuedAt:     tokenInfo.IssuedAt,
	}

	return result, nil
}

func (s *AuthService) CreateSession(ctx context.Context, userID, tenantID string, duration time.Duration, attributes map[string]interface{}, requireMFA bool) (*SessionResult, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "invalid user ID")
	}

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "invalid tenant ID")
	}

	sessionReq := &tokens.SessionRequest{
		UserID:     userUUID,
		TenantID:   tenantUUID,
		Duration:   duration,
		RequireMFA: requireMFA,
		Attributes: attributes,
	}

	session, err := s.sessionManager.CreateSession(ctx, sessionReq)
	if err != nil {
		return nil, err
	}

	result := &SessionResult{
		SessionID:    session.ID,
		SessionToken: session.Token,
		SessionInfo:  s.convertSessionInfo(session),
		CreatedAt:    session.CreatedAt,
	}

	return result, nil
}

func (s *AuthService) ValidateSession(ctx context.Context, sessionID, sessionToken string, extendSession bool, extensionDuration time.Duration) (*SessionValidationResult, error) {
	session, err := s.sessionManager.ValidateSession(ctx, sessionID, sessionToken)
	if err != nil {
		return nil, err
	}

	principal, err := s.getPrincipal(ctx, session.UserID.String())
	if err != nil {
		return nil, err
	}

	result := &SessionValidationResult{
		Valid:       true,
		SessionInfo: s.convertSessionInfo(session),
		Principal:   principal,
		ValidatedAt: time.Now().UTC(),
	}

	if extendSession && extensionDuration > 0 {
		if err := s.sessionManager.ExtendSession(ctx, sessionID, extensionDuration); err != nil {
			s.logger.Warn("Failed to extend session", zap.Error(err))
		} else {
			result.ExtendedUntil = &session.ExpiresAt
		}
	}

	return result, nil
}

func (s *AuthService) RevokeSession(ctx context.Context, sessionID, reason, revokedBy string) error {
	return s.sessionManager.RevokeSession(ctx, sessionID, revokedBy, reason)
}

func (s *AuthService) CreateAPIKey(ctx context.Context, tenantID, name, description string, permissions, scopes []string, expiresAt *time.Time, createdBy string) (*APIKeyResult, error) {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "invalid tenant ID")
	}

	createdByUUID, err := uuid.Parse(createdBy)
	if err != nil {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "invalid created_by user ID")
	}

	apiKeyReq := &tokens.APIKeyRequest{
		TenantID:    tenantUUID,
		Name:        name,
		Description: description,
		Permissions: permissions,
		Scopes:      scopes,
		ExpiresAt:   expiresAt,
		CreatedBy:   createdByUUID,
		Metadata:    make(map[string]interface{}),
	}

	apiKey, fullKey, err := s.apiKeyManager.CreateAPIKey(ctx, apiKeyReq)
	if err != nil {
		return nil, err
	}

	result := &APIKeyResult{
		KeyID:   apiKey.ID.String(),
		Key:     fullKey,
		Prefix:  apiKey.Prefix,
		KeyInfo: s.convertAPIKeyInfo(apiKey),
		CreatedAt: apiKey.CreatedAt,
	}

	return result, nil
}

func (s *AuthService) RevokeAPIKey(ctx context.Context, keyID, reason, revokedBy string) error {
	revokedByUUID, err := uuid.Parse(revokedBy)
	if err != nil {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid revoked_by user ID")
	}

	return s.apiKeyManager.RevokeAPIKey(ctx, keyID, reason, revokedByUUID)
}

func (s *AuthService) VerifyCertificate(ctx context.Context, certificate, certificateChain string, checkRevocation, checkExpiration bool, requiredKeyUsage []string) (*CertificateVerificationResult, error) {
	var chainCerts []string
	if certificateChain != "" {
		chainCerts = []string{certificateChain}
	}

	validationReq := &mtls.CertificateValidationRequest{
		Certificate:      certificate,
		CertificateChain: chainCerts,
		CheckRevocation:  checkRevocation,
		CheckExpiration:  checkExpiration,
		RequiredKeyUsage: requiredKeyUsage,
	}

	result, err := s.mtlsManager.ValidateCertificate(ctx, validationReq)
	if err != nil {
		return nil, err
	}

	verificationResult := &CertificateVerificationResult{
		Valid:              result.Valid,
		CertificateInfo:    s.convertCertificateInfo(result.CertificateInfo),
		ValidationErrors:   s.convertMTLSValidationErrors(result.ValidationErrors),
		TrustChainStatus:   result.TrustChainStatus,
		VerifiedAt:         result.ValidatedAt,
	}

	return verificationResult, nil
}

func (s *AuthService) GetPermissions(ctx context.Context, principalID, resourceType, resourceID string) (*PermissionsResult, error) {
	principal, err := s.getPrincipal(ctx, principalID)
	if err != nil {
		return nil, err
	}

	permissions, err := s.getPrincipalPermissions(ctx, principal)
	if err != nil {
		return nil, err
	}

	roles, err := s.getPrincipalRoles(ctx, principal)
	if err != nil {
		return nil, err
	}

	scopes := s.getPrincipalScopes(principal, resourceType, resourceID)

	result := &PermissionsResult{
		Permissions: permissions,
		Scopes:      scopes,
		Roles:       roles,
		EvaluatedAt: time.Now().UTC(),
		Metadata:    make(map[string]interface{}),
	}

	return result, nil
}

func (s *AuthService) initializeProviders() error {
	apiKeyProvider := providers.NewAPIKeyProvider(s.config, s.db, s.logger)
	if err := s.providerManager.RegisterProvider(providers.MethodAPIKey, apiKeyProvider); err != nil {
		return err
	}

	jwtProvider, err := providers.NewJWTProvider(s.config, s.db, s.logger)
	if err != nil {
		return err
	}
	if err := s.providerManager.RegisterProvider(providers.MethodJWT, jwtProvider); err != nil {
		return err
	}

	basicProvider := providers.NewBasicProvider(s.config, s.db, s.logger)
	if err := s.providerManager.RegisterProvider(providers.MethodBasic, basicProvider); err != nil {
		return err
	}

	s.logger.Info("Authentication providers initialized",
		zap.Strings("methods", s.getSupportedMethods()))

	return nil
}

func (s *AuthService) validateAuthenticationRequest(req *AuthenticationRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "authentication request is required")
	}

	if req.TenantID == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "tenant ID is required")
	}

	if _, err := uuid.Parse(req.TenantID); err != nil {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid tenant ID format")
	}

	if req.Method == authpb.AuthenticationMethod_AUTHENTICATION_METHOD_UNSPECIFIED {
		return errors.New(errors.ErrCodeInvalidRequest, "authentication method is required")
	}

	if req.Credentials == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "credentials are required")
	}

	if req.ClientIP != "" && !utils.IsValidIP(req.ClientIP) {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid client IP address")
	}

	return nil
}

func (s *AuthService) validateAuthorizationRequest(req *AuthorizationRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "authorization request is required")
	}

	if req.PrincipalID == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "principal ID is required")
	}

	if req.Resource == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "resource is required")
	}

	if req.Action == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "action is required")
	}

	return nil
}

func (s *AuthService) getTenantInfo(ctx context.Context, tenantID string) (*tenant.Tenant, error) {
	if cachedTenant, exists := s.tenantCache[tenantID]; exists {
		return cachedTenant, nil
	}

	query := `
		SELECT id, name, slug, status, tier, organization_id, 
		       compliance_config, security_config, resource_limits,
		       created_at, updated_at
		FROM tenants 
		WHERE id = $1`

	var t tenant.Tenant
	err := s.db.Get(ctx, &t, query, tenantID)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, errors.New(errors.ErrCodeNotFound, "tenant not found")
		}
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to retrieve tenant")
	}

	s.tenantCache[tenantID] = &t
	return &t, nil
}

func (s *AuthService) enforceSecurityPolicies(req *AuthenticationRequest, tenantInfo *tenant.Tenant) error {
	if len(tenantInfo.SecurityConfig.IPWhitelist) > 0 {
		allowed := false
		for _, allowedIP := range tenantInfo.SecurityConfig.IPWhitelist {
			if utils.IsValidIP(allowedIP) && allowedIP == req.ClientIP {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New(errors.ErrCodeForbidden, "client IP not whitelisted")
		}
	}

	if tenantInfo.SecurityConfig.MFARequired && !req.RequireMFA {
		return errors.New(errors.ErrCodeAuthenticationError, "MFA is required for this tenant")
	}

	return nil
}

func (s *AuthService) convertProviderResult(result *providers.AuthenticationResult) *AuthenticationResult {
	return &AuthenticationResult{
		Authenticated:   result.Authenticated,
		Principal:       s.convertPrincipal(result.Principal),
		Level:           s.convertAuthLevel(result.Level),
		Permissions:     result.Permissions,
		Scopes:          result.Scopes,
		TokenInfo:       s.convertProviderTokenInfo(result.TokenInfo),
		SessionInfo:     s.convertProviderSessionInfo(result.SessionInfo),
		CertificateInfo: s.convertProviderCertificateInfo(result.CertificateInfo),
		RiskScore:       result.RiskScore,
		RiskFactors:     result.RiskFactors,
		ExpiresAt:       result.ExpiresAt,
		Metadata:        result.Metadata,
	}
}

func (s *AuthService) convertPrincipal(p *providers.Principal) *Principal {
	if p == nil {
		return nil
	}

	return &Principal{
		ID:             p.ID,
		Type:           p.Type,
		Name:           p.Name,
		Email:          p.Email,
		TenantID:       p.TenantID,
		OrganizationID: p.OrganizationID,
		Roles:          p.Roles,
		Groups:         p.Groups,
		Attributes:     p.Attributes,
		CreatedAt:      p.CreatedAt,
		LastLogin:      p.LastLogin,
		IsActive:       p.IsActive,
		MFAEnabled:     p.MFAEnabled,
	}
}

func (s *AuthService) convertAuthLevel(level providers.AuthenticationLevel) authpb.AuthenticationLevel {
	switch level {
	case providers.LevelNone:
		return authpb.AuthenticationLevel_AUTHENTICATION_LEVEL_NONE
	case providers.LevelBasic:
		return authpb.AuthenticationLevel_AUTHENTICATION_LEVEL_BASIC
	case providers.LevelStrong:
		return authpb.AuthenticationLevel_AUTHENTICATION_LEVEL_STRONG
	case providers.LevelMultiFactor:
		return authpb.AuthenticationLevel_AUTHENTICATION_LEVEL_MULTI_FACTOR
	default:
		return authpb.AuthenticationLevel_AUTHENTICATION_LEVEL_UNSPECIFIED
	}
}

func (s *AuthService) convertProviderTokenInfo(ti *providers.TokenInfo) *TokenInfo {
	if ti == nil {
		return nil
	}

	return &TokenInfo{
		TokenID:   ti.TokenID,
		Type:      ti.Type,
		Issuer:    ti.Issuer,
		Subject:   ti.Subject,
		Audience:  ti.Audience,
		IssuedAt:  ti.IssuedAt,
		ExpiresAt: ti.ExpiresAt,
		NotBefore: ti.NotBefore,
		Scopes:    ti.Scopes,
		Claims:    ti.Claims,
		JTI:       ti.JTI,
	}
}

func (s *AuthService) convertProviderSessionInfo(si *providers.SessionInfo) *SessionInfo {
	if si == nil {
		return nil
	}

	return &SessionInfo{
		SessionID:    si.SessionID,
		UserID:       si.UserID,
		TenantID:     si.TenantID,
		CreatedAt:    si.CreatedAt,
		LastActivity: si.LastActivity,
		ExpiresAt:    si.ExpiresAt,
		IPAddress:    si.IPAddress,
		UserAgent:    si.UserAgent,
		IsActive:     si.IsActive,
		Metadata:     si.Metadata,
	}
}

func (s *AuthService) convertProviderCertificateInfo(ci *providers.CertificateInfo) *CertificateInfo {
	if ci == nil {
		return nil
	}

	return &CertificateInfo{
		SerialNumber:       ci.SerialNumber,
		Subject:            ci.Subject,
		Issuer:             ci.Issuer,
		NotBefore:          ci.NotBefore,
		NotAfter:           ci.NotAfter,
		Fingerprint:        ci.Fingerprint,
		PublicKeyAlgorithm: ci.PublicKeyAlgorithm,
		SignatureAlgorithm: ci.SignatureAlgorithm,
		KeyUsage:           ci.KeyUsage,
		ExtendedKeyUsage:   ci.ExtendedKeyUsage,
		SubjectAltNames:    ci.SubjectAltNames,
		Status:             ci.Status,
		RevocationReason:   ci.RevocationReason,
		RevocationTime:     ci.RevocationTime,
	}
}

func (s *AuthService) convertTokenInfo(ti *tokens.TokenInfo) *TokenInfo {
	if ti == nil {
		return nil
	}

	return &TokenInfo{
		TokenID:   ti.ID,
		Type:      string(ti.Type),
		Issuer:    "",
		Subject:   ti.UserID,
		Audience:  []string{},
		IssuedAt:  ti.IssuedAt,
		ExpiresAt: ti.ExpiresAt,
		NotBefore: ti.NotBefore,
		Scopes:    ti.Scopes,
		Claims:    ti.Metadata,
		JTI:       ti.ID,
	}
}

func (s *AuthService) convertSessionInfo(session *tokens.Session) *SessionInfo {
	if session == nil {
		return nil
	}

	return &SessionInfo{
		SessionID:    session.ID,
		UserID:       session.UserID.String(),
		TenantID:     session.TenantID.String(),
		CreatedAt:    session.CreatedAt,
		LastActivity: session.LastActivity,
		ExpiresAt:    session.ExpiresAt,
		IPAddress:    session.IPAddress,
		UserAgent:    session.UserAgent,
		IsActive:     session.IsActive,
		Metadata:     session.Metadata,
	}
}

func (s *AuthService) convertAPIKeyInfo(apiKey *tokens.APIKey) *APIKeyInfo {
	if apiKey == nil {
		return nil
	}

	return &APIKeyInfo{
		KeyID:       apiKey.ID.String(),
		TenantID:    apiKey.TenantID.String(),
		Name:        apiKey.Name,
		Description: apiKey.Description,
		Prefix:      apiKey.Prefix,
		Permissions: apiKey.Permissions,
		Scopes:      apiKey.Scopes,
		ExpiresAt:   apiKey.ExpiresAt,
		LastUsedAt:  apiKey.LastUsedAt,
		IsActive:    apiKey.IsActive,
		CreatedAt:   apiKey.CreatedAt,
		CreatedBy:   apiKey.CreatedBy.String(),
		RevokedAt:   apiKey.RevokedAt,
		Metadata:    apiKey.Metadata,
	}
}

func (s *AuthService) convertCertificateInfo(ci *mtls.CertificateInfo) *CertificateInfo {
	if ci == nil {
		return nil
	}

	return &CertificateInfo{
		SerialNumber:       ci.SerialNumber,
		Subject:            ci.Subject,
		Issuer:             ci.Issuer,
		NotBefore:          ci.NotBefore,
		NotAfter:           ci.NotAfter,
		Fingerprint:        ci.Fingerprint,
		PublicKeyAlgorithm: ci.PublicKeyAlgorithm,
		SignatureAlgorithm: ci.SignatureAlgorithm,
		KeyUsage:           ci.KeyUsage,
		ExtendedKeyUsage:   ci.ExtendedKeyUsage,
		SubjectAltNames:    ci.SubjectAltNames,
		Status:             string(ci.Status),
		RevocationReason:   ci.RevocationReason,
		RevocationTime:     ci.RevocationTime,
	}
}

func (s *AuthService) convertPrincipalFromClaims(claims *tokens.TokenClaims) *Principal {
	if claims == nil {
		return nil
	}

	return &Principal{
		ID:         claims.UserID,
		Type:       "user",
		Name:       claims.Username,
		Email:      claims.Email,
		TenantID:   claims.TenantID,
		Roles:      claims.Roles,
		Groups:     []string{},
		Attributes: claims.CustomClaims,
		IsActive:   true,
		MFAEnabled: claims.MFAVerified,
	}
}

func (s *AuthService) convertValidationErrors(errors []tokens.ValidationError) []ValidationError {
	result := make([]ValidationError, len(errors))
	for i, err := range errors {
		result[i] = ValidationError{
			Code:     err.Code,
			Message:  err.Message,
			Field:    err.Field,
			Severity: err.Severity,
		}
	}
	return result
}

func (s *AuthService) convertMTLSValidationErrors(errors []mtls.ValidationError) []string {
	result := make([]string, len(errors))
	for i, err := range errors {
		result[i] = fmt.Sprintf("%s: %s", err.Code, err.Message)
	}
	return result
}

func (s *AuthService) getPrincipal(ctx context.Context, principalID string) (*Principal, error) {
	query := `
		SELECT id, username, email, tenant_id, is_active, mfa_enabled, 
		       created_at, last_login
		FROM users 
		WHERE id = $1`

	var user struct {
		ID         string     `db:"id"`
		Username   string     `db:"username"`
		Email      string     `db:"email"`
		TenantID   string     `db:"tenant_id"`
		IsActive   bool       `db:"is_active"`
		MFAEnabled bool       `db:"mfa_enabled"`
		CreatedAt  time.Time  `db:"created_at"`
		LastLogin  *time.Time `db:"last_login"`
	}

	err := s.db.Get(ctx, &user, query, principalID)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, errors.New(errors.ErrCodeNotFound, "principal not found")
		}
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to retrieve principal")
	}

	roles, err := s.getUserRoles(ctx, principalID)
	if err != nil {
		s.logger.Warn("Failed to get user roles", zap.Error(err))
		roles = []string{}
	}

	return &Principal{
		ID:         user.ID,
		Type:       "user",
		Name:       user.Username,
		Email:      user.Email,
		TenantID:   user.TenantID,
		Roles:      roles,
		Groups:     []string{},
		Attributes: make(map[string]interface{}),
		CreatedAt:  user.CreatedAt,
		LastLogin:  user.LastLogin,
		IsActive:   user.IsActive,
		MFAEnabled: user.MFAEnabled,
	}, nil
}

func (s *AuthService) getPrincipalPermissions(ctx context.Context, principal *Principal) ([]string, error) {
	query := `
		SELECT DISTINCT p.name 
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1`

	var permissions []string
	err := s.db.Select(ctx, &permissions, query, principal.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to get principal permissions")
	}

	return permissions, nil
}

func (s *AuthService) getPrincipalRoles(ctx context.Context, principal *Principal) ([]RoleInfo, error) {
	query := `
		SELECT r.id, r.name, r.description
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1`

	var roles []RoleInfo
	err := s.db.Select(ctx, &roles, query, principal.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to get principal roles")
	}

	for i := range roles {
		permissions, err := s.getRolePermissions(ctx, roles[i].RoleID)
		if err != nil {
			s.logger.Warn("Failed to get role permissions", zap.Error(err))
			continue
		}
		roles[i].Permissions = permissions
	}

	return roles, nil
}

func (s *AuthService) getUserRoles(ctx context.Context, userID string) ([]string, error) {
	query := `
		SELECT r.name 
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1`

	var roles []string
	err := s.db.Select(ctx, &roles, query, userID)
	if err != nil {
		return nil, err
	}

	return roles, nil
}

func (s *AuthService) getRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	query := `
		SELECT p.name 
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1`

	var permissions []string
	err := s.db.Select(ctx, &permissions, query, roleID)
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (s *AuthService) getPrincipalScopes(principal *Principal, resourceType, resourceID string) []string {
	scopes := []string{"read"}

	for _, role := range principal.Roles {
		switch role {
		case "admin":
			scopes = append(scopes, "write", "delete", "admin")
		case "editor":
			scopes = append(scopes, "write")
		case "viewer":
		default:
		}
	}

	return utils.RemoveDuplicateStrings(scopes)
}

func (s *AuthService) evaluatePermissions(userPermissions, requiredPermissions []string) (bool, []string, []string) {
	granted := []string{}
	denied := []string{}

	for _, required := range requiredPermissions {
		found := false
		for _, userPerm := range userPermissions {
			if userPerm == required || userPerm == "*" {
				granted = append(granted, required)
				found = true
				break
			}
		}
		if !found {
			denied = append(denied, required)
		}
	}

	return len(denied) == 0, granted, denied
}

func (s *AuthService) evaluatePolicies(ctx context.Context, principal *Principal, req *AuthorizationRequest) *PolicyEvaluationResult {
	result := &PolicyEvaluationResult{
		Authorized:  true,
		Reason:      "policy evaluation passed",
		Evaluations: []PolicyEvaluation{},
	}

	tenantPolicy := s.evaluateTenantPolicy(principal, req)
	result.Evaluations = append(result.Evaluations, tenantPolicy)

	if tenantPolicy.Decision != "allow" {
		result.Authorized = false
		result.Reason = tenantPolicy.Reason
	}

	resourcePolicy := s.evaluateResourcePolicy(principal, req)
	result.Evaluations = append(result.Evaluations, resourcePolicy)

	if resourcePolicy.Decision != "allow" {
		result.Authorized = false
		result.Reason = resourcePolicy.Reason
	}

	return result
}

func (s *AuthService) evaluateTenantPolicy(principal *Principal, req *AuthorizationRequest) PolicyEvaluation {
	return PolicyEvaluation{
		PolicyID:   "tenant_access_policy",
		PolicyName: "Tenant Access Policy",
		Decision:   "allow",
		Reason:     "principal belongs to tenant",
		Confidence: 1.0,
		Context:    make(map[string]interface{}),
	}
}

func (s *AuthService) evaluateResourcePolicy(principal *Principal, req *AuthorizationRequest) PolicyEvaluation {
	return PolicyEvaluation{
		PolicyID:   "resource_access_policy",
		PolicyName: "Resource Access Policy",
		Decision:   "allow",
		Reason:     "resource access granted",
		Confidence: 1.0,
		Context:    make(map[string]interface{}),
	}
}

func (s *AuthService) enhanceAuthenticationResult(ctx context.Context, result *AuthenticationResult, req *AuthenticationRequest, tenantInfo *tenant.Tenant) error {
	if result.Principal != nil {
		enrichedPermissions, err := s.getPrincipalPermissions(ctx, result.Principal)
		if err == nil {
			result.Permissions = utils.MergeStringSlices(result.Permissions, enrichedPermissions)
		}

		if result.Principal.Type == "user" {
			lastLoginUpdate := map[string]interface{}{
				"last_login_ip": req.ClientIP,
				"last_login_user_agent": req.UserAgent,
				"last_login_method": req.Method.String(),
			}
			result.Metadata = utils.MergeMaps(result.Metadata, lastLoginUpdate)
		}
	}

	securityEnhancements := map[string]interface{}{
		"tenant_security_level": tenantInfo.SecurityConfig.Level,
		"compliance_requirements": tenantInfo.ComplianceConfig.Requirements,
		"authentication_timestamp": time.Now().UTC(),
	}
	result.Metadata = utils.MergeMaps(result.Metadata, securityEnhancements)

	return nil
}

func (s *AuthService) recordAuthenticationEvent(ctx context.Context, req *AuthenticationRequest, result *AuthenticationResult) error {
	event := map[string]interface{}{
		"event_type": "authentication",
		"tenant_id": req.TenantID,
		"method": req.Method.String(),
		"client_ip": req.ClientIP,
		"user_agent": req.UserAgent,
		"success": result.Authenticated,
		"risk_score": result.RiskScore,
		"risk_factors": result.RiskFactors,
		"timestamp": time.Now().UTC(),
	}

	if result.Principal != nil {
		event["principal_id"] = result.Principal.ID
		event["principal_type"] = result.Principal.Type
	}

	query := `
		INSERT INTO audit_events (
			event_type, tenant_id, principal_id, event_data, created_at
		) VALUES ($1, $2, $3, $4, $5)`

	principalID := ""
	if result.Principal != nil {
		principalID = result.Principal.ID
	}

	_, err := s.db.Exec(ctx, query, "authentication", req.TenantID, principalID, event, time.Now().UTC())
	return err
}

func (s *AuthService) recordAuthorizationEvent(ctx context.Context, req *AuthorizationRequest, result *AuthorizationResult) error {
	event := map[string]interface{}{
		"event_type": "authorization",
		"principal_id": req.PrincipalID,
		"resource": req.Resource,
		"action": req.Action,
		"authorized": result.Authorized,
		"decision": result.Decision,
		"reason": result.Reason,
		"granted_permissions": result.GrantedPermissions,
		"denied_permissions": result.DeniedPermissions,
		"timestamp": time.Now().UTC(),
	}

	query := `
		INSERT INTO audit_events (
			event_type, principal_id, event_data, created_at
		) VALUES ($1, $2, $3, $4)`

	_, err := s.db.Exec(ctx, query, "authorization", req.PrincipalID, event, time.Now().UTC())
	return err
}

func (s *AuthService) logAuthenticationSuccess(req *AuthenticationRequest, result *AuthenticationResult, duration time.Duration) {
	fields := []zap.Field{
		zap.String("method", req.Method.String()),
		zap.String("tenant_id", req.TenantID),
		zap.String("client_ip", req.ClientIP),
		zap.Float64("risk_score", result.RiskScore),
		zap.Strings("risk_factors", result.RiskFactors),
		zap.Duration("duration", duration),
	}

	if result.Principal != nil {
		fields = append(fields,
			zap.String("principal_id", result.Principal.ID),
			zap.String("principal_type", result.Principal.Type),
			zap.String("auth_level", result.Level.String()))
	}

	s.logger.Info("Authentication successful", fields...)
}

func (s *AuthService) logAuthenticationFailure(req *AuthenticationRequest, err error, duration time.Duration) {
	s.logger.Warn("Authentication failed",
		zap.String("method", req.Method.String()),
		zap.String("tenant_id", req.TenantID),
		zap.String("client_ip", req.ClientIP),
		zap.Error(err),
		zap.Duration("duration", duration))
}

func (s *AuthService) logAuthorizationResult(req *AuthorizationRequest, result *AuthorizationResult, duration time.Duration) {
	if result.Authorized {
		s.logger.Info("Authorization successful",
			zap.String("principal_id", req.PrincipalID),
			zap.String("resource", req.Resource),
			zap.String("action", req.Action),
			zap.Strings("granted_permissions", result.GrantedPermissions),
			zap.Duration("duration", duration))
	} else {
		s.logger.Warn("Authorization failed",
			zap.String("principal_id", req.PrincipalID),
			zap.String("resource", req.Resource),
			zap.String("action", req.Action),
			zap.String("reason", result.Reason),
			zap.Strings("denied_permissions", result.DeniedPermissions),
			zap.Duration("duration", duration))
	}
}

func (s *AuthService) getSupportedMethods() []string {
	methods := s.providerManager.GetSupportedMethods()
	result := make([]string, len(methods))
	for i, method := range methods {
		result[i] = string(method)
	}
	return result
}

func (s *AuthService) IsMethodSupported(method authpb.AuthenticationMethod) bool {
	return s.providerManager.IsMethodSupported(providers.AuthenticationMethod(method.String()))
}

func (s *AuthService) GetSupportedMethods() []authpb.AuthenticationMethod {
	methods := s.providerManager.GetSupportedMethods()
	result := make([]authpb.AuthenticationMethod, len(methods))
	for i, method := range methods {
		switch method {
		case providers.MethodAPIKey:
			result[i] = authpb.AuthenticationMethod_AUTHENTICATION_METHOD_API_KEY
		case providers.MethodJWT:
			result[i] = authpb.AuthenticationMethod_AUTHENTICATION_METHOD_JWT
		case providers.MethodMTLS:
			result[i] = authpb.AuthenticationMethod_AUTHENTICATION_METHOD_MTLS
		case providers.MethodOAuth2:
			result[i] = authpb.AuthenticationMethod_AUTHENTICATION_METHOD_OAUTH2
		case providers.MethodBasic:
			result[i] = authpb.AuthenticationMethod_AUTHENTICATION_METHOD_BASIC
		case providers.MethodSAML:
			result[i] = authpb.AuthenticationMethod_AUTHENTICATION_METHOD_SAML
		case providers.MethodOIDC:
			result[i] = authpb.AuthenticationMethod_AUTHENTICATION_METHOD_OIDC
		default:
			result[i] = authpb.AuthenticationMethod_AUTHENTICATION_METHOD_UNSPECIFIED
		}
	}
	return result
}

func (s *AuthService) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down auth service")
	
	if err := s.tokenManager.CleanupExpiredTokens(ctx); err != nil {
		s.logger.Warn("Failed to cleanup expired tokens during shutdown", zap.Error(err))
	}

	if err := s.sessionManager.CleanupExpiredSessions(ctx); err != nil {
		s.logger.Warn("Failed to cleanup expired sessions during shutdown", zap.Error(err))
	}

	s.tenantCache = make(map[string]*tenant.Tenant)
	
	s.logger.Info("Auth service shutdown completed")
	return nil
}
