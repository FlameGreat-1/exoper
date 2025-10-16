package handlers

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"flamo/backend/internal/auth/service"
	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/errors"
	authpb "flamo/backend/pkg/api/proto/auth"
	commonpb "flamo/backend/pkg/api/proto/common"
)

type AuthHandler struct {
	authpb.UnimplementedAuthenticationServiceServer
	service *service.AuthService
	config  *config.Config
	logger  *zap.Logger
}

func NewAuthHandler(authService *service.AuthService, cfg *config.Config, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		service: authService,
		config:  cfg,
		logger:  logger,
	}
}

func (h *AuthHandler) Authenticate(ctx context.Context, req *authpb.AuthenticateRequest) (*authpb.AuthenticateResponse, error) {
	startTime := time.Now()
	
	if err := h.validateAuthenticateRequest(req); err != nil {
		return h.buildAuthenticateErrorResponse(err), nil
	}

	credentials, err := h.extractCredentials(req)
	if err != nil {
		return h.buildAuthenticateErrorResponse(err), nil
	}

	serviceReq := &service.AuthenticationRequest{
		Method:              req.Method,
		Credentials:         credentials,
		TenantID:           req.TenantId,
		ClientIP:           h.extractClientIP(ctx),
		UserAgent:          h.extractUserAgent(ctx),
		RequiredScopes:     req.RequiredScopes,
		RequiredPermissions: req.RequiredPermissions,
		RequireMFA:         req.RequireMfa,
		Context:            h.extractRequestContext(req.Metadata),
	}

	result, err := h.service.Authenticate(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Authentication failed", 
			zap.String("tenant_id", req.TenantId),
			zap.String("method", req.Method.String()),
			zap.Error(err))
		return h.buildAuthenticateErrorResponse(err), nil
	}

	response := &authpb.AuthenticateResponse{
		Status: &commonpb.Status{
			Code:    commonpb.StatusCode_STATUS_CODE_OK,
			Message: "Authentication successful",
		},
		Result:         h.convertAuthenticationResult(result),
		ProcessingTime: durationpb.New(time.Since(startTime)),
	}

	h.logger.Info("Authentication successful",
		zap.String("tenant_id", req.TenantId),
		zap.String("method", req.Method.String()),
		zap.String("principal_id", result.Principal.ID),
		zap.Duration("processing_time", time.Since(startTime)))

	return response, nil
}

func (h *AuthHandler) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest) (*authpb.ValidateTokenResponse, error) {
	startTime := time.Now()

	if err := h.validateTokenRequest(req); err != nil {
		return h.buildValidateTokenErrorResponse(err), nil
	}

	result, err := h.service.ValidateToken(ctx, req.Token, req.TokenType, req.RequiredScopes, req.RequiredPermissions)
	if err != nil {
		h.logger.Error("Token validation failed",
			zap.String("token_type", req.TokenType.String()),
			zap.Error(err))
		return h.buildValidateTokenErrorResponse(err), nil
	}

	response := &authpb.ValidateTokenResponse{
		Status: &commonpb.Status{
			Code:    commonpb.StatusCode_STATUS_CODE_OK,
			Message: "Token validation successful",
		},
		Result:         h.convertTokenValidationResult(result),
		ProcessingTime: durationpb.New(time.Since(startTime)),
	}

	return response, nil
}

func (h *AuthHandler) Authorize(ctx context.Context, req *authpb.AuthorizeRequest) (*authpb.AuthorizeResponse, error) {
	startTime := time.Now()

	if err := h.validateAuthorizeRequest(req); err != nil {
		return h.buildAuthorizeErrorResponse(err), nil
	}

	serviceReq := &service.AuthorizationRequest{
		PrincipalID:         req.PrincipalId,
		Resource:            req.Resource,
		Action:              req.Action,
		ResourceAttributes:  h.convertStructToMap(req.ResourceAttributes),
		Context:             h.extractRequestContext(req.Metadata),
		RequiredPermissions: req.RequiredPermissions,
		EnforceMFA:          req.EnforceMfa,
	}

	result, err := h.service.Authorize(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Authorization failed",
			zap.String("principal_id", req.PrincipalId),
			zap.String("resource", req.Resource),
			zap.String("action", req.Action),
			zap.Error(err))
		return h.buildAuthorizeErrorResponse(err), nil
	}

	response := &authpb.AuthorizeResponse{
		Status: &commonpb.Status{
			Code:    commonpb.StatusCode_STATUS_CODE_OK,
			Message: "Authorization evaluation completed",
		},
		Result:         h.convertAuthorizationResult(result),
		ProcessingTime: durationpb.New(time.Since(startTime)),
	}

	return response, nil
}

func (h *AuthHandler) RefreshToken(ctx context.Context, req *authpb.RefreshTokenRequest) (*authpb.RefreshTokenResponse, error) {
	startTime := time.Now()

	if err := h.validateRefreshTokenRequest(req); err != nil {
		return h.buildRefreshTokenErrorResponse(err), nil
	}

	duration := time.Hour
	if req.Duration != nil {
		duration = req.Duration.AsDuration()
	}

	result, err := h.service.RefreshToken(ctx, req.RefreshToken, req.Scopes, duration)
	if err != nil {
		h.logger.Error("Token refresh failed", zap.Error(err))
		return h.buildRefreshTokenErrorResponse(err), nil
	}

	response := &authpb.RefreshTokenResponse{
		Status: &commonpb.Status{
			Code:    commonpb.StatusCode_STATUS_CODE_OK,
			Message: "Token refresh successful",
		},
		Result:         h.convertTokenRefreshResult(result),
		ProcessingTime: durationpb.New(time.Since(startTime)),
	}

	return response, nil
}

func (h *AuthHandler) GetPermissions(ctx context.Context, req *authpb.GetPermissionsRequest) (*authpb.GetPermissionsResponse, error) {
	startTime := time.Now()

	if err := h.validateGetPermissionsRequest(req); err != nil {
		return h.buildGetPermissionsErrorResponse(err), nil
	}

	result, err := h.service.GetPermissions(ctx, req.PrincipalId, req.ResourceType, req.ResourceId)
	if err != nil {
		h.logger.Error("Get permissions failed",
			zap.String("principal_id", req.PrincipalId),
			zap.Error(err))
		return h.buildGetPermissionsErrorResponse(err), nil
	}

	response := &authpb.GetPermissionsResponse{
		Status: &commonpb.Status{
			Code:    commonpb.StatusCode_STATUS_CODE_OK,
			Message: "Permissions retrieved successfully",
		},
		Result:         h.convertPermissionsResult(result),
		ProcessingTime: durationpb.New(time.Since(startTime)),
	}

	return response, nil
}

func (h *AuthHandler) VerifyCertificate(ctx context.Context, req *authpb.VerifyCertificateRequest) (*authpb.VerifyCertificateResponse, error) {
	startTime := time.Now()

	if err := h.validateVerifyCertificateRequest(req); err != nil {
		return h.buildVerifyCertificateErrorResponse(err), nil
	}

	result, err := h.service.VerifyCertificate(ctx, req.Certificate, req.CertificateChain, req.CheckRevocation, req.CheckExpiration, req.RequiredKeyUsage)
	if err != nil {
		h.logger.Error("Certificate verification failed", zap.Error(err))
		return h.buildVerifyCertificateErrorResponse(err), nil
	}

	response := &authpb.VerifyCertificateResponse{
		Status: &commonpb.Status{
			Code:    commonpb.StatusCode_STATUS_CODE_OK,
			Message: "Certificate verification completed",
		},
		Result:         h.convertCertificateVerificationResult(result),
		ProcessingTime: durationpb.New(time.Since(startTime)),
	}

	return response, nil
}

func (h *AuthHandler) validateAuthenticateRequest(req *authpb.AuthenticateRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.TenantId == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "tenant ID is required")
	}

	if req.Method == authpb.AuthenticationMethod_AUTHENTICATION_METHOD_UNSPECIFIED {
		return errors.New(errors.ErrCodeInvalidRequest, "authentication method is required")
	}

	if req.Credentials == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "credentials are required")
	}

	return nil
}

func (h *AuthHandler) validateTokenRequest(req *authpb.ValidateTokenRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.Token == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "token is required")
	}

	return nil
}

func (h *AuthHandler) validateAuthorizeRequest(req *authpb.AuthorizeRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.PrincipalId == "" {
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

func (h *AuthHandler) validateRefreshTokenRequest(req *authpb.RefreshTokenRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.RefreshToken == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "refresh token is required")
	}

	return nil
}

func (h *AuthHandler) validateGetPermissionsRequest(req *authpb.GetPermissionsRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.PrincipalId == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "principal ID is required")
	}

	return nil
}

func (h *AuthHandler) validateVerifyCertificateRequest(req *authpb.VerifyCertificateRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.Certificate == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "certificate is required")
	}

	return nil
}

func (h *AuthHandler) extractCredentials(req *authpb.AuthenticateRequest) (interface{}, error) {
	switch req.Method {
	case authpb.AuthenticationMethod_AUTHENTICATION_METHOD_API_KEY:
		if apiKeyCreds := req.GetApiKeyCredentials(); apiKeyCreds != nil {
			return apiKeyCreds, nil
		}
		return nil, errors.New(errors.ErrCodeInvalidRequest, "API key credentials required")

	case authpb.AuthenticationMethod_AUTHENTICATION_METHOD_JWT:
		if jwtCreds := req.GetJwtCredentials(); jwtCreds != nil {
			return jwtCreds, nil
		}
		return nil, errors.New(errors.ErrCodeInvalidRequest, "JWT credentials required")

	case authpb.AuthenticationMethod_AUTHENTICATION_METHOD_BASIC:
		if basicCreds := req.GetBasicCredentials(); basicCreds != nil {
			return basicCreds, nil
		}
		return nil, errors.New(errors.ErrCodeInvalidRequest, "basic credentials required")

	case authpb.AuthenticationMethod_AUTHENTICATION_METHOD_MTLS:
		if mtlsCreds := req.GetMtlsCredentials(); mtlsCreds != nil {
			return mtlsCreds, nil
		}
		return nil, errors.New(errors.ErrCodeInvalidRequest, "mTLS credentials required")

	case authpb.AuthenticationMethod_AUTHENTICATION_METHOD_OAUTH2:
		if oauth2Creds := req.GetOauth2Credentials(); oauth2Creds != nil {
			return oauth2Creds, nil
		}
		return nil, errors.New(errors.ErrCodeInvalidRequest, "OAuth2 credentials required")

	case authpb.AuthenticationMethod_AUTHENTICATION_METHOD_SAML:
		if samlCreds := req.GetSamlCredentials(); samlCreds != nil {
			return samlCreds, nil
		}
		return nil, errors.New(errors.ErrCodeInvalidRequest, "SAML credentials required")

	case authpb.AuthenticationMethod_AUTHENTICATION_METHOD_OIDC:
		if oidcCreds := req.GetOidcCredentials(); oidcCreds != nil {
			return oidcCreds, nil
		}
		return nil, errors.New(errors.ErrCodeInvalidRequest, "OIDC credentials required")

	default:
		return nil, errors.New(errors.ErrCodeInvalidRequest, "unsupported authentication method")
	}
}

func (h *AuthHandler) extractClientIP(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
			return ips[0]
		}
		if ips := md.Get("x-real-ip"); len(ips) > 0 {
			return ips[0]
		}
	}
	
	if peer, ok := peer.FromContext(ctx); ok {
		return peer.Addr.String()
	}
	
	return ""
}

func (h *AuthHandler) extractUserAgent(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if agents := md.Get("user-agent"); len(agents) > 0 {
			return agents[0]
		}
	}
	return ""
}

func (h *AuthHandler) extractRequestContext(metadata map[string]string) map[string]interface{} {
	context := make(map[string]interface{})
	for key, value := range metadata {
		context[key] = value
	}
	return context
}

func (h *AuthHandler) convertStructToMap(s *structpb.Struct) map[string]interface{} {
	if s == nil {
		return make(map[string]interface{})
	}
	return s.AsMap()
}

func (h *AuthHandler) convertAuthenticationResult(result *service.AuthenticationResult) *authpb.AuthenticationResult {
	return &authpb.AuthenticationResult{
		Authenticated:   result.Authenticated,
		Principal:       h.convertPrincipal(result.Principal),
		Level:           result.Level,
		Permissions:     result.Permissions,
		Scopes:          result.Scopes,
		TokenInfo:       h.convertTokenInfo(result.TokenInfo),
		SessionInfo:     h.convertSessionInfo(result.SessionInfo),
		CertificateInfo: h.convertCertificateInfo(result.CertificateInfo),
		RiskScore:       result.RiskScore,
		RiskFactors:     result.RiskFactors,
		ExpiresAt:       h.convertTimeToTimestamp(result.ExpiresAt),
		Metadata:        h.convertMapToStruct(result.Metadata),
	}
}

func (h *AuthHandler) convertPrincipal(principal *service.Principal) *authpb.Principal {
	if principal == nil {
		return nil
	}

	return &authpb.Principal{
		Id:             principal.ID,
		Type:           principal.Type,
		Name:           principal.Name,
		Email:          principal.Email,
		TenantId:       principal.TenantID,
		OrganizationId: principal.OrganizationID,
		Roles:          principal.Roles,
		Groups:         principal.Groups,
		Attributes:     h.convertMapToStruct(principal.Attributes),
		CreatedAt:      timestamppb.New(principal.CreatedAt),
		LastLogin:      h.convertTimeToTimestamp(principal.LastLogin),
		IsActive:       principal.IsActive,
		MfaEnabled:     principal.MFAEnabled,
	}
}

func (h *AuthHandler) convertTokenInfo(tokenInfo *service.TokenInfo) *authpb.TokenInfo {
	if tokenInfo == nil {
		return nil
	}

	return &authpb.TokenInfo{
		TokenId:   tokenInfo.TokenID,
		Type:      tokenInfo.Type,
		Issuer:    tokenInfo.Issuer,
		Subject:   tokenInfo.Subject,
		Audience:  tokenInfo.Audience,
		IssuedAt:  timestamppb.New(tokenInfo.IssuedAt),
		ExpiresAt: timestamppb.New(tokenInfo.ExpiresAt),
		NotBefore: h.convertTimeToTimestamp(tokenInfo.NotBefore),
		Scopes:    tokenInfo.Scopes,
		Claims:    h.convertMapToStruct(tokenInfo.Claims),
		Jti:       tokenInfo.JTI,
	}
}

func (h *AuthHandler) convertSessionInfo(sessionInfo *service.SessionInfo) *authpb.SessionInfo {
	if sessionInfo == nil {
		return nil
	}

	return &authpb.SessionInfo{
		SessionId:    sessionInfo.SessionID,
		UserId:       sessionInfo.UserID,
		TenantId:     sessionInfo.TenantID,
		CreatedAt:    timestamppb.New(sessionInfo.CreatedAt),
		LastActivity: timestamppb.New(sessionInfo.LastActivity),
		ExpiresAt:    timestamppb.New(sessionInfo.ExpiresAt),
		IpAddress:    sessionInfo.IPAddress,
		UserAgent:    sessionInfo.UserAgent,
		IsActive:     sessionInfo.IsActive,
		Metadata:     h.convertMapToStruct(sessionInfo.Metadata),
	}
}

func (h *AuthHandler) convertCertificateInfo(certInfo *service.CertificateInfo) *authpb.CertificateInfo {
	if certInfo == nil {
		return nil
	}

	return &authpb.CertificateInfo{
		SerialNumber:       certInfo.SerialNumber,
		Subject:            certInfo.Subject,
		Issuer:             certInfo.Issuer,
		NotBefore:          timestamppb.New(certInfo.NotBefore),
		NotAfter:           timestamppb.New(certInfo.NotAfter),
		Fingerprint:        certInfo.Fingerprint,
		PublicKeyAlgorithm: certInfo.PublicKeyAlgorithm,
		SignatureAlgorithm: certInfo.SignatureAlgorithm,
		KeyUsage:           certInfo.KeyUsage,
		ExtendedKeyUsage:   certInfo.ExtendedKeyUsage,
		SubjectAltNames:    certInfo.SubjectAltNames,
		Status:             certInfo.Status,
		RevocationReason:   certInfo.RevocationReason,
		RevocationTime:     h.convertTimeToTimestamp(certInfo.RevocationTime),
	}
}

func (h *AuthHandler) convertTokenValidationResult(result *service.TokenValidationResult) *authpb.TokenValidationResult {
	return &authpb.TokenValidationResult{
		Valid:            result.Valid,
		TokenInfo:        h.convertTokenInfo(result.TokenInfo),
		Principal:        h.convertPrincipal(result.Principal),
		ValidationErrors: h.convertValidationErrors(result.ValidationErrors),
		RiskScore:        result.RiskScore,
		ValidatedAt:      timestamppb.New(result.ValidatedAt),
	}
}

func (h *AuthHandler) convertAuthorizationResult(result *service.AuthorizationResult) *authpb.AuthorizationResult {
	return &authpb.AuthorizationResult{
		Authorized:         result.Authorized,
		Decision:           result.Decision,
		GrantedPermissions: result.GrantedPermissions,
		DeniedPermissions:  result.DeniedPermissions,
		PolicyEvaluations:  h.convertPolicyEvaluations(result.PolicyEvaluations),
		Reason:             result.Reason,
		Obligations:        h.convertMapToStruct(result.Obligations),
		EvaluatedAt:        timestamppb.New(result.EvaluatedAt),
		Metadata:           h.convertMapToStruct(result.Metadata),
	}
}

func (h *AuthHandler) convertTokenRefreshResult(result *service.TokenRefreshResult) *authpb.TokenRefreshResult {
	return &authpb.TokenRefreshResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenInfo:    h.convertTokenInfo(result.TokenInfo),
		IssuedAt:     timestamppb.New(result.IssuedAt),
	}
}

func (h *AuthHandler) convertPermissionsResult(result *service.PermissionsResult) *authpb.PermissionsResult {
	return &authpb.PermissionsResult{
		Permissions: result.Permissions,
		Scopes:      result.Scopes,
		Roles:       h.convertRoleInfos(result.Roles),
		EvaluatedAt: timestamppb.New(result.EvaluatedAt),
		Metadata:    h.convertMapToStruct(result.Metadata),
	}
}

func (h *AuthHandler) convertCertificateVerificationResult(result *service.CertificateVerificationResult) *authpb.CertificateVerificationResult {
	return &authpb.CertificateVerificationResult{
		Valid:              result.Valid,
		CertificateInfo:    h.convertCertificateInfo(result.CertificateInfo),
		ValidationErrors:   result.ValidationErrors,
		TrustChainStatus:   result.TrustChainStatus,
		VerifiedAt:         timestamppb.New(result.VerifiedAt),
	}
}

func (h *AuthHandler) convertValidationErrors(errors []service.ValidationError) []*authpb.ValidationError {
	result := make([]*authpb.ValidationError, len(errors))
	for i, err := range errors {
		result[i] = &authpb.ValidationError{
			Code:     err.Code,
			Message:  err.Message,
			Field:    err.Field,
			Severity: h.convertErrorSeverity(err.Severity),
		}
	}
	return result
}

func (h *AuthHandler) convertPolicyEvaluations(evaluations []service.PolicyEvaluation) []*authpb.PolicyEvaluation {
	result := make([]*authpb.PolicyEvaluation, len(evaluations))
	for i, eval := range evaluations {
		result[i] = &authpb.PolicyEvaluation{
			PolicyId:   eval.PolicyID,
			PolicyName: eval.PolicyName,
			Decision:   eval.Decision,
			Reason:     eval.Reason,
			Confidence: eval.Confidence,
			Context:    h.convertMapToStruct(eval.Context),
		}
	}
	return result
}

func (h *AuthHandler) convertRoleInfos(roles []service.RoleInfo) []*authpb.RoleInfo {
	result := make([]*authpb.RoleInfo, len(roles))
	for i, role := range roles {
		result[i] = &authpb.RoleInfo{
			RoleId:      role.RoleID,
			Name:        role.Name,
			Description: role.Description,
			Permissions: role.Permissions,
			Scopes:      role.Scopes,
			Metadata:    h.convertMapToStruct(role.Metadata),
		}
	}
	return result
}

func (h *AuthHandler) convertErrorSeverity(severity errors.ErrorSeverity) authpb.ErrorSeverity {
	switch severity {
	case errors.SeverityLow:
		return authpb.ErrorSeverity_ERROR_SEVERITY_LOW
	case errors.SeverityMedium:
		return authpb.ErrorSeverity_ERROR_SEVERITY_MEDIUM
	case errors.SeverityHigh:
		return authpb.ErrorSeverity_ERROR_SEVERITY_HIGH
	case errors.SeverityCritical:
		return authpb.ErrorSeverity_ERROR_SEVERITY_CRITICAL
	default:
		return authpb.ErrorSeverity_ERROR_SEVERITY_UNSPECIFIED
	}
}

func (h *AuthHandler) convertTimeToTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *AuthHandler) convertMapToStruct(m map[string]interface{}) *structpb.Struct {
	if m == nil {
		return nil
	}
	
	s, err := structpb.NewStruct(m)
	if err != nil {
		h.logger.Warn("Failed to convert map to struct", zap.Error(err))
		return nil
	}
	
	return s
}

func (h *AuthHandler) buildAuthenticateErrorResponse(err error) *authpb.AuthenticateResponse {
	return &authpb.AuthenticateResponse{
		Status: h.convertErrorToStatus(err),
		Result: &authpb.AuthenticationResult{
			Authenticated: false,
		},
	}
}

func (h *AuthHandler) buildValidateTokenErrorResponse(err error) *authpb.ValidateTokenResponse {
	return &authpb.ValidateTokenResponse{
		Status: h.convertErrorToStatus(err),
		Result: &authpb.TokenValidationResult{
			Valid: false,
		},
	}
}

func (h *AuthHandler) buildAuthorizeErrorResponse(err error) *authpb.AuthorizeResponse {
	return &authpb.AuthorizeResponse{
		Status: h.convertErrorToStatus(err),
		Result: &authpb.AuthorizationResult{
			Authorized: false,
			Decision:   "deny",
			Reason:     err.Error(),
		},
	}
}

func (h *AuthHandler) buildRefreshTokenErrorResponse(err error) *authpb.RefreshTokenResponse {
	return &authpb.RefreshTokenResponse{
		Status: h.convertErrorToStatus(err),
	}
}

func (h *AuthHandler) buildGetPermissionsErrorResponse(err error) *authpb.GetPermissionsResponse {
	return &authpb.GetPermissionsResponse{
		Status: h.convertErrorToStatus(err),
	}
}

func (h *AuthHandler) buildVerifyCertificateErrorResponse(err error) *authpb.VerifyCertificateResponse {
	return &authpb.VerifyCertificateResponse{
		Status: h.convertErrorToStatus(err),
		Result: &authpb.CertificateVerificationResult{
			Valid: false,
		},
	}
}

func (h *AuthHandler) convertErrorToStatus(err error) *commonpb.Status {
	if customErr, ok := err.(*errors.CustomError); ok {
		return &commonpb.Status{
			Code:    h.convertErrorCodeToStatusCode(customErr.Code),
			Message: customErr.Message,
			Details: customErr.Details,
		}
	}

	return &commonpb.Status{
		Code:    commonpb.StatusCode_STATUS_CODE_INTERNAL_ERROR,
		Message: err.Error(),
	}
}

func (h *AuthHandler) convertErrorCodeToStatusCode(code errors.ErrorCode) commonpb.StatusCode {
	switch code {
	case errors.ErrCodeInvalidRequest:
		return commonpb.StatusCode_STATUS_CODE_INVALID_ARGUMENT
	case errors.ErrCodeUnauthorized:
		return commonpb.StatusCode_STATUS_CODE_UNAUTHENTICATED
	case errors.ErrCodeForbidden:
		return commonpb.StatusCode_STATUS_CODE_PERMISSION_DENIED
	case errors.ErrCodeNotFound:
		return commonpb.StatusCode_STATUS_CODE_NOT_FOUND
	case errors.ErrCodeConflict:
		return commonpb.StatusCode_STATUS_CODE_ALREADY_EXISTS
	case errors.ErrCodeDatabaseError:
		return commonpb.StatusCode_STATUS_CODE_INTERNAL_ERROR
	case errors.ErrCodeConfigError:
		return commonpb.StatusCode_STATUS_CODE_INTERNAL_ERROR
	case errors.ErrCodeServiceUnavailable:
		return commonpb.StatusCode_STATUS_CODE_UNAVAILABLE
	default:
		return commonpb.StatusCode_STATUS_CODE_INTERNAL_ERROR
	}
}
