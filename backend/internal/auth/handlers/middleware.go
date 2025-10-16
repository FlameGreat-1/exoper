package handlers

import (
	"context"
	"strings"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"flamo/backend/internal/auth/service"
	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/errors"
	authpb "flamo/backend/pkg/api/proto/auth"
)

type AuthMiddleware struct {
	service *service.AuthService
	config  *config.Config
	logger  *zap.Logger
}

func NewAuthMiddleware(authService *service.AuthService, cfg *config.Config, logger *zap.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		service: authService,
		config:  cfg,
		logger:  logger,
	}
}

func (m *AuthMiddleware) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()

		if m.isPublicEndpoint(info.FullMethod) {
			return handler(ctx, req)
		}

		authCtx, err := m.authenticateRequest(ctx, info.FullMethod)
		if err != nil {
			m.logAuthenticationFailure(info.FullMethod, err, time.Since(startTime))
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		if err := m.authorizeRequest(authCtx, info.FullMethod, req); err != nil {
			m.logAuthorizationFailure(info.FullMethod, err, time.Since(startTime))
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}

		enrichedCtx := m.enrichContext(authCtx)
		
		resp, err := handler(enrichedCtx, req)
		
		m.logRequestCompletion(info.FullMethod, err, time.Since(startTime))
		
		return resp, err
	}
}

func (m *AuthMiddleware) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		startTime := time.Now()

		if m.isPublicEndpoint(info.FullMethod) {
			return handler(srv, stream)
		}

		authCtx, err := m.authenticateRequest(stream.Context(), info.FullMethod)
		if err != nil {
			m.logAuthenticationFailure(info.FullMethod, err, time.Since(startTime))
			return status.Error(codes.Unauthenticated, err.Error())
		}

		if err := m.authorizeStreamRequest(authCtx, info.FullMethod); err != nil {
			m.logAuthorizationFailure(info.FullMethod, err, time.Since(startTime))
			return status.Error(codes.PermissionDenied, err.Error())
		}

		enrichedCtx := m.enrichContext(authCtx)
		wrappedStream := &wrappedServerStream{
			ServerStream: stream,
			ctx:          enrichedCtx,
		}

		err = handler(srv, wrappedStream)
		
		m.logRequestCompletion(info.FullMethod, err, time.Since(startTime))
		
		return err
	}
}

func (m *AuthMiddleware) isPublicEndpoint(method string) bool {
	publicEndpoints := []string{
		"/auth.AuthenticationService/Authenticate",
		"/auth.AuthenticationService/RefreshToken",
		"/auth.AuthenticationService/VerifyCertificate",
	}

	for _, endpoint := range publicEndpoints {
		if method == endpoint {
			return true
		}
	}

	return false
}

func (m *AuthMiddleware) authenticateRequest(ctx context.Context, method string) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New(errors.ErrCodeUnauthorized, "missing metadata")
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return nil, errors.New(errors.ErrCodeUnauthorized, "missing authorization header")
	}

	token := strings.TrimPrefix(authHeader[0], "Bearer ")
	if token == authHeader[0] {
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid authorization header format")
	}

	result, err := m.service.ValidateToken(ctx, token, authpb.TokenType_TOKEN_TYPE_ACCESS, []string{}, []string{})
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeUnauthorized, "token validation failed")
	}

	if !result.Valid {
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid token")
	}

	authCtx := context.WithValue(ctx, "principal", result.Principal)
	authCtx = context.WithValue(authCtx, "token_info", result.TokenInfo)
	authCtx = context.WithValue(authCtx, "risk_score", result.RiskScore)

	return authCtx, nil
}

func (m *AuthMiddleware) authorizeRequest(ctx context.Context, method string, req interface{}) error {
	principal := ctx.Value("principal").(*service.Principal)
	if principal == nil {
		return errors.New(errors.ErrCodeForbidden, "no principal found in context")
	}

	resource, action := m.extractResourceAndAction(method)
	requiredPermissions := m.getRequiredPermissions(method)

	authReq := &service.AuthorizationRequest{
		PrincipalID:         principal.ID,
		Resource:            resource,
		Action:              action,
		RequiredPermissions: requiredPermissions,
		EnforceMFA:          m.requiresMFA(method),
		Context:             m.extractRequestContext(req),
	}

	result, err := m.service.Authorize(ctx, authReq)
	if err != nil {
		return err
	}

	if !result.Authorized {
		return errors.New(errors.ErrCodeForbidden, result.Reason)
	}

	return nil
}

func (m *AuthMiddleware) authorizeStreamRequest(ctx context.Context, method string) error {
	principal := ctx.Value("principal").(*service.Principal)
	if principal == nil {
		return errors.New(errors.ErrCodeForbidden, "no principal found in context")
	}

	resource, action := m.extractResourceAndAction(method)
	requiredPermissions := m.getRequiredPermissions(method)

	authReq := &service.AuthorizationRequest{
		PrincipalID:         principal.ID,
		Resource:            resource,
		Action:              action,
		RequiredPermissions: requiredPermissions,
		EnforceMFA:          m.requiresMFA(method),
		Context:             make(map[string]interface{}),
	}

	result, err := m.service.Authorize(ctx, authReq)
	if err != nil {
		return err
	}

	if !result.Authorized {
		return errors.New(errors.ErrCodeForbidden, result.Reason)
	}

	return nil
}

func (m *AuthMiddleware) extractResourceAndAction(method string) (string, string) {
	parts := strings.Split(method, "/")
	if len(parts) < 3 {
		return "unknown", "unknown"
	}

	service := parts[1]
	action := parts[2]

	switch service {
	case "auth.AuthenticationService":
		return "authentication", action
	case "auth.APIKeyService":
		return "api_key", action
	case "auth.SessionService":
		return "session", action
	default:
		return service, action
	}
}

func (m *AuthMiddleware) getRequiredPermissions(method string) []string {
	permissionMap := map[string][]string{
		"/auth.AuthenticationService/ValidateToken":     {"auth:token:validate"},
		"/auth.AuthenticationService/Authorize":         {"auth:authorize"},
		"/auth.AuthenticationService/GetPermissions":    {"auth:permissions:read"},
		"/auth.APIKeyService/CreateAPIKey":               {"auth:api_key:create"},
		"/auth.APIKeyService/RevokeAPIKey":               {"auth:api_key:revoke"},
		"/auth.SessionService/CreateSession":             {"auth:session:create"},
		"/auth.SessionService/ValidateSession":           {"auth:session:validate"},
		"/auth.SessionService/RevokeSession":             {"auth:session:revoke"},
	}

	if permissions, exists := permissionMap[method]; exists {
		return permissions
	}

	return []string{}
}

func (m *AuthMiddleware) requiresMFA(method string) bool {
	mfaRequiredMethods := []string{
		"/auth.APIKeyService/CreateAPIKey",
		"/auth.APIKeyService/RevokeAPIKey",
	}

	for _, mfaMethod := range mfaRequiredMethods {
		if method == mfaMethod {
			return true
		}
	}

	return false
}

func (m *AuthMiddleware) extractRequestContext(req interface{}) map[string]interface{} {
	context := make(map[string]interface{})
	
	switch r := req.(type) {
	case *authpb.AuthorizeRequest:
		context["resource"] = r.Resource
		context["action"] = r.Action
	case *authpb.CreateAPIKeyRequest:
		context["tenant_id"] = r.TenantId
		context["key_name"] = r.Name
	case *authpb.CreateSessionRequest:
		context["user_id"] = r.UserId
		context["tenant_id"] = r.TenantId
	}

	return context
}

func (m *AuthMiddleware) enrichContext(ctx context.Context) context.Context {
	enrichedCtx := context.WithValue(ctx, "request_id", generateRequestID())
	enrichedCtx = context.WithValue(enrichedCtx, "timestamp", time.Now().UTC())
	
	return enrichedCtx
}

func (m *AuthMiddleware) logAuthenticationFailure(method string, err error, duration time.Duration) {
	m.logger.Warn("Authentication failed",
		zap.String("method", method),
		zap.Error(err),
		zap.Duration("duration", duration))
}

func (m *AuthMiddleware) logAuthorizationFailure(method string, err error, duration time.Duration) {
	m.logger.Warn("Authorization failed",
		zap.String("method", method),
		zap.Error(err),
		zap.Duration("duration", duration))
}

func (m *AuthMiddleware) logRequestCompletion(method string, err error, duration time.Duration) {
	if err != nil {
		m.logger.Error("Request failed",
			zap.String("method", method),
			zap.Error(err),
			zap.Duration("duration", duration))
	} else {
		m.logger.Info("Request completed",
			zap.String("method", method),
			zap.Duration("duration", duration))
	}
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

func generateRequestID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
