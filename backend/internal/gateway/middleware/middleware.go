package middleware

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	authpb "flamo/backend/pkg/api/proto/auth"
)

type MiddlewareManager struct {
	config       *config.Config
	logger       *zap.Logger
	authClient   authpb.AuthenticationServiceClient
	rateLimiters map[string]*utils.RateLimiter
	mu           sync.RWMutex
}

type AuthContext struct {
	TenantID        string
	UserID          string
	Principal       string
	Scopes          []string
	Claims          map[string]interface{}
	AuthMethod      string
	AuthLevel       string
	IsAuthenticated bool
	TokenExpiry     time.Time
}

type SecurityContext struct {
	ThreatLevel     string
	RiskScore       float64
	BlockedReasons  []string
	SecurityFlags   []string
	PIIDetected     bool
	ComplianceLevel string
}

type auditResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int64
}

func NewMiddlewareManager(cfg *config.Config, logger *zap.Logger, authClient authpb.AuthenticationServiceClient) *MiddlewareManager {
	return &MiddlewareManager{
		config:       cfg,
		logger:       logger,
		authClient:   authClient,
		rateLimiters: make(map[string]*utils.RateLimiter),
	}
}

func (m *MiddlewareManager) AuthenticationMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.isPublicEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			authContext, appErr := m.authenticateRequest(r)
			if appErr != nil {
				m.writeErrorResponse(w, appErr)
				return
			}

			ctx := context.WithValue(r.Context(), "auth_context", authContext)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareManager) RateLimitingMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := utils.GetClientIP(r)
			authContext := m.getAuthContext(r.Context())
			
			rateLimitKey := m.getRateLimitKey(clientIP, authContext)
			
			if !m.checkRateLimit(rateLimitKey) {
				retryAfter := m.getRetryAfter(rateLimitKey)
				appErr := errors.NewRateLimitError(retryAfter)
				m.writeErrorResponse(w, appErr)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *MiddlewareManager) SecurityMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			securityContext, appErr := m.performSecurityChecks(r)
			if appErr != nil {
				m.logSecurityEvent("request_blocked", appErr.Message, map[string]interface{}{
					"client_ip":    utils.GetClientIP(r),
					"path":         r.URL.Path,
					"user_agent":   r.Header.Get("User-Agent"),
					"threat_level": securityContext.ThreatLevel,
				})
				m.writeErrorResponse(w, appErr)
				return
			}

			ctx := context.WithValue(r.Context(), "security_context", securityContext)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareManager) AuditMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := utils.GenerateRequestID()
			startTime := time.Now()

			auditWriter := &auditResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			ctx := context.WithValue(r.Context(), "request_id", requestID)
			ctx = context.WithValue(ctx, "start_time", startTime)

			next.ServeHTTP(auditWriter, r.WithContext(ctx))

			m.logAuditEvent(r, auditWriter, startTime)
		})
	}
}

func (m *MiddlewareManager) TracingMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			traceID := r.Header.Get("X-Trace-ID")
			if traceID == "" {
				traceID = utils.GenerateTraceID()
			}

			spanID := utils.GenerateNonce(16)
			
			w.Header().Set("X-Trace-ID", traceID)
			w.Header().Set("X-Span-ID", spanID)

			ctx := context.WithValue(r.Context(), "trace_id", traceID)
			ctx = context.WithValue(ctx, "span_id", spanID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareManager) CompressionMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !m.shouldCompress(r) {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Vary", "Accept-Encoding")

			next.ServeHTTP(w, r)
		})
	}
}

func (m *MiddlewareManager) authenticateRequest(r *http.Request) (*AuthContext, *errors.AppError) {
	authToken := m.extractAuthToken(r)
	if authToken == "" {
		return nil, errors.NewUnauthorizedError("authentication token required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authReq := &authpb.AuthenticateRequest{
		Token: authToken,
	}

	resp, err := m.authClient.Authenticate(ctx, authReq)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeAuthenticationError, "authentication failed")
	}

	if !resp.Valid {
		return nil, errors.NewUnauthorizedError("invalid authentication token")
	}

	return &AuthContext{
		TenantID:        resp.TenantId,
		UserID:          resp.UserId,
		Principal:       resp.Principal,
		Scopes:          resp.Scopes,
		Claims:          resp.Claims,
		AuthMethod:      m.detectAuthMethod(r),
		AuthLevel:       "standard",
		IsAuthenticated: true,
		TokenExpiry:     time.Unix(resp.ExpiresAt, 0),
	}, nil
}

func (m *MiddlewareManager) performSecurityChecks(r *http.Request) (*SecurityContext, *errors.AppError) {
	securityContext := &SecurityContext{
		ThreatLevel:     "none",
		RiskScore:       0.0,
		BlockedReasons:  []string{},
		SecurityFlags:   []string{},
		PIIDetected:     false,
		ComplianceLevel: "standard",
	}

	if m.isBlockedIP(utils.GetClientIP(r)) {
		securityContext.ThreatLevel = "high"
		securityContext.BlockedReasons = append(securityContext.BlockedReasons, "blocked_ip")
		return securityContext, errors.NewSecurityError("blocked_ip", "IP address is blocked")
	}

	if m.isSuspiciousUserAgent(r.Header.Get("User-Agent")) {
		securityContext.ThreatLevel = "medium"
		securityContext.SecurityFlags = append(securityContext.SecurityFlags, "suspicious_user_agent")
	}

	if m.hasInvalidHeaders(r) {
		securityContext.ThreatLevel = "medium"
		securityContext.SecurityFlags = append(securityContext.SecurityFlags, "invalid_headers")
	}

	return securityContext, nil
}

func (m *MiddlewareManager) isPublicEndpoint(path string) bool {
	publicPaths := []string{
		"/api/v1/health",
		"/api/v1/status",
		"/metrics",
	}

	for _, publicPath := range publicPaths {
		if strings.HasPrefix(path, publicPath) {
			return true
		}
	}

	return false
}

func (m *MiddlewareManager) extractAuthToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}
	
	return ""
}

func (m *MiddlewareManager) detectAuthMethod(r *http.Request) string {
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return "jwt"
	}
	if r.Header.Get("X-API-Key") != "" {
		return "api_key"
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return "mtls"
	}
	return "unknown"
}

func (aw *auditResponseWriter) WriteHeader(statusCode int) {
	aw.statusCode = statusCode
	aw.ResponseWriter.WriteHeader(statusCode)
}

func (aw *auditResponseWriter) Write(data []byte) (int, error) {
	size, err := aw.ResponseWriter.Write(data)
	aw.size += int64(size)
	return size, err
}

func (m *MiddlewareManager) getAuthContext(ctx context.Context) *AuthContext {
	if authContext, ok := ctx.Value("auth_context").(*AuthContext); ok {
		return authContext
	}
	return nil
}

func (m *MiddlewareManager) getRateLimitKey(clientIP string, authContext *AuthContext) string {
	if authContext != nil && authContext.TenantID != "" {
		return "tenant:" + authContext.TenantID
	}
	return "ip:" + clientIP
}

func (m *MiddlewareManager) checkRateLimit(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	rateLimiter, exists := m.rateLimiters[key]
	if !exists {
		rateLimiter = utils.NewRateLimiter(100.0, 1000)
		m.rateLimiters[key] = rateLimiter
	}

	return rateLimiter.Allow()
}

func (m *MiddlewareManager) getRetryAfter(key string) time.Duration {
	if strings.HasPrefix(key, "tenant:") {
		return time.Minute
	}
	return 30 * time.Second
}

func (m *MiddlewareManager) isBlockedIP(ip string) bool {
	blockedIPs := []string{
		"192.168.1.100",
		"10.0.0.50",
	}

	return utils.Contains(blockedIPs, ip)
}

func (m *MiddlewareManager) isSuspiciousUserAgent(userAgent string) bool {
	suspiciousAgents := []string{
		"bot",
		"crawler",
		"scanner",
		"curl",
		"wget",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, suspicious := range suspiciousAgents {
		if strings.Contains(userAgentLower, suspicious) {
			return true
		}
	}

	return false
}

func (m *MiddlewareManager) hasInvalidHeaders(r *http.Request) bool {
	requiredHeaders := []string{
		"User-Agent",
		"Accept",
	}

	for _, header := range requiredHeaders {
		if r.Header.Get(header) == "" {
			return true
		}
	}

	contentType := r.Header.Get("Content-Type")
	if r.Method == "POST" || r.Method == "PUT" {
		if !strings.Contains(contentType, "application/json") {
			return true
		}
	}

	return false
}

func (m *MiddlewareManager) shouldCompress(r *http.Request) bool {
	acceptEncoding := r.Header.Get("Accept-Encoding")
	return strings.Contains(acceptEncoding, "gzip")
}

func (m *MiddlewareManager) logAuditEvent(r *http.Request, aw *auditResponseWriter, startTime time.Time) {
	duration := time.Since(startTime)
	authContext := m.getAuthContext(r.Context())

	auditData := map[string]interface{}{
		"request_id":     r.Context().Value("request_id"),
		"method":         r.Method,
		"path":           r.URL.Path,
		"client_ip":      utils.GetClientIP(r),
		"user_agent":     r.Header.Get("User-Agent"),
		"status_code":    aw.statusCode,
		"response_size":  aw.size,
		"duration_ms":    duration.Milliseconds(),
		"timestamp":      time.Now().UTC(),
	}

	if authContext != nil {
		auditData["tenant_id"] = authContext.TenantID
		auditData["user_id"] = authContext.UserID
		auditData["auth_method"] = authContext.AuthMethod
		auditData["authenticated"] = authContext.IsAuthenticated
	}

	if traceID := r.Context().Value("trace_id"); traceID != nil {
		auditData["trace_id"] = traceID
	}

	if spanID := r.Context().Value("span_id"); spanID != nil {
		auditData["span_id"] = spanID
	}

	m.logger.Info("Request audit", zap.Any("audit", auditData))
}

func (m *MiddlewareManager) logSecurityEvent(eventType, description string, metadata map[string]interface{}) {
	securityEvent := map[string]interface{}{
		"event_type":  eventType,
		"description": description,
		"timestamp":   time.Now().UTC(),
		"service":     "gateway",
		"metadata":    metadata,
	}

	m.logger.Warn("Security event", zap.Any("security_event", securityEvent))
}

func (m *MiddlewareManager) writeErrorResponse(w http.ResponseWriter, appErr *errors.AppError) {
	errorResponse := errors.CreateErrorResponse(
		appErr,
		appErr.RequestID,
		"",
		"",
		"",
		"",
	)

	statusCode := errors.GetHTTPStatus(appErr)
	utils.WriteJSONResponse(w, statusCode, errorResponse)
}

func (m *MiddlewareManager) GRPCAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if m.isPublicGRPCMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		authContext, err := m.authenticateGRPCRequest(ctx)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, "auth_context", authContext)
		return handler(ctx, req)
	}
}

func (m *MiddlewareManager) GRPCRateLimitInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		clientIP := m.getGRPCClientIP(ctx)
		authContext := m.getAuthContext(ctx)
		
		rateLimitKey := m.getRateLimitKey(clientIP, authContext)
		
		if !m.checkRateLimit(rateLimitKey) {
			return nil, errors.NewRateLimitError(time.Minute)
		}

		return handler(ctx, req)
	}
}

func (m *MiddlewareManager) GRPCSecurityInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		clientIP := m.getGRPCClientIP(ctx)
		
		if m.isBlockedIP(clientIP) {
			m.logSecurityEvent("grpc_request_blocked", "blocked IP address", map[string]interface{}{
				"client_ip": clientIP,
				"method":    info.FullMethod,
			})
			return nil, errors.NewSecurityError("blocked_ip", "IP address is blocked")
		}

		return handler(ctx, req)
	}
}

func (m *MiddlewareManager) GRPCAuditInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()
		requestID := utils.GenerateRequestID()
		
		ctx = context.WithValue(ctx, "request_id", requestID)
		ctx = context.WithValue(ctx, "start_time", startTime)

		resp, err := handler(ctx, req)

		m.logGRPCAuditEvent(ctx, info.FullMethod, req, resp, err, startTime)

		return resp, err
	}
}

func (m *MiddlewareManager) GRPCTracingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.New(nil)
		}

		traceID := m.getMetadataValue(md, "trace-id")
		if traceID == "" {
			traceID = utils.GenerateTraceID()
		}

		spanID := utils.GenerateNonce(16)

		ctx = context.WithValue(ctx, "trace_id", traceID)
		ctx = context.WithValue(ctx, "span_id", spanID)

		outgoingMD := metadata.Pairs(
			"trace-id", traceID,
			"span-id", spanID,
		)
		ctx = metadata.NewOutgoingContext(ctx, outgoingMD)

		return handler(ctx, req)
	}
}

func (m *MiddlewareManager) authenticateGRPCRequest(ctx context.Context) (*AuthContext, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.NewUnauthorizedError("missing metadata")
	}

	authToken := m.getMetadataValue(md, "authorization")
	if authToken == "" {
		authToken = m.getMetadataValue(md, "x-api-key")
	}

	if authToken == "" {
		return nil, errors.NewUnauthorizedError("authentication token required")
	}

	authCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authReq := &authpb.AuthenticateRequest{
		Token: authToken,
	}

	resp, err := m.authClient.Authenticate(authCtx, authReq)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeAuthenticationError, "authentication failed")
	}

	if !resp.Valid {
		return nil, errors.NewUnauthorizedError("invalid authentication token")
	}

	return &AuthContext{
		TenantID:        resp.TenantId,
		UserID:          resp.UserId,
		Principal:       resp.Principal,
		Scopes:          resp.Scopes,
		Claims:          resp.Claims,
		AuthMethod:      "grpc",
		AuthLevel:       "standard",
		IsAuthenticated: true,
		TokenExpiry:     time.Unix(resp.ExpiresAt, 0),
	}, nil
}

func (m *MiddlewareManager) isPublicGRPCMethod(method string) bool {
	publicMethods := []string{
		"/gateway.GatewayService/GetHealthStatus",
		"/gateway.GatewayService/GetMetrics",
	}

	return utils.Contains(publicMethods, method)
}

func (m *MiddlewareManager) getGRPCClientIP(ctx context.Context) string {
	if clientIP := ctx.Value("client_ip"); clientIP != nil {
		return clientIP.(string)
	}
	return "unknown"
}

func (m *MiddlewareManager) getMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func (m *MiddlewareManager) logGRPCAuditEvent(ctx context.Context, method string, req interface{}, resp interface{}, err error, startTime time.Time) {
	duration := time.Since(startTime)
	authContext := m.getAuthContext(ctx)

	auditData := map[string]interface{}{
		"request_id":  ctx.Value("request_id"),
		"method":      method,
		"duration_ms": duration.Milliseconds(),
		"timestamp":   time.Now().UTC(),
		"protocol":    "grpc",
	}

	if authContext != nil {
		auditData["tenant_id"] = authContext.TenantID
		auditData["user_id"] = authContext.UserID
		auditData["auth_method"] = authContext.AuthMethod
		auditData["authenticated"] = authContext.IsAuthenticated
	}

	if traceID := ctx.Value("trace_id"); traceID != nil {
		auditData["trace_id"] = traceID
	}

	if spanID := ctx.Value("span_id"); spanID != nil {
		auditData["span_id"] = spanID
	}

	if err != nil {
		auditData["error"] = err.Error()
		auditData["success"] = false
	} else {
		auditData["success"] = true
	}

	m.logger.Info("gRPC request audit", zap.Any("audit", auditData))
}

func (m *MiddlewareManager) CircuitBreakerMiddleware(serviceName string) mux.MiddlewareFunc {
	circuitBreaker := utils.NewCircuitBreaker(utils.CircuitBreakerConfig{
		MaxRequests:      100,
		Interval:         time.Minute,
		Timeout:          30 * time.Second,
		FailureThreshold: 0.6,
		SuccessThreshold: 5,
	})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := circuitBreaker.Execute(func() error {
				responseWriter := &circuitBreakerResponseWriter{
					ResponseWriter: w,
					statusCode:     http.StatusOK,
				}
				
				next.ServeHTTP(responseWriter, r)
				
				if responseWriter.statusCode >= 500 {
					return errors.New(errors.ErrCodeInternalError, "server error")
				}
				
				return nil
			})

			if err != nil {
				appErr := errors.New(errors.ErrCodeServiceUnavailable, "service temporarily unavailable")
				m.writeErrorResponse(w, appErr)
			}
		})
	}
}

func (m *MiddlewareManager) TimeoutMiddleware(timeout time.Duration) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			done := make(chan struct{})
			go func() {
				defer close(done)
				next.ServeHTTP(w, r.WithContext(ctx))
			}()

			select {
			case <-done:
				return
			case <-ctx.Done():
				if ctx.Err() == context.DeadlineExceeded {
					appErr := errors.NewTimeoutError("request")
					m.writeErrorResponse(w, appErr)
				}
			}
		})
	}
}

func (m *MiddlewareManager) ContentValidationMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" || r.Method == "PUT" {
				if err := m.validateRequestContent(r); err != nil {
					m.writeErrorResponse(w, err)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *MiddlewareManager) PIIDetectionMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" || r.Method == "PUT" {
				if hasPII, err := m.detectPIIInRequest(r); err != nil {
					m.writeErrorResponse(w, err)
					return
				} else if hasPII {
					m.logSecurityEvent("pii_detected", "PII detected in request", map[string]interface{}{
						"path":      r.URL.Path,
						"client_ip": utils.GetClientIP(r),
					})

					ctx := context.WithValue(r.Context(), "pii_detected", true)
					r = r.WithContext(ctx)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *MiddlewareManager) ComplianceMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authContext := m.getAuthContext(r.Context())
			if authContext == nil {
				next.ServeHTTP(w, r)
				return
			}

			complianceLevel := m.getTenantComplianceLevel(authContext.TenantID)
			
			if complianceLevel == "strict" {
				if err := m.enforceStrictCompliance(r); err != nil {
					m.writeErrorResponse(w, err)
					return
				}
			}

			ctx := context.WithValue(r.Context(), "compliance_level", complianceLevel)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareManager) CacheMiddleware() mux.MiddlewareFunc {
	cache := make(map[string]cacheEntry)
	cacheMutex := sync.RWMutex{}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				next.ServeHTTP(w, r)
				return
			}

			cacheKey := m.generateCacheKey(r)
			
			cacheMutex.RLock()
			entry, exists := cache[cacheKey]
			cacheMutex.RUnlock()

			if exists && time.Since(entry.timestamp) < 5*time.Minute {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Cache", "HIT")
				w.WriteHeader(entry.statusCode)
				w.Write(entry.data)
				return
			}

			cacheWriter := &cacheResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(cacheWriter, r)

			if cacheWriter.statusCode == http.StatusOK && len(cacheWriter.data) > 0 {
				cacheMutex.Lock()
				cache[cacheKey] = cacheEntry{
					data:       cacheWriter.data,
					statusCode: cacheWriter.statusCode,
					timestamp:  time.Now(),
				}
				cacheMutex.Unlock()
			}
		})
	}
}

func (m *MiddlewareManager) validateRequestContent(r *http.Request) *errors.AppError {
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return errors.New(errors.ErrCodeUnsupportedMedia, "content-type must be application/json")
	}

	if r.ContentLength > 10*1024*1024 {
		return errors.New(errors.ErrCodePayloadTooLarge, "request body too large")
	}

	if r.ContentLength == 0 {
		return errors.New(errors.ErrCodeInvalidRequest, "request body is required")
	}

	return nil
}

func (m *MiddlewareManager) detectPIIInRequest(r *http.Request) (bool, *errors.AppError) {
	body := make([]byte, r.ContentLength)
	if _, err := r.Body.Read(body); err != nil {
		return false, errors.Wrap(err, errors.ErrCodeInternalError, "failed to read request body")
	}

	piiResult := utils.DetectPII(string(body))
	return piiResult.HasPII, nil
}

func (m *MiddlewareManager) getTenantComplianceLevel(tenantID string) string {
	complianceLevels := map[string]string{
		"tenant-1": "strict",
		"tenant-2": "standard",
		"tenant-3": "basic",
	}

	if level, exists := complianceLevels[tenantID]; exists {
		return level
	}

	return "standard"
}

func (m *MiddlewareManager) enforceStrictCompliance(r *http.Request) *errors.AppError {
	if r.Header.Get("X-Compliance-Token") == "" {
		return errors.NewComplianceError("missing_compliance_token", "compliance token required for strict mode")
	}

	if !m.isSecureConnection(r) {
		return errors.NewComplianceError("insecure_connection", "HTTPS required for strict compliance")
	}

	return nil
}

func (m *MiddlewareManager) isSecureConnection(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func (m *MiddlewareManager) generateCacheKey(r *http.Request) string {
	authContext := m.getAuthContext(r.Context())
	key := r.URL.Path + "?" + r.URL.RawQuery
	
	if authContext != nil {
		key += "|tenant:" + authContext.TenantID
	}

	return utils.HashSHA256(key)
}

type circuitBreakerResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (cbw *circuitBreakerResponseWriter) WriteHeader(statusCode int) {
	cbw.statusCode = statusCode
	cbw.ResponseWriter.WriteHeader(statusCode)
}

type cacheEntry struct {
	data       []byte
	statusCode int
	timestamp  time.Time
}

type cacheResponseWriter struct {
	http.ResponseWriter
	data       []byte
	statusCode int
}

func (cw *cacheResponseWriter) WriteHeader(statusCode int) {
	cw.statusCode = statusCode
	cw.ResponseWriter.WriteHeader(statusCode)
}

func (cw *cacheResponseWriter) Write(data []byte) (int, error) {
	cw.data = append(cw.data, data...)
	return cw.ResponseWriter.Write(data)
}

func (m *MiddlewareManager) MetricsMiddleware() mux.MiddlewareFunc {
	requestCount := make(map[string]int64)
	requestDuration := make(map[string]time.Duration)
	metricsMutex := sync.RWMutex{}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()
			
			metricsWriter := &metricsResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(metricsWriter, r)

			duration := time.Since(startTime)
			endpoint := r.Method + " " + r.URL.Path

			metricsMutex.Lock()
			requestCount[endpoint]++
			requestDuration[endpoint] = (requestDuration[endpoint] + duration) / 2
			metricsMutex.Unlock()

			m.logger.Debug("Request metrics",
				zap.String("endpoint", endpoint),
				zap.Int("status_code", metricsWriter.statusCode),
				zap.Duration("duration", duration),
			)
		})
	}
}

type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (mw *metricsResponseWriter) WriteHeader(statusCode int) {
	mw.statusCode = statusCode
	mw.ResponseWriter.WriteHeader(statusCode)
}

func (m *MiddlewareManager) RequestIDMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = utils.GenerateRequestID()
			}

			w.Header().Set("X-Request-ID", requestID)
			ctx := context.WithValue(r.Context(), "request_id", requestID)
			
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareManager) PanicRecoveryMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					m.logger.Error("Panic recovered in middleware",
						zap.Any("panic", err),
						zap.String("path", r.URL.Path),
						zap.String("method", r.Method),
						zap.Stack("stack"))

					appErr := errors.New(errors.ErrCodeInternalError, "internal server error")
					m.writeErrorResponse(w, appErr)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

func (m *MiddlewareManager) CORSMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			utils.SetCORSHeaders(w,
				m.config.Security.AllowedOrigins,
				[]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				[]string{"Content-Type", "Authorization", "X-API-Key", "X-Request-ID"},
			)

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *MiddlewareManager) RequestSizeMiddleware(maxSize int64) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxSize {
				appErr := errors.New(errors.ErrCodePayloadTooLarge, 
					"request body exceeds maximum size limit")
				m.writeErrorResponse(w, appErr)
				return
			}

			r.Body = http.MaxBytesReader(w, r.Body, maxSize)
			next.ServeHTTP(w, r)
		})
	}
}

func (m *MiddlewareManager) HeaderValidationMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := m.validateHeaders(r); err != nil {
				m.writeErrorResponse(w, err)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *MiddlewareManager) validateHeaders(r *http.Request) *errors.AppError {
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "User-Agent header is required")
	}

	if len(userAgent) > 500 {
		return errors.New(errors.ErrCodeInvalidRequest, "User-Agent header too long")
	}

	contentType := r.Header.Get("Content-Type")
	if r.Method == "POST" || r.Method == "PUT" {
		if !strings.Contains(contentType, "application/json") {
			return errors.New(errors.ErrCodeUnsupportedMedia, "Content-Type must be application/json")
		}
	}

	accept := r.Header.Get("Accept")
	if accept != "" && !strings.Contains(accept, "application/json") && !strings.Contains(accept, "*/*") {
		return errors.New(errors.ErrCodeNotAcceptable, "Accept header must include application/json")
	}

	return nil
}

func (m *MiddlewareManager) GRPCStreamingInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		
		if !m.isPublicGRPCMethod(info.FullMethod) {
			authContext, err := m.authenticateGRPCRequest(ctx)
			if err != nil {
				return err
			}
			ctx = context.WithValue(ctx, "auth_context", authContext)
		}

		requestID := utils.GenerateRequestID()
		traceID := utils.GenerateTraceID()
		
		ctx = context.WithValue(ctx, "request_id", requestID)
		ctx = context.WithValue(ctx, "trace_id", traceID)

		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		startTime := time.Now()
		err := handler(srv, wrappedStream)
		duration := time.Since(startTime)

		m.logger.Info("gRPC streaming request",
			zap.String("method", info.FullMethod),
			zap.String("request_id", requestID),
			zap.String("trace_id", traceID),
			zap.Duration("duration", duration),
			zap.Bool("success", err == nil),
		)

		return err
	}
}

func (m *MiddlewareManager) CreateMiddlewareChain() []mux.MiddlewareFunc {
	return []mux.MiddlewareFunc{
		m.PanicRecoveryMiddleware(),
		m.RequestIDMiddleware(),
		m.TracingMiddleware(),
		m.CORSMiddleware(),
		m.HeaderValidationMiddleware(),
		m.RequestSizeMiddleware(10 * 1024 * 1024),
		m.SecurityMiddleware(),
		m.RateLimitingMiddleware(),
		m.AuthenticationMiddleware(),
		m.AuthorizationMiddleware(),
		m.PIIDetectionMiddleware(),
		m.ComplianceMiddleware(),
		m.AuditMiddleware(),
		m.MetricsMiddleware(),
		m.CompressionMiddleware(),
		m.CacheMiddleware(),
	}
}

func (m *MiddlewareManager) CreateGRPCInterceptors() ([]grpc.UnaryServerInterceptor, []grpc.StreamServerInterceptor) {
	unaryInterceptors := []grpc.UnaryServerInterceptor{
		m.GRPCTracingInterceptor(),
		m.GRPCSecurityInterceptor(),
		m.GRPCRateLimitInterceptor(),
		m.GRPCAuthInterceptor(),
		m.GRPCAuditInterceptor(),
	}

	streamInterceptors := []grpc.StreamServerInterceptor{
		m.GRPCStreamingInterceptor(),
	}

	return unaryInterceptors, streamInterceptors
}

func (m *MiddlewareManager) GetRateLimitStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]interface{})
	for key, limiter := range m.rateLimiters {
		status[key] = map[string]interface{}{
			"tokens_available": limiter.GetTokens(),
			"capacity":         limiter.GetCapacity(),
			"rate":             limiter.GetRate(),
		}
	}

	return status
}

func (m *MiddlewareManager) ResetRateLimiter(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limiter, exists := m.rateLimiters[key]; exists {
		limiter.Reset()
	}
}

func (m *MiddlewareManager) ClearExpiredRateLimiters() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, limiter := range m.rateLimiters {
		if limiter.IsExpired() {
			delete(m.rateLimiters, key)
		}
	}
}

func (m *MiddlewareManager) GetSecurityMetrics() map[string]interface{} {
	return map[string]interface{}{
		"blocked_requests":     m.getBlockedRequestCount(),
		"suspicious_requests":  m.getSuspiciousRequestCount(),
		"pii_detections":       m.getPIIDetectionCount(),
		"compliance_violations": m.getComplianceViolationCount(),
	}
}

func (m *MiddlewareManager) getBlockedRequestCount() int64 {
	return 0
}

func (m *MiddlewareManager) getSuspiciousRequestCount() int64 {
	return 0
}

func (m *MiddlewareManager) getPIIDetectionCount() int64 {
	return 0
}

func (m *MiddlewareManager) getComplianceViolationCount() int64 {
	return 0
}

func (m *MiddlewareManager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down middleware manager")

	m.mu.Lock()
	defer m.mu.Unlock()

	for key := range m.rateLimiters {
		delete(m.rateLimiters, key)
	}

	m.logger.Info("Middleware manager shutdown completed")
	return nil
}

func (m *MiddlewareManager) HealthCheck() error {
	if m.config == nil {
		return errors.New(errors.ErrCodeConfigError, "configuration not available")
	}

	if m.logger == nil {
		return errors.New(errors.ErrCodeInternalError, "logger not available")
	}

	if m.authClient == nil {
		return errors.New(errors.ErrCodeInternalError, "auth client not available")
	}

	return nil
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

func ValidateMiddlewareConfig(cfg *config.Config) error {
	if len(cfg.Security.AllowedOrigins) == 0 {
		return errors.New(errors.ErrCodeConfigError, "no allowed origins configured")
	}

	if cfg.Gateway.RequestTimeout <= 0 {
		return errors.New(errors.ErrCodeConfigError, "invalid request timeout")
	}

	if cfg.Gateway.MaxConcurrentRequests <= 0 {
		return errors.New(errors.ErrCodeConfigError, "invalid max concurrent requests")
	}

	return nil
}

func NewSecurityContext() *SecurityContext {
	return &SecurityContext{
		ThreatLevel:     "none",
		RiskScore:       0.0,
		BlockedReasons:  []string{},
		SecurityFlags:   []string{},
		PIIDetected:     false,
		ComplianceLevel: "standard",
	}
}

func NewAuthContext() *AuthContext {
	return &AuthContext{
		Claims:          make(map[string]interface{}),
		Scopes:          []string{},
		IsAuthenticated: false,
		AuthLevel:       "none",
	}
}

func (m *MiddlewareManager) isAuthorized(authContext *AuthContext, r *http.Request) bool {
	if !authContext.IsAuthenticated {
		return false
	}

	requiredScopes := m.getRequiredScopes(r.URL.Path, r.Method)
	for _, required := range requiredScopes {
		if !utils.Contains(authContext.Scopes, required) {
			return false
		}
	}

	return true
}

func (m *MiddlewareManager) getRequiredScopes(path, method string) []string {
	scopeMap := map[string][]string{
		"POST /api/v1/ai/chat":       {"ai:chat"},
		"POST /api/v1/ai/completion": {"ai:completion"},
		"POST /api/v1/ai/batch":      {"ai:batch"},
		"GET /api/v1/tenant/*/quota": {"tenant:read"},
	}

	key := method + " " + path
	if scopes, exists := scopeMap[key]; exists {
		return scopes
	}

	return []string{}
}
