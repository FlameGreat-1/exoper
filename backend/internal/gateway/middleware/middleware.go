package middleware

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	commonpb "flamo/backend/pkg/api/proto/common"
	authpb "flamo/backend/pkg/api/proto/auth"
	"flamo/backend/pkg/api/proto/models/request"
	"flamo/backend/pkg/api/proto/models/response"
	"flamo/backend/pkg/api/proto/models/tenant"
)

type MiddlewareManager struct {
	config       *config.Config
	logger       *zap.Logger
	authClient   authpb.AuthenticationServiceClient
	rateLimiters map[string]*utils.RateLimiter
	tenantCache  map[string]*tenant.Tenant
	mu           sync.RWMutex
}

type auditResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int64
}

type circuitBreakerResponseWriter struct {
	http.ResponseWriter
	statusCode int
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

type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func NewMiddlewareManager(cfg *config.Config, logger *zap.Logger, authClient authpb.AuthenticationServiceClient) *MiddlewareManager {
	return &MiddlewareManager{
		config:       cfg,
		logger:       logger,
		authClient:   authClient,
		rateLimiters: make(map[string]*utils.RateLimiter),
		tenantCache:  make(map[string]*tenant.Tenant),
	}
}

func (m *MiddlewareManager) AuthenticationMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.isPublicEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			securityContext, appErr := m.authenticateRequest(r)
			if appErr != nil {
				m.writeErrorResponse(w, appErr)
				return
			}

			ctx := context.WithValue(r.Context(), "security_context", securityContext)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareManager) RateLimitingMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientInfo := request.ExtractClientInfo(r)
			securityContext := m.getSecurityContext(r.Context())
			
			rateLimitKey := m.getRateLimitKey(clientInfo.IPAddress, securityContext)
			
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
			threatContext, appErr := m.performSecurityChecks(r)
			if appErr != nil {
				clientInfo := request.ExtractClientInfo(r)
				m.logSecurityEvent("request_blocked", appErr.Message, map[string]interface{}{
					"client_ip":    clientInfo.IPAddress,
					"path":         r.URL.Path,
					"user_agent":   clientInfo.UserAgent,
					"threat_level": threatContext.ThreatLevel,
				})
				m.writeErrorResponse(w, appErr)
				return
			}

			ctx := context.WithValue(r.Context(), "threat_context", threatContext)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareManager) AuditMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := uuid.New().String()
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
				traceID = uuid.New().String()
			}

			spanID := uuid.New().String()
			
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

func (m *MiddlewareManager) AuthorizationMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.isPublicEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			securityContext := m.getSecurityContext(r.Context())
			if securityContext == nil {
				m.writeErrorResponse(w, errors.NewUnauthorizedError("authentication required"))
				return
			}

			if !m.isAuthorized(securityContext, r) {
				m.writeErrorResponse(w, errors.NewForbiddenError("insufficient permissions"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *MiddlewareManager) authenticateRequest(r *http.Request) (*request.SecurityContext, *errors.AppError) {
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

	securityContext := &request.SecurityContext{
		SessionToken:         authToken,
		AuthenticationMethod: m.detectAuthMethod(r),
		AuthenticationLevel:  "standard",
		UserID:               resp.UserId,
		TenantID:             resp.TenantId,
		Permissions:          resp.Scopes,
		SessionExpiry:        time.Unix(resp.ExpiresAt, 0),
		MFAVerified:          false,
		DeviceFingerprint:    "",
	}

	return securityContext, nil
}

func (m *MiddlewareManager) performSecurityChecks(r *http.Request) (*commonpb.ThreatDetection, *errors.AppError) {
	clientInfo := request.ExtractClientInfo(r)
	
	threatDetection := &commonpb.ThreatDetection{
		ThreatType:  commonpb.ThreatType_THREAT_TYPE_NONE,
		Severity:    commonpb.Severity_SEVERITY_LOW,
		Confidence:  0.0,
		Description: "No threats detected",
		Mitigations: []string{},
	}

	if m.isBlockedIP(clientInfo.IPAddress) {
		threatDetection.ThreatType = commonpb.ThreatType_THREAT_TYPE_MALICIOUS_IP
		threatDetection.Severity = commonpb.Severity_SEVERITY_HIGH
		threatDetection.Description = "IP address is blocked"
		return threatDetection, errors.NewSecurityError("blocked_ip", "IP address is blocked")
	}

	if m.isSuspiciousUserAgent(clientInfo.UserAgent) {
		threatDetection.ThreatType = commonpb.ThreatType_THREAT_TYPE_SUSPICIOUS_ACTIVITY
		threatDetection.Severity = commonpb.Severity_SEVERITY_MEDIUM
		threatDetection.Description = "Suspicious user agent detected"
	}

	if m.hasInvalidHeaders(r) {
		threatDetection.ThreatType = commonpb.ThreatType_THREAT_TYPE_SUSPICIOUS_ACTIVITY
		threatDetection.Severity = commonpb.Severity_SEVERITY_MEDIUM
		threatDetection.Description = "Invalid headers detected"
	}

	return threatDetection, nil
}

func (m *MiddlewareManager) PIIDetectionMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" || r.Method == "PUT" {
				complianceContext, err := m.detectPIIInRequest(r)
				if err != nil {
					m.writeErrorResponse(w, err)
					return
				}
				
				if complianceContext.PIIDetected {
					clientInfo := request.ExtractClientInfo(r)
					m.logSecurityEvent("pii_detected", "PII detected in request", map[string]interface{}{
						"path":      r.URL.Path,
						"client_ip": clientInfo.IPAddress,
					})

					ctx := context.WithValue(r.Context(), "compliance_context", complianceContext)
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
			securityContext := m.getSecurityContext(r.Context())
			if securityContext == nil {
				next.ServeHTTP(w, r)
				return
			}

			tenantObj, err := m.getTenant(securityContext.TenantID)
			if err != nil {
				m.writeErrorResponse(w, err)
				return
			}

			if len(tenantObj.ComplianceConfig.Frameworks) > 0 {
				for _, framework := range tenantObj.ComplianceConfig.Frameworks {
					if framework == tenant.ComplianceSOC2 || framework == tenant.ComplianceHIPAA {
						if err := m.enforceStrictCompliance(r); err != nil {
							m.writeErrorResponse(w, err)
							return
						}
					}
				}
			}

			ctx := context.WithValue(r.Context(), "tenant", tenantObj)
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

func (m *MiddlewareManager) RequestIDMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
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
				[]string{"Content-Type", "Authorization", "X-API-Key", "X-Request-ID", "X-Tenant-ID"},
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

func (m *MiddlewareManager) GRPCAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if m.isPublicGRPCMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		securityContext, err := m.authenticateGRPCRequest(ctx)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, "security_context", securityContext)
		return handler(ctx, req)
	}
}

func (m *MiddlewareManager) GRPCRateLimitInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		clientIP := m.getGRPCClientIP(ctx)
		securityContext := m.getSecurityContext(ctx)
		
		rateLimitKey := m.getRateLimitKey(clientIP, securityContext)
		
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
		requestID := uuid.New().String()
		
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
			traceID = uuid.New().String()
		}

		spanID := uuid.New().String()

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

func (m *MiddlewareManager) GRPCStreamingInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		
		if !m.isPublicGRPCMethod(info.FullMethod) {
			securityContext, err := m.authenticateGRPCRequest(ctx)
			if err != nil {
				return err
			}
			ctx = context.WithValue(ctx, "security_context", securityContext)
		}

		requestID := uuid.New().String()
		traceID := uuid.New().String()
		
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

func (m *MiddlewareManager) authenticateGRPCRequest(ctx context.Context) (*request.SecurityContext, error) {
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

	securityContext := &request.SecurityContext{
		SessionToken:         authToken,
		AuthenticationMethod: "grpc",
		AuthenticationLevel:  "standard",
		UserID:               resp.UserId,
		TenantID:             resp.TenantId,
		Permissions:          resp.Scopes,
		SessionExpiry:        time.Unix(resp.ExpiresAt, 0),
		MFAVerified:          false,
		DeviceFingerprint:    "",
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

func (m *MiddlewareManager) isPublicGRPCMethod(method string) bool {
	publicMethods := []string{
		"/gateway.GatewayService/GetHealthStatus",
		"/gateway.GatewayService/GetMetrics",
	}

	return utils.Contains(publicMethods, method)
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

func (m *MiddlewareManager) getSecurityContext(ctx context.Context) *request.SecurityContext {
	if securityContext, ok := ctx.Value("security_context").(*request.SecurityContext); ok {
		return securityContext
	}
	return nil
}

func (m *MiddlewareManager) getRateLimitKey(clientIP string, securityContext *request.SecurityContext) string {
	if securityContext != nil && securityContext.TenantID != "" {
		return "tenant:" + securityContext.TenantID
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

func (m *MiddlewareManager) detectPIIInRequest(r *http.Request) (*request.ComplianceContext, *errors.AppError) {
	body := make([]byte, r.ContentLength)
	if _, err := r.Body.Read(body); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "failed to read request body")
	}

	piiResult := utils.DetectPII(string(body))
	
	complianceContext := &request.ComplianceContext{
		PIIDetected:    piiResult.HasPII,
		DataClassification: request.ClassificationPublic,
		RedactionRules: []request.RedactionRule{},
		RetentionPolicy: request.RetentionPolicy{
			RetentionPeriod: time.Hour * 24 * 365,
			AutoDelete:      false,
		},
		AuditRequired: piiResult.HasPII,
	}

	if piiResult.HasPII {
		complianceContext.DataClassification = request.ClassificationSensitive
		complianceContext.RedactionRules = []request.RedactionRule{
			{
				Type:        "email",
				Pattern:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
				Replacement: "[REDACTED_EMAIL]",
				Enabled:     true,
			},
			{
				Type:        "phone",
				Pattern:     `\b\d{3}-\d{3}-\d{4}\b`,
				Replacement: "[REDACTED_PHONE]",
				Enabled:     true,
			},
		}
	}

	return complianceContext, nil
}

func (m *MiddlewareManager) getTenant(tenantID string) (*tenant.Tenant, *errors.AppError) {
	m.mu.RLock()
	if cachedTenant, exists := m.tenantCache[tenantID]; exists {
		m.mu.RUnlock()
		return cachedTenant, nil
	}
	m.mu.RUnlock()

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, errors.New(errors.ErrCodeValidationError, "invalid tenant ID format")
	}

	tenantObj := &tenant.Tenant{
		ID:             tenantUUID,
		Name:           "Default Tenant",
		Slug:           "default",
		Status:         tenant.TenantStatusActive,
		Tier:           tenant.TenantTierEnterprise,
		OrganizationID: "default-org",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		CreatedBy:      uuid.New(),
		UpdatedBy:      uuid.New(),
		Version:        1,
		ComplianceConfig: tenant.ComplianceConfiguration{
			Frameworks:          []tenant.ComplianceFramework{tenant.ComplianceSOC2},
			DataResidency:       tenant.ResidencyUS,
			DataRetentionDays:   2555,
			PIIRedactionEnabled: true,
			AuditLogRetention:   2555,
			RegulatoryReporting: false,
		},
		SecurityConfig: tenant.SecurityConfiguration{
			EncryptionLevel:      tenant.EncryptionAES256GCM,
			MTLSRequired:         true,
			SessionTimeout:       time.Hour * 8,
			MFARequired:          true,
			ThreatDetectionLevel: "high",
		},
		ResourceLimits: tenant.ResourceLimits{
			MaxUsers:              1000,
			MaxAPICallsPerMinute:  1000,
			MaxAPICallsPerDay:     100000,
			MaxStorageGB:          1000,
			MaxModelsPerTenant:    20,
			MaxConcurrentRequests: 100,
			BandwidthLimitMbps:    100.0,
			ComputeUnitsLimit:     10000,
		},
		Metadata: make(map[string]interface{}),
	}

	m.mu.Lock()
	m.tenantCache[tenantID] = tenantObj
	m.mu.Unlock()

	return tenantObj, nil
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
	securityContext := m.getSecurityContext(r.Context())
	key := r.URL.Path + "?" + r.URL.RawQuery
	
	if securityContext != nil {
		key += "|tenant:" + securityContext.TenantID
	}

	return utils.HashSHA256(key)
}

func (m *MiddlewareManager) logAuditEvent(r *http.Request, aw *auditResponseWriter, startTime time.Time) {
	duration := time.Since(startTime)
	securityContext := m.getSecurityContext(r.Context())
	clientInfo := request.ExtractClientInfo(r)

	auditEvent := &commonpb.AuditEvent{
		EventId:   uuid.New().String(),
		EventType: "http_request",
		ActorId:   "system",
		ActorType: "service",
		Action:    r.Method + " " + r.URL.Path,
		Status:    commonpb.Status_STATUS_SUCCESS,
		SourceIp:  clientInfo.IPAddress,
		UserAgent: clientInfo.UserAgent,
		TraceId:   r.Context().Value("request_id").(string),
		Severity:  commonpb.Severity_SEVERITY_LOW,
	}

	if securityContext != nil {
		auditEvent.ActorId = securityContext.UserID
		auditEvent.ActorType = "user"
		auditEvent.TenantId = securityContext.TenantID
	}

	if aw.statusCode >= 400 {
		auditEvent.Status = commonpb.Status_STATUS_ERROR
		auditEvent.Severity = commonpb.Severity_SEVERITY_MEDIUM
	}

	m.logger.Info("Request audit", zap.Any("audit_event", auditEvent))
}

func (m *MiddlewareManager) logGRPCAuditEvent(ctx context.Context, method string, req interface{}, resp interface{}, err error, startTime time.Time) {
	duration := time.Since(startTime)
	securityContext := m.getSecurityContext(ctx)

	auditEvent := &commonpb.AuditEvent{
		EventId:   uuid.New().String(),
		EventType: "grpc_request",
		ActorId:   "system",
		ActorType: "service",
		Action:    method,
		Status:    commonpb.Status_STATUS_SUCCESS,
		TraceId:   ctx.Value("request_id").(string),
		Severity:  commonpb.Severity_SEVERITY_LOW,
	}

	if securityContext != nil {
		auditEvent.ActorId = securityContext.UserID
		auditEvent.ActorType = "user"
		auditEvent.TenantId = securityContext.TenantID
	}

	if err != nil {
		auditEvent.Status = commonpb.Status_STATUS_ERROR
		auditEvent.Severity = commonpb.Severity_SEVERITY_MEDIUM
	}

	m.logger.Info("gRPC request audit", zap.Any("audit_event", auditEvent))
}

func (m *MiddlewareManager) logSecurityEvent(eventType, description string, metadata map[string]interface{}) {
	securityEvent := &commonpb.AuditEvent{
		EventId:     uuid.New().String(),
		EventType:   eventType,
		ActorId:     "system",
		ActorType:   "security_monitor",
		Action:      description,
		Status:      commonpb.Status_STATUS_SUCCESS,
		Severity:    commonpb.Severity_SEVERITY_HIGH,
		TenantId:    "",
		TraceId:     uuid.New().String(),
	}

	m.logger.Warn("Security event", zap.Any("security_event", securityEvent))
}

func (m *MiddlewareManager) writeErrorResponse(w http.ResponseWriter, appErr *errors.AppError) {
	errorResponse := response.NewErrorResponse(
		uuid.New(),
		uuid.New().String(),
		response.ErrorCode(appErr.Code),
		appErr.Message,
		response.SeverityHigh,
	)

	statusCode := m.getHTTPStatusFromError(appErr)
	utils.WriteJSONResponse(w, statusCode, errorResponse)
}

func (m *MiddlewareManager) getHTTPStatusFromError(appErr *errors.AppError) int {
	switch appErr.Code {
	case errors.ErrCodeInvalidRequest, errors.ErrCodeValidationError:
		return http.StatusBadRequest
	case errors.ErrCodeUnauthorized, errors.ErrCodeAuthenticationError:
		return http.StatusUnauthorized
	case errors.ErrCodeForbidden, errors.ErrCodeAuthorizationError:
		return http.StatusForbidden
	case errors.ErrCodeNotFound:
		return http.StatusNotFound
	case errors.ErrCodeConflict:
		return http.StatusConflict
	case errors.ErrCodeRateLimit, errors.ErrCodeQuotaExceeded:
		return http.StatusTooManyRequests
	case errors.ErrCodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case errors.ErrCodeTimeout:
		return http.StatusRequestTimeout
	case errors.ErrCodeServiceUnavailable, errors.ErrCodeModelUnavailable:
		return http.StatusServiceUnavailable
	case errors.ErrCodeInternalError, errors.ErrCodeDatabaseError:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
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

func (m *MiddlewareManager) isAuthorized(securityContext *request.SecurityContext, r *http.Request) bool {
	if securityContext == nil {
		return false
	}

	tenantObj, err := m.getTenant(securityContext.TenantID)
	if err != nil {
		return false
	}

	requiredScopes := m.getRequiredScopes(r.URL.Path, r.Method)
	for _, required := range requiredScopes {
		if !utils.Contains(securityContext.Permissions, required) {
			return false
		}
	}

	if tenantObj.SecurityConfig.MFARequired && !securityContext.MFAVerified {
		return false
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
		"blocked_requests":      m.getBlockedRequestCount(),
		"suspicious_requests":   m.getSuspiciousRequestCount(),
		"pii_detections":        m.getPIIDetectionCount(),
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

	for key := range m.tenantCache {
		delete(m.tenantCache, key)
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

func (aw *auditResponseWriter) WriteHeader(statusCode int) {
	aw.statusCode = statusCode
	aw.ResponseWriter.WriteHeader(statusCode)
}

func (aw *auditResponseWriter) Write(data []byte) (int, error) {
	size, err := aw.ResponseWriter.Write(data)
	aw.size += int64(size)
	return size, err
}

func (cbw *circuitBreakerResponseWriter) WriteHeader(statusCode int) {
	cbw.statusCode = statusCode
	cbw.ResponseWriter.WriteHeader(statusCode)
}

func (cw *cacheResponseWriter) WriteHeader(statusCode int) {
	cw.statusCode = statusCode
	cw.ResponseWriter.WriteHeader(statusCode)
}

func (cw *cacheResponseWriter) Write(data []byte) (int, error) {
	cw.data = append(cw.data, data...)
	return cw.ResponseWriter.Write(data)
}

func (mw *metricsResponseWriter) WriteHeader(statusCode int) {
	mw.statusCode = statusCode
	mw.ResponseWriter.WriteHeader(statusCode)
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

func NewSecurityContext() *request.SecurityContext {
	return &request.SecurityContext{
		SessionToken:         "",
		AuthenticationMethod: "none",
		AuthenticationLevel:  "none",
		UserID:               "",
		TenantID:             "",
		Permissions:          []string{},
		SessionExpiry:        time.Time{},
		MFAVerified:          false,
		DeviceFingerprint:    "",
	}
}

func NewComplianceContext() *request.ComplianceContext {
	return &request.ComplianceContext{
		PIIDetected:        false,
		DataClassification: request.ClassificationPublic,
		RedactionRules:     []request.RedactionRule{},
		RetentionPolicy: request.RetentionPolicy{
			RetentionPeriod: time.Hour * 24 * 30,
			AutoDelete:      false,
		},
		AuditRequired: false,
	}
}

func NewThreatContext() *commonpb.ThreatDetection {
	return &commonpb.ThreatDetection{
		ThreatType:  commonpb.ThreatType_THREAT_TYPE_NONE,
		Severity:    commonpb.Severity_SEVERITY_LOW,
		Confidence:  0.0,
		Description: "No threats detected",
		Mitigations: []string{},
	}
}
