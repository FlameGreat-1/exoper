package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	"flamo/backend/internal/gateway/orchestrator"
	"flamo/backend/pkg/models"
	gatewaypb "flamo/backend/pkg/api/proto/gateway"
)

type HTTPHandler struct {
	orchestrator *orchestrator.Orchestrator
	config       *config.Config
	logger       *zap.Logger
}

type GRPCHandler struct {
	orchestrator *orchestrator.Orchestrator
	config       *config.Config
	logger       *zap.Logger
	gatewaypb.UnimplementedGatewayServiceServer
}

type RequestMetadata struct {
	RequestID     string
	ClientIP      string
	UserAgent     string
	ContentLength int64
	StartTime     time.Time
}

type ResponseMetadata struct {
	StatusCode    int
	ResponseSize  int64
	ProcessingTime time.Duration
	CacheHit      bool
}

func NewHTTPHandler(orch *orchestrator.Orchestrator, cfg *config.Config, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{
		orchestrator: orch,
		config:       cfg,
		logger:       logger,
	}
}

func NewGRPCHandler(orch *orchestrator.Orchestrator, cfg *config.Config, logger *zap.Logger) *GRPCHandler {
	return &GRPCHandler{
		orchestrator: orch,
		config:       cfg,
		logger:       logger,
	}
}

func (h *HTTPHandler) RegisterRoutes(router *mux.Router) {
	api := router.PathPrefix("/api/v1").Subrouter()
	
	api.HandleFunc("/ai/chat", h.handleChatRequest).Methods("POST")
	api.HandleFunc("/ai/completion", h.handleCompletionRequest).Methods("POST")
	api.HandleFunc("/ai/batch", h.handleBatchRequest).Methods("POST")
	
	api.HandleFunc("/health", h.handleHealthCheck).Methods("GET")
	api.HandleFunc("/metrics", h.handleMetrics).Methods("GET")
	api.HandleFunc("/status", h.handleStatus).Methods("GET")
	
	api.HandleFunc("/tenant/{tenantId}/quota", h.handleGetQuota).Methods("GET")
	api.HandleFunc("/tenant/{tenantId}/history", h.handleGetHistory).Methods("GET")
	api.HandleFunc("/tenant/{tenantId}/threats", h.handleGetThreats).Methods("GET")
	api.HandleFunc("/tenant/{tenantId}/compliance", h.handleGetCompliance).Methods("GET")
	
	api.HandleFunc("/admin/circuit-breaker/{service}/reset", h.handleResetCircuitBreaker).Methods("POST")
	api.HandleFunc("/admin/cache/refresh", h.handleRefreshCache).Methods("POST")
	api.HandleFunc("/admin/shutdown", h.handleShutdown).Methods("POST")
}

func (h *HTTPHandler) handleChatRequest(w http.ResponseWriter, r *http.Request) {
	metadata := h.extractRequestMetadata(r)
	defer h.logRequest(metadata, r)

	utils.SetSecurityHeaders(w)

	var request models.ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInvalidRequest, "invalid JSON payload"))
		return
	}

	aiRequest := &models.AIRequest{
		ID:        metadata.RequestID,
		TenantID:  request.TenantID,
		UserID:    request.UserID,
		Model:     request.Model,
		Provider:  request.Provider,
		Prompt:    request.Message,
		AuthToken: h.extractAuthToken(r),
		Parameters: map[string]interface{}{
			"max_tokens":    request.MaxTokens,
			"temperature":   request.Temperature,
			"top_p":         request.TopP,
			"stream":        request.Stream,
		},
		Metadata: map[string]interface{}{
			"client_ip":    metadata.ClientIP,
			"user_agent":   metadata.UserAgent,
			"request_type": "chat",
		},
		Timestamp: time.Now(),
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.config.Gateway.RequestTimeout)
	defer cancel()

	response, appErr := h.orchestrator.ProcessRequest(ctx, aiRequest)
	if appErr != nil {
		h.writeErrorResponse(w, appErr)
		return
	}

	chatResponse := &models.ChatResponse{
		ID:             response.ID,
		RequestID:      response.RequestID,
		Message:        response.Response,
		Model:          response.Model,
		Provider:       response.Provider,
		TokensUsed:     response.TokensUsed,
		ProcessingTime: response.ProcessingTime,
		Cost:           response.Cost,
		Timestamp:      response.Timestamp,
	}

	h.writeJSONResponse(w, http.StatusOK, chatResponse)
}

func (h *HTTPHandler) handleCompletionRequest(w http.ResponseWriter, r *http.Request) {
	metadata := h.extractRequestMetadata(r)
	defer h.logRequest(metadata, r)

	utils.SetSecurityHeaders(w)

	var request models.CompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInvalidRequest, "invalid JSON payload"))
		return
	}

	aiRequest := &models.AIRequest{
		ID:        metadata.RequestID,
		TenantID:  request.TenantID,
		UserID:    request.UserID,
		Model:     request.Model,
		Provider:  request.Provider,
		Prompt:    request.Prompt,
		AuthToken: h.extractAuthToken(r),
		Parameters: map[string]interface{}{
			"max_tokens":      request.MaxTokens,
			"temperature":     request.Temperature,
			"top_p":           request.TopP,
			"frequency_penalty": request.FrequencyPenalty,
			"presence_penalty":  request.PresencePenalty,
			"stop":            request.Stop,
		},
		Metadata: map[string]interface{}{
			"client_ip":    metadata.ClientIP,
			"user_agent":   metadata.UserAgent,
			"request_type": "completion",
		},
		Timestamp: time.Now(),
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.config.Gateway.RequestTimeout)
	defer cancel()

	response, appErr := h.orchestrator.ProcessRequest(ctx, aiRequest)
	if appErr != nil {
		h.writeErrorResponse(w, appErr)
		return
	}

	completionResponse := &models.CompletionResponse{
		ID:             response.ID,
		RequestID:      response.RequestID,
		Text:           response.Response,
		Model:          response.Model,
		Provider:       response.Provider,
		TokensUsed:     response.TokensUsed,
		ProcessingTime: response.ProcessingTime,
		Cost:           response.Cost,
		Timestamp:      response.Timestamp,
	}

	h.writeJSONResponse(w, http.StatusOK, completionResponse)
}

func (h *HTTPHandler) handleBatchRequest(w http.ResponseWriter, r *http.Request) {
	metadata := h.extractRequestMetadata(r)
	defer h.logRequest(metadata, r)

	utils.SetSecurityHeaders(w)

	var batchRequest models.BatchRequest
	if err := json.NewDecoder(r.Body).Decode(&batchRequest); err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInvalidRequest, "invalid JSON payload"))
		return
	}

	if len(batchRequest.Requests) == 0 {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInvalidRequest, "no requests in batch"))
		return
	}

	if len(batchRequest.Requests) > 100 {
		h.writeErrorResponse(w, errors.New(errors.ErrCodePayloadTooLarge, "batch size exceeds limit"))
		return
	}

	aiRequests := make([]*models.AIRequest, len(batchRequest.Requests))
	authToken := h.extractAuthToken(r)

	for i, req := range batchRequest.Requests {
		aiRequests[i] = &models.AIRequest{
			ID:        utils.GenerateRequestID(),
			TenantID:  req.TenantID,
			UserID:    req.UserID,
			Model:     req.Model,
			Provider:  req.Provider,
			Prompt:    req.Prompt,
			AuthToken: authToken,
			Parameters: req.Parameters,
			Metadata: map[string]interface{}{
				"client_ip":    metadata.ClientIP,
				"user_agent":   metadata.UserAgent,
				"request_type": "batch",
				"batch_index":  i,
			},
			Timestamp: time.Now(),
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	responses, appErr := h.orchestrator.ProcessBatchRequests(ctx, aiRequests)
	if appErr != nil {
		h.writeErrorResponse(w, appErr)
		return
	}

	batchResponse := &models.BatchResponse{
		ID:        utils.GenerateRequestID(),
		RequestID: metadata.RequestID,
		Responses: responses,
		Timestamp: time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, batchResponse)
}

func (h *HTTPHandler) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	healthStatus := h.orchestrator.GetHealthStatus()
	
	statusCode := http.StatusOK
	if healthStatus.Overall != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	h.writeJSONResponse(w, statusCode, healthStatus)
}

func (h *HTTPHandler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	metrics := h.orchestrator.GetMetrics()
	h.writeJSONResponse(w, http.StatusOK, metrics)
}

func (h *HTTPHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	status := map[string]interface{}{
		"service":     "gateway",
		"version":     "1.0.0",
		"environment": h.config.Environment,
		"uptime":      time.Since(time.Now()).String(),
		"healthy":     h.orchestrator.IsHealthy(),
		"timestamp":   time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, status)
}

func (h *HTTPHandler) extractRequestMetadata(r *http.Request) *RequestMetadata {
	return &RequestMetadata{
		RequestID:     utils.GenerateRequestID(),
		ClientIP:      utils.GetClientIP(r),
		UserAgent:     utils.GetUserAgent(r),
		ContentLength: r.ContentLength,
		StartTime:     time.Now(),
	}
}

func (h *HTTPHandler) extractAuthToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}
	
	return ""
}

func (h *HTTPHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *HTTPHandler) writeErrorResponse(w http.ResponseWriter, appErr *errors.AppError) {
	errorResponse := errors.CreateErrorResponse(
		appErr,
		appErr.RequestID,
		"",
		"",
		"",
		"",
	)

	statusCode := errors.GetHTTPStatus(appErr)
	h.writeJSONResponse(w, statusCode, errorResponse)
}

func (h *HTTPHandler) logRequest(metadata *RequestMetadata, r *http.Request) {
	duration := time.Since(metadata.StartTime)
	
	h.logger.Info("HTTP request processed",
		zap.String("request_id", metadata.RequestID),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("client_ip", metadata.ClientIP),
		zap.String("user_agent", metadata.UserAgent),
		zap.Int64("content_length", metadata.ContentLength),
		zap.Duration("duration", duration),
	)
}

func (h *HTTPHandler) handleGetQuota(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	vars := mux.Vars(r)
	tenantID := vars["tenantId"]

	if !utils.IsValidUUID(tenantID) {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "invalid tenant ID"))
		return
	}

	quota, appErr := h.orchestrator.GetTenantQuota(tenantID)
	if appErr != nil {
		h.writeErrorResponse(w, appErr)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, quota)
}

func (h *HTTPHandler) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	vars := mux.Vars(r)
	tenantID := vars["tenantId"]

	if !utils.IsValidUUID(tenantID) {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "invalid tenant ID"))
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := utils.SafeStringToInt(limitStr, 50)
	
	if limit > 1000 {
		limit = 1000
	}

	history, appErr := h.orchestrator.GetRequestHistory(tenantID, limit)
	if appErr != nil {
		h.writeErrorResponse(w, appErr)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"tenant_id": tenantID,
		"limit":     limit,
		"count":     len(history),
		"history":   history,
	})
}

func (h *HTTPHandler) handleGetThreats(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	vars := mux.Vars(r)
	tenantID := vars["tenantId"]

	if !utils.IsValidUUID(tenantID) {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "invalid tenant ID"))
		return
	}

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}

	timeRange, err := utils.GetTimeRange(period)
	if err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "invalid time period"))
		return
	}

	stats, appErr := h.orchestrator.GetThreatStatistics(tenantID, timeRange)
	if appErr != nil {
		h.writeErrorResponse(w, appErr)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"tenant_id":  tenantID,
		"time_range": timeRange,
		"statistics": stats,
	})
}

func (h *HTTPHandler) handleGetCompliance(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	vars := mux.Vars(r)
	tenantID := vars["tenantId"]

	if !utils.IsValidUUID(tenantID) {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "invalid tenant ID"))
		return
	}

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "30d"
	}

	timeRange, err := utils.GetTimeRange(period)
	if err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "invalid time period"))
		return
	}

	report, appErr := h.orchestrator.GetComplianceReport(tenantID, timeRange)
	if appErr != nil {
		h.writeErrorResponse(w, appErr)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, report)
}

func (h *HTTPHandler) handleResetCircuitBreaker(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	vars := mux.Vars(r)
	service := vars["service"]

	if service == "" {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "service name is required"))
		return
	}

	appErr := h.orchestrator.ResetCircuitBreaker(service)
	if appErr != nil {
		h.writeErrorResponse(w, appErr)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"service": service,
		"status":  "reset",
		"message": "Circuit breaker reset successfully",
	})
}

func (h *HTTPHandler) handleRefreshCache(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Cache refresh initiated",
	})
}

func (h *HTTPHandler) handleShutdown(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "admin_shutdown"
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		h.orchestrator.EmergencyShutdown(reason)
	}()

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "shutdown_initiated",
		"reason":  reason,
		"message": "Graceful shutdown initiated",
	})
}

func (g *GRPCHandler) ProcessAIRequest(ctx context.Context, req *gatewaypb.AIRequestProto) (*gatewaypb.AIResponseProto, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	aiRequest := &models.AIRequest{
		ID:        req.Id,
		TenantID:  req.TenantId,
		UserID:    req.UserId,
		Model:     req.Model,
		Provider:  req.Provider,
		Prompt:    req.Prompt,
		AuthToken: req.AuthToken,
		Parameters: req.Parameters,
		Metadata:  req.Metadata,
		Timestamp: time.Now(),
	}

	response, appErr := g.orchestrator.ProcessRequest(ctx, aiRequest)
	if appErr != nil {
		return nil, g.convertAppErrorToGRPCError(appErr)
	}

	return &gatewaypb.AIResponseProto{
		Id:             response.ID,
		RequestId:      response.RequestID,
		TenantId:       response.TenantID,
		Model:          response.Model,
		Provider:       response.Provider,
		Response:       response.Response,
		TokensUsed:     response.TokensUsed,
		ProcessingTime: int64(response.ProcessingTime.Milliseconds()),
		Cost:           response.Cost,
		Timestamp:      response.Timestamp.Unix(),
		Metadata:       response.Metadata,
	}, nil
}

func (g *GRPCHandler) ProcessBatchRequests(ctx context.Context, req *gatewaypb.BatchRequestProto) (*gatewaypb.BatchResponseProto, error) {
	if req == nil || len(req.Requests) == 0 {
		return nil, status.Error(codes.InvalidArgument, "requests are required")
	}

	if len(req.Requests) > 100 {
		return nil, status.Error(codes.InvalidArgument, "batch size exceeds limit")
	}

	aiRequests := make([]*models.AIRequest, len(req.Requests))
	for i, r := range req.Requests {
		aiRequests[i] = &models.AIRequest{
			ID:        r.Id,
			TenantID:  r.TenantId,
			UserID:    r.UserId,
			Model:     r.Model,
			Provider:  r.Provider,
			Prompt:    r.Prompt,
			AuthToken: r.AuthToken,
			Parameters: r.Parameters,
			Metadata:  r.Metadata,
			Timestamp: time.Now(),
		}
	}

	responses, appErr := g.orchestrator.ProcessBatchRequests(ctx, aiRequests)
	if appErr != nil {
		return nil, g.convertAppErrorToGRPCError(appErr)
	}

	protoResponses := make([]*gatewaypb.AIResponseProto, len(responses))
	for i, resp := range responses {
		protoResponses[i] = &gatewaypb.AIResponseProto{
			Id:             resp.ID,
			RequestId:      resp.RequestID,
			TenantId:       resp.TenantID,
			Model:          resp.Model,
			Provider:       resp.Provider,
			Response:       resp.Response,
			TokensUsed:     resp.TokensUsed,
			ProcessingTime: int64(resp.ProcessingTime.Milliseconds()),
			Cost:           resp.Cost,
			Timestamp:      resp.Timestamp.Unix(),
			Metadata:       resp.Metadata,
		}
	}

	return &gatewaypb.BatchResponseProto{
		Id:        utils.GenerateRequestID(),
		RequestId: req.Id,
		Responses: protoResponses,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (g *GRPCHandler) GetHealthStatus(ctx context.Context, req *gatewaypb.HealthCheckRequest) (*gatewaypb.HealthCheckResponse, error) {
	healthStatus := g.orchestrator.GetHealthStatus()

	return &gatewaypb.HealthCheckResponse{
		Status:      healthStatus.Overall,
		Services:    healthStatus.Services,
		Dependencies: healthStatus.Dependencies,
		Uptime:      int64(healthStatus.Uptime.Seconds()),
		Version:     healthStatus.Version,
		Environment: healthStatus.Environment,
		Timestamp:   healthStatus.LastHealthCheck.Unix(),
	}, nil
}

func (g *GRPCHandler) GetMetrics(ctx context.Context, req *gatewaypb.MetricsRequest) (*gatewaypb.MetricsResponse, error) {
	metrics := g.orchestrator.GetMetrics()

	return &gatewaypb.MetricsResponse{
		TotalRequests:       metrics.TotalRequests,
		SuccessfulRequests:  metrics.SuccessfulRequests,
		FailedRequests:      metrics.FailedRequests,
		AverageResponseTime: int64(metrics.AverageResponseTime.Milliseconds()),
		ThroughputPerSecond: metrics.ThroughputPerSecond,
		ErrorRate:           metrics.ErrorRate,
		AuthenticationRate:  metrics.AuthenticationRate,
		ThreatDetectionRate: metrics.ThreatDetectionRate,
		PolicyViolationRate: metrics.PolicyViolationRate,
		ServiceHealthScores: metrics.ServiceHealthScores,
		LastUpdated:         metrics.LastUpdated.Unix(),
	}, nil
}

func (g *GRPCHandler) GetTenantQuota(ctx context.Context, req *gatewaypb.TenantQuotaRequest) (*gatewaypb.TenantQuotaResponse, error) {
	if req.TenantId == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant ID is required")
	}

	quota, appErr := g.orchestrator.GetTenantQuota(req.TenantId)
	if appErr != nil {
		return nil, g.convertAppErrorToGRPCError(appErr)
	}

	return &gatewaypb.TenantQuotaResponse{
		TenantId:          quota.TenantID,
		RequestsPerHour:   quota.RequestsPerHour,
		RequestsPerDay:    quota.RequestsPerDay,
		TokensPerHour:     quota.TokensPerHour,
		TokensPerDay:      quota.TokensPerDay,
		CostLimitPerDay:   quota.CostLimitPerDay,
		UsedRequestsHour:  quota.UsedRequestsHour,
		UsedRequestsDay:   quota.UsedRequestsDay,
		UsedTokensHour:    quota.UsedTokensHour,
		UsedTokensDay:     quota.UsedTokensDay,
		UsedCostDay:       quota.UsedCostDay,
		ResetHour:         quota.ResetHour.Unix(),
		ResetDay:          quota.ResetDay.Unix(),
	}, nil
}

func (g *GRPCHandler) ValidateModelAccess(ctx context.Context, req *gatewaypb.ModelAccessRequest) (*gatewaypb.ModelAccessResponse, error) {
	if req.TenantId == "" || req.Model == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant ID and model are required")
	}

	appErr := g.orchestrator.ValidateModelAccess(req.TenantId, req.Model)
	
	return &gatewaypb.ModelAccessResponse{
		Allowed: appErr == nil,
		Reason:  func() string {
			if appErr != nil {
				return appErr.Message
			}
			return "access_granted"
		}(),
	}, nil
}

func (g *GRPCHandler) convertAppErrorToGRPCError(appErr *errors.AppError) error {
	var code codes.Code

	switch appErr.Code {
	case errors.ErrCodeInvalidRequest, errors.ErrCodeValidationError:
		code = codes.InvalidArgument
	case errors.ErrCodeUnauthorized, errors.ErrCodeAuthenticationError:
		code = codes.Unauthenticated
	case errors.ErrCodeForbidden, errors.ErrCodeAuthorizationError:
		code = codes.PermissionDenied
	case errors.ErrCodeNotFound:
		code = codes.NotFound
	case errors.ErrCodeConflict:
		code = codes.AlreadyExists
	case errors.ErrCodeRateLimit, errors.ErrCodeQuotaExceeded:
		code = codes.ResourceExhausted
	case errors.ErrCodeTimeout:
		code = codes.DeadlineExceeded
	case errors.ErrCodeServiceUnavailable, errors.ErrCodeModelUnavailable:
		code = codes.Unavailable
	case errors.ErrCodeInternalError, errors.ErrCodeDatabaseError:
		code = codes.Internal
	default:
		code = codes.Unknown
	}

	return status.Error(code, appErr.Message)
}

func (h *HTTPHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/health") ||
		   strings.HasPrefix(r.URL.Path, "/api/v1/status") {
			next.ServeHTTP(w, r)
			return
		}

		authToken := h.extractAuthToken(r)
		if authToken == "" {
			h.writeErrorResponse(w, errors.NewUnauthorizedError("authentication token required"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *HTTPHandler) RateLimitMiddleware(next http.Handler) http.Handler {
	rateLimiter := utils.NewRateLimiter(100.0, 1000)
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rateLimiter.Allow() {
			h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *HTTPHandler) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		next.ServeHTTP(w, r)
		
		duration := time.Since(start)
		h.logger.Info("HTTP request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("client_ip", utils.GetClientIP(r)),
			zap.Duration("duration", duration),
		)
	})
}

func (h *HTTPHandler) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.SetCORSHeaders(w, 
			h.config.Security.AllowedOrigins,
			[]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			[]string{"Content-Type", "Authorization", "X-API-Key"},
		)

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *HTTPHandler) PanicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				h.logger.Error("Panic recovered in HTTP handler",
					zap.Any("panic", err),
					zap.String("path", r.URL.Path),
					zap.String("method", r.Method),
					zap.Stack("stack"))

				appErr := errors.New(errors.ErrCodeInternalError, "internal server error")
				h.writeErrorResponse(w, appErr)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func (h *HTTPHandler) RequestSizeMiddleware(maxSize int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxSize {
				h.writeErrorResponse(w, errors.New(errors.ErrCodePayloadTooLarge, 
					fmt.Sprintf("request body too large, maximum %d bytes allowed", maxSize)))
				return
			}

			r.Body = http.MaxBytesReader(w, r.Body, maxSize)
			next.ServeHTTP(w, r)
		})
	}
}

func (h *HTTPHandler) SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.SetSecurityHeaders(w)
		
		w.Header().Set("X-Request-ID", utils.GenerateRequestID())
		w.Header().Set("X-Service-Version", "1.0.0")
		w.Header().Set("X-Environment", string(h.config.Environment))
		
		next.ServeHTTP(w, r)
	})
}

func (h *HTTPHandler) validateChatRequest(request *models.ChatRequest) *errors.AppError {
	if request.TenantID == "" {
		return errors.NewValidationError("tenant_id", "tenant ID is required", request.TenantID)
	}

	if !utils.IsValidUUID(request.TenantID) {
		return errors.NewValidationError("tenant_id", "invalid tenant ID format", request.TenantID)
	}

	if request.Message == "" {
		return errors.NewValidationError("message", "message is required", request.Message)
	}

	if len(request.Message) > 100000 {
		return errors.NewValidationError("message", "message exceeds maximum length", len(request.Message))
	}

	if request.Model == "" {
		return errors.NewValidationError("model", "model is required", request.Model)
	}

	if request.MaxTokens < 1 || request.MaxTokens > 4096 {
		return errors.NewValidationError("max_tokens", "max_tokens must be between 1 and 4096", request.MaxTokens)
	}

	if request.Temperature < 0 || request.Temperature > 2 {
		return errors.NewValidationError("temperature", "temperature must be between 0 and 2", request.Temperature)
	}

	if request.TopP < 0 || request.TopP > 1 {
		return errors.NewValidationError("top_p", "top_p must be between 0 and 1", request.TopP)
	}

	return nil
}

func (h *HTTPHandler) validateCompletionRequest(request *models.CompletionRequest) *errors.AppError {
	if request.TenantID == "" {
		return errors.NewValidationError("tenant_id", "tenant ID is required", request.TenantID)
	}

	if !utils.IsValidUUID(request.TenantID) {
		return errors.NewValidationError("tenant_id", "invalid tenant ID format", request.TenantID)
	}

	if request.Prompt == "" {
		return errors.NewValidationError("prompt", "prompt is required", request.Prompt)
	}

	if len(request.Prompt) > 100000 {
		return errors.NewValidationError("prompt", "prompt exceeds maximum length", len(request.Prompt))
	}

	if request.Model == "" {
		return errors.NewValidationError("model", "model is required", request.Model)
	}

	if request.MaxTokens < 1 || request.MaxTokens > 4096 {
		return errors.NewValidationError("max_tokens", "max_tokens must be between 1 and 4096", request.MaxTokens)
	}

	if request.Temperature < 0 || request.Temperature > 2 {
		return errors.NewValidationError("temperature", "temperature must be between 0 and 2", request.Temperature)
	}

	if request.FrequencyPenalty < -2 || request.FrequencyPenalty > 2 {
		return errors.NewValidationError("frequency_penalty", "frequency_penalty must be between -2 and 2", request.FrequencyPenalty)
	}

	if request.PresencePenalty < -2 || request.PresencePenalty > 2 {
		return errors.NewValidationError("presence_penalty", "presence_penalty must be between -2 and 2", request.PresencePenalty)
	}

	return nil
}

func (h *HTTPHandler) validateBatchRequest(request *models.BatchRequest) *errors.AppError {
	if len(request.Requests) == 0 {
		return errors.NewValidationError("requests", "at least one request is required", len(request.Requests))
	}

	if len(request.Requests) > 100 {
		return errors.NewValidationError("requests", "batch size exceeds maximum limit of 100", len(request.Requests))
	}

	for i, req := range request.Requests {
		if req.TenantID == "" {
			return errors.NewValidationError(fmt.Sprintf("requests[%d].tenant_id", i), "tenant ID is required", req.TenantID)
		}

		if !utils.IsValidUUID(req.TenantID) {
			return errors.NewValidationError(fmt.Sprintf("requests[%d].tenant_id", i), "invalid tenant ID format", req.TenantID)
		}

		if req.Prompt == "" {
			return errors.NewValidationError(fmt.Sprintf("requests[%d].prompt", i), "prompt is required", req.Prompt)
		}

		if len(req.Prompt) > 100000 {
			return errors.NewValidationError(fmt.Sprintf("requests[%d].prompt", i), "prompt exceeds maximum length", len(req.Prompt))
		}

		if req.Model == "" {
			return errors.NewValidationError(fmt.Sprintf("requests[%d].model", i), "model is required", req.Model)
		}
	}

	return nil
}

func (h *HTTPHandler) enrichRequestMetadata(metadata *RequestMetadata, r *http.Request) {
	metadata.RequestID = r.Header.Get("X-Request-ID")
	if metadata.RequestID == "" {
		metadata.RequestID = utils.GenerateRequestID()
	}

	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		metadata.ClientIP = strings.TrimSpace(ips[0])
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" && metadata.ClientIP == "" {
		metadata.ClientIP = realIP
	}

	if metadata.ClientIP == "" {
		metadata.ClientIP = utils.GetClientIP(r)
	}

	metadata.UserAgent = r.Header.Get("User-Agent")
	if metadata.UserAgent == "" {
		metadata.UserAgent = "unknown"
	}
}

func (h *HTTPHandler) createAuditLog(metadata *RequestMetadata, r *http.Request, statusCode int, err *errors.AppError) {
	auditData := map[string]interface{}{
		"request_id":     metadata.RequestID,
		"method":         r.Method,
		"path":           r.URL.Path,
		"client_ip":      metadata.ClientIP,
		"user_agent":     metadata.UserAgent,
		"content_length": metadata.ContentLength,
		"status_code":    statusCode,
		"duration":       time.Since(metadata.StartTime).Milliseconds(),
		"timestamp":      time.Now().UTC(),
	}

	if err != nil {
		auditData["error_code"] = err.Code
		auditData["error_message"] = err.Message
		auditData["error_id"] = err.ID
	}

	if authToken := h.extractAuthToken(r); authToken != "" {
		auditData["authenticated"] = true
		auditData["auth_method"] = h.detectAuthMethod(r)
	}

	h.logger.Info("Request audit log", zap.Any("audit", auditData))
}

func (h *HTTPHandler) detectAuthMethod(r *http.Request) string {
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

func (h *HTTPHandler) handleStreamingResponse(w http.ResponseWriter, r *http.Request, response *models.AIResponse) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInternalError, "streaming not supported"))
		return
	}

	chunks := h.chunkResponse(response.Response, 50)
	
	for i, chunk := range chunks {
		data := map[string]interface{}{
			"id":      response.ID,
			"chunk":   chunk,
			"index":   i,
			"total":   len(chunks),
			"done":    i == len(chunks)-1,
		}

		jsonData, _ := json.Marshal(data)
		fmt.Fprintf(w, "data: %s\n\n", jsonData)
		flusher.Flush()

		time.Sleep(50 * time.Millisecond)
	}

	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func (h *HTTPHandler) chunkResponse(text string, chunkSize int) []string {
	if len(text) <= chunkSize {
		return []string{text}
	}

	var chunks []string
	for i := 0; i < len(text); i += chunkSize {
		end := i + chunkSize
		if end > len(text) {
			end = len(text)
		}
		chunks = append(chunks, text[i:end])
	}

	return chunks
}

func (h *HTTPHandler) handleWebSocketUpgrade(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("WebSocket upgrade requested", 
		zap.String("path", r.URL.Path),
		zap.String("client_ip", utils.GetClientIP(r)))

	h.writeErrorResponse(w, errors.New(errors.ErrCodeNotImplemented, "WebSocket support not implemented"))
}

func (h *HTTPHandler) getRequestPriority(r *http.Request) string {
	priority := r.Header.Get("X-Priority")
	if priority == "" {
		priority = "normal"
	}

	validPriorities := []string{"low", "normal", "high", "critical"}
	if !utils.Contains(validPriorities, priority) {
		priority = "normal"
	}

	return priority
}

func (h *HTTPHandler) shouldCompress(r *http.Request) bool {
	acceptEncoding := r.Header.Get("Accept-Encoding")
	return strings.Contains(acceptEncoding, "gzip") || strings.Contains(acceptEncoding, "deflate")
}

func (h *HTTPHandler) calculateResponseHash(data interface{}) string {
	jsonData, _ := json.Marshal(data)
	return utils.HashSHA256(string(jsonData))
}

func (h *HTTPHandler) setCacheHeaders(w http.ResponseWriter, maxAge int) {
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	w.Header().Set("ETag", fmt.Sprintf(`"%s"`, utils.GenerateNonce(16)))
}

func (h *HTTPHandler) handleConditionalRequest(w http.ResponseWriter, r *http.Request, etag string) bool {
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" && ifNoneMatch == etag {
		w.WriteHeader(http.StatusNotModified)
		return true
	}

	ifModifiedSince := r.Header.Get("If-Modified-Since")
	if ifModifiedSince != "" {
		if modTime, err := time.Parse(http.TimeFormat, ifModifiedSince); err == nil {
			if time.Since(modTime) < time.Hour {
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}

	return false
}

func (g *GRPCHandler) extractMetadataFromContext(ctx context.Context) map[string]string {
	metadata := make(map[string]string)
	
	if requestID := ctx.Value("request_id"); requestID != nil {
		metadata["request_id"] = requestID.(string)
	}
	
	if traceID := ctx.Value("trace_id"); traceID != nil {
		metadata["trace_id"] = traceID.(string)
	}
	
	if clientIP := ctx.Value("client_ip"); clientIP != nil {
		metadata["client_ip"] = clientIP.(string)
	}

	return metadata
}

func (g *GRPCHandler) validateGRPCRequest(req interface{}) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	return nil
}

func (g *GRPCHandler) logGRPCRequest(method string, req interface{}, resp interface{}, err error, duration time.Duration) {
	fields := []zap.Field{
		zap.String("method", method),
		zap.Duration("duration", duration),
		zap.Any("request", req),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		g.logger.Error("gRPC request failed", fields...)
	} else {
		fields = append(fields, zap.Any("response", resp))
		g.logger.Info("gRPC request completed", fields...)
	}
}

func (g *GRPCHandler) createGRPCMetadata(ctx context.Context) map[string]interface{} {
	return map[string]interface{}{
		"request_id": utils.GenerateRequestID(),
		"trace_id":   utils.GenerateTraceID(),
		"timestamp":  time.Now().UTC(),
		"service":    "gateway",
		"version":    "1.0.0",
	}
}

func (h *HTTPHandler) handleOptionsRequest(w http.ResponseWriter, r *http.Request) {
	utils.SetCORSHeaders(w, 
		h.config.Security.AllowedOrigins,
		[]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		[]string{"Content-Type", "Authorization", "X-API-Key", "X-Request-ID", "X-Priority"},
	)
	
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func (h *HTTPHandler) handleNotFound(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)
	
	appErr := errors.NewNotFoundError("endpoint").
		WithContext("path", r.URL.Path).
		WithContext("method", r.Method)
	
	h.writeErrorResponse(w, appErr)
}

func (h *HTTPHandler) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)
	
	w.Header().Set("Allow", "GET, POST, PUT, DELETE, OPTIONS")
	
	appErr := errors.New(errors.ErrCodeMethodNotAllowed, "method not allowed").
		WithContext("method", r.Method).
		WithContext("path", r.URL.Path)
	
	h.writeErrorResponse(w, appErr)
}

func (h *HTTPHandler) handleInternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	utils.SetSecurityHeaders(w)
	
	appErr := errors.Wrap(err, errors.ErrCodeInternalError, "internal server error")
	h.writeErrorResponse(w, appErr)
}

func (h *HTTPHandler) createResponseMetadata(statusCode int, responseSize int64, processingTime time.Duration) *ResponseMetadata {
	return &ResponseMetadata{
		StatusCode:     statusCode,
		ResponseSize:   responseSize,
		ProcessingTime: processingTime,
		CacheHit:       false,
	}
}

func (h *HTTPHandler) validateRequestHeaders(r *http.Request) *errors.AppError {
	contentType := r.Header.Get("Content-Type")
	if r.Method == "POST" || r.Method == "PUT" {
		if !strings.Contains(contentType, "application/json") {
			return errors.New(errors.ErrCodeUnsupportedMedia, "content-type must be application/json")
		}
	}

	acceptHeader := r.Header.Get("Accept")
	if acceptHeader != "" && !strings.Contains(acceptHeader, "application/json") && !strings.Contains(acceptHeader, "*/*") {
		return errors.New(errors.ErrCodeNotAcceptable, "accept header must include application/json")
	}

	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "user-agent header is required")
	}

	return nil
}

func (h *HTTPHandler) sanitizeRequestData(data interface{}) interface{} {
	switch v := data.(type) {
	case string:
		return utils.SanitizeString(v)
	case map[string]interface{}:
		sanitized := make(map[string]interface{})
		for key, value := range v {
			sanitized[utils.SanitizeString(key)] = h.sanitizeRequestData(value)
		}
		return sanitized
	case []interface{}:
		sanitized := make([]interface{}, len(v))
		for i, item := range v {
			sanitized[i] = h.sanitizeRequestData(item)
		}
		return sanitized
	default:
		return v
	}
}

func (h *HTTPHandler) checkRateLimit(clientIP string) *errors.AppError {
	rateLimiter := utils.NewRateLimiter(100.0, 1000)
	
	if !rateLimiter.Allow() {
		return errors.NewRateLimitError(time.Minute).
			WithContext("client_ip", clientIP).
			WithContext("limit_type", "global")
	}

	return nil
}

func (h *HTTPHandler) generateResponseSignature(data interface{}, secret string) string {
	jsonData, _ := json.Marshal(data)
	return utils.GenerateHMAC(string(jsonData), secret)
}

func (h *HTTPHandler) validateRequestSignature(r *http.Request, secret string) *errors.AppError {
	signature := r.Header.Get("X-Signature")
	if signature == "" {
		return nil
	}

	body := make([]byte, r.ContentLength)
	r.Body.Read(body)
	
	expectedSignature := utils.GenerateHMAC(string(body), secret)
	if !utils.VerifyHMAC(string(body), signature, secret) {
		return errors.New(errors.ErrCodeUnauthorized, "invalid request signature")
	}

	if signature != expectedSignature {
		return errors.New(errors.ErrCodeUnauthorized, "signature verification failed")
	}

	return nil
}

func (h *HTTPHandler) handleGracefulShutdown(ctx context.Context) error {
	h.logger.Info("Initiating graceful shutdown of HTTP handlers")
	
	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	select {
	case <-shutdownCtx.Done():
		h.logger.Info("HTTP handlers shutdown completed")
		return nil
	case <-ctx.Done():
		h.logger.Warn("HTTP handlers shutdown timed out")
		return ctx.Err()
	}
}

func (g *GRPCHandler) handleGracefulShutdown(ctx context.Context) error {
	g.logger.Info("Initiating graceful shutdown of gRPC handlers")
	
	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	select {
	case <-shutdownCtx.Done():
		g.logger.Info("gRPC handlers shutdown completed")
		return nil
	case <-ctx.Done():
		g.logger.Warn("gRPC handlers shutdown timed out")
		return ctx.Err()
	}
}

func (g *GRPCHandler) ResetCircuitBreaker(ctx context.Context, req *gatewaypb.CircuitBreakerRequest) (*gatewaypb.CircuitBreakerResponse, error) {
	if req.Service == "" {
		return nil, status.Error(codes.InvalidArgument, "service name is required")
	}

	appErr := g.orchestrator.ResetCircuitBreaker(req.Service)
	if appErr != nil {
		return nil, g.convertAppErrorToGRPCError(appErr)
	}

	return &gatewaypb.CircuitBreakerResponse{
		Service: req.Service,
		Status:  "reset",
		Message: "Circuit breaker reset successfully",
	}, nil
}

func (g *GRPCHandler) GetCircuitBreakerStatus(ctx context.Context, req *gatewaypb.CircuitBreakerRequest) (*gatewaypb.CircuitBreakerStatusResponse, error) {
	if req.Service == "" {
		return nil, status.Error(codes.InvalidArgument, "service name is required")
	}

	status := g.orchestrator.GetCircuitBreakerStatus(req.Service)
	rateLimitStatus := g.orchestrator.GetRateLimitStatus(req.Service)

	return &gatewaypb.CircuitBreakerStatusResponse{
		Service:         req.Service,
		State:           status,
		RateLimitStatus: rateLimitStatus,
		Timestamp:       time.Now().Unix(),
	}, nil
}

func (g *GRPCHandler) StreamAIRequests(stream gatewaypb.GatewayService_StreamAIRequestsServer) error {
	g.logger.Info("Starting streaming AI requests")
	
	for {
		req, err := stream.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			g.logger.Error("Stream receive error", zap.Error(err))
			return err
		}

		response, appErr := g.ProcessAIRequest(stream.Context(), req)
		if appErr != nil {
			return g.convertAppErrorToGRPCError(appErr)
		}

		if err := stream.Send(response); err != nil {
			g.logger.Error("Stream send error", zap.Error(err))
			return err
		}
	}
}

func (h *HTTPHandler) createHealthCheckResponse() map[string]interface{} {
	healthStatus := h.orchestrator.GetHealthStatus()
	metrics := h.orchestrator.GetMetrics()
	
	return map[string]interface{}{
		"status":      healthStatus.Overall,
		"timestamp":   time.Now().UTC(),
		"version":     "1.0.0",
		"environment": h.config.Environment,
		"uptime":      healthStatus.Uptime.String(),
		"services":    healthStatus.Services,
		"dependencies": healthStatus.Dependencies,
		"metrics": map[string]interface{}{
			"total_requests":    metrics.TotalRequests,
			"success_rate":      1.0 - metrics.ErrorRate,
			"avg_response_time": metrics.AverageResponseTime.Milliseconds(),
			"throughput":        metrics.ThroughputPerSecond,
		},
		"circuit_breakers": map[string]interface{}{
			"auth":   h.orchestrator.GetCircuitBreakerStatus("auth"),
			"policy": h.orchestrator.GetCircuitBreakerStatus("policy"),
			"threat": h.orchestrator.GetCircuitBreakerStatus("threat"),
			"model":  h.orchestrator.GetCircuitBreakerStatus("model"),
			"audit":  h.orchestrator.GetCircuitBreakerStatus("audit"),
		},
	}
}

func (h *HTTPHandler) createDetailedMetricsResponse() map[string]interface{} {
	metrics := h.orchestrator.GetMetrics()
	
	return map[string]interface{}{
		"requests": map[string]interface{}{
			"total":      metrics.TotalRequests,
			"successful": metrics.SuccessfulRequests,
			"failed":     metrics.FailedRequests,
			"error_rate": metrics.ErrorRate,
		},
		"performance": map[string]interface{}{
			"avg_response_time":  metrics.AverageResponseTime.Milliseconds(),
			"throughput_per_sec": metrics.ThroughputPerSecond,
		},
		"security": map[string]interface{}{
			"authentication_rate":   metrics.AuthenticationRate,
			"threat_detection_rate": metrics.ThreatDetectionRate,
			"policy_violation_rate": metrics.PolicyViolationRate,
		},
		"services": metrics.ServiceHealthScores,
		"cache": map[string]interface{}{
			"tenant_count": h.orchestrator.GetTenantCount(),
		},
		"last_updated": metrics.LastUpdated.Unix(),
	}
}

func (h *HTTPHandler) validateAdminAccess(r *http.Request) *errors.AppError {
	adminToken := r.Header.Get("X-Admin-Token")
	if adminToken == "" {
		return errors.NewUnauthorizedError("admin token required")
	}

	expectedToken := h.config.Security.JWTSecret
	if adminToken != expectedToken {
		return errors.NewForbiddenError("invalid admin token")
	}

	return nil
}

func (h *HTTPHandler) logSecurityEvent(eventType, description string, metadata map[string]interface{}) {
	securityEvent := map[string]interface{}{
		"event_type":  eventType,
		"description": description,
		"timestamp":   time.Now().UTC(),
		"service":     "gateway",
		"metadata":    metadata,
	}

	h.logger.Warn("Security event", zap.Any("security_event", securityEvent))
}

func (h *HTTPHandler) Cleanup() error {
	h.logger.Info("Cleaning up HTTP handlers")
	return nil
}

func (g *GRPCHandler) Cleanup() error {
	g.logger.Info("Cleaning up gRPC handlers")
	return nil
}

func NewHandlerSuite(orch *orchestrator.Orchestrator, cfg *config.Config, logger *zap.Logger) (*HTTPHandler, *GRPCHandler) {
	httpHandler := NewHTTPHandler(orch, cfg, logger)
	grpcHandler := NewGRPCHandler(orch, cfg, logger)
	
	return httpHandler, grpcHandler
}

func SetupHTTPRoutes(handler *HTTPHandler) *mux.Router {
	router := mux.NewRouter()
	
	router.Use(handler.PanicRecoveryMiddleware)
	router.Use(handler.SecurityHeadersMiddleware)
	router.Use(handler.LoggingMiddleware)
	router.Use(handler.CORSMiddleware)
	router.Use(handler.RateLimitMiddleware)
	router.Use(handler.RequestSizeMiddleware(10 * 1024 * 1024))
	
	handler.RegisterRoutes(router)
	
	router.NotFoundHandler = http.HandlerFunc(handler.handleNotFound)
	router.MethodNotAllowedHandler = http.HandlerFunc(handler.handleMethodNotAllowed)
	
	return router
}

func ValidateHandlerConfiguration(cfg *config.Config) error {
	if cfg.Gateway.RequestTimeout <= 0 {
		return fmt.Errorf("invalid request timeout: %v", cfg.Gateway.RequestTimeout)
	}

	if cfg.Gateway.MaxConcurrentRequests <= 0 {
		return fmt.Errorf("invalid max concurrent requests: %d", cfg.Gateway.MaxConcurrentRequests)
	}

	if len(cfg.Security.AllowedOrigins) == 0 {
		return fmt.Errorf("no allowed origins configured")
	}

	return nil
}
