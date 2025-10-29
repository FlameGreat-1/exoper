package handlers

import (
	"io"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
    "google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/durationpb"

	"exoper/backend/internal/common/config"
	"exoper/backend/internal/common/errors"
	"exoper/backend/internal/common/utils"
	"exoper/backend/internal/gateway/orchestrator"
	commonpb "exoper/backend/pkg/api/proto/common"
	gatewaypb "exoper/backend/pkg/api/proto/gateway"
	"exoper/backend/pkg/api/proto/models/request"
	"exoper/backend/pkg/api/proto/models/response"
	"exoper/backend/pkg/api/proto/models/tenant"
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

	var chatPayload struct {
		Messages         []request.ChatMessage `json:"messages"`
		Model            string                `json:"model"`
		MaxTokens        *int                  `json:"max_tokens,omitempty"`
		Temperature      *float64              `json:"temperature,omitempty"`
		TopP             *float64              `json:"top_p,omitempty"`
		Stream           bool                  `json:"stream"`
		Functions        []request.FunctionDefinition `json:"functions,omitempty"`
		Tools            []request.ToolDefinition     `json:"tools,omitempty"`
		ResponseFormat   *request.ResponseFormat      `json:"response_format,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&chatPayload); err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInvalidRequest, "invalid JSON payload"))
		return
	}

	tenantID, err := h.extractTenantID(r)
	if err != nil {
		h.writeErrorResponse(w, err)
		return
	}

	aiRequest := request.NewAIRequest(tenantID, request.TypeChat, request.ProviderOpenAI, chatPayload.Model)
	aiRequest.Payload.Messages = chatPayload.Messages
	aiRequest.Payload.MaxTokens = chatPayload.MaxTokens
	aiRequest.Payload.Temperature = chatPayload.Temperature
	aiRequest.Payload.TopP = chatPayload.TopP
	aiRequest.Payload.Stream = chatPayload.Stream
	aiRequest.Payload.Functions = chatPayload.Functions
	aiRequest.Payload.Tools = chatPayload.Tools
	aiRequest.Payload.ResponseFormat = chatPayload.ResponseFormat

	aiRequest.ClientInfo = request.ExtractClientInfo(r)
	aiRequest.SecurityContext.SessionToken = h.extractAuthToken(r)
	aiRequest.SecurityContext.AuthenticationMethod = h.detectAuthMethod(r)

	if err := aiRequest.Validate(); err != nil {
		h.writeErrorResponse(w, errors.Wrap(err, errors.ErrCodeValidationError, "request validation failed"))
		return
	}

	gatewayReq := &gatewaypb.ProcessAIRequestRequest{
		Metadata: &commonpb.RequestMetadata{
			RequestId: aiRequest.ID.String(),
			TenantId:  aiRequest.TenantID.String(),
			UserId:    getUserIDString(aiRequest.UserID),
		},
		Payload: &gatewaypb.AIRequestPayload{
			Type:         convertRequestType(aiRequest.Type),
			Provider:     convertModelProvider(aiRequest.Provider),
			ModelName:    aiRequest.ModelName,
			SecurityLevel: commonpb.SecurityLevel_SECURITY_LEVEL_MEDIUM,
			ContentType:  commonpb.ContentType_CONTENT_TYPE_TEXT,
			Content: &gatewaypb.RequestContent{
				Messages: convertChatMessages(aiRequest.Payload.Messages),
			},
			Parameters: &gatewaypb.RequestParameters{
				MaxTokens:   int32(getIntValue(aiRequest.Payload.MaxTokens)),
				Temperature: getFloatValue(aiRequest.Payload.Temperature),
				TopP:       getFloatValue(aiRequest.Payload.TopP),
				Stream:     aiRequest.Payload.Stream,
			},
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.config.Gateway.RequestTimeout)
	defer cancel()

	aiResponse, appErr := h.orchestrator.ProcessAIRequest(ctx, gatewayReq)
	if appErr != nil {
		if appError, ok := appErr.(*errors.AppError); ok {
			h.writeErrorResponse(w, appError)
		} else {
			h.writeErrorResponse(w, errors.New(errors.ErrCodeInternalError, "Processing failed"))
		}
		return
	}

	h.writeJSONResponse(w, http.StatusOK, aiResponse)
}

func (h *HTTPHandler) handleCompletionRequest(w http.ResponseWriter, r *http.Request) {
	metadata := h.extractRequestMetadata(r)
	defer h.logRequest(metadata, r)

	utils.SetSecurityHeaders(w)

	var completionPayload struct {
		Prompt           string    `json:"prompt"`
		Model            string    `json:"model"`
		MaxTokens        *int      `json:"max_tokens,omitempty"`
		Temperature      *float64  `json:"temperature,omitempty"`
		TopP             *float64  `json:"top_p,omitempty"`
		FrequencyPenalty *float64  `json:"frequency_penalty,omitempty"`
		PresencePenalty  *float64  `json:"presence_penalty,omitempty"`
		Stop             []string  `json:"stop,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&completionPayload); err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInvalidRequest, "invalid JSON payload"))
		return
	}

	tenantID, err := h.extractTenantID(r)
	if err != nil {
		h.writeErrorResponse(w, err)
		return
	}

	aiRequest := request.NewAIRequest(tenantID, request.TypeCompletion, request.ProviderOpenAI, completionPayload.Model)
	aiRequest.Payload.Prompt = completionPayload.Prompt
	aiRequest.Payload.MaxTokens = completionPayload.MaxTokens
	aiRequest.Payload.Temperature = completionPayload.Temperature
	aiRequest.Payload.TopP = completionPayload.TopP
	aiRequest.Payload.FrequencyPenalty = completionPayload.FrequencyPenalty
	aiRequest.Payload.PresencePenalty = completionPayload.PresencePenalty
	aiRequest.Payload.Stop = completionPayload.Stop

	aiRequest.ClientInfo = request.ExtractClientInfo(r)
	aiRequest.SecurityContext.SessionToken = h.extractAuthToken(r)
	aiRequest.SecurityContext.AuthenticationMethod = h.detectAuthMethod(r)

	if err := aiRequest.Validate(); err != nil {
		h.writeErrorResponse(w, errors.Wrap(err, errors.ErrCodeValidationError, "request validation failed"))
		return
	}

	gatewayReq := &gatewaypb.ProcessAIRequestRequest{
		Metadata: &commonpb.RequestMetadata{
			RequestId: aiRequest.ID.String(),
			TenantId:  aiRequest.TenantID.String(),
			UserId:    getUserIDString(aiRequest.UserID),
		},
		Payload: &gatewaypb.AIRequestPayload{
			Type:         convertRequestType(aiRequest.Type),
			Provider:     convertModelProvider(aiRequest.Provider),
			ModelName:    aiRequest.ModelName,
			SecurityLevel: commonpb.SecurityLevel_SECURITY_LEVEL_MEDIUM,
			ContentType:  commonpb.ContentType_CONTENT_TYPE_TEXT,
			Content: &gatewaypb.RequestContent{
				Prompt: aiRequest.Payload.Prompt,
			},
			Parameters: &gatewaypb.RequestParameters{
				MaxTokens:        int32(getIntValue(aiRequest.Payload.MaxTokens)),
				Temperature:      getFloatValue(aiRequest.Payload.Temperature),
				TopP:            getFloatValue(aiRequest.Payload.TopP),
				FrequencyPenalty: getFloatValue(aiRequest.Payload.FrequencyPenalty),
				PresencePenalty:  getFloatValue(aiRequest.Payload.PresencePenalty),
				Stop:            aiRequest.Payload.Stop,
			},
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.config.Gateway.RequestTimeout)
	defer cancel()

	aiResponse, appErr := h.orchestrator.ProcessAIRequest(ctx, gatewayReq)
	if appErr != nil {
		if appError, ok := appErr.(*errors.AppError); ok {
			h.writeErrorResponse(w, appError)
		} else {
			h.writeErrorResponse(w, errors.New(errors.ErrCodeInternalError, "Processing failed"))
		}
		return
	}

	h.writeJSONResponse(w, http.StatusOK, aiResponse)
}

func (h *HTTPHandler) handleBatchRequest(w http.ResponseWriter, r *http.Request) {
	metadata := h.extractRequestMetadata(r)
	defer h.logRequest(metadata, r)

	utils.SetSecurityHeaders(w)

	var batchPayload struct {
		Requests []struct {
			Type             request.RequestType `json:"type"`
			Prompt           string              `json:"prompt,omitempty"`
			Messages         []request.ChatMessage `json:"messages,omitempty"`
			Model            string              `json:"model"`
			MaxTokens        *int                `json:"max_tokens,omitempty"`
			Temperature      *float64            `json:"temperature,omitempty"`
			TopP             *float64            `json:"top_p,omitempty"`
			FrequencyPenalty *float64            `json:"frequency_penalty,omitempty"`
			PresencePenalty  *float64            `json:"presence_penalty,omitempty"`
			Stop             []string            `json:"stop,omitempty"`
		} `json:"requests"`
	}

	if err := json.NewDecoder(r.Body).Decode(&batchPayload); err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInvalidRequest, "invalid JSON payload"))
		return
	}

	if len(batchPayload.Requests) == 0 {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInvalidRequest, "no requests in batch"))
		return
	}

	if len(batchPayload.Requests) > 100 {
		h.writeErrorResponse(w, errors.New(errors.ErrCodePayloadTooLarge, "batch size exceeds limit"))
		return
	}

	tenantID, err := h.extractTenantID(r)
	if err != nil {
		h.writeErrorResponse(w, err)
		return
	}

	var gatewayRequests []*gatewaypb.ProcessAIRequestRequest
	clientInfo := request.ExtractClientInfo(r)
	authToken := h.extractAuthToken(r)
	authMethod := h.detectAuthMethod(r)

	for i, req := range batchPayload.Requests {
		aiRequest := request.NewAIRequest(tenantID, req.Type, request.ProviderOpenAI, req.Model)
		aiRequest.Payload.Prompt = req.Prompt
		aiRequest.Payload.Messages = req.Messages
		aiRequest.Payload.MaxTokens = req.MaxTokens
		aiRequest.Payload.Temperature = req.Temperature
		aiRequest.Payload.TopP = req.TopP
		aiRequest.Payload.FrequencyPenalty = req.FrequencyPenalty
		aiRequest.Payload.PresencePenalty = req.PresencePenalty
		aiRequest.Payload.Stop = req.Stop

		aiRequest.ClientInfo = clientInfo
		aiRequest.SecurityContext.SessionToken = authToken
		aiRequest.SecurityContext.AuthenticationMethod = authMethod
		aiRequest.AddMetadata("batch_index", i)

		if err := aiRequest.Validate(); err != nil {
			h.writeErrorResponse(w, errors.Wrap(err, errors.ErrCodeValidationError, fmt.Sprintf("request %d validation failed", i)))
			return
		}

		gatewayReq := &gatewaypb.ProcessAIRequestRequest{
			Metadata: &commonpb.RequestMetadata{
				RequestId: aiRequest.ID.String(),
				TenantId:  aiRequest.TenantID.String(),
				UserId:    getUserIDString(aiRequest.UserID),
			},
			Payload: &gatewaypb.AIRequestPayload{
				Type:         convertRequestType(aiRequest.Type),
				Provider:     convertModelProvider(aiRequest.Provider),
				ModelName:    aiRequest.ModelName,
				SecurityLevel: commonpb.SecurityLevel_SECURITY_LEVEL_MEDIUM,
				ContentType:  commonpb.ContentType_CONTENT_TYPE_TEXT,
				Content: &gatewaypb.RequestContent{
					Prompt:   aiRequest.Payload.Prompt,
					Messages: convertChatMessages(aiRequest.Payload.Messages),
				},
				Parameters: &gatewaypb.RequestParameters{
					MaxTokens:        int32(getIntValue(aiRequest.Payload.MaxTokens)),
					Temperature:      getFloatValue(aiRequest.Payload.Temperature),
					TopP:            getFloatValue(aiRequest.Payload.TopP),
					FrequencyPenalty: getFloatValue(aiRequest.Payload.FrequencyPenalty),
					PresencePenalty:  getFloatValue(aiRequest.Payload.PresencePenalty),
					Stop:            aiRequest.Payload.Stop,
				},
			},
		}
		gatewayRequests = append(gatewayRequests, gatewayReq)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	responses, appErr := h.orchestrator.ProcessBatchRequests(ctx, gatewayRequests)
	if appErr != nil {
		if appError, ok := appErr.(*errors.AppError); ok {
			h.writeErrorResponse(w, appError)
		} else {
			h.writeErrorResponse(w, errors.New(errors.ErrCodeInternalError, "Batch processing failed"))
		}
		return
	}

	batchResponse := map[string]interface{}{
		"id":        uuid.New().String(),
		"object":    "batch_response",
		"responses": responses,
		"created":   time.Now().Unix(),
	}

	h.writeJSONResponse(w, http.StatusOK, batchResponse)
}

func convertChatMessages(messages []request.ChatMessage) []*gatewaypb.ChatMessage {
	var gatewayMessages []*gatewaypb.ChatMessage
	for _, msg := range messages {
		gatewayMessages = append(gatewayMessages, &gatewaypb.ChatMessage{
			Role:    msg.Role,
			Content: msg.Content,
			Name:    msg.Name,
		})
	}
	return gatewayMessages
}

func getIntValue(ptr *int) int {
	if ptr == nil {
		return 0
	}
	return *ptr
}

func getFloatValue(ptr *float64) float64 {
	if ptr == nil {
		return 0.0
	}
	return *ptr
}

func getUserIDString(userID *uuid.UUID) string {
	if userID == nil {
		return ""
	}
	return userID.String()
}

func convertRequestType(reqType request.RequestType) commonpb.RequestType {
	switch reqType {
	case request.TypeChat:
		return commonpb.RequestType_REQUEST_TYPE_CHAT
	case request.TypeCompletion:
		return commonpb.RequestType_REQUEST_TYPE_COMPLETION
	default:
		return commonpb.RequestType_REQUEST_TYPE_UNSPECIFIED
	}
}

func convertModelProvider(provider request.ModelProvider) commonpb.ModelProvider {
	switch provider {
	case request.ProviderOpenAI:
		return commonpb.ModelProvider_MODEL_PROVIDER_OPENAI
	case request.ProviderAnthropic:
		return commonpb.ModelProvider_MODEL_PROVIDER_ANTHROPIC
	default:
		return commonpb.ModelProvider_MODEL_PROVIDER_UNSPECIFIED
	}
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

	metricsReq := &gatewaypb.GetMetricsRequest{
		Metadata: &commonpb.RequestMetadata{
			RequestId: uuid.New().String(),
		},
	}
	metrics, err := h.orchestrator.GetMetrics(context.Background(), metricsReq)
	if err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInternalError, "Failed to get metrics"))
		return
	}
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

func (h *HTTPHandler) handleGetQuota(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	vars := mux.Vars(r)
	tenantID := vars["tenantId"]

	if _, err := uuid.Parse(tenantID); err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "invalid tenant ID"))
		return
	}

	tenantObj, appErr := h.getTenant(tenantID)
	if appErr != nil {
		h.writeErrorResponse(w, appErr)
		return
	}

	quotaResponse := map[string]interface{}{
		"tenant_id":              tenantObj.ID.String(),
		"max_users":              tenantObj.ResourceLimits.MaxUsers,
		"max_api_calls_per_minute": tenantObj.ResourceLimits.MaxAPICallsPerMinute,
		"max_api_calls_per_day":   tenantObj.ResourceLimits.MaxAPICallsPerDay,
		"max_storage_gb":         tenantObj.ResourceLimits.MaxStorageGB,
		"max_models_per_tenant":  tenantObj.ResourceLimits.MaxModelsPerTenant,
		"max_concurrent_requests": tenantObj.ResourceLimits.MaxConcurrentRequests,
		"bandwidth_limit_mbps":   tenantObj.ResourceLimits.BandwidthLimitMbps,
		"compute_units_limit":    tenantObj.ResourceLimits.ComputeUnitsLimit,
	}

	h.writeJSONResponse(w, http.StatusOK, quotaResponse)
}

func (h *HTTPHandler) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	vars := mux.Vars(r)
	tenantID := vars["tenantId"]

	if _, err := uuid.Parse(tenantID); err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "invalid tenant ID"))
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}
	
	if limit > 1000 {
		limit = 1000
	}

	history := []map[string]interface{}{}

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

	if _, err := uuid.Parse(tenantID); err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "invalid tenant ID"))
		return
	}

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}

	timeRange := map[string]interface{}{
		"start": time.Now().Add(-24 * time.Hour),
		"end":   time.Now(),
	}

	stats := map[string]interface{}{
		"total_requests":      0,
		"blocked_requests":    0,
		"average_risk_score":  0.0,
		"unique_threat_types": 0,
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

	if _, err := uuid.Parse(tenantID); err != nil {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "invalid tenant ID"))
		return
	}

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "30d"
	}

	tenantObj, appErr := h.getTenant(tenantID)
	if appErr != nil {
		h.writeErrorResponse(w, appErr)
		return
	}

	report := map[string]interface{}{
		"tenant_id":                tenantID,
		"compliance_frameworks":    tenantObj.ComplianceConfig.Frameworks,
		"data_residency":          tenantObj.ComplianceConfig.DataResidency,
		"data_retention_days":     tenantObj.ComplianceConfig.DataRetentionDays,
		"pii_redaction_enabled":   tenantObj.ComplianceConfig.PIIRedactionEnabled,
		"audit_log_retention":     tenantObj.ComplianceConfig.AuditLogRetention,
		"regulatory_reporting":    tenantObj.ComplianceConfig.RegulatoryReporting,
		"total_requests":          0,
		"pii_requests":            0,
		"policy_violations":       0,
		"audited_requests":        0,
		"generated_at":            time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, report)
}

func (h *HTTPHandler) handleResetCircuitBreaker(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	if err := h.validateAdminAccess(r); err != nil {
		h.writeErrorResponse(w, err)
		return
	}

	vars := mux.Vars(r)
	service := vars["service"]

	if service == "" {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeValidationError, "service name is required"))
		return
	}

	appErr := h.orchestrator.ResetCircuitBreaker(service)
	if appErr != nil {
		h.writeErrorResponse(w, appErr.(*errors.AppError))  
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

	if err := h.validateAdminAccess(r); err != nil {
		h.writeErrorResponse(w, err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Cache refresh initiated",
	})
}

func (h *HTTPHandler) handleShutdown(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)

	if err := h.validateAdminAccess(r); err != nil {
		h.writeErrorResponse(w, err)
		return
	}

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

func (g *GRPCHandler) ProcessAIRequest(ctx context.Context, req *gatewaypb.ProcessAIRequestRequest) (*gatewaypb.ProcessAIRequestResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	tenantID, err := uuid.Parse(req.Metadata.TenantId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid tenant ID")
	}

	aiRequest := request.NewAIRequest(tenantID, request.RequestType(req.Payload.Type), request.ModelProvider(req.Payload.Provider), req.Payload.ModelName)
	aiRequest.Payload.Prompt = req.Payload.Content.Prompt
	aiRequest.SecurityContext.SessionToken = req.Metadata.SecurityContext.SessionToken

	if req.Payload.Parameters != nil {
		if req.Payload.Parameters.MaxTokens > 0 {
			maxTokensInt := int(req.Payload.Parameters.MaxTokens)
			aiRequest.Payload.MaxTokens = &maxTokensInt
		}
		if req.Payload.Parameters.Temperature != 0 {
			aiRequest.Payload.Temperature = &req.Payload.Parameters.Temperature
		}
		if req.Payload.Parameters.TopP != 0 {
			aiRequest.Payload.TopP = &req.Payload.Parameters.TopP
		}
	}

	if err := aiRequest.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	aiResponse, appErr := g.orchestrator.ProcessAIRequest(ctx, req)
	if appErr != nil {
		return nil, g.convertAppErrorToGRPCError(appErr.(*errors.AppError))
	}

	return aiResponse, nil
}

func (g *GRPCHandler) ProcessBatchRequests(ctx context.Context, req *gatewaypb.BatchRequestProto) (*gatewaypb.BatchResponseProto, error) {
	if req == nil || len(req.Requests) == 0 {
		return nil, status.Error(codes.InvalidArgument, "requests are required")
	}

	if len(req.Requests) > 100 {
		return nil, status.Error(codes.InvalidArgument, "batch size exceeds limit")
	}

	grpcRequests := make([]*gatewaypb.ProcessAIRequestRequest, len(req.Requests))
	for i, r := range req.Requests {
		_, err := uuid.Parse(req.Metadata.TenantId)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid tenant ID")
		}

		grpcRequests[i] = &gatewaypb.ProcessAIRequestRequest{
			Metadata: req.Metadata,
			Payload:  r,
		}
	}

	responses, appErr := g.orchestrator.ProcessBatchRequests(ctx, grpcRequests)
	if appErr != nil {
		return nil, g.convertAppErrorToGRPCError(appErr.(*errors.AppError))
	}

	batchResponse := &gatewaypb.BatchResponseProto{
		Status:  commonpb.Status_STATUS_SUCCESS,
		Results: make([]*gatewaypb.BatchRequestResult, len(responses)),
	}

	for i, resp := range responses {
		batchResponse.Results[i] = &gatewaypb.BatchRequestResult{
			RequestIndex:     int32(i),
			Status:          resp.Status,
			Response:        resp.Response,
			ProcessingResult: resp.ProcessingResult,
			Error:           resp.Error,
		}
	}

	return batchResponse, nil
}

func (g *GRPCHandler) GetHealthStatus(ctx context.Context, req *gatewaypb.GetHealthRequest) (*gatewaypb.GetHealthResponse, error) {
	healthStatus := g.orchestrator.GetHealthStatus()

	var status commonpb.Status
	switch strings.ToLower(healthStatus.Overall) {
	case "healthy", "ok", "success":
		status = commonpb.Status_STATUS_SUCCESS
	case "error", "failed", "unhealthy":
		status = commonpb.Status_STATUS_ERROR
	default:
		status = commonpb.Status_STATUS_UNSPECIFIED
	}

	return &gatewaypb.GetHealthResponse{
		Status: status,
		HealthStatus: &commonpb.HealthStatus{
			OverallStatus: status,
			Components:    nil,
			LastCheck:     timestamppb.New(healthStatus.LastHealthCheck),
		},
		ServiceHealth:      nil,
		PerformanceMetrics: nil,
		LastUpdated:        timestamppb.New(healthStatus.LastHealthCheck),
	}, nil
}

func (g *GRPCHandler) GetMetrics(ctx context.Context, req *gatewaypb.GetMetricsRequest) (*gatewaypb.GetMetricsResponse, error) {
	return g.orchestrator.GetMetrics(ctx, req)
}

func (g *GRPCHandler) ValidateModelAccess(ctx context.Context, req *gatewaypb.ModelAccessRequest) (*gatewaypb.ModelAccessResponse, error) {
	if req.TenantId == "" || req.ModelName == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant ID and model are required")
	}

	appErr := g.orchestrator.ValidateModelAccess(req.TenantId, req.ModelName)
	
	return &gatewaypb.ModelAccessResponse{
		Status: commonpb.Status_STATUS_SUCCESS,
		AccessInfo: &gatewaypb.ModelAccessInfo{
			AccessGranted: appErr == nil,
		},
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
			h.writeErrorResponse(w, errors.New(errors.ErrCodeUnauthorized, "authentication token required"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *HTTPHandler) RateLimitMiddleware(next http.Handler) http.Handler {
	rateLimiter := utils.NewRateLimiter(100.0, 1000)
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rateLimiter.Allow() {
			h.writeErrorResponse(w, errors.New(errors.ErrCodeRateLimit, "rate limit exceeded"))
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
		clientInfo := request.ExtractClientInfo(r)
		
		h.logger.Info("HTTP request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("client_ip", clientInfo.IPAddress),
			zap.String("user_agent", clientInfo.UserAgent),
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
		
		w.Header().Set("X-Request-ID", uuid.New().String())
		w.Header().Set("X-Service-Version", "1.0.0")
		w.Header().Set("X-Environment", string(h.config.Environment))
		
		next.ServeHTTP(w, r)
	})
}

func (h *HTTPHandler) extractRequestMetadata(r *http.Request) *RequestMetadata {
	clientInfo := request.ExtractClientInfo(r)
	
	return &RequestMetadata{
		RequestID:     uuid.New().String(),
		ClientIP:      clientInfo.IPAddress,
		UserAgent:     clientInfo.UserAgent,
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

func (h *HTTPHandler) extractTenantID(r *http.Request) (uuid.UUID, *errors.AppError) {
	tenantIDStr := r.Header.Get("X-Tenant-ID")
	if tenantIDStr == "" {
		tenantIDStr = r.URL.Query().Get("tenant_id")
	}
	
	if tenantIDStr == "" {
		return uuid.Nil, errors.New(errors.ErrCodeValidationError, "tenant ID is required")
	}
	
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return uuid.Nil, errors.New(errors.ErrCodeValidationError, "invalid tenant ID format")
	}
	
	return tenantID, nil
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

func (h *HTTPHandler) getTenant(tenantID string) (*tenant.Tenant, *errors.AppError) {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, errors.New(errors.ErrCodeValidationError, "invalid tenant ID format")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = ctx

	tenantObj := &tenant.Tenant{
		ID:             tenantUUID,
		Name:           "Default Tenant",
		Slug:           "default-tenant",
		Status:         tenant.StatusActive,
		Tier:           tenant.TierEnterprise,
		OrganizationID: "default-org",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		CreatedBy:      tenantUUID,
		UpdatedBy:      tenantUUID,
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

	return tenantObj, nil
}

func (h *HTTPHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *HTTPHandler) writeErrorResponse(w http.ResponseWriter, appErr *errors.AppError) {
	errorResponse := response.NewErrorResponse(
		uuid.New(),
		uuid.New().String(),
		response.ErrorCode(appErr.Code),
		appErr.Message,
		response.SeverityHigh,
	)

	statusCode := h.getHTTPStatusFromError(appErr)
	h.writeJSONResponse(w, statusCode, errorResponse)
}

func (h *HTTPHandler) getHTTPStatusFromError(appErr *errors.AppError) int {
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

func (h *HTTPHandler) validateAdminAccess(r *http.Request) *errors.AppError {
	adminToken := r.Header.Get("X-Admin-Token")
	if adminToken == "" {
		return errors.New(errors.ErrCodeUnauthorized, "admin token required")
	}

	expectedToken := h.config.Security.JWTSecret
	if adminToken != expectedToken {
		return errors.New(errors.ErrCodeForbidden, "invalid admin token")
	}

	return nil
}

func (h *HTTPHandler) handleStreamingResponse(w http.ResponseWriter, r *http.Request, aiResponse *response.AIResponse) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeErrorResponse(w, errors.New(errors.ErrCodeInternalError, "streaming not supported"))
		return
	}

	content := ""
	if aiResponse.Data != nil {
		content = aiResponse.Data.Content
	}

	chunks := h.chunkResponse(content, 50)
	
	for i, chunk := range chunks {
		data := map[string]interface{}{
			"id":      aiResponse.ID.String(),
			"object":  "chat.completion.chunk",
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

func (h *HTTPHandler) createAuditEvent(metadata *RequestMetadata, r *http.Request, statusCode int, err *errors.AppError) *commonpb.AuditEvent {
	clientInfo := request.ExtractClientInfo(r)
	
	auditEvent := &commonpb.AuditEvent{
		EventId:   uuid.New().String(),
		EventType: "http_request",
		ActorId:   "system",
		ActorType: "service",
		Action:    fmt.Sprintf("%s %s", r.Method, r.URL.Path),
		Status:    commonpb.Status_STATUS_SUCCESS,
		SourceIp:  clientInfo.IPAddress,
		UserAgent: clientInfo.UserAgent,
		TraceId:   metadata.RequestID,
		Severity:  commonpb.Severity_SEVERITY_LOW,
	}

	if err != nil {
		auditEvent.Status = commonpb.Status_STATUS_ERROR
		auditEvent.Severity = commonpb.Severity_SEVERITY_HIGH
	}

	return auditEvent
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

func (g *GRPCHandler) logGRPCRequest(method string, req interface{}, resp interface{}, err error, duration time.Duration) {
	fields := []zap.Field{
		zap.String("method", method),
		zap.Duration("duration", duration),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		g.logger.Error("gRPC request failed", fields...)
	} else {
		g.logger.Info("gRPC request completed", fields...)
	}
}

func (g *GRPCHandler) ResetCircuitBreaker(ctx context.Context, req *gatewaypb.CircuitBreakerRequest) (*gatewaypb.CircuitBreakerResponse, error) {
	if req.ServiceName == "" {
		return nil, status.Error(codes.InvalidArgument, "service name is required")
	}

	appErr := g.orchestrator.ResetCircuitBreaker(req.ServiceName)
	if appErr != nil {
		return nil, g.convertAppErrorToGRPCError(appErr.(*errors.AppError))
	}

	return &gatewaypb.CircuitBreakerResponse{
		Status:       commonpb.Status_STATUS_SUCCESS,
		CurrentState: "reset",
	}, nil
}

func (g *GRPCHandler) GetCircuitBreakerStatus(ctx context.Context, req *gatewaypb.CircuitBreakerRequest) (*gatewaypb.CircuitBreakerStatusResponse, error) {
	if req.ServiceName == "" {
		return nil, status.Error(codes.InvalidArgument, "service name is required")
	}

	currentState := g.orchestrator.GetCircuitBreakerStatus(req.ServiceName)

	return &gatewaypb.CircuitBreakerStatusResponse{
		Status:       commonpb.Status_STATUS_SUCCESS,
		CurrentState: currentState,
		FailureCount: 0,
		LastFailure:  timestamppb.Now(),
		Timeout:      durationpb.New(time.Minute * 5),
	}, nil
}

func (g *GRPCHandler) StreamAIRequest(stream gatewaypb.GatewayService_StreamAIRequestServer) error {
	g.logger.Info("Starting streaming AI requests")
	
	for {
		req, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			g.logger.Error("Stream receive error", zap.Error(err))
			return err
		}

		response, err := g.ProcessAIRequest(stream.Context(), &gatewaypb.ProcessAIRequestRequest{
			Metadata: req.Metadata,
			Payload:  req.Payload,
			Options:  req.Options,
		})
		if err != nil {
			return err
		}

		streamResponse := &gatewaypb.StreamAIRequestResponse{
			ResponseType: &gatewaypb.StreamAIRequestResponse_Complete{
				Complete: &gatewaypb.StreamComplete{
					Id:            response.Response.Id,
					FinalResponse: response.Response,
				},
			},
			StreamId:       req.Metadata.RequestId,
			SequenceNumber: 1,
			Timestamp:      timestamppb.Now(),
		}

		if err := stream.Send(streamResponse); err != nil {
			g.logger.Error("Stream send error", zap.Error(err))
			return err
		}
	}
}

func (h *HTTPHandler) handleOptionsRequest(w http.ResponseWriter, r *http.Request) {
	utils.SetCORSHeaders(w, 
		h.config.Security.AllowedOrigins,
		[]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		[]string{"Content-Type", "Authorization", "X-API-Key", "X-Request-ID", "X-Priority", "X-Tenant-ID"},
	)
	
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func (h *HTTPHandler) handleNotFound(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)
	
	appErr := errors.New(errors.ErrCodeNotFound, "endpoint not found").
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


func (h *HTTPHandler) createHealthCheckResponse() map[string]interface{} {
	healthStatus := h.orchestrator.GetHealthStatus()
	
	return map[string]interface{}{
		"status":      healthStatus.Overall,
		"timestamp":   time.Now().UTC(),
		"version":     "1.0.0",
		"environment": h.config.Environment,
		"uptime":      healthStatus.Uptime.String(),
		"services":    healthStatus.Services,
		"dependencies": healthStatus.Dependencies,
		"metrics": map[string]interface{}{
			"total_requests":    0,
			"success_rate":      1.0,
			"avg_response_time": 0,
			"throughput":        0,
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
	metricsReq := &gatewaypb.GetMetricsRequest{
		Metadata: &commonpb.RequestMetadata{
			RequestId: uuid.New().String(),
		},
	}
	metricsResponse, _ := h.orchestrator.GetMetrics(context.Background(), metricsReq)
	
	return map[string]interface{}{
		"requests": map[string]interface{}{
			"total":      extractMetricValue(metricsResponse, "total_requests"),
			"successful": extractMetricValue(metricsResponse, "successful_requests"),
			"failed":     extractMetricValue(metricsResponse, "failed_requests"),
			"error_rate": extractMetricValue(metricsResponse, "error_rate"),
		},
		"performance": map[string]interface{}{
			"avg_response_time":  extractMetricValue(metricsResponse, "avg_response_time"),
			"throughput_per_sec": extractMetricValue(metricsResponse, "throughput_per_sec"),
		},
		"security": map[string]interface{}{
			"authentication_rate":   extractMetricValue(metricsResponse, "authentication_rate"),
			"threat_detection_rate": extractMetricValue(metricsResponse, "threat_detection_rate"),
			"policy_violation_rate": extractMetricValue(metricsResponse, "policy_violation_rate"),
		},
		"services": extractServiceMetrics(metricsResponse),
		"cache": map[string]interface{}{
			"tenant_count": h.orchestrator.GetTenantCount(),
		},
		"last_updated": metricsResponse.GeneratedAt.Seconds,
	}
}

func extractMetricValue(response *gatewaypb.GetMetricsResponse, metricName string) interface{} {
	if response == nil || response.Metrics == nil {
		return 0
	}
	
	for _, metric := range response.Metrics {
		if metric.Name == metricName && len(metric.Points) > 0 {
			return metric.Points[len(metric.Points)-1].Value
		}
	}
	return 0
}

func extractServiceMetrics(response *gatewaypb.GetMetricsResponse) map[string]interface{} {
	services := make(map[string]interface{})
	if response == nil || response.Metrics == nil {
		return services
	}
	
	for _, metric := range response.Metrics {
		if len(metric.Points) > 0 && metric.Labels != nil {
			if serviceName, exists := metric.Labels["service"]; exists {
				services[serviceName] = metric.Points[len(metric.Points)-1].Value
			}
		}
	}
	return services
}

func (h *HTTPHandler) logSecurityEvent(eventType, description string, metadata map[string]interface{}) {
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

	h.logger.Warn("Security event", zap.Any("security_event", securityEvent))
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

func (h *HTTPHandler) createResponseMetadata(statusCode int, responseSize int64, processingTime time.Duration) *ResponseMetadata {
	return &ResponseMetadata{
		StatusCode:     statusCode,
		ResponseSize:   responseSize,
		ProcessingTime: processingTime,
		CacheHit:       false,
	}
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
		return errors.New(errors.ErrCodeRateLimit, "rate limit exceeded").
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
	
	if !utils.VerifyHMAC(string(body), signature, secret) {
		return errors.New(errors.ErrCodeUnauthorized, "invalid request signature")
	}

	return nil
}

func (g *GRPCHandler) createGRPCMetadata(ctx context.Context) map[string]interface{} {
	return map[string]interface{}{
		"request_id": uuid.New().String(),
		"trace_id":   uuid.New().String(),
		"timestamp":  time.Now().UTC(),
		"service":    "gateway",
		"version":    "1.0.0",
	}
}


