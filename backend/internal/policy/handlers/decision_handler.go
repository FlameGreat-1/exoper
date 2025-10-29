package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	"flamo/backend/pkg/api/models/policy"
	v1 "flamo/backend/pkg/api/policy/v1"
)

type DecisionHandler struct {
	decisionService v1.DecisionService
	config          *config.Config
	logger          *zap.Logger
	rateLimiter     *utils.RateLimiter
}

type EvaluateRequest struct {
	TenantID    string                 `json:"tenant_id" validate:"required,uuid"`
	SubjectID   string                 `json:"subject_id" validate:"required"`
	Resource    string                 `json:"resource" validate:"required"`
	Action      string                 `json:"action" validate:"required"`
	Context     map[string]interface{} `json:"context"`
	Input       map[string]interface{} `json:"input"`
	RequestID   string                 `json:"request_id"`
	TraceID     string                 `json:"trace_id"`
	Timestamp   time.Time              `json:"timestamp"`
	CachePolicy string                 `json:"cache_policy" validate:"omitempty,oneof=allow deny force_refresh"`
}

type EvaluateResponse struct {
	Decision policy.PolicyDecision `json:"decision"`
	Cached   bool                  `json:"cached"`
	Duration time.Duration         `json:"duration"`
}

type BatchEvaluateRequest struct {
	Requests []EvaluateRequest `json:"requests" validate:"required,min=1,max=100"`
}

type BatchEvaluateResponse struct {
	Responses []EvaluateResponse `json:"responses"`
	Duration  time.Duration      `json:"duration"`
}

type ExplainRequest struct {
	TenantID  string                 `json:"tenant_id" validate:"required,uuid"`
	SubjectID string                 `json:"subject_id" validate:"required"`
	Resource  string                 `json:"resource" validate:"required"`
	Action    string                 `json:"action" validate:"required"`
	Context   map[string]interface{} `json:"context"`
	Input     map[string]interface{} `json:"input"`
	RequestID string                 `json:"request_id"`
}

type ExplainResponse struct {
	Decision    policy.PolicyDecision `json:"decision"`
	Explanation PolicyExplanation     `json:"explanation"`
	Duration    time.Duration         `json:"duration"`
}

type PolicyExplanation struct {
	MatchedPolicies []MatchedPolicy   `json:"matched_policies"`
	AppliedRules    []AppliedRule     `json:"applied_rules"`
	FailedRules     []FailedRule      `json:"failed_rules"`
	Trace           []EvaluationStep  `json:"trace"`
	Metadata        map[string]string `json:"metadata"`
}

type MatchedPolicy struct {
	PolicyID    string              `json:"policy_id"`
	PolicyName  string              `json:"policy_name"`
	Version     string              `json:"version"`
	Priority    policy.Priority     `json:"priority"`
	Effect      policy.Effect       `json:"effect"`
	MatchReason string              `json:"match_reason"`
	Rules       []policy.Rule       `json:"rules"`
}

type AppliedRule struct {
	RuleID      string             `json:"rule_id"`
	PolicyID    string             `json:"policy_id"`
	Resource    string             `json:"resource"`
	Action      string             `json:"action"`
	Effect      policy.Effect      `json:"effect"`
	Conditions  []policy.Condition `json:"conditions"`
	Metadata    map[string]string  `json:"metadata"`
}

type FailedRule struct {
	RuleID        string             `json:"rule_id"`
	PolicyID      string             `json:"policy_id"`
	Resource      string             `json:"resource"`
	Action        string             `json:"action"`
	FailureType   string             `json:"failure_type"`
	FailureReason string             `json:"failure_reason"`
	Conditions    []policy.Condition `json:"conditions"`
	Metadata      map[string]string  `json:"metadata"`
}

type EvaluationStep struct {
	Step        int                    `json:"step"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Input       map[string]interface{} `json:"input"`
	Output      map[string]interface{} `json:"output"`
	Duration    time.Duration          `json:"duration"`
	Timestamp   time.Time              `json:"timestamp"`
}

type QueryRequest struct {
	TenantID string                 `json:"tenant_id" validate:"required,uuid"`
	Query    string                 `json:"query" validate:"required"`
	Input    map[string]interface{} `json:"input"`
	Options  QueryOptions           `json:"options"`
}

type QueryOptions struct {
	Explain     bool          `json:"explain"`
	Trace       bool          `json:"trace"`
	Metrics     bool          `json:"metrics"`
	Timeout     time.Duration `json:"timeout"`
	CachePolicy string        `json:"cache_policy"`
}

type QueryResponse struct {
	Result      map[string]interface{} `json:"result"`
	Explanation *PolicyExplanation     `json:"explanation,omitempty"`
	Metrics     map[string]interface{} `json:"metrics,omitempty"`
	Duration    time.Duration          `json:"duration"`
}

type CompileRequest struct {
	TenantID string                 `json:"tenant_id" validate:"required,uuid"`
	Query    string                 `json:"query" validate:"required"`
	Input    map[string]interface{} `json:"input"`
	Unknowns []string               `json:"unknowns"`
}

type CompileResponse struct {
	Result   map[string]interface{} `json:"result"`
	Duration time.Duration          `json:"duration"`
}

func NewDecisionHandler(decisionService v1.DecisionService, cfg *config.Config, logger *zap.Logger) *DecisionHandler {
	rateLimiter := utils.NewRateLimiter(5000.0, 50000)

	return &DecisionHandler{
		decisionService: decisionService,
		config:          cfg,
		logger:          logger,
		rateLimiter:     rateLimiter,
	}
}

func (h *DecisionHandler) Evaluate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" || !utils.IsValidUUID(req.TenantID) {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Invalid tenant ID", req.TenantID), http.StatusBadRequest)
		return
	}
	if req.SubjectID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("subject_id", "Subject ID is required", req.SubjectID), http.StatusBadRequest)
		return
	}
	if req.Resource == "" {
		h.writeErrorResponse(w, errors.NewValidationError("resource", "Resource is required", req.Resource), http.StatusBadRequest)
		return
	}
	if req.Action == "" {
		h.writeErrorResponse(w, errors.NewValidationError("action", "Action is required", req.Action), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID), http.StatusBadRequest)
			return
		}
		req.TenantID = tenantID
	}

	serviceReq := &v1.EvaluateRequest{
		TenantID:    req.TenantID,
		SubjectID:   req.SubjectID,
		Resource:    req.Resource,
		Action:      req.Action,
		Context:     req.Context,
		Input:       req.Input,
		RequestID:   req.RequestID,
		TraceID:     req.TraceID,
		Timestamp:   time.Now().UTC(),
		CachePolicy: req.CachePolicy,
	}

	response, err := h.decisionService.Evaluate(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	evalResponse := &EvaluateResponse{
		Decision: response.Decision,
		Cached:   response.Cached,
		Duration: response.Duration,
	}

	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(evalResponse); err != nil {
		h.logger.Error("Failed to encode evaluate response", zap.Error(err))
		return
	}

	h.logger.Info("Policy evaluation completed",
		zap.String("tenant_id", req.TenantID),
		zap.String("subject_id", req.SubjectID),
		zap.String("resource", req.Resource),
		zap.String("action", req.Action),
		zap.Bool("allow", response.Decision.Allow),
		zap.Bool("cached", response.Cached),
		zap.Duration("duration", time.Since(start)),
		zap.String("trace_id", req.TraceID))
}

func (h *DecisionHandler) BatchEvaluate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	var req BatchEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if len(req.Requests) == 0 {
		h.writeErrorResponse(w, errors.NewValidationError("requests", "At least one request is required", ""), http.StatusBadRequest)
		return
	}
	if len(req.Requests) > 100 {
		h.writeErrorResponse(w, errors.NewValidationError("requests", "Maximum 100 requests allowed", ""), http.StatusBadRequest)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	for i := range req.Requests {
		if req.Requests[i].TenantID == "" {
			req.Requests[i].TenantID = tenantID
		}
		if req.Requests[i].Timestamp.IsZero() {
			req.Requests[i].Timestamp = time.Now().UTC()
		}
	}

	serviceReq := &v1.BatchEvaluateRequest{
		Requests: make([]v1.EvaluateRequest, len(req.Requests)),
	}

	for i, evalReq := range req.Requests {
		serviceReq.Requests[i] = v1.EvaluateRequest{
			TenantID:    evalReq.TenantID,
			SubjectID:   evalReq.SubjectID,
			Resource:    evalReq.Resource,
			Action:      evalReq.Action,
			Context:     evalReq.Context,
			Input:       evalReq.Input,
			RequestID:   evalReq.RequestID,
			TraceID:     evalReq.TraceID,
			Timestamp:   evalReq.Timestamp,
			CachePolicy: evalReq.CachePolicy,
		}
	}

	response, err := h.decisionService.BatchEvaluate(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	batchResponse := &BatchEvaluateResponse{
		Responses: make([]EvaluateResponse, len(response.Responses)),
		Duration:  response.Duration,
	}

	for i, resp := range response.Responses {
		batchResponse.Responses[i] = EvaluateResponse{
			Decision: resp.Decision,
			Cached:   resp.Cached,
			Duration: resp.Duration,
		}
	}

	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(batchResponse); err != nil {
		h.logger.Error("Failed to encode batch evaluate response", zap.Error(err))
		return
	}

	h.logger.Info("Batch evaluation completed",
		zap.String("tenant_id", tenantID),
		zap.Int("request_count", len(req.Requests)),
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) Explain(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	var req ExplainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" || !utils.IsValidUUID(req.TenantID) {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Invalid tenant ID", req.TenantID), http.StatusBadRequest)
		return
	}
	if req.SubjectID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("subject_id", "Subject ID is required", req.SubjectID), http.StatusBadRequest)
		return
	}
	if req.Resource == "" {
		h.writeErrorResponse(w, errors.NewValidationError("resource", "Resource is required", req.Resource), http.StatusBadRequest)
		return
	}
	if req.Action == "" {
		h.writeErrorResponse(w, errors.NewValidationError("action", "Action is required", req.Action), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID), http.StatusBadRequest)
			return
		}
		req.TenantID = tenantID
	}

	serviceReq := &v1.ExplainRequest{
		TenantID:  req.TenantID,
		SubjectID: req.SubjectID,
		Resource:  req.Resource,
		Action:    req.Action,
		Context:   req.Context,
		Input:     req.Input,
		RequestID: req.RequestID,
	}

	response, err := h.decisionService.Explain(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	explainResponse := &ExplainResponse{
		Decision: response.Decision,
		Explanation: PolicyExplanation{
			MatchedPolicies: h.convertMatchedPolicies(response.Explanation.MatchedPolicies),
			AppliedRules:    h.convertAppliedRules(response.Explanation.AppliedRules),
			FailedRules:     h.convertFailedRules(response.Explanation.FailedRules),
			Trace:           h.convertEvaluationSteps(response.Explanation.Trace),
			Metadata:        response.Explanation.Metadata,
		},
		Duration: response.Duration,
	}

	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(explainResponse); err != nil {
		h.logger.Error("Failed to encode explain response", zap.Error(err))
		return
	}

	h.logger.Info("Policy explanation completed",
		zap.String("tenant_id", req.TenantID),
		zap.String("subject_id", req.SubjectID),
		zap.String("resource", req.Resource),
		zap.String("action", req.Action),
		zap.Bool("allow", response.Decision.Allow),
		zap.Int("matched_policies", len(response.Explanation.MatchedPolicies)),
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) Query(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" || !utils.IsValidUUID(req.TenantID) {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Invalid tenant ID", req.TenantID), http.StatusBadRequest)
		return
	}
	if req.Query == "" {
		h.writeErrorResponse(w, errors.NewValidationError("query", "Query is required", req.Query), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID), http.StatusBadRequest)
			return
		}
		req.TenantID = tenantID
	}

	serviceReq := &v1.QueryRequest{
		TenantID: req.TenantID,
		Query:    req.Query,
		Input:    req.Input,
		Options: v1.QueryOptions{
			Explain:     req.Options.Explain,
			Trace:       req.Options.Trace,
			Metrics:     req.Options.Metrics,
			Timeout:     req.Options.Timeout,
			CachePolicy: req.Options.CachePolicy,
		},
	}

	response, err := h.decisionService.Query(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	queryResponse := &QueryResponse{
		Result:   response.Result,
		Duration: response.Duration,
	}

	if response.Explanation != nil {
		queryResponse.Explanation = &PolicyExplanation{
			MatchedPolicies: h.convertMatchedPolicies(response.Explanation.MatchedPolicies),
			AppliedRules:    h.convertAppliedRules(response.Explanation.AppliedRules),
			FailedRules:     h.convertFailedRules(response.Explanation.FailedRules),
			Trace:           h.convertEvaluationSteps(response.Explanation.Trace),
			Metadata:        response.Explanation.Metadata,
		}
	}

	if response.Metrics != nil {
		queryResponse.Metrics = response.Metrics
	}

	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(queryResponse); err != nil {
		h.logger.Error("Failed to encode query response", zap.Error(err))
		return
	}

	h.logger.Info("Policy query completed",
		zap.String("tenant_id", req.TenantID),
		zap.String("query", req.Query),
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) Compile(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	var req CompileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" || !utils.IsValidUUID(req.TenantID) {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Invalid tenant ID", req.TenantID), http.StatusBadRequest)
		return
	}
	if req.Query == "" {
		h.writeErrorResponse(w, errors.NewValidationError("query", "Query is required", req.Query), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID), http.StatusBadRequest)
			return
		}
		req.TenantID = tenantID
	}

	serviceReq := &v1.CompileRequest{
		TenantID: req.TenantID,
		Query:    req.Query,
		Input:    req.Input,
		Unknowns: req.Unknowns,
	}

	response, err := h.decisionService.Compile(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	compileResponse := &CompileResponse{
		Result:   response.Result,
		Duration: response.Duration,
	}

	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(compileResponse); err != nil {
		h.logger.Error("Failed to encode compile response", zap.Error(err))
		return
	}

	h.logger.Info("Policy compilation completed",
		zap.String("tenant_id", req.TenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	metrics, err := h.decisionService.GetDecisionMetrics(ctx, tenantID)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		h.logger.Error("Failed to encode metrics response", zap.Error(err))
		return
	}

	h.logger.Debug("Decision metrics retrieved",
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) ClearCache(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	query := r.URL.Query()
	policyID := query.Get("policy_id")

	clearReq := &v1.ClearCacheRequest{
		TenantID: tenantID,
		PolicyID: policyID,
	}
	if err := h.decisionService.ClearCache(ctx, clearReq); err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	w.WriteHeader(http.StatusOK)
	
	response := map[string]interface{}{
		"message":   "Decision cache cleared successfully",
		"tenant_id": tenantID,
	}
	
	if policyID != "" {
		response["policy_id"] = policyID
	}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode clear cache response", zap.Error(err))
		return
	}

	h.logger.Info("Decision cache cleared",
		zap.String("tenant_id", tenantID),
		zap.String("policy_id", policyID),
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) WarmupCache(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	if err := h.decisionService.WarmupCache(ctx, tenantID); err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)
	
	response := map[string]interface{}{
		"message":   "Cache warmup initiated",
		"tenant_id": tenantID,
		"status":    "warming_up",
	}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode warmup cache response", zap.Error(err))
		return
	}

	h.logger.Info("Cache warmup initiated",
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) convertMatchedPolicies(servicePolicies []v1.MatchedPolicy) []MatchedPolicy {
	policies := make([]MatchedPolicy, len(servicePolicies))
	for i, sp := range servicePolicies {
		policies[i] = MatchedPolicy{
			PolicyID:    sp.PolicyID,
			PolicyName:  sp.PolicyName,
			Version:     sp.Version,
			Priority:    sp.Priority,
			Effect:      sp.Effect,
			MatchReason: sp.MatchReason,
			Rules:       sp.Rules,
		}
	}
	return policies
}

func (h *DecisionHandler) convertAppliedRules(serviceRules []v1.AppliedRule) []AppliedRule {
	rules := make([]AppliedRule, len(serviceRules))
	for i, sr := range serviceRules {
		rules[i] = AppliedRule{
			RuleID:     sr.RuleID,
			PolicyID:   sr.PolicyID,
			Resource:   sr.Resource,
			Action:     sr.Action,
			Effect:     sr.Effect,
			Conditions: sr.Conditions,
			Metadata:   sr.Metadata,
		}
	}
	return rules
}

func (h *DecisionHandler) convertFailedRules(serviceRules []v1.FailedRule) []FailedRule {
	rules := make([]FailedRule, len(serviceRules))
	for i, sr := range serviceRules {
		rules[i] = FailedRule{
			RuleID:        sr.RuleID,
			PolicyID:      sr.PolicyID,
			Resource:      sr.Resource,
			Action:        sr.Action,
			FailureType:   sr.FailureType,
			FailureReason: sr.FailureReason,
			Conditions:    sr.Conditions,
			Metadata:      sr.Metadata,
		}
	}
	return rules
}

func (h *DecisionHandler) convertEvaluationSteps(serviceSteps []v1.EvaluationStep) []EvaluationStep {
	steps := make([]EvaluationStep, len(serviceSteps))
	for i, ss := range serviceSteps {
		steps[i] = EvaluationStep{
			Step:        ss.Step,
			Type:        ss.Type,
			Description: ss.Description,
			Input:       ss.Input,
			Output:      ss.Output,
			Duration:    ss.Duration,
			Timestamp:   ss.Timestamp,
		}
	}
	return steps
}

func (h *DecisionHandler) writeErrorResponse(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := &ErrorResponse{
		Error:   err.Error(),
		Code:    h.getErrorCode(err),
		Message: h.getErrorMessage(err),
		Details: h.getErrorDetails(err),
	}

	if encodeErr := json.NewEncoder(w).Encode(errorResponse); encodeErr != nil {
		h.logger.Error("Failed to encode error response", 
			zap.Error(encodeErr),
			zap.Error(err))
	}

	h.logger.Error("Decision request failed",
		zap.Error(err),
		zap.Int("status_code", statusCode),
		zap.String("error_code", errorResponse.Code))
}

func (h *DecisionHandler) getStatusCodeFromError(err error) int {
	if errors.IsAppError(err) {
		return errors.GetHTTPStatus(err)
	}
	return http.StatusInternalServerError
}

func (h *DecisionHandler) getErrorCode(err error) string {
	if appErr, ok := err.(*errors.AppError); ok {
		return string(appErr.Code)
	}
	return "INTERNAL_ERROR"
}

func (h *DecisionHandler) getErrorMessage(err error) string {
	if appErr, ok := err.(*errors.AppError); ok {
		return appErr.Message
	}
	return err.Error()
}

func (h *DecisionHandler) getErrorDetails(err error) map[string]interface{} {
	if appErr, ok := err.(*errors.AppError); ok {
		return appErr.Context
	}
	return nil
}

func (h *DecisionHandler) GetCircuitBreakerStatus(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	status := h.decisionService.GetCircuitBreakerState()

	response := map[string]interface{}{
		"circuit_breaker_state": status,
		"timestamp":             time.Now().UTC(),
	}

	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode circuit breaker status response", zap.Error(err))
		return
	}

	h.logger.Debug("Circuit breaker status retrieved",
		zap.String("state", status),
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) ResetCircuitBreaker(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	h.decisionService.ResetCircuitBreaker()

	response := map[string]interface{}{
		"message":   "Circuit breaker reset successfully",
		"timestamp": time.Now().UTC(),
	}

	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode reset circuit breaker response", zap.Error(err))
		return
	}

	h.logger.Info("Circuit breaker reset",
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) GetRateLimiterStatus(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	status := h.decisionService.GetRateLimiterStatus()
	status["handler_rate_limiter"] = map[string]interface{}{
		"tokens":   h.rateLimiter.GetTokens(),
		"capacity": h.rateLimiter.GetCapacity(),
		"rate":     h.rateLimiter.GetRate(),
	}

	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(status); err != nil {
		h.logger.Error("Failed to encode rate limiter status response", zap.Error(err))
		return
	}

	h.logger.Debug("Rate limiter status retrieved",
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) GetHealthStatus(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	status := h.decisionService.GetHealthStatus()
	status["handler"] = map[string]interface{}{
		"healthy":      true,
		"rate_limited": h.decisionService.IsRateLimited(),
	}

	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(status); err != nil {
		h.logger.Error("Failed to encode health status response", zap.Error(err))
		return
	}

	h.logger.Debug("Health status retrieved",
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) ValidateRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	validation := map[string]interface{}{
		"valid":     true,
		"tenant_id": tenantID,
		"request":   req,
		"timestamp": time.Now().UTC(),
	}

	requiredFields := []string{"subject_id", "resource", "action"}
	missing := []string{}

	for _, field := range requiredFields {
		if _, exists := req[field]; !exists {
			missing = append(missing, field)
		}
	}

	if len(missing) > 0 {
		validation["valid"] = false
		validation["missing_fields"] = missing
	}

	statusCode := http.StatusOK
	if !validation["valid"].(bool) {
		statusCode = http.StatusBadRequest
	}

	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(validation); err != nil {
		h.logger.Error("Failed to encode validate request response", zap.Error(err))
		return
	}

	h.logger.Debug("Request validation completed",
		zap.String("tenant_id", tenantID),
		zap.Bool("valid", validation["valid"].(bool)),
		zap.Duration("duration", time.Since(start)))
}

func (h *DecisionHandler) RegisterRoutes(router *mux.Router) {
	apiRouter := router.PathPrefix("/api/v1/decisions").Subrouter()

	apiRouter.HandleFunc("/evaluate", h.Evaluate).Methods("POST")
	apiRouter.HandleFunc("/batch", h.BatchEvaluate).Methods("POST")
	apiRouter.HandleFunc("/explain", h.Explain).Methods("POST")
	apiRouter.HandleFunc("/query", h.Query).Methods("POST")
	apiRouter.HandleFunc("/compile", h.Compile).Methods("POST")

	apiRouter.HandleFunc("/metrics", h.GetMetrics).Methods("GET")
	apiRouter.HandleFunc("/cache/clear", h.ClearCache).Methods("POST")
	apiRouter.HandleFunc("/cache/warmup", h.WarmupCache).Methods("POST")

	apiRouter.HandleFunc("/circuit-breaker/status", h.GetCircuitBreakerStatus).Methods("GET")
	apiRouter.HandleFunc("/circuit-breaker/reset", h.ResetCircuitBreaker).Methods("POST")
	apiRouter.HandleFunc("/rate-limiter/status", h.GetRateLimiterStatus).Methods("GET")
	apiRouter.HandleFunc("/health", h.GetHealthStatus).Methods("GET")
	apiRouter.HandleFunc("/validate", h.ValidateRequest).Methods("POST")

	h.logger.Info("Decision handler routes registered",
		zap.Strings("endpoints", []string{
			"POST /api/v1/decisions/evaluate",
			"POST /api/v1/decisions/batch",
			"POST /api/v1/decisions/explain",
			"POST /api/v1/decisions/query",
			"POST /api/v1/decisions/compile",
			"GET /api/v1/decisions/metrics",
			"POST /api/v1/decisions/cache/clear",
			"POST /api/v1/decisions/cache/warmup",
			"GET /api/v1/decisions/circuit-breaker/status",
			"POST /api/v1/decisions/circuit-breaker/reset",
			"GET /api/v1/decisions/rate-limiter/status",
			"GET /api/v1/decisions/health",
			"POST /api/v1/decisions/validate",
		}))
}

func (h *DecisionHandler) RegisterMiddleware(router *mux.Router) {
	router.Use(h.loggingMiddleware)
	router.Use(h.corsMiddleware)
	router.Use(h.securityMiddleware)
	router.Use(h.rateLimitMiddleware)

	h.logger.Info("Decision handler middleware registered")
}

func (h *DecisionHandler) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		h.logger.Debug("Decision request started",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()))

		next.ServeHTTP(w, r)

		h.logger.Debug("Decision request completed",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Duration("duration", time.Since(start)))
	})
}

func (h *DecisionHandler) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Request-ID, X-Trace-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *DecisionHandler) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.SetSecurityHeaders(w)
		next.ServeHTTP(w, r)
	})
}

func (h *DecisionHandler) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.rateLimiter.Allow() {
			h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *DecisionHandler) Shutdown(ctx context.Context) error {
	h.logger.Info("Decision handler shutting down")
	return nil
}
