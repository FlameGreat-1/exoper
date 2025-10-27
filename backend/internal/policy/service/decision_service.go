package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	"flamo/backend/pkg/api/models/policy"
	"flamo/backend/internal/policy/storage"
	"flamo/backend/internal/policy/opa"
)

type DecisionService struct {
	opaEngine     *opa.Engine
	opaClient     *opa.Client
	cache         *opa.Cache
	policyStore   *storage.PolicyStore
	bundleManager *storage.BundleManager
	db            *database.Database
	config        *config.Config
	logger        *zap.Logger
	rateLimiter   *utils.RateLimiter
	circuitBreaker *utils.CircuitBreaker
	mu            sync.RWMutex
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
	CachePolicy string                 `json:"cache_policy" validate:"oneof=allow deny force_refresh"`
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
	MatchedPolicies []MatchedPolicy        `json:"matched_policies"`
	AppliedRules    []AppliedRule          `json:"applied_rules"`
	FailedRules     []FailedRule           `json:"failed_rules"`
	Trace           []EvaluationStep       `json:"trace"`
	Metadata        map[string]interface{} `json:"metadata"`
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
	RuleID      string                 `json:"rule_id"`
	PolicyID    string                 `json:"policy_id"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Effect      policy.Effect          `json:"effect"`
	Conditions  []policy.Condition     `json:"conditions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type FailedRule struct {
	RuleID       string                 `json:"rule_id"`
	PolicyID     string                 `json:"policy_id"`
	Resource     string                 `json:"resource"`
	Action       string                 `json:"action"`
	FailureType  string                 `json:"failure_type"`
	FailureReason string                `json:"failure_reason"`
	Conditions   []policy.Condition     `json:"conditions"`
	Metadata     map[string]interface{} `json:"metadata"`
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

func NewDecisionService(
	opaEngine *opa.Engine,
	opaClient *opa.Client,
	cache *opa.Cache,
	policyStore *storage.PolicyStore,
	bundleManager *storage.BundleManager,
	db *database.Database,
	cfg *config.Config,
	logger *zap.Logger,
) *DecisionService {
	rateLimiter := utils.NewRateLimiter(5000.0, 50000)
	
	circuitConfig := utils.CircuitBreakerConfig{
		MaxRequests:      100,
		Interval:         30 * time.Second,
		Timeout:          60 * time.Second,
		FailureThreshold: 0.6,
		SuccessThreshold: 5,
	}
	circuitBreaker := utils.NewCircuitBreaker(circuitConfig)

	return &DecisionService{
		opaEngine:      opaEngine,
		opaClient:      opaClient,
		cache:          cache,
		policyStore:    policyStore,
		bundleManager:  bundleManager,
		db:             db,
		config:         cfg,
		logger:         logger,
		rateLimiter:    rateLimiter,
		circuitBreaker: circuitBreaker,
	}
}

func (ds *DecisionService) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ds.logger.Debug("Policy evaluation completed", 
			zap.String("tenant_id", req.TenantID),
			zap.String("resource", req.Resource),
			zap.String("action", req.Action),
			zap.Duration("duration", duration))
	}()

	if !ds.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "evaluate").
			WithContext("resource", req.Resource).
			WithContext("action", req.Action)
	}

	if err := ds.validateEvaluateRequest(req); err != nil {
		return nil, err
	}

	ds.enrichRequest(req)

	var response *EvaluateResponse
	err := ds.circuitBreaker.Execute(func() error {
		var evalErr error
		response, evalErr = ds.performEvaluation(ctx, req)
		return evalErr
	})

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Policy evaluation failed").
			WithTenantID(req.TenantID).
			WithTraceID(req.TraceID).
			WithContext("resource", req.Resource).
			WithContext("action", req.Action)
	}

	ds.logger.Info("Policy evaluation completed",
		zap.String("tenant_id", req.TenantID),
		zap.String("subject_id", req.SubjectID),
		zap.String("resource", req.Resource),
		zap.String("action", req.Action),
		zap.Bool("allow", response.Decision.Allow),
		zap.Bool("cached", response.Cached),
		zap.Duration("duration", response.Duration),
		zap.String("trace_id", req.TraceID))

	return response, nil
}

func (ds *DecisionService) BatchEvaluate(ctx context.Context, req *BatchEvaluateRequest) (*BatchEvaluateResponse, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ds.logger.Debug("Batch evaluation completed", 
			zap.Int("request_count", len(req.Requests)),
			zap.Duration("duration", duration))
	}()

	if !ds.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithContext("operation", "batch_evaluate").
			WithContext("request_count", len(req.Requests))
	}

	if err := ds.validateBatchEvaluateRequest(req); err != nil {
		return nil, err
	}

	response, err := ds.opaEngine.BatchEvaluate(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Batch evaluation failed").
			WithContext("request_count", len(req.Requests))
	}

	ds.logger.Info("Batch evaluation completed",
		zap.Int("request_count", len(req.Requests)),
		zap.Int("response_count", len(response.Responses)),
		zap.Duration("duration", response.Duration))

	return response, nil
}

func (ds *DecisionService) Explain(ctx context.Context, req *ExplainRequest) (*ExplainResponse, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ds.logger.Debug("Policy explanation completed", 
			zap.String("tenant_id", req.TenantID),
			zap.String("resource", req.Resource),
			zap.String("action", req.Action),
			zap.Duration("duration", duration))
	}()

	if !ds.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "explain").
			WithContext("resource", req.Resource).
			WithContext("action", req.Action)
	}

	if err := ds.validateExplainRequest(req); err != nil {
		return nil, err
	}

	evalReq := &EvaluateRequest{
		TenantID:  req.TenantID,
		SubjectID: req.SubjectID,
		Resource:  req.Resource,
		Action:    req.Action,
		Context:   req.Context,
		Input:     req.Input,
		RequestID: req.RequestID,
		TraceID:   utils.GenerateTraceID(),
		Timestamp: time.Now().UTC(),
	}

	decision, err := ds.performEvaluation(ctx, evalReq)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to evaluate for explanation").
			WithTenantID(req.TenantID).
			WithContext("resource", req.Resource).
			WithContext("action", req.Action)
	}

	explanation, err := ds.generateExplanation(ctx, evalReq, &decision.Decision)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to generate explanation").
			WithTenantID(req.TenantID).
			WithContext("resource", req.Resource).
			WithContext("action", req.Action)
	}

	response := &ExplainResponse{
		Decision:    decision.Decision,
		Explanation: *explanation,
		Duration:    time.Since(start),
	}

	ds.logger.Info("Policy explanation completed",
		zap.String("tenant_id", req.TenantID),
		zap.String("resource", req.Resource),
		zap.String("action", req.Action),
		zap.Bool("allow", decision.Decision.Allow),
		zap.Int("matched_policies", len(explanation.MatchedPolicies)),
		zap.Duration("duration", response.Duration))

	return response, nil
}

func (ds *DecisionService) Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ds.logger.Debug("Policy query completed", 
			zap.String("tenant_id", req.TenantID),
			zap.String("query", req.Query),
			zap.Duration("duration", duration))
	}()

	if !ds.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "query")
	}

	if err := ds.validateQueryRequest(req); err != nil {
		return nil, err
	}

	timeout := req.Options.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	compileReq := &opa.CompileRequest{
		Query:   req.Query,
		Input:   req.Input,
		Unknowns: []string{},
	}

	compileResp, err := ds.opaClient.Compile(queryCtx, compileReq)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to compile query").
			WithTenantID(req.TenantID).
			WithContext("query", req.Query)
	}

	response := &QueryResponse{
		Result:   compileResp.Result,
		Duration: time.Since(start),
	}

	if req.Options.Explain {
		explanation, err := ds.generateQueryExplanation(ctx, req, compileResp.Result)
		if err != nil {
			ds.logger.Warn("Failed to generate query explanation",
				zap.String("tenant_id", req.TenantID),
				zap.Error(err))
		} else {
			response.Explanation = explanation
		}
	}

	if req.Options.Metrics {
		metrics, err := ds.opaClient.GetMetrics(queryCtx)
		if err != nil {
			ds.logger.Warn("Failed to get OPA metrics",
				zap.String("tenant_id", req.TenantID),
				zap.Error(err))
		} else {
			response.Metrics = metrics
		}
	}

	ds.logger.Info("Policy query completed",
		zap.String("tenant_id", req.TenantID),
		zap.String("query", req.Query),
		zap.Duration("duration", response.Duration))

	return response, nil
}

func (ds *DecisionService) Compile(ctx context.Context, req *CompileRequest) (*CompileResponse, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ds.logger.Debug("Policy compilation completed", 
			zap.String("tenant_id", req.TenantID),
			zap.Duration("duration", duration))
	}()

	if !ds.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "compile")
	}

	if err := ds.validateCompileRequest(req); err != nil {
		return nil, err
	}

	compileReq := &opa.CompileRequest{
		Query:   req.Query,
		Input:   req.Input,
		Unknowns: req.Unknowns,
	}

	compileResp, err := ds.opaClient.Compile(ctx, compileReq)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to compile policy").
			WithTenantID(req.TenantID).
			WithContext("query", req.Query)
	}

	response := &CompileResponse{
		Result:   compileResp.Result,
		Duration: time.Since(start),
	}

	ds.logger.Info("Policy compilation completed",
		zap.String("tenant_id", req.TenantID),
		zap.Duration("duration", response.Duration))

	return response, nil
}

func (ds *DecisionService) performEvaluation(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	cacheKey := ds.buildCacheKey(req)
	
	if req.CachePolicy != "force_refresh" {
		if cached := ds.cache.Get(cacheKey); cached != nil {
			return &EvaluateResponse{
				Decision: *cached,
				Cached:   true,
				Duration: 0,
			}, nil
		}
	}

	evalReq := &EvaluateRequest{
		TenantID:  req.TenantID,
		SubjectID: req.SubjectID,
		Resource:  req.Resource,
		Action:    req.Action,
		Context:   req.Context,
		Input:     req.Input,
		RequestID: req.RequestID,
		TraceID:   req.TraceID,
		Timestamp: req.Timestamp,
	}

	response, err := ds.opaEngine.Evaluate(ctx, evalReq)
	if err != nil {
		return nil, err
	}

	if req.CachePolicy != "deny" {
		cacheTTL := 5 * time.Minute
		if req.CachePolicy == "allow" {
			cacheTTL = 15 * time.Minute
		}
		
		if err := ds.cache.Set(cacheKey, &response.Decision, cacheTTL); err != nil {
			ds.logger.Warn("Failed to cache decision",
				zap.String("cache_key", cacheKey),
				zap.Error(err))
		}
	}

	return response, nil
}

func (ds *DecisionService) generateExplanation(ctx context.Context, req *EvaluateRequest, decision *policy.PolicyDecision) (*PolicyExplanation, error) {
	explanation := &PolicyExplanation{
		MatchedPolicies: []MatchedPolicy{},
		AppliedRules:    []AppliedRule{},
		FailedRules:     []FailedRule{},
		Trace:           []EvaluationStep{},
		Metadata:        make(map[string]interface{}),
	}

	policies, _, err := ds.policyStore.ListPolicies(ctx, &ListPoliciesRequest{
		TenantID: req.TenantID,
		Status:   policy.PolicyStatusActive,
		Limit:    1000,
		Offset:   0,
	})
	if err != nil {
		return nil, err
	}

	for _, pol := range policies.Policies {
		matched, appliedRules, failedRules := ds.evaluatePolicyAgainstRequest(&pol, req)
		
		if matched {
			matchedPolicy := MatchedPolicy{
				PolicyID:    pol.ID,
				PolicyName:  pol.Name,
				Version:     pol.Version,
				Priority:    pol.Priority,
				Effect:      pol.Effect,
				MatchReason: "Resource and action match",
				Rules:       pol.Rules,
			}
			explanation.MatchedPolicies = append(explanation.MatchedPolicies, matchedPolicy)
		}

		explanation.AppliedRules = append(explanation.AppliedRules, appliedRules...)
		explanation.FailedRules = append(explanation.FailedRules, failedRules...)
	}

	explanation.Metadata["evaluation_time"] = time.Now().UTC()
	explanation.Metadata["tenant_id"] = req.TenantID
	explanation.Metadata["subject_id"] = req.SubjectID
	explanation.Metadata["resource"] = req.Resource
	explanation.Metadata["action"] = req.Action
	explanation.Metadata["decision_allow"] = decision.Allow
	explanation.Metadata["decision_reason"] = decision.Reason

	return explanation, nil
}

func (ds *DecisionService) generateQueryExplanation(ctx context.Context, req *QueryRequest, result map[string]interface{}) (*PolicyExplanation, error) {
	explanation := &PolicyExplanation{
		MatchedPolicies: []MatchedPolicy{},
		AppliedRules:    []AppliedRule{},
		FailedRules:     []FailedRule{},
		Trace:           []EvaluationStep{},
		Metadata:        make(map[string]interface{}),
	}

	explanation.Metadata["query"] = req.Query
	explanation.Metadata["tenant_id"] = req.TenantID
	explanation.Metadata["result"] = result
	explanation.Metadata["evaluation_time"] = time.Now().UTC()

	return explanation, nil
}

func (ds *DecisionService) evaluatePolicyAgainstRequest(pol *policy.Policy, req *EvaluateRequest) (bool, []AppliedRule, []FailedRule) {
	var appliedRules []AppliedRule
	var failedRules []FailedRule
	matched := false

	for _, rule := range pol.Rules {
		if rule.Resource == req.Resource && rule.Action == req.Action {
			matched = true
			
			conditionsMet := true
			for _, condition := range rule.Conditions {
				if !ds.evaluateCondition(condition, req.Context, req.Input) {
					conditionsMet = false
					failedRule := FailedRule{
						RuleID:        fmt.Sprintf("%s_%d", pol.ID, 0),
						PolicyID:      pol.ID,
						Resource:      rule.Resource,
						Action:        rule.Action,
						FailureType:   "condition_not_met",
						FailureReason: fmt.Sprintf("Condition %s %s %v not satisfied", condition.Field, condition.Operator, condition.Value),
						Conditions:    rule.Conditions,
						Metadata:      make(map[string]interface{}),
					}
					failedRules = append(failedRules, failedRule)
					break
				}
			}

			if conditionsMet {
				appliedRule := AppliedRule{
					RuleID:     fmt.Sprintf("%s_%d", pol.ID, 0),
					PolicyID:   pol.ID,
					Resource:   rule.Resource,
					Action:     rule.Action,
					Effect:     rule.Effect,
					Conditions: rule.Conditions,
					Metadata:   make(map[string]interface{}),
				}
				appliedRules = append(appliedRules, appliedRule)
			}
		}
	}

	return matched, appliedRules, failedRules
}

func (ds *DecisionService) evaluateCondition(condition policy.Condition, context map[string]interface{}, input map[string]interface{}) bool {
	var value interface{}
	
	if contextValue, exists := context[condition.Field]; exists {
		value = contextValue
	} else if inputValue, exists := input[condition.Field]; exists {
		value = inputValue
	} else {
		return false
	}

	switch condition.Operator {
	case "==", "eq":
		return fmt.Sprintf("%v", value) == fmt.Sprintf("%v", condition.Value)
	case "!=", "ne":
		return fmt.Sprintf("%v", value) != fmt.Sprintf("%v", condition.Value)
	case "in":
		if valueSlice, ok := condition.Value.([]interface{}); ok {
			for _, v := range valueSlice {
				if fmt.Sprintf("%v", value) == fmt.Sprintf("%v", v) {
					return true
				}
			}
		}
		return false
	case "not_in":
		if valueSlice, ok := condition.Value.([]interface{}); ok {
			for _, v := range valueSlice {
				if fmt.Sprintf("%v", value) == fmt.Sprintf("%v", v) {
					return false
				}
			}
		}
		return true
	case "contains":
		valueStr := fmt.Sprintf("%v", value)
		conditionStr := fmt.Sprintf("%v", condition.Value)
		return utils.MatchPattern(conditionStr, valueStr)
	case "starts_with":
		valueStr := fmt.Sprintf("%v", value)
		conditionStr := fmt.Sprintf("%v", condition.Value)
		return len(valueStr) >= len(conditionStr) && valueStr[:len(conditionStr)] == conditionStr
	case "ends_with":
		valueStr := fmt.Sprintf("%v", value)
		conditionStr := fmt.Sprintf("%v", condition.Value)
		return len(valueStr) >= len(conditionStr) && valueStr[len(valueStr)-len(conditionStr):] == conditionStr
	default:
		return false
	}
}

func (ds *DecisionService) buildCacheKey(req *EvaluateRequest) string {
	key := fmt.Sprintf("decision:%s:%s:%s:%s", req.TenantID, req.SubjectID, req.Resource, req.Action)
	
	if len(req.Context) > 0 {
		contextHash := utils.HashSHA256(utils.CoalesceString(utils.ToJSON(req.Context)))
		key += ":" + contextHash[:8]
	}
	
	if len(req.Input) > 0 {
		inputHash := utils.HashSHA256(utils.CoalesceString(utils.ToJSON(req.Input)))
		key += ":" + inputHash[:8]
	}
	
	return key
}

func (ds *DecisionService) enrichRequest(req *EvaluateRequest) {
	if req.RequestID == "" {
		req.RequestID = utils.GenerateRequestID()
	}
	
	if req.TraceID == "" {
		req.TraceID = utils.GenerateTraceID()
	}
	
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now().UTC()
	}
	
	if req.CachePolicy == "" {
		req.CachePolicy = "allow"
	}
	
	if req.Context == nil {
		req.Context = make(map[string]interface{})
	}
	
	if req.Input == nil {
		req.Input = make(map[string]interface{})
	}
	
	req.Context["request_id"] = req.RequestID
	req.Context["trace_id"] = req.TraceID
	req.Context["timestamp"] = req.Timestamp
}

func (ds *DecisionService) validateEvaluateRequest(req *EvaluateRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.SubjectID == "" {
		return errors.NewValidationError("subject_id", "Subject ID is required", req.SubjectID)
	}

	if req.Resource == "" {
		return errors.NewValidationError("resource", "Resource is required", req.Resource)
	}

	if req.Action == "" {
		return errors.NewValidationError("action", "Action is required", req.Action)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	if req.CachePolicy != "" {
		validPolicies := []string{"allow", "deny", "force_refresh"}
		if !utils.Contains(validPolicies, req.CachePolicy) {
			return errors.NewValidationError("cache_policy", "Invalid cache policy", req.CachePolicy)
		}
	}

	return nil
}

func (ds *DecisionService) validateBatchEvaluateRequest(req *BatchEvaluateRequest) error {
	if len(req.Requests) == 0 {
		return errors.NewValidationError("requests", "At least one request is required", len(req.Requests))
	}

	if len(req.Requests) > 100 {
		return errors.NewValidationError("requests", "Too many requests in batch", len(req.Requests))
	}

	for i, evalReq := range req.Requests {
		if err := ds.validateEvaluateRequest(&evalReq); err != nil {
			return errors.Wrap(err, errors.ErrCodeValidationError, fmt.Sprintf("Request %d validation failed", i+1))
		}
	}

	return nil
}

func (ds *DecisionService) validateExplainRequest(req *ExplainRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.SubjectID == "" {
		return errors.NewValidationError("subject_id", "Subject ID is required", req.SubjectID)
	}

	if req.Resource == "" {
		return errors.NewValidationError("resource", "Resource is required", req.Resource)
	}

	if req.Action == "" {
		return errors.NewValidationError("action", "Action is required", req.Action)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ds *DecisionService) validateQueryRequest(req *QueryRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.Query == "" {
		return errors.NewValidationError("query", "Query is required", req.Query)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	if req.Options.Timeout < 0 {
		return errors.NewValidationError("timeout", "Timeout cannot be negative", req.Options.Timeout)
	}

	if req.Options.Timeout > 5*time.Minute {
		return errors.NewValidationError("timeout", "Timeout too long", req.Options.Timeout)
	}

	if req.Options.CachePolicy != "" {
		validPolicies := []string{"allow", "deny", "force_refresh"}
		if !utils.Contains(validPolicies, req.Options.CachePolicy) {
			return errors.NewValidationError("cache_policy", "Invalid cache policy", req.Options.CachePolicy)
		}
	}

	return nil
}

func (ds *DecisionService) validateCompileRequest(req *CompileRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.Query == "" {
		return errors.NewValidationError("query", "Query is required", req.Query)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ds *DecisionService) GetDecisionMetrics(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	if tenantID == "" {
		return nil, errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID)
	}

	if !utils.IsValidUUID(tenantID) {
		return nil, errors.NewValidationError("tenant_id", "Invalid tenant ID format", tenantID)
	}

	engineMetrics := ds.opaEngine.GetMetrics()
	cacheStats := ds.cache.GetStats()

	metrics := map[string]interface{}{
		"tenant_id": tenantID,
		"engine": map[string]interface{}{
			"total_evaluations":      engineMetrics.TotalEvaluations,
			"successful_evaluations": engineMetrics.SuccessfulEvaluations,
			"failed_evaluations":     engineMetrics.FailedEvaluations,
			"cache_hits":             engineMetrics.CacheHits,
			"cache_misses":           engineMetrics.CacheMisses,
			"average_latency_ms":     engineMetrics.AverageLatency.Milliseconds(),
			"policy_syncs":           engineMetrics.PolicySyncs,
			"last_sync_time":         engineMetrics.LastSyncTime,
			"active_policies":        engineMetrics.ActivePolicies,
		},
		"cache": map[string]interface{}{
			"hit_rate":               cacheStats.HitRate,
			"total_entries":          cacheStats.TotalEntries,
			"total_size_bytes":       cacheStats.TotalSize,
			"hits":                   cacheStats.Hits,
			"misses":                 cacheStats.Misses,
			"evictions":              cacheStats.Evictions,
			"expirations":            cacheStats.Expirations,
			"average_access_time_ms": cacheStats.AverageAccessTime.Milliseconds(),
		},
		"circuit_breaker": map[string]interface{}{
			"state": ds.circuitBreaker.GetState(),
		},
		"rate_limiter": map[string]interface{}{
			"tokens":   ds.rateLimiter.GetTokens(),
			"capacity": ds.rateLimiter.GetCapacity(),
			"rate":     ds.rateLimiter.GetRate(),
		},
	}

	return metrics, nil
}

func (ds *DecisionService) ClearDecisionCache(ctx context.Context, tenantID string, policyID string) error {
	if tenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID)
	}

	if !utils.IsValidUUID(tenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", tenantID)
	}

	if policyID != "" && !utils.IsValidUUID(policyID) {
		return errors.NewValidationError("policy_id", "Invalid policy ID format", policyID)
	}

	pattern := fmt.Sprintf("decision:%s:*", tenantID)
	if policyID != "" {
		pattern = fmt.Sprintf("decision:%s:*:%s:*", tenantID, policyID)
	}

	cleared := ds.cache.ClearPattern(pattern)

	ds.logger.Info("Decision cache cleared",
		zap.String("tenant_id", tenantID),
		zap.String("policy_id", policyID),
		zap.String("pattern", pattern),
		zap.Int("cleared_entries", cleared))

	return nil
}

func (ds *DecisionService) WarmupCache(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID)
	}

	if !utils.IsValidUUID(tenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", tenantID)
	}

	policies, _, err := ds.policyStore.ListPolicies(ctx, &ListPoliciesRequest{
		TenantID: tenantID,
		Status:   policy.PolicyStatusActive,
		Limit:    100,
		Offset:   0,
	})
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to list policies for cache warmup").
			WithTenantID(tenantID)
	}

	warmedUp := 0
	for _, pol := range policies.Policies {
		for _, rule := range pol.Rules {
			evalReq := &EvaluateRequest{
				TenantID:    tenantID,
				SubjectID:   "warmup_subject",
				Resource:    rule.Resource,
				Action:      rule.Action,
				Context:     make(map[string]interface{}),
				Input:       make(map[string]interface{}),
				CachePolicy: "allow",
			}

			_, err := ds.performEvaluation(ctx, evalReq)
			if err != nil {
				ds.logger.Warn("Failed to warmup cache for policy rule",
					zap.String("tenant_id", tenantID),
					zap.String("policy_id", pol.ID),
					zap.String("resource", rule.Resource),
					zap.String("action", rule.Action),
					zap.Error(err))
			} else {
				warmedUp++
			}
		}
	}

	ds.logger.Info("Cache warmup completed",
		zap.String("tenant_id", tenantID),
		zap.Int("policies_processed", len(policies.Policies)),
		zap.Int("rules_warmed_up", warmedUp))

	return nil
}

func (ds *DecisionService) HealthCheck(ctx context.Context) error {
	if !ds.opaEngine.IsHealthy() {
		return errors.NewServiceUnavailable("OPA engine is not healthy")
	}

	if !ds.opaClient.IsHealthy(ctx) {
		return errors.NewServiceUnavailable("OPA client is not healthy")
	}

	if err := ds.cache.HealthCheck(); err != nil {
		return errors.Wrap(err, errors.ErrCodeServiceUnavailable, "Cache health check failed")
	}

	if err := ds.policyStore.HealthCheck(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeServiceUnavailable, "Policy store health check failed")
	}

	circuitState := ds.circuitBreaker.GetState()
	if circuitState == "open" {
		return errors.NewServiceUnavailable("Circuit breaker is open")
	}

	return nil
}

func (ds *DecisionService) GetHealthStatus() map[string]interface{} {
	return map[string]interface{}{
		"opa_engine":      ds.opaEngine.GetHealthStatus(),
		"opa_client":      ds.opaClient.IsHealthy(context.Background()),
		"cache":           ds.cache.HealthCheck() == nil,
		"policy_store":    ds.policyStore.HealthCheck(context.Background()) == nil,
		"circuit_breaker": ds.circuitBreaker.GetState(),
		"rate_limiter": map[string]interface{}{
			"tokens":   ds.rateLimiter.GetTokens(),
			"capacity": ds.rateLimiter.GetCapacity(),
		},
	}
}

func (ds *DecisionService) ResetCircuitBreaker() {
	ds.circuitBreaker.Reset()
	ds.logger.Info("Circuit breaker reset")
}

func (ds *DecisionService) GetCircuitBreakerState() string {
	return ds.circuitBreaker.GetState()
}

func (ds *DecisionService) IsRateLimited() bool {
	return !ds.rateLimiter.Allow()
}

func (ds *DecisionService) GetRateLimiterStatus() map[string]interface{} {
	return map[string]interface{}{
		"tokens":   ds.rateLimiter.GetTokens(),
		"capacity": ds.rateLimiter.GetCapacity(),
		"rate":     ds.rateLimiter.GetRate(),
	}
}

func (ds *DecisionService) Close() error {
	ds.logger.Info("Shutting down decision service")

	if err := ds.opaEngine.Close(); err != nil {
		ds.logger.Error("Failed to close OPA engine", zap.Error(err))
	}

	if err := ds.opaClient.Close(); err != nil {
		ds.logger.Error("Failed to close OPA client", zap.Error(err))
	}

	if err := ds.cache.Close(); err != nil {
		ds.logger.Error("Failed to close cache", zap.Error(err))
	}

	ds.logger.Info("Decision service shutdown completed")
	return nil
}
