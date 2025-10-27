package opa

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
	"flamo/backend/internal/policy/service"
	"flamo/backend/internal/policy/storage"
)

type Engine struct {
	client       *Client
	policyStore  *storage.PolicyStore
	cache        *Cache
	db           *database.Database
	config       *config.Config
	logger       *zap.Logger
	rateLimiter  *utils.RateLimiter
	metrics      *EngineMetrics
	mu           sync.RWMutex
	isHealthy    bool
	lastSync     time.Time
	syncInterval time.Duration
}

type EngineMetrics struct {
	TotalEvaluations     int64         `json:"total_evaluations"`
	SuccessfulEvaluations int64         `json:"successful_evaluations"`
	FailedEvaluations    int64         `json:"failed_evaluations"`
	CacheHits            int64         `json:"cache_hits"`
	CacheMisses          int64         `json:"cache_misses"`
	AverageLatency       time.Duration `json:"average_latency"`
	PolicySyncs          int64         `json:"policy_syncs"`
	LastSyncTime         time.Time     `json:"last_sync_time"`
	ActivePolicies       int64         `json:"active_policies"`
	mu                   sync.RWMutex
}

type EvaluationContext struct {
	TenantID    string                 `json:"tenant_id"`
	SubjectID   string                 `json:"subject_id"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Context     map[string]interface{} `json:"context"`
	Input       map[string]interface{} `json:"input"`
	RequestID   string                 `json:"request_id"`
	TraceID     string                 `json:"trace_id"`
	Timestamp   time.Time              `json:"timestamp"`
	CacheKey    string                 `json:"cache_key"`
	PolicyRules []policy.Rule          `json:"policy_rules"`
}

type EvaluationResult struct {
	Decision     policy.PolicyDecision `json:"decision"`
	Duration     time.Duration         `json:"duration"`
	CacheHit     bool                  `json:"cache_hit"`
	PolicyCount  int                   `json:"policy_count"`
	RulesApplied []string              `json:"rules_applied"`
	Metadata     map[string]string     `json:"metadata"`
}

type PolicySyncResult struct {
	SyncedPolicies   int       `json:"synced_policies"`
	FailedPolicies   int       `json:"failed_policies"`
	Duration         time.Duration `json:"duration"`
	Timestamp        time.Time `json:"timestamp"`
	Errors           []string  `json:"errors,omitempty"`
}

func NewEngine(client *Client, policyStore *storage.PolicyStore, cache *Cache, db *database.Database, cfg *config.Config, logger *zap.Logger) *Engine {
	rateLimiter := utils.NewRateLimiter(1000.0, 10000)
	
	engine := &Engine{
		client:       client,
		policyStore:  policyStore,
		cache:        cache,
		db:           db,
		config:       cfg,
		logger:       logger,
		rateLimiter:  rateLimiter,
		metrics:      &EngineMetrics{},
		isHealthy:    true,
		syncInterval: 5 * time.Minute,
	}

	go engine.startPeriodicSync()
	
	return engine
}

func (e *Engine) Evaluate(ctx context.Context, req *service.EvaluateRequest) (*service.EvaluateResponse, error) {
	if !e.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("resource", req.Resource).
			WithContext("action", req.Action)
	}

	start := time.Now()
	traceID := utils.GenerateTraceID()
	if req.RequestID == "" {
		req.RequestID = utils.GenerateRequestID()
	}

	evalCtx := &EvaluationContext{
		TenantID:  req.TenantID,
		SubjectID: req.SubjectID,
		Resource:  req.Resource,
		Action:    req.Action,
		Context:   req.Context,
		Input:     req.Input,
		RequestID: req.RequestID,
		TraceID:   traceID,
		Timestamp: time.Now().UTC(),
		CacheKey:  e.buildCacheKey(req),
	}

	result, err := e.evaluateWithCache(ctx, evalCtx)
	if err != nil {
		e.recordEvaluationMetrics(time.Since(start), false, false)
		return nil, err
	}

	e.recordEvaluationMetrics(time.Since(start), true, result.CacheHit)

	e.logger.Debug("Policy evaluation completed",
		zap.String("tenant_id", req.TenantID),
		zap.String("trace_id", traceID),
		zap.String("resource", req.Resource),
		zap.String("action", req.Action),
		zap.Bool("allow", result.Decision.Allow),
		zap.Bool("cache_hit", result.CacheHit),
		zap.Duration("duration", result.Duration))

	return &service.EvaluateResponse{
		Decision: result.Decision,
		Cached:   result.CacheHit,
		Duration: result.Duration,
	}, nil
}

func (e *Engine) BatchEvaluate(ctx context.Context, req *service.BatchEvaluateRequest) (*service.BatchEvaluateResponse, error) {
	if len(req.Requests) == 0 {
		return nil, errors.NewValidationError("requests", "At least one request is required", len(req.Requests))
	}

	if len(req.Requests) > 100 {
		return nil, errors.NewValidationError("requests", "Too many requests in batch", len(req.Requests))
	}

	start := time.Now()
	responses := make([]service.EvaluateResponse, len(req.Requests))
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for i, evalReq := range req.Requests {
		wg.Add(1)
		go func(index int, request service.EvaluateRequest) {
			defer wg.Done()
			
			resp, err := e.Evaluate(ctx, &request)
			
			mu.Lock()
			if err != nil {
				responses[index] = service.EvaluateResponse{
					Decision: policy.PolicyDecision{
						Allow:     false,
						Deny:      true,
						Reason:    "Evaluation error: " + err.Error(),
						Timestamp: time.Now().UTC(),
						TenantID:  request.TenantID,
						SubjectID: request.SubjectID,
						Resource:  request.Resource,
						Action:    request.Action,
						Context:   request.Context,
						Metadata:  map[string]string{"error": err.Error()},
					},
					Cached:   false,
					Duration: 0,
				}
			} else {
				responses[index] = *resp
			}
			mu.Unlock()
		}(i, evalReq)
	}
	
	wg.Wait()

	return &service.BatchEvaluateResponse{
		Responses: responses,
		Duration:  time.Since(start),
	}, nil
}

func (e *Engine) SyncPolicies(ctx context.Context, tenantID string) (*PolicySyncResult, error) {
	if tenantID == "" {
		return nil, errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID)
	}

	start := time.Now()
	result := &PolicySyncResult{
		Timestamp: start,
		Errors:    []string{},
	}

	policies, _, err := e.policyStore.ListPolicies(ctx, &service.ListPoliciesRequest{
		TenantID: tenantID,
		Status:   policy.PolicyStatusActive,
		Limit:    1000,
		Offset:   0,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "Failed to fetch policies for sync").
			WithTenantID(tenantID)
	}

	for _, pol := range policies.Policies {
		if err := e.syncPolicyToOPA(ctx, &pol); err != nil {
			result.FailedPolicies++
			result.Errors = append(result.Errors, fmt.Sprintf("Policy %s: %s", pol.ID, err.Error()))
			e.logger.Error("Failed to sync policy to OPA",
				zap.String("policy_id", pol.ID),
				zap.String("tenant_id", tenantID),
				zap.Error(err))
		} else {
			result.SyncedPolicies++
		}
	}

	result.Duration = time.Since(start)
	
	e.mu.Lock()
	e.lastSync = time.Now()
	e.mu.Unlock()
	
	e.metrics.mu.Lock()
	e.metrics.PolicySyncs++
	e.metrics.LastSyncTime = time.Now()
	e.metrics.ActivePolicies = int64(result.SyncedPolicies)
	e.metrics.mu.Unlock()

	e.logger.Info("Policy sync completed",
		zap.String("tenant_id", tenantID),
		zap.Int("synced_policies", result.SyncedPolicies),
		zap.Int("failed_policies", result.FailedPolicies),
		zap.Duration("duration", result.Duration))

	return result, nil
}

func (e *Engine) evaluateWithCache(ctx context.Context, evalCtx *EvaluationContext) (*EvaluationResult, error) {
	if cached := e.cache.Get(evalCtx.CacheKey); cached != nil {
		e.metrics.mu.Lock()
		e.metrics.CacheHits++
		e.metrics.mu.Unlock()

		return &EvaluationResult{
			Decision:    *cached,
			Duration:    0,
			CacheHit:    true,
			PolicyCount: 0,
			Metadata:    map[string]string{"cache": "hit"},
		}, nil
	}

	e.metrics.mu.Lock()
	e.metrics.CacheMisses++
	e.metrics.mu.Unlock()

	start := time.Now()
	
	opaReq := &service.EvaluateRequest{
		TenantID:  evalCtx.TenantID,
		SubjectID: evalCtx.SubjectID,
		Resource:  evalCtx.Resource,
		Action:    evalCtx.Action,
		Context:   evalCtx.Context,
		Input:     evalCtx.Input,
		RequestID: evalCtx.RequestID,
	}

	opaResp, err := e.client.Evaluate(ctx, opaReq)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "OPA evaluation failed").
			WithTenantID(evalCtx.TenantID).
			WithTraceID(evalCtx.TraceID)
	}

	duration := time.Since(start)
	
	e.cache.Set(evalCtx.CacheKey, &opaResp.Decision, 5*time.Minute)

	result := &EvaluationResult{
		Decision:    opaResp.Decision,
		Duration:    duration,
		CacheHit:    false,
		PolicyCount: 1,
		Metadata:    map[string]string{"cache": "miss"},
	}

	if err := e.recordEvaluationAudit(ctx, evalCtx, result); err != nil {
		e.logger.Error("Failed to record evaluation audit",
			zap.String("tenant_id", evalCtx.TenantID),
			zap.String("trace_id", evalCtx.TraceID),
			zap.Error(err))
	}

	return result, nil
}

func (e *Engine) syncPolicyToOPA(ctx context.Context, pol *policy.Policy) error {
	regoPolicy := e.convertToRego(pol)
	
	policyDoc := &PolicyDocument{
		ID:      pol.ID,
		Path:    fmt.Sprintf("tenants/%s/policies/%s", pol.TenantID, pol.ID),
		Content: regoPolicy,
		Metadata: map[string]interface{}{
			"tenant_id":   pol.TenantID,
			"policy_name": pol.Name,
			"version":     pol.Version,
			"created_at":  pol.CreatedAt,
			"updated_at":  pol.UpdatedAt,
		},
	}

	return e.client.UploadPolicy(ctx, policyDoc)
}

func (e *Engine) convertToRego(pol *policy.Policy) string {
	packageName := fmt.Sprintf("tenants.%s.policies", pol.TenantID)
	
	rego := fmt.Sprintf(`package %s

default allow = false

allow {
    input.tenant_id == "%s"
    policy_rules[_]
}

policy_rules[rule] {
    rule := {
        "id": "%s",
        "name": "%s",
        "effect": "%s",
        "priority": %d
    }
    evaluate_conditions
}

evaluate_conditions {
`, packageName, pol.TenantID, pol.ID, pol.Name, pol.Effect, pol.Priority)

	for i, rule := range pol.Rules {
		rego += fmt.Sprintf(`    rule_%d
`, i)
	}

	rego += "}\n\n"

	for i, rule := range pol.Rules {
		rego += fmt.Sprintf(`rule_%d {
    input.resource == "%s"
    input.action == "%s"
`, i, rule.Resource, rule.Action)

		for _, condition := range rule.Conditions {
			rego += fmt.Sprintf(`    input.%s %s %v
`, condition.Field, condition.Operator, condition.Value)
		}

		rego += "}\n\n"
	}

	return rego
}

func (e *Engine) recordEvaluationAudit(ctx context.Context, evalCtx *EvaluationContext, result *EvaluationResult) error {
	auditEntry := database.AuditEntry{
		TraceID:          evalCtx.TraceID,
		TenantID:         evalCtx.TenantID,
		RequestHash:      utils.HashSHA256(fmt.Sprintf("%s:%s:%s", evalCtx.Resource, evalCtx.Action, evalCtx.SubjectID)),
		DetectorVerdicts: map[string]interface{}{
			"policy_decision": result.Decision,
			"cache_hit":       result.CacheHit,
			"policy_count":    result.PolicyCount,
		},
		PoliciesApplied: map[string]interface{}{
			"rules_applied": result.RulesApplied,
			"duration_ms":   result.Duration.Milliseconds(),
		},
		ProcessingTimeMs: result.Duration.Milliseconds(),
		Timestamp:        evalCtx.Timestamp,
	}

	if e.config.Security.EnableAuditLogging {
		encryptedPayload, err := e.encryptAuditPayload(evalCtx)
		if err != nil {
			e.logger.Warn("Failed to encrypt audit payload", zap.Error(err))
		} else {
			auditEntry.EncryptedPayload = encryptedPayload
		}
	}

	return e.db.StreamAuditEntry(auditEntry)
}

func (e *Engine) encryptAuditPayload(evalCtx *EvaluationContext) ([]byte, error) {
	payload := map[string]interface{}{
		"tenant_id":  evalCtx.TenantID,
		"subject_id": evalCtx.SubjectID,
		"resource":   evalCtx.Resource,
		"action":     evalCtx.Action,
		"context":    evalCtx.Context,
		"input":      evalCtx.Input,
		"timestamp":  evalCtx.Timestamp,
	}

	jsonData, err := utils.ToJSON(payload)
	if err != nil {
		return nil, err
	}

	encryptedData, err := utils.EncryptAES(jsonData, e.config.Security.EncryptionKey)
	if err != nil {
		return nil, err
	}

	return []byte(encryptedData), nil
}

func (e *Engine) buildCacheKey(req *service.EvaluateRequest) string {
	key := fmt.Sprintf("eval:%s:%s:%s:%s", req.TenantID, req.SubjectID, req.Resource, req.Action)
	
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

func (e *Engine) recordEvaluationMetrics(duration time.Duration, success bool, cacheHit bool) {
	e.metrics.mu.Lock()
	defer e.metrics.mu.Unlock()

	e.metrics.TotalEvaluations++
	
	if success {
		e.metrics.SuccessfulEvaluations++
	} else {
		e.metrics.FailedEvaluations++
	}

	if cacheHit {
		e.metrics.CacheHits++
	} else {
		e.metrics.CacheMisses++
	}

	if e.metrics.TotalEvaluations > 0 {
		totalDuration := time.Duration(e.metrics.TotalEvaluations-1) * e.metrics.AverageLatency
		e.metrics.AverageLatency = (totalDuration + duration) / time.Duration(e.metrics.TotalEvaluations)
	} else {
		e.metrics.AverageLatency = duration
	}
}

func (e *Engine) startPeriodicSync() {
	ticker := time.NewTicker(e.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.performHealthCheck()
			if e.shouldPerformSync() {
				e.performPeriodicSync()
			}
		}
	}
}

func (e *Engine) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	healthy := true

	if !e.client.IsHealthy(ctx) {
		healthy = false
		e.logger.Warn("OPA client health check failed")
	}

	if err := e.policyStore.HealthCheck(ctx); err != nil {
		healthy = false
		e.logger.Warn("Policy store health check failed", zap.Error(err))
	}

	if err := e.cache.HealthCheck(); err != nil {
		healthy = false
		e.logger.Warn("Cache health check failed", zap.Error(err))
	}

	e.mu.Lock()
	e.isHealthy = healthy
	e.mu.Unlock()

	if !healthy {
		e.logger.Error("Engine health check failed")
	}
}

func (e *Engine) shouldPerformSync() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return time.Since(e.lastSync) > e.syncInterval
}

func (e *Engine) performPeriodicSync() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tenants, err := e.getActiveTenants(ctx)
	if err != nil {
		e.logger.Error("Failed to get active tenants for sync", zap.Error(err))
		return
	}

	for _, tenantID := range tenants {
		if _, err := e.SyncPolicies(ctx, tenantID); err != nil {
			e.logger.Error("Failed to sync policies for tenant",
				zap.String("tenant_id", tenantID),
				zap.Error(err))
		}
	}
}

func (e *Engine) getActiveTenants(ctx context.Context) ([]string, error) {
	query := "SELECT DISTINCT tenant_id FROM policies WHERE status = 'active'"
	
	rows, err := e.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Rows.Close()

	var tenants []string
	for rows.Rows.Next() {
		var tenantID string
		if err := rows.Rows.Scan(&tenantID); err != nil {
			continue
		}
		tenants = append(tenants, tenantID)
	}

	return tenants, nil
}

func (e *Engine) ClearCache(ctx context.Context, req *service.ClearCacheRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	pattern := fmt.Sprintf("eval:%s:*", req.TenantID)
	if req.PolicyID != "" {
		pattern = fmt.Sprintf("eval:%s:*:%s:*", req.TenantID, req.PolicyID)
	}

	cleared := e.cache.ClearPattern(pattern)

	e.logger.Info("Cache cleared",
		zap.String("tenant_id", req.TenantID),
		zap.String("policy_id", req.PolicyID),
		zap.String("pattern", pattern),
		zap.Int("cleared_entries", cleared))

	return nil
}

func (e *Engine) GetMetrics() *EngineMetrics {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	metrics := *e.metrics
	return &metrics
}

func (e *Engine) GetHealthStatus() map[string]interface{} {
	e.mu.RLock()
	isHealthy := e.isHealthy
	lastSync := e.lastSync
	e.mu.RUnlock()

	metrics := e.GetMetrics()

	return map[string]interface{}{
		"healthy":     isHealthy,
		"last_sync":   lastSync,
		"metrics": map[string]interface{}{
			"total_evaluations":      metrics.TotalEvaluations,
			"successful_evaluations": metrics.SuccessfulEvaluations,
			"failed_evaluations":     metrics.FailedEvaluations,
			"cache_hits":             metrics.CacheHits,
			"cache_misses":           metrics.CacheMisses,
			"average_latency_ms":     metrics.AverageLatency.Milliseconds(),
			"policy_syncs":           metrics.PolicySyncs,
			"last_sync_time":         metrics.LastSyncTime,
			"active_policies":        metrics.ActivePolicies,
		},
		"cache_stats": e.cache.GetStats(),
		"opa_client": map[string]interface{}{
			"base_url": e.client.GetBaseURL(),
			"healthy":  e.client.IsHealthy(context.Background()),
		},
	}
}

func (e *Engine) RefreshPolicies(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID)
	}

	e.cache.ClearPattern(fmt.Sprintf("eval:%s:*", tenantID))

	_, err := e.SyncPolicies(ctx, tenantID)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to refresh policies").
			WithTenantID(tenantID)
	}

	e.logger.Info("Policies refreshed successfully",
		zap.String("tenant_id", tenantID))

	return nil
}

func (e *Engine) ValidatePolicy(ctx context.Context, pol *policy.Policy) error {
	regoPolicy := e.convertToRego(pol)

	compileReq := &CompileRequest{
		Query: regoPolicy,
		Input: map[string]interface{}{
			"tenant_id":  pol.TenantID,
			"subject_id": "test_subject",
			"resource":   "test_resource",
			"action":     "test_action",
		},
	}

	_, err := e.client.Compile(ctx, compileReq)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeValidationError, "Policy validation failed").
			WithContext("policy_id", pol.ID).
			WithContext("policy_name", pol.Name)
	}

	return nil
}

func (e *Engine) SetSyncInterval(interval time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.syncInterval = interval
}

func (e *Engine) GetSyncInterval() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.syncInterval
}

func (e *Engine) IsHealthy() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isHealthy
}

func (e *Engine) GetLastSyncTime() time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastSync
}

func (e *Engine) Close() error {
	e.logger.Info("Shutting down OPA engine")

	if err := e.client.Close(); err != nil {
		e.logger.Error("Failed to close OPA client", zap.Error(err))
	}

	if err := e.cache.Close(); err != nil {
		e.logger.Error("Failed to close cache", zap.Error(err))
	}

	e.logger.Info("OPA engine shutdown completed")
	return nil
}
