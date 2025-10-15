package orchestrator

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	"flamo/backend/pkg/models"
	authpb "flamo/backend/pkg/api/proto/auth"
	gatewaypb "flamo/backend/pkg/api/proto/gateway"
)

type Orchestrator struct {
	config           *config.Config
	db               *database.Database
	logger           *zap.Logger
	
	authClient       authpb.AuthenticationServiceClient
	policyClient     PolicyEngineClient
	threatClient     ThreatDetectionClient
	modelProxyClient ModelProxyClient
	auditClient      AuditServiceClient
	
	circuitBreakers  map[string]*utils.CircuitBreaker
	rateLimiters     map[string]*utils.RateLimiter
	
	tenantCache      *TenantCache
	policyCache      *PolicyCache
	
	metrics          *OrchestratorMetrics
	healthStatus     *HealthStatus
	
	mu               sync.RWMutex
	shutdown         chan struct{}
	wg               sync.WaitGroup
}

type RequestContext struct {
	RequestID        string
	TraceID          string
	SpanID           string
	TenantID         string
	UserID           string
	ClientIP         string
	UserAgent        string
	Timestamp        time.Time
	Request          *models.AIRequest
	Tenant           *models.Tenant
	AuthContext      *AuthenticationContext
	PolicyContext    *PolicyContext
	ThreatContext    *ThreatContext
	ModelContext     *ModelContext
	AuditContext     *AuditContext
	Metadata         map[string]interface{}
	ProcessingStage  ProcessingStage
	StartTime        time.Time
	EndTime          time.Time
	Duration         time.Duration
	Error            *errors.AppError
}

type AuthenticationContext struct {
	Method           string
	Principal        string
	Scopes           []string
	Claims           map[string]interface{}
	TokenExpiry      time.Time
	IsAuthenticated  bool
	AuthLevel        AuthenticationLevel
	MFAVerified      bool
	DeviceFingerprint string
}

type PolicyContext struct {
	PolicyVersion    string
	AppliedPolicies  []string
	PolicyDecision   PolicyDecision
	Constraints      map[string]interface{}
	Violations       []PolicyViolation
	ComplianceFlags  []string
}

type ThreatContext struct {
	ThreatLevel      ThreatLevel
	DetectedThreats  []ThreatDetection
	RiskScore        float64
	Mitigations      []string
	BlockReason      string
	Confidence       float64
}

type ModelContext struct {
	SelectedModel    string
	Provider         string
	Endpoint         string
	LoadBalanceKey   string
	RetryAttempts    int
	ResponseTime     time.Duration
	TokensUsed       int64
	CostEstimate     float64
}

type AuditContext struct {
	AuditID          string
	ComplianceLevel  string
	DataClassification string
	RetentionPolicy  string
	PIIDetected      bool
	Encrypted        bool
	AuditTrail       []AuditEvent
}

type ProcessingStage string

const (
	StageReceived         ProcessingStage = "received"
	StageAuthenticated    ProcessingStage = "authenticated"
	StageTenantResolved   ProcessingStage = "tenant_resolved"
	StagePolicyEvaluated  ProcessingStage = "policy_evaluated"
	StageThreatAnalyzed   ProcessingStage = "threat_analyzed"
	StageModelRouted      ProcessingStage = "model_routed"
	StageResponseReceived ProcessingStage = "response_received"
	StagePostProcessed    ProcessingStage = "post_processed"
	StageAudited          ProcessingStage = "audited"
	StageCompleted        ProcessingStage = "completed"
	StageFailed           ProcessingStage = "failed"
)

type AuthenticationLevel string

const (
	AuthLevelNone     AuthenticationLevel = "none"
	AuthLevelBasic    AuthenticationLevel = "basic"
	AuthLevelStandard AuthenticationLevel = "standard"
	AuthLevelHigh     AuthenticationLevel = "high"
	AuthLevelCritical AuthenticationLevel = "critical"
)

type PolicyDecision string

const (
	PolicyAllow      PolicyDecision = "allow"
	PolicyDeny       PolicyDecision = "deny"
	PolicyModify     PolicyDecision = "modify"
	PolicyFlag       PolicyDecision = "flag"
	PolicyQuarantine PolicyDecision = "quarantine"
)

type ThreatLevel string

const (
	ThreatNone     ThreatLevel = "none"
	ThreatLow      ThreatLevel = "low"
	ThreatMedium   ThreatLevel = "medium"
	ThreatHigh     ThreatLevel = "high"
	ThreatCritical ThreatLevel = "critical"
)

type PolicyViolation struct {
	PolicyID     string
	Severity     string
	Description  string
	Field        string
	Value        interface{}
	Remediation  string
	Metadata     map[string]interface{}
}

type ThreatDetection struct {
	ThreatType   string
	Severity     string
	Description  string
	Confidence   float64
	Location     string
	Signature    string
	Metadata     map[string]interface{}
}

type AuditEvent struct {
	EventID      string
	EventType    string
	Timestamp    time.Time
	Actor        string
	Action       string
	Resource     string
	Result       string
	Details      map[string]interface{}
}

type TenantCache struct {
	cache    map[string]*models.Tenant
	ttl      time.Duration
	lastSync time.Time
	mu       sync.RWMutex
}

type PolicyCache struct {
	cache    map[string]interface{}
	ttl      time.Duration
	lastSync time.Time
	mu       sync.RWMutex
}

type OrchestratorMetrics struct {
	TotalRequests        int64
	SuccessfulRequests   int64
	FailedRequests       int64
	AverageResponseTime  time.Duration
	ThroughputPerSecond  float64
	ErrorRate            float64
	AuthenticationRate   float64
	ThreatDetectionRate  float64
	PolicyViolationRate  float64
	ServiceHealthScores  map[string]float64
	LastUpdated          time.Time
	mu                   sync.RWMutex
}

type HealthStatus struct {
	Overall          string
	Services         map[string]string
	Dependencies     map[string]string
	LastHealthCheck  time.Time
	Uptime           time.Duration
	Version          string
	Environment      string
	mu               sync.RWMutex
}

type PolicyEngineClient interface {
	EvaluatePolicy(ctx context.Context, req *PolicyRequest) (*PolicyResponse, error)
	GetPolicy(ctx context.Context, policyID string) (*Policy, error)
	HealthCheck(ctx context.Context) error
}

type ThreatDetectionClient interface {
	AnalyzeThreat(ctx context.Context, req *ThreatAnalysisRequest) (*ThreatAnalysisResponse, error)
	GetThreatSignatures(ctx context.Context) (*ThreatSignatures, error)
	HealthCheck(ctx context.Context) error
}

type ModelProxyClient interface {
	RouteRequest(ctx context.Context, req *ModelRequest) (*ModelResponse, error)
	GetAvailableModels(ctx context.Context, tenantID string) (*AvailableModels, error)
	HealthCheck(ctx context.Context) error
}

type AuditServiceClient interface {
	LogEvent(ctx context.Context, event *AuditEvent) error
	LogRequest(ctx context.Context, reqCtx *RequestContext) error
	HealthCheck(ctx context.Context) error
}

func NewOrchestrator(cfg *config.Config, db *database.Database, logger *zap.Logger) (*Orchestrator, error) {
	if cfg == nil {
		return nil, errors.New(errors.ErrCodeConfigError, "configuration is required")
	}
	if db == nil {
		return nil, errors.New(errors.ErrCodeDatabaseError, "database connection is required")
	}
	if logger == nil {
		return nil, errors.New(errors.ErrCodeInternalError, "logger is required")
	}

	orchestrator := &Orchestrator{
		config:          cfg,
		db:              db,
		logger:          logger,
		circuitBreakers: make(map[string]*utils.CircuitBreaker),
		rateLimiters:    make(map[string]*utils.RateLimiter),
		shutdown:        make(chan struct{}),
		metrics: &OrchestratorMetrics{
			ServiceHealthScores: make(map[string]float64),
			LastUpdated:         time.Now(),
		},
		healthStatus: &HealthStatus{
			Services:     make(map[string]string),
			Dependencies: make(map[string]string),
			Version:      "1.0.0",
			Environment:  string(cfg.Environment),
		},
	}

	if err := orchestrator.initialize(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "failed to initialize orchestrator")
	}

	logger.Info("Orchestrator initialized successfully",
		zap.String("environment", string(cfg.Environment)))

	return orchestrator, nil
}

func (o *Orchestrator) initialize() error {
	if err := o.initializeClients(); err != nil {
		return err
	}

	if err := o.initializeCaches(); err != nil {
		return err
	}

	if err := o.initializeCircuitBreakers(); err != nil {
		return err
	}

	if err := o.initializeRateLimiters(); err != nil {
		return err
	}

	o.startBackgroundTasks()
	return nil
}

func (o *Orchestrator) ProcessRequest(ctx context.Context, request *models.AIRequest) (*models.AIResponse, *errors.AppError) {
	reqCtx := o.createRequestContext(ctx, request)
	
	defer func() {
		reqCtx.EndTime = time.Now()
		reqCtx.Duration = reqCtx.EndTime.Sub(reqCtx.StartTime)
		o.updateMetrics(reqCtx)
		o.auditRequest(reqCtx)
	}()

	if err := o.validateRequest(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = StageFailed
		return nil, err
	}

	if err := o.authenticateRequest(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = StageFailed
		return nil, err
	}

	if err := o.resolveTenant(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = StageFailed
		return nil, err
	}

	if err := o.evaluatePolicy(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = StageFailed
		return nil, err
	}

	if err := o.analyzeThreat(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = StageFailed
		return nil, err
	}

	response, err := o.routeToModel(reqCtx)
	if err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = StageFailed
		return nil, err
	}

	if err := o.postProcessResponse(reqCtx, response); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = StageFailed
		return nil, err
	}

	reqCtx.ProcessingStage = StageCompleted
	return response, nil
}

func (o *Orchestrator) createRequestContext(ctx context.Context, request *models.AIRequest) *RequestContext {
	requestID := utils.GenerateRequestID()
	traceID := utils.GenerateTraceID()
	
	return &RequestContext{
		RequestID:       requestID,
		TraceID:         traceID,
		SpanID:          utils.GenerateNonce(16),
		Timestamp:       time.Now(),
		Request:         request,
		Metadata:        make(map[string]interface{}),
		ProcessingStage: StageReceived,
		StartTime:       time.Now(),
		AuthContext:     &AuthenticationContext{},
		PolicyContext:   &PolicyContext{},
		ThreatContext:   &ThreatContext{},
		ModelContext:    &ModelContext{},
		AuditContext:    &AuditContext{},
	}
}

func (o *Orchestrator) initializeClients() error {
	authConn, err := grpc.Dial(
		o.getServiceAddress(o.config.Services.AuthService),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeNetworkError, "failed to connect to auth service")
	}
	o.authClient = authpb.NewAuthenticationServiceClient(authConn)

	return nil
}

func (o *Orchestrator) initializeCaches() error {
	o.tenantCache = &TenantCache{
		cache:    make(map[string]*models.Tenant),
		ttl:      5 * time.Minute,
		lastSync: time.Now(),
	}

	o.policyCache = &PolicyCache{
		cache:    make(map[string]interface{}),
		ttl:      10 * time.Minute,
		lastSync: time.Now(),
	}

	return nil
}

func (o *Orchestrator) initializeCircuitBreakers() error {
	services := []string{"auth", "policy", "threat", "model", "audit"}
	
	for _, service := range services {
		config := utils.CircuitBreakerConfig{
			MaxRequests:      100,
			Interval:         time.Minute,
			Timeout:          30 * time.Second,
			FailureThreshold: 0.6,
			SuccessThreshold: 5,
		}
		o.circuitBreakers[service] = utils.NewCircuitBreaker(config)
	}

	return nil
}

func (o *Orchestrator) initializeRateLimiters() error {
	services := []string{"auth", "policy", "threat", "model", "audit"}
	
	for _, service := range services {
		o.rateLimiters[service] = utils.NewRateLimiter(100.0, 1000)
	}

	return nil
}

func (o *Orchestrator) validateRequest(reqCtx *RequestContext) *errors.AppError {
	if reqCtx.Request == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if reqCtx.Request.Prompt == "" {
		return errors.New(errors.ErrCodeValidationError, "prompt is required")
	}

	if len(reqCtx.Request.Prompt) > 100000 {
		return errors.New(errors.ErrCodePayloadTooLarge, "prompt exceeds maximum length")
	}

	if reqCtx.Request.Model == "" {
		return errors.New(errors.ErrCodeInvalidModel, "model is required")
	}

	if !utils.IsValidUUID(reqCtx.Request.TenantID) {
		return errors.New(errors.ErrCodeValidationError, "invalid tenant ID format")
	}

	return nil
}

func (o *Orchestrator) authenticateRequest(reqCtx *RequestContext) *errors.AppError {
	if !o.rateLimiters["auth"].Allow() {
		return errors.NewRateLimitError(time.Minute)
	}

	var authErr *errors.AppError
	err := o.circuitBreakers["auth"].Execute(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		authReq := &authpb.AuthenticateRequest{
			Token:    reqCtx.Request.AuthToken,
			TenantId: reqCtx.Request.TenantID,
		}

		resp, err := o.authClient.Authenticate(ctx, authReq)
		if err != nil {
			authErr = errors.Wrap(err, errors.ErrCodeAuthenticationError, "authentication failed")
			return err
		}

		reqCtx.AuthContext.IsAuthenticated = resp.Valid
		reqCtx.AuthContext.Principal = resp.Principal
		reqCtx.AuthContext.Scopes = resp.Scopes
		reqCtx.AuthContext.Claims = make(map[string]interface{})
		reqCtx.AuthContext.AuthLevel = AuthLevelStandard
		reqCtx.ProcessingStage = StageAuthenticated

		return nil
	})

	if err != nil {
		return authErr
	}

	if !reqCtx.AuthContext.IsAuthenticated {
		return errors.NewUnauthorizedError("invalid authentication credentials")
	}

	return nil
}

func (o *Orchestrator) resolveTenant(reqCtx *RequestContext) *errors.AppError {
	tenant, err := o.getTenantFromCache(reqCtx.Request.TenantID)
	if err != nil {
		tenant, err = o.getTenantFromDatabase(reqCtx.Request.TenantID)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeNotFound, "tenant not found")
		}
		o.cacheTenant(tenant)
	}

	if !tenant.IsActive {
		return errors.NewForbiddenError("tenant is inactive")
	}

	if tenant.IsBlocked {
		return errors.NewForbiddenError("tenant is blocked")
	}

	reqCtx.Tenant = tenant
	reqCtx.TenantID = tenant.ID
	reqCtx.ProcessingStage = StageTenantResolved

	return nil
}

func (o *Orchestrator) evaluatePolicy(reqCtx *RequestContext) *errors.AppError {
	if !o.rateLimiters["policy"].Allow() {
		return errors.NewRateLimitError(time.Minute)
	}

	var policyErr *errors.AppError
	err := o.circuitBreakers["policy"].Execute(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		policyReq := &PolicyRequest{
			TenantID:    reqCtx.TenantID,
			UserID:      reqCtx.AuthContext.Principal,
			Action:      "ai_request",
			Resource:    reqCtx.Request.Model,
			Context:     reqCtx.Metadata,
			RequestData: reqCtx.Request,
		}

		resp, err := o.policyClient.EvaluatePolicy(ctx, policyReq)
		if err != nil {
			policyErr = errors.Wrap(err, errors.ErrCodeAuthorizationError, "policy evaluation failed")
			return err
		}

		reqCtx.PolicyContext.PolicyDecision = resp.Decision
		reqCtx.PolicyContext.AppliedPolicies = resp.Policies
		reqCtx.PolicyContext.Violations = resp.Violations
		reqCtx.PolicyContext.Constraints = resp.Constraints
		reqCtx.ProcessingStage = StagePolicyEvaluated

		return nil
	})

	if err != nil {
		return policyErr
	}

	switch reqCtx.PolicyContext.PolicyDecision {
	case PolicyDeny:
		return errors.NewForbiddenError("request denied by policy")
	case PolicyQuarantine:
		return errors.NewForbiddenError("request quarantined by policy")
	}

	return nil
}

func (o *Orchestrator) analyzeThreat(reqCtx *RequestContext) *errors.AppError {
	if !o.rateLimiters["threat"].Allow() {
		return errors.NewRateLimitError(time.Minute)
	}

	var threatErr *errors.AppError
	err := o.circuitBreakers["threat"].Execute(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		threatReq := &ThreatAnalysisRequest{
			RequestID:   reqCtx.RequestID,
			TenantID:    reqCtx.TenantID,
			Content:     reqCtx.Request.Prompt,
			ContentType: "text/plain",
			Context:     reqCtx.Metadata,
		}

		resp, err := o.threatClient.AnalyzeThreat(ctx, threatReq)
		if err != nil {
			threatErr = errors.Wrap(err, errors.ErrCodeInternalError, "threat analysis failed")
			return err
		}

		reqCtx.ThreatContext.ThreatLevel = resp.ThreatLevel
		reqCtx.ThreatContext.RiskScore = resp.RiskScore
		reqCtx.ThreatContext.DetectedThreats = resp.Detections
		reqCtx.ThreatContext.Confidence = 0.95
		reqCtx.ProcessingStage = StageThreatAnalyzed

		return nil
	})

	if err != nil {
		return threatErr
	}

	if reqCtx.ThreatContext.ThreatLevel == ThreatHigh || reqCtx.ThreatContext.ThreatLevel == ThreatCritical {
		return errors.NewSecurityError("high_threat", "request blocked due to security threat")
	}

	return nil
}

func (o *Orchestrator) routeToModel(reqCtx *RequestContext) (*models.AIResponse, *errors.AppError) {
	if !o.rateLimiters["model"].Allow() {
		return nil, errors.NewRateLimitError(time.Minute)
	}

	var response *models.AIResponse
	var modelErr *errors.AppError

	err := o.circuitBreakers["model"].Execute(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		modelReq := &ModelRequest{
			RequestID: reqCtx.RequestID,
			TenantID:  reqCtx.TenantID,
			Model:     reqCtx.Request.Model,
			Provider:  reqCtx.Request.Provider,
			Prompt:    reqCtx.Request.Prompt,
			Parameters: reqCtx.Request.Parameters,
			Context:   reqCtx.Metadata,
		}

		resp, err := o.modelProxyClient.RouteRequest(ctx, modelReq)
		if err != nil {
			modelErr = errors.Wrap(err, errors.ErrCodeModelUnavailable, "model request failed")
			return err
		}

		response = &models.AIResponse{
			ID:             uuid.New().String(),
			RequestID:      reqCtx.RequestID,
			TenantID:       reqCtx.TenantID,
			Model:          resp.Model,
			Provider:       resp.Provider,
			Response:       resp.Response,
			TokensUsed:     resp.TokensUsed,
			ProcessingTime: resp.ProcessingTime,
			Cost:           resp.Cost,
			Timestamp:      time.Now(),
			Metadata:       resp.Metadata,
		}

		reqCtx.ModelContext.SelectedModel = resp.Model
		reqCtx.ModelContext.Provider = resp.Provider
		reqCtx.ModelContext.ResponseTime = resp.ProcessingTime
		reqCtx.ModelContext.TokensUsed = resp.TokensUsed
		reqCtx.ModelContext.CostEstimate = resp.Cost
		reqCtx.ProcessingStage = StageResponseReceived

		return nil
	})

	if err != nil {
		return nil, modelErr
	}

	return response, nil
}

func (o *Orchestrator) postProcessResponse(reqCtx *RequestContext, response *models.AIResponse) *errors.AppError {
	if response.Response == "" {
		return errors.New(errors.ErrCodeInternalError, "empty response from model")
	}

	piiResult := utils.DetectPII(response.Response)
	if piiResult.HasPII {
		reqCtx.AuditContext.PIIDetected = true
		if reqCtx.Tenant.ComplianceLevel == "strict" {
			response.Response = utils.MaskPII(response.Response)
		}
	}

	response.Response = utils.SanitizeString(response.Response)
	reqCtx.ProcessingStage = StagePostProcessed

	return nil
}

func (o *Orchestrator) getTenantFromCache(tenantID string) (*models.Tenant, *errors.AppError) {
	o.tenantCache.mu.RLock()
	defer o.tenantCache.mu.RUnlock()

	if time.Since(o.tenantCache.lastSync) > o.tenantCache.ttl {
		return nil, errors.New(errors.ErrCodeNotFound, "cache expired")
	}

	tenant, exists := o.tenantCache.cache[tenantID]
	if !exists {
		return nil, errors.New(errors.ErrCodeNotFound, "tenant not in cache")
	}

	return tenant, nil
}

func (o *Orchestrator) getTenantFromDatabase(tenantID string) (*models.Tenant, *errors.AppError) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var tenant models.Tenant
	query := `SELECT id, name, email, is_active, is_blocked, compliance_level, 
			  created_at, updated_at FROM tenants WHERE id = $1`
	
	err := o.db.Get(ctx, &tenant, query, tenantID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to fetch tenant")
	}

	return &tenant, nil
}

func (o *Orchestrator) cacheTenant(tenant *models.Tenant) {
	o.tenantCache.mu.Lock()
	defer o.tenantCache.mu.Unlock()

	o.tenantCache.cache[tenant.ID] = tenant
	o.tenantCache.lastSync = time.Now()
}

func (o *Orchestrator) getServiceAddress(endpoint config.ServiceEndpoint) string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

func (o *Orchestrator) auditRequest(reqCtx *RequestContext) {
	if !o.rateLimiters["audit"].Allow() {
		o.logger.Warn("Audit rate limit exceeded", zap.String("request_id", reqCtx.RequestID))
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		auditEvent := &AuditEvent{
			EventID:   uuid.New().String(),
			EventType: "ai_request",
			Timestamp: time.Now(),
			Actor:     reqCtx.AuthContext.Principal,
			Action:    "process_request",
			Resource:  reqCtx.Request.Model,
			Result:    string(reqCtx.ProcessingStage),
			Details: map[string]interface{}{
				"request_id":       reqCtx.RequestID,
				"trace_id":         reqCtx.TraceID,
				"tenant_id":        reqCtx.TenantID,
				"model":            reqCtx.Request.Model,
				"provider":         reqCtx.Request.Provider,
				"processing_time":  reqCtx.Duration.Milliseconds(),
				"threat_level":     reqCtx.ThreatContext.ThreatLevel,
				"policy_decision":  reqCtx.PolicyContext.PolicyDecision,
				"tokens_used":      reqCtx.ModelContext.TokensUsed,
				"cost":             reqCtx.ModelContext.CostEstimate,
				"pii_detected":     reqCtx.AuditContext.PIIDetected,
				"compliance_level": reqCtx.Tenant.ComplianceLevel,
			},
		}

		if reqCtx.Error != nil {
			auditEvent.Result = "failed"
			auditEvent.Details["error_code"] = reqCtx.Error.Code
			auditEvent.Details["error_message"] = reqCtx.Error.Message
		}

		if err := o.auditClient.LogEvent(ctx, auditEvent); err != nil {
			o.logger.Error("Failed to log audit event",
				zap.String("request_id", reqCtx.RequestID),
				zap.Error(err))
		}
	}()
}

func (o *Orchestrator) updateMetrics(reqCtx *RequestContext) {
	o.metrics.mu.Lock()
	defer o.metrics.mu.Unlock()

	o.metrics.TotalRequests++
	
	if reqCtx.Error == nil {
		o.metrics.SuccessfulRequests++
	} else {
		o.metrics.FailedRequests++
	}

	if o.metrics.TotalRequests > 0 {
		totalDuration := time.Duration(o.metrics.TotalRequests) * o.metrics.AverageResponseTime
		o.metrics.AverageResponseTime = (totalDuration + reqCtx.Duration) / time.Duration(o.metrics.TotalRequests)
		o.metrics.ErrorRate = float64(o.metrics.FailedRequests) / float64(o.metrics.TotalRequests)
	}

	if reqCtx.AuthContext.IsAuthenticated {
		o.metrics.AuthenticationRate = float64(o.metrics.SuccessfulRequests) / float64(o.metrics.TotalRequests)
	}

	if len(reqCtx.ThreatContext.DetectedThreats) > 0 {
		o.metrics.ThreatDetectionRate++
	}

	if len(reqCtx.PolicyContext.Violations) > 0 {
		o.metrics.PolicyViolationRate++
	}

	o.metrics.LastUpdated = time.Now()
}

func (o *Orchestrator) startBackgroundTasks() {
	o.wg.Add(3)

	go o.healthCheckWorker()
	go o.cacheRefreshWorker()
	go o.metricsWorker()
}

func (o *Orchestrator) healthCheckWorker() {
	defer o.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			o.performHealthCheck()
		case <-o.shutdown:
			return
		}
	}
}

func (o *Orchestrator) cacheRefreshWorker() {
	defer o.wg.Done()
	
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			o.refreshCaches()
		case <-o.shutdown:
			return
		}
	}
}

func (o *Orchestrator) metricsWorker() {
	defer o.wg.Done()
	
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			o.calculateThroughput()
		case <-o.shutdown:
			return
		}
	}
}

func (o *Orchestrator) performHealthCheck() {
	o.healthStatus.mu.Lock()
	defer o.healthStatus.mu.Unlock()

	o.healthStatus.LastHealthCheck = time.Now()
	healthyServices := 0
	totalServices := 0

	services := map[string]func() error{
		"auth":   func() error { return o.authClient.HealthCheck(context.Background()) },
		"policy": func() error { return o.policyClient.HealthCheck(context.Background()) },
		"threat": func() error { return o.threatClient.HealthCheck(context.Background()) },
		"model":  func() error { return o.modelProxyClient.HealthCheck(context.Background()) },
		"audit":  func() error { return o.auditClient.HealthCheck(context.Background()) },
	}

	for serviceName, healthCheck := range services {
		totalServices++
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		
		if err := healthCheck(); err != nil {
			o.healthStatus.Services[serviceName] = "unhealthy"
			o.logger.Warn("Service health check failed",
				zap.String("service", serviceName),
				zap.Error(err))
		} else {
			o.healthStatus.Services[serviceName] = "healthy"
			healthyServices++
		}
		cancel()
	}

	if err := o.db.HealthCheck(); err != nil {
		o.healthStatus.Dependencies["database"] = "unhealthy"
	} else {
		o.healthStatus.Dependencies["database"] = "healthy"
		healthyServices++
	}
	totalServices++

	healthRatio := float64(healthyServices) / float64(totalServices)
	if healthRatio >= 0.8 {
		o.healthStatus.Overall = "healthy"
	} else if healthRatio >= 0.5 {
		o.healthStatus.Overall = "degraded"
	} else {
		o.healthStatus.Overall = "unhealthy"
	}
}

func (o *Orchestrator) refreshCaches() {
	o.logger.Debug("Refreshing caches")

	if time.Since(o.tenantCache.lastSync) > o.tenantCache.ttl {
		o.refreshTenantCache()
	}

	if time.Since(o.policyCache.lastSync) > o.policyCache.ttl {
		o.refreshPolicyCache()
	}
}

func (o *Orchestrator) refreshTenantCache() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := `SELECT id, name, email, is_active, is_blocked, compliance_level, 
			  created_at, updated_at FROM tenants WHERE is_active = true`
	
	var tenants []models.Tenant
	if err := o.db.Select(ctx, &tenants, query); err != nil {
		o.logger.Error("Failed to refresh tenant cache", zap.Error(err))
		return
	}

	o.tenantCache.mu.Lock()
	defer o.tenantCache.mu.Unlock()

	o.tenantCache.cache = make(map[string]*models.Tenant)
	for i := range tenants {
		o.tenantCache.cache[tenants[i].ID] = &tenants[i]
	}
	o.tenantCache.lastSync = time.Now()

	o.logger.Debug("Tenant cache refreshed", zap.Int("count", len(tenants)))
}

func (o *Orchestrator) refreshPolicyCache() {
	o.policyCache.mu.Lock()
	defer o.policyCache.mu.Unlock()
	
	o.policyCache.lastSync = time.Now()
	o.logger.Debug("Policy cache refreshed")
}

func (o *Orchestrator) calculateThroughput() {
	o.metrics.mu.Lock()
	defer o.metrics.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(o.metrics.LastUpdated).Seconds()
	
	if elapsed > 0 {
		o.metrics.ThroughputPerSecond = float64(o.metrics.TotalRequests) / elapsed
	}
}

func (o *Orchestrator) GetMetrics() *OrchestratorMetrics {
	o.metrics.mu.RLock()
	defer o.metrics.mu.RUnlock()
	
	metrics := *o.metrics
	return &metrics
}

func (o *Orchestrator) GetHealthStatus() *HealthStatus {
	o.healthStatus.mu.RLock()
	defer o.healthStatus.mu.RUnlock()
	
	status := *o.healthStatus
	return &status
}

func (o *Orchestrator) Shutdown(ctx context.Context) error {
	o.logger.Info("Shutting down orchestrator")
	
	close(o.shutdown)
	
	done := make(chan struct{})
	go func() {
		o.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		o.logger.Info("Orchestrator shutdown completed")
		return nil
	case <-ctx.Done():
		o.logger.Warn("Orchestrator shutdown timed out")
		return ctx.Err()
	}
}

func (o *Orchestrator) IsHealthy() bool {
	status := o.GetHealthStatus()
	return status.Overall == "healthy"
}

func (o *Orchestrator) GetTenantCount() int {
	o.tenantCache.mu.RLock()
	defer o.tenantCache.mu.RUnlock()
	return len(o.tenantCache.cache)
}

func (o *Orchestrator) GetCircuitBreakerStatus(service string) string {
	if cb, exists := o.circuitBreakers[service]; exists {
		return cb.GetState()
	}
	return "unknown"
}

func (o *Orchestrator) ResetCircuitBreaker(service string) error {
	if cb, exists := o.circuitBreakers[service]; exists {
		cb.Reset()
		return nil
	}
	return errors.New(errors.ErrCodeNotFound, "circuit breaker not found")
}

func (o *Orchestrator) GetRateLimitStatus(service string) map[string]interface{} {
	if rl, exists := o.rateLimiters[service]; exists {
		return map[string]interface{}{
			"tokens_available": rl.GetTokens(),
			"capacity":         rl.GetCapacity(),
			"rate":             rl.GetRate(),
		}
	}
	return nil
}

type PolicyRequest struct {
	TenantID     string
	UserID       string
	Action       string
	Resource     string
	Context      map[string]interface{}
	RequestData  interface{}
}

type PolicyResponse struct {
	Decision     PolicyDecision
	Policies     []string
	Violations   []PolicyViolation
	Constraints  map[string]interface{}
	Metadata     map[string]interface{}
}

type Policy struct {
	ID           string
	Version      string
	Name         string
	Description  string
	Rules        interface{}
	Metadata     map[string]interface{}
}

type ThreatAnalysisRequest struct {
	RequestID    string
	TenantID     string
	Content      string
	ContentType  string
	Context      map[string]interface{}
	Metadata     map[string]interface{}
}

type ThreatAnalysisResponse struct {
	ThreatLevel     ThreatLevel
	RiskScore       float64
	Detections      []ThreatDetection
	Recommendations []string
	ProcessingTime  time.Duration
	Metadata        map[string]interface{}
}

type ThreatSignatures struct {
	Version     string
	Signatures  map[string]interface{}
	LastUpdated time.Time
}

type ModelRequest struct {
	RequestID   string
	TenantID    string
	Model       string
	Provider    string
	Prompt      string
	Parameters  map[string]interface{}
	Context     map[string]interface{}
	Metadata    map[string]interface{}
}

type ModelResponse struct {
	RequestID      string
	Response       string
	Model          string
	Provider       string
	TokensUsed     int64
	ProcessingTime time.Duration
	Cost           float64
	Metadata       map[string]interface{}
}

type AvailableModels struct {
	Models   []ModelInfo
	Metadata map[string]interface{}
}

type ModelInfo struct {
	ID           string
	Name         string
	Provider     string
	Version      string
	Capabilities []string
	Pricing      map[string]float64
	Limits       map[string]interface{}
	Metadata     map[string]interface{}
}

func (o *Orchestrator) ProcessBatchRequests(ctx context.Context, requests []*models.AIRequest) ([]*models.AIResponse, *errors.AppError) {
	if len(requests) == 0 {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "no requests provided")
	}

	if len(requests) > 100 {
		return nil, errors.New(errors.ErrCodePayloadTooLarge, "batch size exceeds maximum limit")
	}

	responses := make([]*models.AIResponse, len(requests))
	errChan := make(chan error, len(requests))
	
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for i, request := range requests {
		wg.Add(1)
		go func(index int, req *models.AIRequest) {
			defer wg.Done()
			
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			response, err := o.ProcessRequest(ctx, req)
			if err != nil {
				errChan <- err
				return
			}
			responses[index] = response
		}(i, request)
	}

	wg.Wait()
	close(errChan)

	var firstError error
	for err := range errChan {
		if firstError == nil {
			firstError = err
		}
	}

	if firstError != nil {
		return nil, errors.Handle(firstError)
	}

	return responses, nil
}

func (o *Orchestrator) ValidateModelAccess(tenantID, model string) *errors.AppError {
	tenant, err := o.getTenantFromCache(tenantID)
	if err != nil {
		tenant, err = o.getTenantFromDatabase(tenantID)
		if err != nil {
			return err
		}
	}

	if !utils.Contains(tenant.AllowedModels, model) {
		return errors.NewForbiddenError("model not allowed for tenant")
	}

	return nil
}

func (o *Orchestrator) GetTenantQuota(tenantID string) (*models.TenantQuota, *errors.AppError) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var quota models.TenantQuota
	query := `SELECT tenant_id, requests_per_hour, requests_per_day, tokens_per_hour, 
			  tokens_per_day, cost_limit_per_day, used_requests_hour, used_requests_day,
			  used_tokens_hour, used_tokens_day, used_cost_day, reset_hour, reset_day
			  FROM tenant_quotas WHERE tenant_id = $1`
	
	err := o.db.Get(ctx, &quota, query, tenantID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to fetch tenant quota")
	}

	return &quota, nil
}

func (o *Orchestrator) CheckQuotaLimits(reqCtx *RequestContext) *errors.AppError {
	quota, err := o.GetTenantQuota(reqCtx.TenantID)
	if err != nil {
		return err
	}

	if quota.UsedRequestsHour >= quota.RequestsPerHour {
		return errors.NewQuotaExceededError("hourly request limit exceeded")
	}

	if quota.UsedRequestsDay >= quota.RequestsPerDay {
		return errors.NewQuotaExceededError("daily request limit exceeded")
	}

	if quota.UsedTokensHour >= quota.TokensPerHour {
		return errors.NewQuotaExceededError("hourly token limit exceeded")
	}

	if quota.UsedTokensDay >= quota.TokensPerDay {
		return errors.NewQuotaExceededError("daily token limit exceeded")
	}

	if quota.UsedCostDay >= quota.CostLimitPerDay {
		return errors.NewQuotaExceededError("daily cost limit exceeded")
	}

	return nil
}

func (o *Orchestrator) UpdateQuotaUsage(reqCtx *RequestContext) *errors.AppError {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `UPDATE tenant_quotas SET 
			  used_requests_hour = used_requests_hour + 1,
			  used_requests_day = used_requests_day + 1,
			  used_tokens_hour = used_tokens_hour + $2,
			  used_tokens_day = used_tokens_day + $2,
			  used_cost_day = used_cost_day + $3
			  WHERE tenant_id = $1`
	
	_, err := o.db.Exec(ctx, query, reqCtx.TenantID, 
		reqCtx.ModelContext.TokensUsed, reqCtx.ModelContext.CostEstimate)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to update quota usage")
	}

	return nil
}

func (o *Orchestrator) GetRequestHistory(tenantID string, limit int) ([]*models.RequestHistory, *errors.AppError) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var history []*models.RequestHistory
	query := `SELECT request_id, tenant_id, model, provider, prompt_hash, 
			  response_hash, tokens_used, cost, processing_time, threat_level,
			  policy_decision, created_at FROM request_history 
			  WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`
	
	err := o.db.Select(ctx, &history, query, tenantID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to fetch request history")
	}

	return history, nil
}

func (o *Orchestrator) GetThreatStatistics(tenantID string, timeRange TimeRange) (*ThreatStatistics, *errors.AppError) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var stats ThreatStatistics
	query := `SELECT 
			  COUNT(*) as total_requests,
			  COUNT(CASE WHEN threat_level = 'high' OR threat_level = 'critical' THEN 1 END) as blocked_requests,
			  AVG(risk_score) as average_risk_score,
			  COUNT(DISTINCT threat_type) as unique_threat_types
			  FROM request_history 
			  WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3`
	
	err := o.db.Get(ctx, &stats, query, tenantID, timeRange.Start, timeRange.End)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to fetch threat statistics")
	}

	return &stats, nil
}

func (o *Orchestrator) GetComplianceReport(tenantID string, timeRange TimeRange) (*ComplianceReport, *errors.AppError) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var report ComplianceReport
	query := `SELECT 
			  COUNT(*) as total_requests,
			  COUNT(CASE WHEN pii_detected = true THEN 1 END) as pii_requests,
			  COUNT(CASE WHEN policy_violations > 0 THEN 1 END) as policy_violations,
			  COUNT(CASE WHEN audit_logged = true THEN 1 END) as audited_requests,
			  AVG(processing_time) as average_processing_time
			  FROM request_history 
			  WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3`
	
	err := o.db.Get(ctx, &report, query, tenantID, timeRange.Start, timeRange.End)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to fetch compliance report")
	}

	report.TenantID = tenantID
	report.TimeRange = timeRange
	report.GeneratedAt = time.Now()

	return &report, nil
}

func (o *Orchestrator) EmergencyShutdown(reason string) {
	o.logger.Error("Emergency shutdown initiated", zap.String("reason", reason))
	
	o.healthStatus.mu.Lock()
	o.healthStatus.Overall = "emergency_shutdown"
	o.healthStatus.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := o.Shutdown(ctx); err != nil {
		o.logger.Error("Emergency shutdown failed", zap.Error(err))
	}
}

func (o *Orchestrator) RecoverFromPanic() {
	if r := recover(); r != nil {
		o.logger.Error("Orchestrator panic recovered",
			zap.Any("panic", r),
			zap.Stack("stack"))
		
		o.EmergencyShutdown("panic_recovery")
	}
}

type TimeRange struct {
	Start time.Time
	End   time.Time
}

type ThreatStatistics struct {
	TotalRequests     int64
	BlockedRequests   int64
	AverageRiskScore  float64
	UniqueThreatTypes int64
}

type ComplianceReport struct {
	TenantID              string
	TimeRange             TimeRange
	TotalRequests         int64
	PIIRequests           int64
	PolicyViolations      int64
	AuditedRequests       int64
	AverageProcessingTime time.Duration
	GeneratedAt           time.Time
}

func NewQuotaExceededError(message string) *errors.AppError {
	return errors.New(errors.ErrCodeQuotaExceeded, message).WithRetryAfter(time.Hour)
}
