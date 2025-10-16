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
	commonpb "flamo/backend/pkg/api/proto/common"
	authpb "flamo/backend/pkg/api/proto/auth"
	gatewaypb "flamo/backend/pkg/api/proto/gateway"
	"flamo/backend/pkg/api/proto/models/request"
	"flamo/backend/pkg/api/proto/models/response"
	"flamo/backend/pkg/api/proto/models/tenant"
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
	Request          *request.AIRequest
	Tenant           *tenant.Tenant
	AuthContext      *AuthenticationContext
	PolicyContext    *PolicyContext
	ThreatContext    *ThreatContext
	ModelContext     *ModelContext
	AuditContext     *AuditContext
	Metadata         map[string]interface{}
	ProcessingStage  commonpb.Status
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
	AuthLevel        string
	MFAVerified      bool
	DeviceFingerprint string
}

type PolicyContext struct {
	PolicyVersion    string
	AppliedPolicies  []string
	PolicyDecision   string
	Constraints      map[string]interface{}
	Violations       []*commonpb.ComplianceViolation
	ComplianceFlags  []string
}

type ThreatContext struct {
	ThreatLevel      commonpb.ThreatLevel
	DetectedThreats  []*commonpb.ThreatDetection
	RiskScore        float64
	Mitigations      []string
	BlockReason      string
	Confidence       float64
}

type ModelContext struct {
	SelectedModel    string
	Provider         commonpb.ModelProvider
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
	AuditTrail       []*commonpb.AuditEvent
}

type TenantCache struct {
	cache    map[string]*tenant.Tenant
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
	LogEvent(ctx context.Context, event *commonpb.AuditEvent) error
	LogRequest(ctx context.Context, reqCtx *RequestContext) error
	HealthCheck(ctx context.Context) error
}

type PolicyRequest struct {
	TenantID     string
	UserID       string
	Action       string
	Resource     string
	Context      map[string]interface{}
	RequestData  *request.AIRequest
}

type PolicyResponse struct {
	Decision     string
	Policies     []string
	Violations   []*commonpb.ComplianceViolation
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
	ThreatLevel     commonpb.ThreatLevel
	RiskScore       float64
	Detections      []*commonpb.ThreatDetection
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
	Payload     *request.RequestPayload
	Context     map[string]interface{}
	Metadata    map[string]interface{}
}

type ModelResponse struct {
	RequestID      string
	Data           *response.ResponseData
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
		cache:    make(map[string]*tenant.Tenant),
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

func (o *Orchestrator) ProcessRequest(ctx context.Context, aiRequest *request.AIRequest) (*response.AIResponse, *errors.AppError) {
	reqCtx := o.createRequestContext(ctx, aiRequest)
	
	defer func() {
		reqCtx.EndTime = time.Now()
		reqCtx.Duration = reqCtx.EndTime.Sub(reqCtx.StartTime)
		o.updateMetrics(reqCtx)
		o.auditRequest(reqCtx)
	}()

	if err := o.validateRequest(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = commonpb.Status_STATUS_ERROR
		return nil, err
	}

	if err := o.authenticateRequest(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = commonpb.Status_STATUS_ERROR
		return nil, err
	}

	if err := o.resolveTenant(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = commonpb.Status_STATUS_ERROR
		return nil, err
	}

	if err := o.evaluatePolicy(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = commonpb.Status_STATUS_ERROR
		return nil, err
	}

	if err := o.analyzeThreat(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = commonpb.Status_STATUS_ERROR
		return nil, err
	}

	aiResponse, err := o.routeToModel(reqCtx)
	if err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = commonpb.Status_STATUS_ERROR
		return nil, err
	}

	if err := o.postProcessResponse(reqCtx, aiResponse); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = commonpb.Status_STATUS_ERROR
		return nil, err
	}

	reqCtx.ProcessingStage = commonpb.Status_STATUS_SUCCESS
	return aiResponse, nil
}

func (o *Orchestrator) createRequestContext(ctx context.Context, aiRequest *request.AIRequest) *RequestContext {
	requestID := uuid.New().String()
	traceID := aiRequest.TraceID
	if traceID == "" {
		traceID = uuid.New().String()
	}
	
	return &RequestContext{
		RequestID:       requestID,
		TraceID:         traceID,
		SpanID:          aiRequest.SpanID,
		TenantID:        aiRequest.TenantID.String(),
		UserID:          "",
		Timestamp:       time.Now(),
		Request:         aiRequest,
		Metadata:        make(map[string]interface{}),
		ProcessingStage: commonpb.Status_STATUS_PENDING,
		StartTime:       time.Now(),
		AuthContext:     &AuthenticationContext{},
		PolicyContext:   &PolicyContext{},
		ThreatContext:   &ThreatContext{},
		ModelContext:    &ModelContext{},
		AuditContext:    &AuditContext{},
	}
}

func (o *Orchestrator) validateRequest(reqCtx *RequestContext) *errors.AppError {
	if reqCtx.Request == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if err := reqCtx.Request.Validate(); err != nil {
		return errors.Wrap(err, errors.ErrCodeValidationError, "request validation failed")
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
			Token:    reqCtx.Request.SecurityContext.SessionToken,
			TenantId: reqCtx.TenantID,
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
		reqCtx.AuthContext.AuthLevel = reqCtx.Request.SecurityContext.AuthenticationLevel
		reqCtx.ProcessingStage = commonpb.Status_STATUS_PROCESSING

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
	tenantObj, err := o.getTenantFromCache(reqCtx.TenantID)
	if err != nil {
		tenantObj, err = o.getTenantFromDatabase(reqCtx.TenantID)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeNotFound, "tenant not found")
		}
		o.cacheTenant(tenantObj)
	}

	if !tenantObj.IsActive() {
		return errors.NewForbiddenError("tenant is inactive")
	}

	if !tenantObj.CanAccess() {
		return errors.NewForbiddenError("tenant access denied")
	}

	reqCtx.Tenant = tenantObj
	reqCtx.ProcessingStage = commonpb.Status_STATUS_PROCESSING

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
			Resource:    reqCtx.Request.ModelName,
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
		reqCtx.ProcessingStage = commonpb.Status_STATUS_PROCESSING

		return nil
	})

	if err != nil {
		return policyErr
	}

	if reqCtx.PolicyContext.PolicyDecision == "deny" {
		return errors.NewForbiddenError("request denied by policy")
	}

	if reqCtx.PolicyContext.PolicyDecision == "quarantine" {
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
			Content:     reqCtx.Request.Payload.Prompt,
			ContentType: string(reqCtx.Request.ContentType),
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
		reqCtx.ProcessingStage = commonpb.Status_STATUS_PROCESSING

		return nil
	})

	if err != nil {
		return threatErr
	}

	if reqCtx.ThreatContext.ThreatLevel == commonpb.ThreatLevel_THREAT_LEVEL_HIGH || 
	   reqCtx.ThreatContext.ThreatLevel == commonpb.ThreatLevel_THREAT_LEVEL_CRITICAL {
		return errors.NewSecurityError("high_threat", "request blocked due to security threat")
	}

	return nil
}

func (o *Orchestrator) routeToModel(reqCtx *RequestContext) (*response.AIResponse, *errors.AppError) {
	if !o.rateLimiters["model"].Allow() {
		return nil, errors.NewRateLimitError(time.Minute)
	}

	var aiResponse *response.AIResponse
	var modelErr *errors.AppError

	err := o.circuitBreakers["model"].Execute(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		modelReq := &ModelRequest{
			RequestID: reqCtx.RequestID,
			TenantID:  reqCtx.TenantID,
			Model:     reqCtx.Request.ModelName,
			Provider:  string(reqCtx.Request.Provider),
			Payload:   &reqCtx.Request.Payload,
			Context:   reqCtx.Metadata,
		}

		resp, err := o.modelProxyClient.RouteRequest(ctx, modelReq)
		if err != nil {
			modelErr = errors.Wrap(err, errors.ErrCodeModelUnavailable, "model request failed")
			return err
		}

		aiResponse = response.NewAIResponse(
			reqCtx.Request.ID,
			reqCtx.Request.TenantID,
			reqCtx.TraceID,
			reqCtx.SpanID,
		)

		aiResponse.SetSuccess(resp.Data)
		aiResponse.Usage.PromptTokens = int(resp.TokensUsed)
		aiResponse.Usage.TotalTokens = int(resp.TokensUsed)
		aiResponse.Performance.TotalLatencyMs = resp.ProcessingTime.Milliseconds()
		aiResponse.Performance.ModelLatencyMs = resp.ProcessingTime.Milliseconds()

		if aiResponse.Usage.Cost == nil {
			aiResponse.Usage.Cost = &response.CostBreakdown{
				Currency:   "USD",
				TotalCost:  resp.Cost,
			}
		}

		reqCtx.ModelContext.SelectedModel = resp.Model
		reqCtx.ModelContext.Provider = commonpb.ModelProvider(commonpb.ModelProvider_value[resp.Provider])
		reqCtx.ModelContext.ResponseTime = resp.ProcessingTime
		reqCtx.ModelContext.TokensUsed = resp.TokensUsed
		reqCtx.ModelContext.CostEstimate = resp.Cost
		reqCtx.ProcessingStage = commonpb.Status_STATUS_PROCESSING

		return nil
	})

	if err != nil {
		return nil, modelErr
	}

	return aiResponse, nil
}

func (o *Orchestrator) postProcessResponse(reqCtx *RequestContext, aiResponse *response.AIResponse) *errors.AppError {
	if aiResponse.Data == nil || aiResponse.Data.Content == "" {
		return errors.New(errors.ErrCodeInternalError, "empty response from model")
	}

	if reqCtx.Request.ComplianceContext.PIIDetected {
		reqCtx.AuditContext.PIIDetected = true
		
		for _, rule := range reqCtx.Request.ComplianceContext.RedactionRules {
			if rule.Enabled {
				aiResponse.AddRedaction(
					rule.Type,
					"response_content",
					rule.Replacement,
					"PII protection",
				)
			}
		}
	}

	if reqCtx.Tenant.ComplianceConfig.PIIRedactionEnabled {
		for i, choice := range aiResponse.Data.Choices {
			if choice.Message != nil && choice.Message.Content != "" {
				aiResponse.Data.Choices[i].Message.Content = o.sanitizeContent(choice.Message.Content)
			}
		}
		aiResponse.Data.Content = o.sanitizeContent(aiResponse.Data.Content)
	}

	reqCtx.ProcessingStage = commonpb.Status_STATUS_SUCCESS
	return nil
}

func (o *Orchestrator) sanitizeContent(content string) string {
	return content
}

func (o *Orchestrator) getTenantFromCache(tenantID string) (*tenant.Tenant, *errors.AppError) {
	o.tenantCache.mu.RLock()
	defer o.tenantCache.mu.RUnlock()

	if time.Since(o.tenantCache.lastSync) > o.tenantCache.ttl {
		return nil, errors.New(errors.ErrCodeNotFound, "cache expired")
	}

	tenantObj, exists := o.tenantCache.cache[tenantID]
	if !exists {
		return nil, errors.New(errors.ErrCodeNotFound, "tenant not in cache")
	}

	return tenantObj, nil
}

func (o *Orchestrator) getTenantFromDatabase(tenantID string) (*tenant.Tenant, *errors.AppError) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeValidationError, "invalid tenant ID format")
	}

	var tenantData struct {
		ID                uuid.UUID `db:"id"`
		Name              string    `db:"name"`
		Slug              string    `db:"slug"`
		Status            string    `db:"status"`
		Tier              string    `db:"tier"`
		OrganizationID    string    `db:"organization_id"`
		CreatedAt         time.Time `db:"created_at"`
		UpdatedAt         time.Time `db:"updated_at"`
		CreatedBy         uuid.UUID `db:"created_by"`
		UpdatedBy         uuid.UUID `db:"updated_by"`
		Version           int64     `db:"version"`
	}

	query := `SELECT id, name, slug, status, tier, organization_id, created_at, updated_at, created_by, updated_by, version FROM tenants WHERE id = $1`
	
	err = o.db.Get(ctx, &tenantData, query, tenantUUID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to fetch tenant")
	}

	tenantObj := &tenant.Tenant{
		ID:             tenantData.ID,
		Name:           tenantData.Name,
		Slug:           tenantData.Slug,
		Status:         tenant.TenantStatus(tenantData.Status),
		Tier:           tenant.TenantTier(tenantData.Tier),
		OrganizationID: tenantData.OrganizationID,
		CreatedAt:      tenantData.CreatedAt,
		UpdatedAt:      tenantData.UpdatedAt,
		CreatedBy:      tenantData.CreatedBy,
		UpdatedBy:      tenantData.UpdatedBy,
		Version:        tenantData.Version,
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
		Metadata: make(map[string]interface{}),
	}

	return tenantObj, nil
}

func (o *Orchestrator) cacheTenant(tenantObj *tenant.Tenant) {
	o.tenantCache.mu.Lock()
	defer o.tenantCache.mu.Unlock()

	o.tenantCache.cache[tenantObj.ID.String()] = tenantObj
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

		auditEvent := &commonpb.AuditEvent{
			EventId:   uuid.New().String(),
			EventType: "ai_request",
			ActorId:   reqCtx.AuthContext.Principal,
			ActorType: "user",
			Action:    "process_request",
			Status:    reqCtx.ProcessingStage,
			SourceIp:  reqCtx.Request.ClientInfo.IPAddress,
			UserAgent: reqCtx.Request.ClientInfo.UserAgent,
			TraceId:   reqCtx.TraceID,
			TenantId:  reqCtx.TenantID,
			Severity:  commonpb.Severity_SEVERITY_MEDIUM,
		}

		if reqCtx.Error != nil {
			auditEvent.Status = commonpb.Status_STATUS_ERROR
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

	query := `SELECT id, name, slug, status, tier, organization_id, created_at, updated_at, created_by, updated_by, version FROM tenants WHERE status = 'active'`
	
	var tenantsData []struct {
		ID             uuid.UUID `db:"id"`
		Name           string    `db:"name"`
		Slug           string    `db:"slug"`
		Status         string    `db:"status"`
		Tier           string    `db:"tier"`
		OrganizationID string    `db:"organization_id"`
		CreatedAt      time.Time `db:"created_at"`
		UpdatedAt      time.Time `db:"updated_at"`
		CreatedBy      uuid.UUID `db:"created_by"`
		UpdatedBy      uuid.UUID `db:"updated_by"`
		Version        int64     `db:"version"`
	}

	if err := o.db.Select(ctx, &tenantsData, query); err != nil {
		o.logger.Error("Failed to refresh tenant cache", zap.Error(err))
		return
	}

	o.tenantCache.mu.Lock()
	defer o.tenantCache.mu.Unlock()

	o.tenantCache.cache = make(map[string]*tenant.Tenant)
	for _, data := range tenantsData {
		tenantObj := &tenant.Tenant{
			ID:             data.ID,
			Name:           data.Name,
			Slug:           data.Slug,
			Status:         tenant.TenantStatus(data.Status),
			Tier:           tenant.TenantTier(data.Tier),
			OrganizationID: data.OrganizationID,
			CreatedAt:      data.CreatedAt,
			UpdatedAt:      data.UpdatedAt,
			CreatedBy:      data.CreatedBy,
			UpdatedBy:      data.UpdatedBy,
			Version:        data.Version,
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
			Metadata: make(map[string]interface{}),
		}
		o.tenantCache.cache[data.ID.String()] = tenantObj
	}
	o.tenantCache.lastSync = time.Now()

	o.logger.Debug("Tenant cache refreshed", zap.Int("count", len(tenantsData)))
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

func (o *Orchestrator) ProcessBatchRequests(ctx context.Context, requests []*request.AIRequest) ([]*response.AIResponse, *errors.AppError) {
	if len(requests) == 0 {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "no requests provided")
	}

	if len(requests) > 100 {
		return nil, errors.New(errors.ErrCodePayloadTooLarge, "batch size exceeds maximum limit")
	}

	responses := make([]*response.AIResponse, len(requests))
	errChan := make(chan error, len(requests))
	
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for i, req := range requests {
		wg.Add(1)
		go func(index int, aiRequest *request.AIRequest) {
			defer wg.Done()
			
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			resp, err := o.ProcessRequest(ctx, aiRequest)
			if err != nil {
				errChan <- err
				return
			}
			responses[index] = resp
		}(i, req)
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
	tenantObj, err := o.getTenantFromCache(tenantID)
	if err != nil {
		tenantObj, err = o.getTenantFromDatabase(tenantID)
		if err != nil {
			return err
		}
	}

	if tenantObj.ResourceLimits.MaxModelsPerTenant <= 0 {
		return errors.NewForbiddenError("model access not allowed for tenant")
	}

	return nil
}

func (o *Orchestrator) CheckQuotaLimits(reqCtx *RequestContext) *errors.AppError {
	if reqCtx.Tenant.ResourceLimits.MaxAPICallsPerMinute > 0 {
		return nil
	}

	if reqCtx.Tenant.ResourceLimits.MaxAPICallsPerDay > 0 {
		return nil
	}

	return nil
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
