package orchestrator

import (
	"fmt"
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/durationpb"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	commonpb "flamo/backend/pkg/api/proto/common"
	authpb "flamo/backend/pkg/api/proto/auth"
	gatewaypb "flamo/backend/pkg/api/proto/gateway"
	"flamo/backend/pkg/api/proto/models/tenant"
)

type Orchestrator struct {
	gatewaypb.UnimplementedGatewayServiceServer
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
	Request          *gatewaypb.ProcessAIRequestRequest
	Tenant           *tenant.Tenant
	AuthContext      *AuthenticationContext
	PolicyContext    *PolicyContext
	ThreatContext    *ThreatContext
	ModelContext     *ModelContext
	AuditContext     *AuditContext
	Metadata         map[string]interface{}
	ProcessingStage  gatewaypb.ProcessingStage
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
	RequestData  *gatewaypb.AIRequestPayload
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
	Payload     *gatewaypb.RequestContent
	Context     map[string]interface{}
	Metadata    map[string]interface{}
}

type ModelResponse struct {
	RequestID      string
	Data           *gatewaypb.AIResponsePayload
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

func (o *Orchestrator) ProcessAIRequest(ctx context.Context, req *gatewaypb.ProcessAIRequestRequest) (*gatewaypb.ProcessAIRequestResponse, error) {
	reqCtx := o.createRequestContext(ctx, req)
	
	defer func() {
		reqCtx.EndTime = time.Now()
		reqCtx.Duration = reqCtx.EndTime.Sub(reqCtx.StartTime)
		o.updateMetrics(reqCtx)
		o.auditRequest(reqCtx)
	}()

	if err := o.validateRequest(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_FAILED
		return &gatewaypb.ProcessAIRequestResponse{
			Status: commonpb.Status_STATUS_ERROR,
			Error: &commonpb.ErrorDetails{
				Message: string(err.Code) + ": " + err.Message,
			},
		}, nil
	}

	if err := o.authenticateRequest(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_FAILED
		return &gatewaypb.ProcessAIRequestResponse{
			Status: commonpb.Status_STATUS_ERROR,
			Error: &commonpb.ErrorDetails{
				Message: string(err.Code) + ": " + err.Message,
			},
		}, nil
	}

	if err := o.resolveTenant(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_FAILED
		return &gatewaypb.ProcessAIRequestResponse{
			Status: commonpb.Status_STATUS_ERROR,
			Error: &commonpb.ErrorDetails{
				Message: string(err.Code) + ": " + err.Message,
			},
		}, nil
	}

	if err := o.evaluatePolicy(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_FAILED
		return &gatewaypb.ProcessAIRequestResponse{
			Status: commonpb.Status_STATUS_ERROR,
			Error: &commonpb.ErrorDetails{
				Message: string(err.Code) + ": " + err.Message,
			},
		}, nil
	}

	if err := o.analyzeThreat(reqCtx); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_FAILED
		return &gatewaypb.ProcessAIRequestResponse{
			Status: commonpb.Status_STATUS_ERROR,
			Error: &commonpb.ErrorDetails{
				Message: string(err.Code) + ": " + err.Message,
			},
		}, nil
	}

	aiResponse, err := o.routeToModel(reqCtx)
	if err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_FAILED
		return &gatewaypb.ProcessAIRequestResponse{
			Status: commonpb.Status_STATUS_ERROR,
			Error: &commonpb.ErrorDetails{
				Message: string(err.Code) + ": " + err.Message,
			},
		}, nil
	}

	if err := o.postProcessResponse(reqCtx, aiResponse); err != nil {
		reqCtx.Error = err
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_FAILED
		return &gatewaypb.ProcessAIRequestResponse{
			Status: commonpb.Status_STATUS_ERROR,
			Error: &commonpb.ErrorDetails{
				Message: string(err.Code) + ": " + err.Message,
			},
		}, nil
	}

	reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_COMPLETED

	processingResult := &gatewaypb.ProcessingResult{
		RequestId:   reqCtx.RequestID,
		TraceId:     reqCtx.TraceID,
		FinalStage:  reqCtx.ProcessingStage,
		RoutingDecision: gatewaypb.RoutingDecision_ROUTING_DECISION_ALLOW,
		SecurityAnalysis: &commonpb.SecurityAnalysis{
			ThreatLevel: reqCtx.ThreatContext.ThreatLevel,
			RiskScore:   reqCtx.ThreatContext.RiskScore,
		},
		PerformanceMetrics: &commonpb.PerformanceMetrics{
			TotalLatencyMs: reqCtx.Duration.Milliseconds(),
		},
	}

	return &gatewaypb.ProcessAIRequestResponse{
		Status:           commonpb.Status_STATUS_SUCCESS,
		Response:         aiResponse,
		ProcessingResult: processingResult,
		TotalProcessingTime: durationpb.New(reqCtx.Duration),
	}, nil
}

func (o *Orchestrator) createRequestContext(ctx context.Context, req *gatewaypb.ProcessAIRequestRequest) *RequestContext {
	requestID := uuid.New().String()
	traceID := req.Metadata.TraceId
	if traceID == "" {
		traceID = uuid.New().String()
	}
	
	return &RequestContext{
		RequestID:       requestID,
		TraceID:         traceID,
		SpanID:          req.Metadata.SpanId,
		TenantID:        req.Metadata.TenantId,
		UserID:          req.Metadata.UserId,
		Timestamp:       time.Now(),
		Request:         req,
		Metadata:        make(map[string]interface{}),
		ProcessingStage: gatewaypb.ProcessingStage_PROCESSING_STAGE_RECEIVED,
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

	if reqCtx.Request.Payload == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request payload is required")
	}

	if reqCtx.Request.Payload.ModelName == "" {
		return errors.New(errors.ErrCodeValidationError, "model name is required")
	}

	reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_VALIDATED

	return nil
}

func (o *Orchestrator) convertProcessingStageToStatus(stage gatewaypb.ProcessingStage) commonpb.Status {
	switch stage {
	case gatewaypb.ProcessingStage_PROCESSING_STAGE_COMPLETED:
		return commonpb.Status_STATUS_SUCCESS
	case gatewaypb.ProcessingStage_PROCESSING_STAGE_FAILED:
		return commonpb.Status_STATUS_ERROR
	default:
		return commonpb.Status_STATUS_PROCESSING
	}
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
			Metadata: &commonpb.RequestMetadata{
				RequestId: reqCtx.RequestID,
				TenantId:  reqCtx.TenantID,
				UserId:    reqCtx.UserID,
				SecurityContext: &commonpb.SecurityContext{
					SessionToken: reqCtx.Request.Metadata.SecurityContext.SessionToken,
				},
			},
			Method: authpb.AuthenticationMethod_AUTHENTICATION_METHOD_JWT,
			Credentials: &authpb.AuthenticateRequest_Jwt{
				Jwt: &authpb.JWTCredentials{
					Token: reqCtx.Request.Metadata.SecurityContext.SessionToken,
				},
			},
		}

		resp, err := o.authClient.Authenticate(ctx, authReq)
		if err != nil {
			authErr = errors.Wrap(err, errors.ErrCodeAuthenticationError, "authentication failed")
			return err
		}

		reqCtx.AuthContext.IsAuthenticated = resp.Result.Authenticated
		reqCtx.AuthContext.Principal = resp.Result.Principal.Name
		reqCtx.AuthContext.Scopes = resp.Result.Scopes
		reqCtx.AuthContext.Claims = make(map[string]interface{})
		reqCtx.AuthContext.AuthLevel = reqCtx.Request.Payload.SecurityLevel.String()
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_AUTHENTICATED

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
	reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_AUTHORIZED

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
			Resource:    reqCtx.Request.Payload.ModelName,
			Context:     reqCtx.Metadata,
			RequestData: reqCtx.Request.Payload,
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
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_COMPLIANCE_CHECKED

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
			Content:     reqCtx.Request.Payload.Content.Prompt,
			ContentType: reqCtx.Request.Payload.ContentType.String(),
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
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_SECURITY_ANALYZED

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

func (o *Orchestrator) routeToModel(reqCtx *RequestContext) (*gatewaypb.AIResponsePayload, *errors.AppError) {
	if !o.rateLimiters["model"].Allow() {
		return nil, errors.NewRateLimitError(time.Minute)
	}

	var aiResponse *gatewaypb.AIResponsePayload
	var modelErr *errors.AppError

	err := o.circuitBreakers["model"].Execute(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		modelReq := &ModelRequest{
			RequestID: reqCtx.RequestID,
			TenantID:  reqCtx.TenantID,
			Model:     reqCtx.Request.Payload.ModelName,
			Provider:  reqCtx.Request.Payload.Provider.String(),
			Payload:   reqCtx.Request.Payload.Content,
			Context:   reqCtx.Metadata,
		}

		resp, err := o.modelProxyClient.RouteRequest(ctx, modelReq)
		if err != nil {
			modelErr = errors.Wrap(err, errors.ErrCodeModelUnavailable, "model request failed")
			return err
		}

		aiResponse = resp.Data

		reqCtx.ModelContext.SelectedModel = resp.Model
		reqCtx.ModelContext.Provider = commonpb.ModelProvider(commonpb.ModelProvider_value[resp.Provider])
		reqCtx.ModelContext.ResponseTime = resp.ProcessingTime
		reqCtx.ModelContext.TokensUsed = resp.TokensUsed
		reqCtx.ModelContext.CostEstimate = resp.Cost
		reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_ROUTED

		return nil
	})

	if err != nil {
		return nil, modelErr
	}

	return aiResponse, nil
}

func (o *Orchestrator) postProcessResponse(reqCtx *RequestContext, aiResponse *gatewaypb.AIResponsePayload) *errors.AppError {
	if aiResponse == nil || len(aiResponse.Choices) == 0 {
		return errors.New(errors.ErrCodeInternalError, "empty response from model")
	}

	if reqCtx.Request.Context != nil && reqCtx.Request.Context.Fields != nil {
		if piiField, exists := reqCtx.Request.Context.Fields["pii_detected"]; exists {
			if piiField.GetBoolValue() {
				reqCtx.AuditContext.PIIDetected = true
			}
		}
	}

	if reqCtx.Tenant.ComplianceConfig.PIIRedactionEnabled {
		for i, choice := range aiResponse.Choices {
			if choice.Message != nil && choice.Message.Content != "" {
				aiResponse.Choices[i].Message.Content = o.sanitizeContent(choice.Message.Content)
			}
		}
	}

	reqCtx.ProcessingStage = gatewaypb.ProcessingStage_PROCESSING_STAGE_PROCESSED
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

		auditStatus := o.convertProcessingStageToStatus(reqCtx.ProcessingStage)

		auditEvent := &commonpb.AuditEvent{
			EventId:   uuid.New().String(),
			EventType: "ai_request",
			ActorId:   reqCtx.AuthContext.Principal,
			ActorType: "user",
			Action:    "process_request",
			Status:    auditStatus,
			SourceIp:  reqCtx.Request.Metadata.ClientInfo.IpAddress,
			UserAgent: reqCtx.Request.Metadata.ClientInfo.UserAgent,
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
		"policy": func() error { return o.policyClient.HealthCheck(context.Background()) },
		"threat": func() error { return o.threatClient.HealthCheck(context.Background()) },
		"model":  func() error { return o.modelProxyClient.HealthCheck(context.Background()) },
		"audit":  func() error { return o.auditClient.HealthCheck(context.Background()) },
	}

	for serviceName, healthCheck := range services {
		totalServices++
		
		if err := healthCheck(); err != nil {
			o.healthStatus.Services[serviceName] = "unhealthy"
			o.logger.Warn("Service health check failed",
				zap.String("service", serviceName),
				zap.Error(err))
		} else {
			o.healthStatus.Services[serviceName] = "healthy"
			healthyServices++
		}
	}

	dbCtx, dbCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dbCancel()

	if err := o.db.HealthCheck(dbCtx); err != nil {
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

func (o *Orchestrator) GetHealth(ctx context.Context, req *gatewaypb.GetHealthRequest) (*gatewaypb.GetHealthResponse, error) {
	o.performHealthCheck()
	
	serviceHealthList := make([]*gatewaypb.ServiceHealth, 0)
	for serviceName, status := range o.healthStatus.Services {
		serviceHealthList = append(serviceHealthList, &gatewaypb.ServiceHealth{
			ServiceName: serviceName,
			Status:      o.convertHealthStringToStatus(status),
			LastCheck:   timestamppb.New(o.healthStatus.LastHealthCheck),
		})
	}
	
	return &gatewaypb.GetHealthResponse{
		Status: commonpb.Status_STATUS_SUCCESS,
		ServiceHealth: serviceHealthList,
		LastUpdated:   timestamppb.New(o.healthStatus.LastHealthCheck),
	}, nil
}

func (o *Orchestrator) GetMetrics(ctx context.Context, req *gatewaypb.GetMetricsRequest) (*gatewaypb.GetMetricsResponse, error) {
	o.metrics.mu.RLock()
	defer o.metrics.mu.RUnlock()
	
	metrics := []*gatewaypb.MetricData{
		{
			Name:        "total_requests",
			Type:        "counter",
			Description: "Total number of requests processed",
			Points: []*gatewaypb.MetricPoint{
				{
					Timestamp: timestamppb.New(o.metrics.LastUpdated),
					Value:     float64(o.metrics.TotalRequests),
				},
			},
		},
		{
			Name:        "error_rate",
			Type:        "gauge",
			Description: "Current error rate",
			Points: []*gatewaypb.MetricPoint{
				{
					Timestamp: timestamppb.New(o.metrics.LastUpdated),
					Value:     o.metrics.ErrorRate,
				},
			},
		},
	}
	
	return &gatewaypb.GetMetricsResponse{
		Status:      commonpb.Status_STATUS_SUCCESS,
		Metrics:     metrics,
		GeneratedAt: timestamppb.New(time.Now()),
	}, nil
}

func (o *Orchestrator) ValidateRequest(ctx context.Context, req *gatewaypb.ValidateRequestRequest) (*gatewaypb.ValidateRequestResponse, error) {
	validationErrors := make([]*gatewaypb.ValidationError, 0)
	
	if req.Payload == nil {
		validationErrors = append(validationErrors, &gatewaypb.ValidationError{
			Field:   "payload",
			Code:    "required",
			Message: "payload is required",
		})
	} else {
		if req.Payload.ModelName == "" {
			validationErrors = append(validationErrors, &gatewaypb.ValidationError{
				Field:   "model_name",
				Code:    "required",
				Message: "model name is required",
			})
		}
	}
	
	isValid := len(validationErrors) == 0
	
	return &gatewaypb.ValidateRequestResponse{
		Status: commonpb.Status_STATUS_SUCCESS,
		Result: &gatewaypb.ValidationResult{
			Valid:       isValid,
			Errors:      validationErrors,
			ValidatedAt: timestamppb.New(time.Now()),
		},
	}, nil
}

func (o *Orchestrator) GetRoutingInfo(ctx context.Context, req *gatewaypb.GetRoutingInfoRequest) (*gatewaypb.GetRoutingInfoResponse, error) {
	return &gatewaypb.GetRoutingInfoResponse{
		Status: commonpb.Status_STATUS_SUCCESS,
		RoutingInfo: &gatewaypb.RoutingInfo{
			TargetEndpoint:      "model-proxy-service",
			LoadBalancerPolicy:  "round_robin",
			AvailableEndpoints:  []string{"endpoint1", "endpoint2"},
		},
	}, nil
}

func (o *Orchestrator) StreamAIRequest(req *gatewaypb.StreamAIRequestRequest, stream gatewaypb.GatewayService_StreamAIRequestServer) error {
	return fmt.Errorf("streaming not implemented")
}

func (o *Orchestrator) ProcessBatchRequests(ctx context.Context, requests []*gatewaypb.ProcessAIRequestRequest) ([]*gatewaypb.ProcessAIRequestResponse, error) {
	if len(requests) == 0 {
		return nil, fmt.Errorf("no requests provided")
	}

	if len(requests) > 100 {
		return nil, fmt.Errorf("batch size exceeds maximum limit")
	}

	responses := make([]*gatewaypb.ProcessAIRequestResponse, len(requests))
	errChan := make(chan error, len(requests))
	
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for i, req := range requests {
		wg.Add(1)
		go func(index int, aiRequest *gatewaypb.ProcessAIRequestRequest) {
			defer wg.Done()
			
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			resp, err := o.ProcessAIRequest(ctx, aiRequest)
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
		return nil, firstError
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

func (o *Orchestrator) GetInternalMetrics() *OrchestratorMetrics {
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

func (o *Orchestrator) convertHealthStringToStatus(health string) commonpb.Status {
	switch health {
	case "healthy":
		return commonpb.Status_STATUS_SUCCESS
	case "unhealthy":
		return commonpb.Status_STATUS_ERROR
	default:
		return commonpb.Status_STATUS_PROCESSING
	}
}

func (o *Orchestrator) convertErrorCode(errCode errors.ErrorCode) string {
	return string(errCode)
}

