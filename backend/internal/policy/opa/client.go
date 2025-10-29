package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	"flamo/backend/pkg/api/models/policy"
	v1 "flamo/backend/pkg/api/policy/v1"
)

type Client struct {
	httpClient    *utils.HTTPClient
	config        *config.Config
	logger        *zap.Logger
	baseURL       string
	authToken     string
	timeout       time.Duration
	retryConfig   utils.RetryConfig
	circuitConfig utils.CircuitBreakerConfig
	mu            sync.RWMutex
}

type OPARequest struct {
	Input map[string]interface{} `json:"input"`
}

type OPAResponse struct {
	DecisionID string                 `json:"decision_id"`
	Result     map[string]interface{} `json:"result"`
	Metrics    map[string]interface{} `json:"metrics,omitempty"`
}

type OPAError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type PolicyDocument struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Content  string `json:"content"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type BundleManifest struct {
	Revision string                    `json:"revision"`
	Roots    []string                  `json:"roots,omitempty"`
	Metadata map[string]interface{}    `json:"metadata,omitempty"`
	Policies map[string]PolicyDocument `json:"policies"`
}

type DataDocument struct {
	Path string      `json:"path"`
	Data interface{} `json:"data"`
}

type CompileRequest struct {
	Query   string                 `json:"query"`
	Input   map[string]interface{} `json:"input,omitempty"`
	Unknowns []string              `json:"unknowns,omitempty"`
}

type CompileResponse struct {
	Result map[string]interface{} `json:"result"`
}

type HealthStatus struct {
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Uptime    time.Duration          `json:"uptime"`
	Version   string                 `json:"version"`
	Metrics   map[string]interface{} `json:"metrics,omitempty"`
}

func NewClient(cfg *config.Config, logger *zap.Logger) *Client {
	retryConfig := utils.RetryConfig{
		MaxAttempts:   3,
		BaseDelay:     100 * time.Millisecond,
		MaxDelay:      5 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
	}

	circuitConfig := utils.CircuitBreakerConfig{
		MaxRequests:      10,
		Interval:         30 * time.Second,
		Timeout:          60 * time.Second,
		FailureThreshold: 0.6,
		SuccessThreshold: 3,
	}

	httpClient := utils.NewHTTPClient(30*time.Second, retryConfig, circuitConfig)

	baseURL := fmt.Sprintf("%s://%s:%d",
		cfg.Services.OPAService.Protocol,
		cfg.Services.OPAService.Host,
		cfg.Services.OPAService.Port)

	return &Client{
		httpClient:    httpClient,
		config:        cfg,
		logger:        logger,
		baseURL:       baseURL,
		timeout:       cfg.Services.OPAService.Timeout,
		retryConfig:   retryConfig,
		circuitConfig: circuitConfig,
	}
}

func (c *Client) Evaluate(ctx context.Context, req *v1.EvaluateRequest) (*v1.EvaluateResponse, error) {
	if err := c.validateEvaluateRequest(req); err != nil {
		return nil, err
	}

	start := time.Now()
	traceID := utils.GenerateTraceID()

	opaReq := &OPARequest{
		Input: map[string]interface{}{
			"tenant_id":  req.TenantID,
			"subject_id": req.SubjectID,
			"resource":   req.Resource,
			"action":     req.Action,
			"context":    req.Context,
			"input":      req.Input,
			"trace_id":   traceID,
			"timestamp":  time.Now().UTC(),
		},
	}

	policyPath := c.buildPolicyPath(req.TenantID)
	opaResp, err := c.queryPolicy(ctx, policyPath, opaReq)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "OPA policy evaluation failed").
			WithTenantID(req.TenantID).
			WithTraceID(traceID).
			WithContext("resource", req.Resource).
			WithContext("action", req.Action)
	}

	decision := c.parseDecision(opaResp, req, traceID)
	duration := time.Since(start)

	c.logger.Debug("Policy evaluation completed",
		zap.String("tenant_id", req.TenantID),
		zap.String("trace_id", traceID),
		zap.String("resource", req.Resource),
		zap.String("action", req.Action),
		zap.Bool("allow", decision.Allow),
		zap.Duration("duration", duration))

	return &v1.EvaluateResponse{
		Decision: decision,
		Cached:   false,
		Duration: duration,
	}, nil
}

func (c *Client) BatchEvaluate(ctx context.Context, req *v1.BatchEvaluateRequest) (*v1.BatchEvaluateResponse, error) {
	if len(req.Requests) == 0 {
		return nil, errors.NewValidationError("requests", "At least one request is required", len(req.Requests))
	}

	if len(req.Requests) > 100 {
		return nil, errors.NewValidationError("requests", "Too many requests in batch", len(req.Requests))
	}

	start := time.Now()
	responses := make([]v1.EvaluateResponse, len(req.Requests))

	for i, evalReq := range req.Requests {
		resp, err := c.Evaluate(ctx, &evalReq)
		if err != nil {
			responses[i] = v1.EvaluateResponse{
				Decision: policy.PolicyDecision{
					Allow:     false,
					Deny:      true,
					Reason:    "Evaluation error: " + err.Error(),
					Timestamp: time.Now().UTC(),
					TenantID:  evalReq.TenantID,
					SubjectID: evalReq.SubjectID,
					Resource:  evalReq.Resource,
					Action:    evalReq.Action,
				},
				Cached:   false,
				Duration: 0,
			}
		} else {
			responses[i] = *resp
		}
	}

	return &v1.BatchEvaluateResponse{
		Responses: responses,
		Duration:  time.Since(start),
	}, nil
}

func (c *Client) UploadPolicy(ctx context.Context, policyDoc *PolicyDocument) error {
	if err := c.validatePolicyDocument(policyDoc); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/policies/%s", c.baseURL, policyDoc.ID)
	
	payload := map[string]interface{}{
		"content": policyDoc.Content,
	}
	if policyDoc.Metadata != nil {
		payload["metadata"] = policyDoc.Metadata
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to marshal policy document")
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to create HTTP request")
	}

	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.NewNetworkError(url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return errors.Newf(errors.ErrCodeInternalError, "OPA policy upload failed: %s", string(body)).
			WithContext("status_code", resp.StatusCode).
			WithContext("policy_id", policyDoc.ID)
	}

	c.logger.Info("Policy uploaded to OPA",
		zap.String("policy_id", policyDoc.ID),
		zap.String("path", policyDoc.Path),
		zap.Int("status_code", resp.StatusCode))

	return nil
}

func (c *Client) DeletePolicy(ctx context.Context, policyID string) error {
	if policyID == "" {
		return errors.NewValidationError("policy_id", "Policy ID is required", policyID)
	}

	url := fmt.Sprintf("%s/v1/policies/%s", c.baseURL, policyID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to create HTTP request")
	}

	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.NewNetworkError(url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 && resp.StatusCode != 404 {
		body, _ := io.ReadAll(resp.Body)
		return errors.Newf(errors.ErrCodeInternalError, "OPA policy deletion failed: %s", string(body)).
			WithContext("status_code", resp.StatusCode).
			WithContext("policy_id", policyID)
	}

	c.logger.Info("Policy deleted from OPA",
		zap.String("policy_id", policyID),
		zap.Int("status_code", resp.StatusCode))

	return nil
}

func (c *Client) UploadData(ctx context.Context, dataDoc *DataDocument) error {
	if err := c.validateDataDocument(dataDoc); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/data/%s", c.baseURL, strings.TrimPrefix(dataDoc.Path, "/"))

	jsonData, err := json.Marshal(dataDoc.Data)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to marshal data document")
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to create HTTP request")
	}

	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.NewNetworkError(url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return errors.Newf(errors.ErrCodeInternalError, "OPA data upload failed: %s", string(body)).
			WithContext("status_code", resp.StatusCode).
			WithContext("data_path", dataDoc.Path)
	}

	c.logger.Info("Data uploaded to OPA",
		zap.String("data_path", dataDoc.Path),
		zap.Int("status_code", resp.StatusCode))

	return nil
}

func (c *Client) queryPolicy(ctx context.Context, policyPath string, opaReq *OPARequest) (*OPAResponse, error) {
	url := fmt.Sprintf("%s/v1/data/%s", c.baseURL, strings.TrimPrefix(policyPath, "/"))

	jsonData, err := json.Marshal(opaReq)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to marshal OPA request")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to create HTTP request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.NewNetworkError(url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to read OPA response")
	}

	if resp.StatusCode >= 400 {
		var opaErr OPAError
		if json.Unmarshal(body, &opaErr) == nil {
			return nil, errors.Newf(errors.ErrCodeInternalError, "OPA query failed: %s", opaErr.Message).
				WithContext("opa_code", opaErr.Code).
				WithContext("status_code", resp.StatusCode)
		}
		return nil, errors.Newf(errors.ErrCodeInternalError, "OPA query failed: %s", string(body)).
			WithContext("status_code", resp.StatusCode)
	}

	var opaResp OPAResponse
	if err := json.Unmarshal(body, &opaResp); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to unmarshal OPA response")
	}

	return &opaResp, nil
}

func (c *Client) Compile(ctx context.Context, compileReq *CompileRequest) (*CompileResponse, error) {
	if compileReq.Query == "" {
		return nil, errors.NewValidationError("query", "Query is required", compileReq.Query)
	}

	url := fmt.Sprintf("%s/v1/compile", c.baseURL)

	jsonData, err := json.Marshal(compileReq)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to marshal compile request")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to create HTTP request")
	}

	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.NewNetworkError(url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to read compile response")
	}

	if resp.StatusCode >= 400 {
		return nil, errors.Newf(errors.ErrCodeInternalError, "OPA compile failed: %s", string(body)).
			WithContext("status_code", resp.StatusCode)
	}

	var compileResp CompileResponse
	if err := json.Unmarshal(body, &compileResp); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to unmarshal compile response")
	}

	return &compileResp, nil
}

func (c *Client) HealthCheck(ctx context.Context) (*HealthStatus, error) {
	url := fmt.Sprintf("%s/health", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to create health check request")
	}

	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.NewNetworkError(url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &HealthStatus{
			Status:    "unhealthy",
			Timestamp: time.Now().UTC(),
		}, errors.Newf(errors.ErrCodeServiceUnavailable, "OPA health check failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to read health check response")
	}

	var health HealthStatus
	if err := json.Unmarshal(body, &health); err != nil {
		health = HealthStatus{
			Status:    "healthy",
			Timestamp: time.Now().UTC(),
		}
	}

	return &health, nil
}

func (c *Client) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/metrics", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to create metrics request")
	}

	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.NewNetworkError(url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, errors.Newf(errors.ErrCodeInternalError, "OPA metrics request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to read metrics response")
	}

	var metrics map[string]interface{}
	if err := json.Unmarshal(body, &metrics); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to unmarshal metrics response")
	}

	return metrics, nil
}

func (c *Client) SetAuthToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authToken = token
}

func (c *Client) GetAuthToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authToken
}

func (c *Client) validateEvaluateRequest(req *v1.EvaluateRequest) error {
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

func (c *Client) validatePolicyDocument(doc *PolicyDocument) error {
	if doc.ID == "" {
		return errors.NewValidationError("id", "Policy document ID is required", doc.ID)
	}

	if doc.Content == "" {
		return errors.NewValidationError("content", "Policy document content is required", doc.Content)
	}

	if !strings.HasPrefix(doc.Content, "package ") {
		return errors.NewValidationError("content", "Policy document must start with package declaration", doc.Content)
	}

	return nil
}

func (c *Client) validateDataDocument(doc *DataDocument) error {
	if doc.Path == "" {
		return errors.NewValidationError("path", "Data document path is required", doc.Path)
	}

	if doc.Data == nil {
		return errors.NewValidationError("data", "Data document data is required", doc.Data)
	}

	return nil
}

func (c *Client) buildPolicyPath(tenantID string) string {
	return fmt.Sprintf("tenants/%s/policies/allow", tenantID)
}

func (c *Client) parseDecision(opaResp *OPAResponse, req *v1.EvaluateRequest, traceID string) policy.PolicyDecision {
	decision := policy.PolicyDecision{
		Allow:     false,
		Deny:      true,
		Reason:    "Default deny",
		Timestamp: time.Now().UTC(),
		RequestID: req.RequestID,
		TenantID:  req.TenantID,
		SubjectID: req.SubjectID,
		Resource:  req.Resource,
		Action:    req.Action,
		Context:   make(map[string]string),
		Metadata:  make(map[string]string),
	}

	if opaResp.Result != nil {
		if allow, ok := opaResp.Result["allow"].(bool); ok {
			decision.Allow = allow
			decision.Deny = !allow
		}

		if reason, ok := opaResp.Result["reason"].(string); ok {
			decision.Reason = reason
		}

		if policyID, ok := opaResp.Result["policy_id"].(string); ok {
			decision.PolicyID = policyID
		}

		if ruleID, ok := opaResp.Result["rule_id"].(string); ok {
			decision.RuleID = ruleID
		}

		if metadata, ok := opaResp.Result["metadata"].(map[string]interface{}); ok {
			for k, v := range metadata {
				if str, ok := v.(string); ok {
					decision.Metadata[k] = str
				}
			}
		}
	}

	if opaResp.DecisionID != "" {
		decision.Metadata["opa_decision_id"] = opaResp.DecisionID
	}

	decision.Metadata["trace_id"] = traceID

	return decision
}

func (c *Client) IsHealthy(ctx context.Context) bool {
	health, err := c.HealthCheck(ctx)
	if err != nil {
		return false
	}
	return health.Status == "healthy"
}

func (c *Client) GetBaseURL() string {
	return c.baseURL
}

func (c *Client) Close() error {
	c.logger.Info("OPA client closed")
	return nil
}
