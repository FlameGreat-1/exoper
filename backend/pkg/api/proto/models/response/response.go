package response

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type ResponseStatus string
type ErrorCode string
type ErrorSeverity string
type ThreatLevel string
type ComplianceStatus string

const (
	StatusSuccess   ResponseStatus = "success"
	StatusError     ResponseStatus = "error"
	StatusBlocked   ResponseStatus = "blocked"
	StatusFlagged   ResponseStatus = "flagged"
	StatusThrottled ResponseStatus = "throttled"

	ErrorCodeInvalidRequest     ErrorCode = "invalid_request"
	ErrorCodeUnauthorized       ErrorCode = "unauthorized"
	ErrorCodeForbidden          ErrorCode = "forbidden"
	ErrorCodeNotFound           ErrorCode = "not_found"
	ErrorCodeRateLimit          ErrorCode = "rate_limit_exceeded"
	ErrorCodeQuotaExceeded      ErrorCode = "quota_exceeded"
	ErrorCodeModelUnavailable   ErrorCode = "model_unavailable"
	ErrorCodeThreatDetected     ErrorCode = "threat_detected"
	ErrorCodeComplianceViolation ErrorCode = "compliance_violation"
	ErrorCodeInternalError      ErrorCode = "internal_error"
	ErrorCodeTimeout            ErrorCode = "timeout"
	ErrorCodeInvalidModel       ErrorCode = "invalid_model"
	ErrorCodeContentFiltered    ErrorCode = "content_filtered"

	SeverityLow      ErrorSeverity = "low"
	SeverityMedium   ErrorSeverity = "medium"
	SeverityHigh     ErrorSeverity = "high"
	SeverityCritical ErrorSeverity = "critical"

	ThreatLevelNone     ThreatLevel = "none"
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"

	CompliancePass ComplianceStatus = "pass"
	ComplianceFail ComplianceStatus = "fail"
	ComplianceWarn ComplianceStatus = "warn"
	ComplianceSkip ComplianceStatus = "skip"
)

type AIResponse struct {
	ID                uuid.UUID              `json:"id"`
	RequestID         uuid.UUID              `json:"request_id"`
	TenantID          uuid.UUID              `json:"tenant_id"`
	TraceID           string                 `json:"trace_id"`
	SpanID            string                 `json:"span_id"`
	Status            ResponseStatus         `json:"status"`
	Data              *ResponseData          `json:"data,omitempty"`
	Error             *ErrorResponse         `json:"error,omitempty"`
	SecurityAnalysis  SecurityAnalysis       `json:"security_analysis"`
	ComplianceReport  ComplianceReport       `json:"compliance_report"`
	Usage             UsageMetrics           `json:"usage"`
	Performance       PerformanceMetrics     `json:"performance"`
	Metadata          map[string]interface{} `json:"metadata"`
	Timestamp         time.Time              `json:"timestamp"`
	ProcessingTimeMs  int64                  `json:"processing_time_ms"`
	Version           string                 `json:"version"`
}

type ResponseData struct {
	Content           string                 `json:"content,omitempty"`
	Choices           []Choice               `json:"choices,omitempty"`
	Embeddings        []Embedding            `json:"embeddings,omitempty"`
	FunctionCall      *FunctionCallResult    `json:"function_call,omitempty"`
	ToolCalls         []ToolCallResult       `json:"tool_calls,omitempty"`
	FinishReason      string                 `json:"finish_reason,omitempty"`
	Model             string                 `json:"model"`
	Object            string                 `json:"object"`
	Created           int64                  `json:"created"`
	SystemFingerprint string                 `json:"system_fingerprint,omitempty"`
	CustomData        map[string]interface{} `json:"custom_data,omitempty"`
}

type Choice struct {
	Index        int                    `json:"index"`
	Message      *ResponseMessage       `json:"message,omitempty"`
	Text         string                 `json:"text,omitempty"`
	Delta        *ResponseMessage       `json:"delta,omitempty"`
	FinishReason string                 `json:"finish_reason"`
	Logprobs     *LogprobsResult        `json:"logprobs,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type ResponseMessage struct {
	Role         string                 `json:"role"`
	Content      string                 `json:"content"`
	Name         string                 `json:"name,omitempty"`
	FunctionCall *FunctionCallResult    `json:"function_call,omitempty"`
	ToolCalls    []ToolCallResult       `json:"tool_calls,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type Embedding struct {
	Object    string    `json:"object"`
	Index     int       `json:"index"`
	Embedding []float64 `json:"embedding"`
}

type FunctionCallResult struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ToolCallResult struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function FunctionCallResult `json:"function"`
}

type LogprobsResult struct {
	Tokens        []string             `json:"tokens"`
	TokenLogprobs []float64            `json:"token_logprobs"`
	TopLogprobs   []map[string]float64 `json:"top_logprobs"`
	TextOffset    []int                `json:"text_offset"`
}

type ErrorResponse struct {
	Code        ErrorCode              `json:"code"`
	Message     string                 `json:"message"`
	Details     string                 `json:"details,omitempty"`
	Severity    ErrorSeverity          `json:"severity"`
	Retryable   bool                   `json:"retryable"`
	RetryAfter  *time.Duration         `json:"retry_after,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	RequestID   uuid.UUID              `json:"request_id"`
	TraceID     string                 `json:"trace_id"`
	HelpURL     string                 `json:"help_url,omitempty"`
	InnerErrors []ErrorResponse        `json:"inner_errors,omitempty"`
}

type SecurityAnalysis struct {
	ThreatLevel       ThreatLevel        `json:"threat_level"`
	ThreatsDetected   []ThreatDetection  `json:"threats_detected"`
	RiskScore         float64            `json:"risk_score"`
	Confidence        float64            `json:"confidence"`
	DetectionMethods  []string           `json:"detection_methods"`
	Recommendations   []string           `json:"recommendations,omitempty"`
	ProcessingTimeMs  int64              `json:"processing_time_ms"`
	EngineVersion     string             `json:"engine_version"`
	Signatures        []SignatureMatch   `json:"signatures,omitempty"`
	Anomalies         []AnomalyDetection `json:"anomalies,omitempty"`
}

type ThreatDetection struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Location    string                 `json:"location,omitempty"`
	Evidence    string                 `json:"evidence,omitempty"`
	Confidence  float64                `json:"confidence"`
	Mitigation  string                 `json:"mitigation,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type SignatureMatch struct {
	SignatureID   string  `json:"signature_id"`
	SignatureName string  `json:"signature_name"`
	MatchType     string  `json:"match_type"`
	Confidence    float64 `json:"confidence"`
	Location      string  `json:"location"`
	Context       string  `json:"context,omitempty"`
}

type AnomalyDetection struct {
	Type        string  `json:"type"`
	Score       float64 `json:"score"`
	Threshold   float64 `json:"threshold"`
	Description string  `json:"description"`
	Features    string  `json:"features,omitempty"`
}

type ComplianceReport struct {
	Status            ComplianceStatus       `json:"status"`
	Frameworks        []FrameworkResult      `json:"frameworks"`
	PIIDetected       bool                   `json:"pii_detected"`
	PIITypes          []string               `json:"pii_types,omitempty"`
	RedactionsApplied []RedactionApplied     `json:"reductions_applied,omitempty"`
	DataClassification []string              `json:"data_classification"`
	RetentionRequired bool                   `json:"retention_required"`
	AuditRequired     bool                   `json:"audit_required"`
	Violations        []ComplianceViolation  `json:"violations,omitempty"`
	Recommendations   []string               `json:"recommendations,omitempty"`
	ProcessingTimeMs  int64                  `json:"processing_time_ms"`
	EngineVersion     string                 `json:"engine_version"`
}

type FrameworkResult struct {
	Framework   string                 `json:"framework"`
	Status      ComplianceStatus       `json:"status"`
	Score       float64                `json:"score"`
	Requirements []RequirementResult   `json:"requirements"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type RequirementResult struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Status      ComplianceStatus `json:"status"`
	Description string           `json:"description,omitempty"`
	Evidence    string           `json:"evidence,omitempty"`
}

type ComplianceViolation struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Framework   string                 `json:"framework"`
	Requirement string                 `json:"requirement"`
	Location    string                 `json:"location,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type RedactionApplied struct {
	Type        string `json:"type"`
	Location    string `json:"location"`
	Original    string `json:"original,omitempty"`
	Replacement string `json:"replacement"`
	Reason      string `json:"reason"`
}

type UsageMetrics struct {
	PromptTokens     int                    `json:"prompt_tokens"`
	CompletionTokens int                    `json:"completion_tokens"`
	TotalTokens      int                    `json:"total_tokens"`
	RequestCount     int                    `json:"request_count"`
	CacheHits        int                    `json:"cache_hits"`
	CacheMisses      int                    `json:"cache_misses"`
	BandwidthBytes   int64                  `json:"bandwidth_bytes"`
	ComputeUnits     float64                `json:"compute_units"`
	Cost             *CostBreakdown         `json:"cost,omitempty"`
	Quotas           map[string]interface{} `json:"quotas,omitempty"`
}

type CostBreakdown struct {
	Currency        string  `json:"currency"`
	PromptCost      float64 `json:"prompt_cost"`
	CompletionCost  float64 `json:"completion_cost"`
	ProcessingCost  float64 `json:"processing_cost"`
	StorageCost     float64 `json:"storage_cost"`
	TotalCost       float64 `json:"total_cost"`
	BillingTier     string  `json:"billing_tier"`
	DiscountApplied float64 `json:"discount_applied"`
}

type PerformanceMetrics struct {
	TotalLatencyMs      int64                  `json:"total_latency_ms"`
	ModelLatencyMs      int64                  `json:"model_latency_ms"`
	SecurityLatencyMs   int64                  `json:"security_latency_ms"`
	ComplianceLatencyMs int64                  `json:"compliance_latency_ms"`
	NetworkLatencyMs    int64                  `json:"network_latency_ms"`
	QueueTimeMs         int64                  `json:"queue_time_ms"`
	TimeToFirstTokenMs  int64                  `json:"time_to_first_token_ms"`
	TokensPerSecond     float64                `json:"tokens_per_second"`
	Throughput          float64                `json:"throughput"`
	ConcurrentRequests  int                    `json:"concurrent_requests"`
	RetryCount          int                    `json:"retry_count"`
	CacheHitRatio       float64                `json:"cache_hit_ratio"`
	ResourceUtilization map[string]interface{} `json:"resource_utilization,omitempty"`
}

func NewAIResponse(requestID uuid.UUID, tenantID uuid.UUID, traceID, spanID string) *AIResponse {
	return &AIResponse{
		ID:        uuid.New(),
		RequestID: requestID,
		TenantID:  tenantID,
		TraceID:   traceID,
		SpanID:    spanID,
		Status:    StatusSuccess,
		SecurityAnalysis: SecurityAnalysis{
			ThreatLevel:      ThreatLevelNone,
			ThreatsDetected:  []ThreatDetection{},
			RiskScore:        0.0,
			Confidence:       1.0,
			DetectionMethods: []string{},
			Signatures:       []SignatureMatch{},
			Anomalies:        []AnomalyDetection{},
		},
		ComplianceReport: ComplianceReport{
			Status:             CompliancePass,
			Frameworks:         []FrameworkResult{},
			PIIDetected:        false,
			PIITypes:           []string{},
			RedactionsApplied:  []RedactionApplied{},
			DataClassification: []string{},
			Violations:         []ComplianceViolation{},
		},
		Usage: UsageMetrics{
			RequestCount: 1,
			Quotas:       make(map[string]interface{}),
		},
		Performance: PerformanceMetrics{
			ResourceUtilization: make(map[string]interface{}),
		},
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now().UTC(),
		Version:   "1.0",
	}
}

func NewErrorResponse(requestID uuid.UUID, traceID string, code ErrorCode, message string, severity ErrorSeverity) *AIResponse {
	response := &AIResponse{
		ID:        uuid.New(),
		RequestID: requestID,
		TraceID:   traceID,
		Status:    StatusError,
		Error: &ErrorResponse{
			Code:      code,
			Message:   message,
			Severity:  severity,
			Timestamp: time.Now().UTC(),
			RequestID: requestID,
			TraceID:   traceID,
			Context:   make(map[string]interface{}),
		},
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now().UTC(),
		Version:   "1.0",
	}

	response.Error.Retryable = isRetryableError(code)
	if response.Error.Retryable {
		retryAfter := getRetryAfterDuration(code)
		response.Error.RetryAfter = &retryAfter
	}

	return response
}

func (r *AIResponse) Validate() error {
	if r.ID == uuid.Nil {
		return fmt.Errorf("response ID is required")
	}

	if r.RequestID == uuid.Nil {
		return fmt.Errorf("request ID is required")
	}

	if r.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}

	if r.TraceID == "" {
		return fmt.Errorf("trace ID is required")
	}

	if !isValidResponseStatus(r.Status) {
		return fmt.Errorf("invalid response status: %s", r.Status)
	}

	if r.Status == StatusError && r.Error == nil {
		return fmt.Errorf("error response must include error details")
	}

	if r.Status == StatusSuccess && r.Data == nil {
		return fmt.Errorf("success response must include data")
	}

	if r.Error != nil {
		if err := r.Error.Validate(); err != nil {
			return fmt.Errorf("invalid error response: %w", err)
		}
	}

	if r.Data != nil {
		if err := r.Data.Validate(); err != nil {
			return fmt.Errorf("invalid response data: %w", err)
		}
	}

	if err := r.SecurityAnalysis.Validate(); err != nil {
		return fmt.Errorf("invalid security analysis: %w", err)
	}

	if err := r.ComplianceReport.Validate(); err != nil {
		return fmt.Errorf("invalid compliance report: %w", err)
	}

	return nil
}

func (r *AIResponse) SetSuccess(data *ResponseData) {
	r.Status = StatusSuccess
	r.Data = data
	r.Error = nil
}

func (r *AIResponse) SetError(code ErrorCode, message string, severity ErrorSeverity) {
	r.Status = StatusError
	r.Data = nil
	r.Error = &ErrorResponse{
		Code:      code,
		Message:   message,
		Severity:  severity,
		Retryable: isRetryableError(code),
		Timestamp: time.Now().UTC(),
		RequestID: r.RequestID,
		TraceID:   r.TraceID,
		Context:   make(map[string]interface{}),
	}

	if r.Error.Retryable {
		retryAfter := getRetryAfterDuration(code)
		r.Error.RetryAfter = &retryAfter
	}
}

func (r *AIResponse) SetBlocked(reason string, threatLevel ThreatLevel) {
	r.Status = StatusBlocked
	r.Data = nil
	r.SecurityAnalysis.ThreatLevel = threatLevel
	r.SetError(ErrorCodeThreatDetected, fmt.Sprintf("Request blocked: %s", reason), SeverityHigh)
}

func (r *AIResponse) SetFlagged(reason string, threatLevel ThreatLevel) {
	r.Status = StatusFlagged
	r.SecurityAnalysis.ThreatLevel = threatLevel
	r.AddMetadata("flag_reason", reason)
}

func (r *AIResponse) AddThreat(threatType, severity, description string, confidence float64) {
	threat := ThreatDetection{
		Type:        threatType,
		Severity:    severity,
		Description: description,
		Confidence:  confidence,
		Metadata:    make(map[string]interface{}),
	}

	r.SecurityAnalysis.ThreatsDetected = append(r.SecurityAnalysis.ThreatsDetected, threat)
	r.updateThreatLevel()
}

func (r *AIResponse) AddComplianceViolation(violationType, framework, requirement, description string) {
	violation := ComplianceViolation{
		Type:        violationType,
		Severity:    "high",
		Description: description,
		Framework:   framework,
		Requirement: requirement,
		Metadata:    make(map[string]interface{}),
	}

	r.ComplianceReport.Violations = append(r.ComplianceReport.Violations, violation)
	r.ComplianceReport.Status = ComplianceFail
}

func (r *AIResponse) AddRedaction(redactionType, location, replacement, reason string) {
	redaction := RedactionApplied{
		Type:        redactionType,
		Location:    location,
		Replacement: replacement,
		Reason:      reason,
	}

	r.ComplianceReport.RedactionsApplied = append(r.ComplianceReport.RedactionsApplied, redaction)
	r.ComplianceReport.PIIDetected = true
}

func (r *AIResponse) SetProcessingTime(startTime time.Time) {
	r.ProcessingTimeMs = time.Since(startTime).Milliseconds()
}

func (r *AIResponse) AddMetadata(key string, value interface{}) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]interface{})
	}
	r.Metadata[key] = value
}

func (r *AIResponse) GetMetadata(key string) (interface{}, bool) {
	if r.Metadata == nil {
		return nil, false
	}
	value, exists := r.Metadata[key]
	return value, exists
}

func (r *AIResponse) IsSuccess() bool {
	return r.Status == StatusSuccess
}

func (r *AIResponse) IsError() bool {
	return r.Status == StatusError
}

func (r *AIResponse) IsBlocked() bool {
	return r.Status == StatusBlocked
}

func (r *AIResponse) IsFlagged() bool {
	return r.Status == StatusFlagged
}

func (r *AIResponse) HasThreats() bool {
	return len(r.SecurityAnalysis.ThreatsDetected) > 0
}

func (r *AIResponse) HasComplianceViolations() bool {
	return len(r.ComplianceReport.Violations) > 0
}

func (r *AIResponse) SanitizeForLogging() *AIResponse {
	sanitized := *r

	if r.Data != nil {
		sanitizedData := *r.Data
		if r.ComplianceReport.PIIDetected {
			sanitizedData.Content = "[REDACTED - PII DETECTED]"
			for i := range sanitizedData.Choices {
				if sanitizedData.Choices[i].Message != nil {
					sanitizedData.Choices[i].Message.Content = "[REDACTED - PII DETECTED]"
				}
				sanitizedData.Choices[i].Text = "[REDACTED - PII DETECTED]"
			}
		}
		sanitized.Data = &sanitizedData
	}

	return &sanitized
}

func (e *ErrorResponse) Validate() error {
	if e.Code == "" {
		return fmt.Errorf("error code is required")
	}

	if e.Message == "" {
		return fmt.Errorf("error message is required")
	}

	if !isValidErrorCode(e.Code) {
		return fmt.Errorf("invalid error code: %s", e.Code)
	}

	if !isValidErrorSeverity(e.Severity) {
		return fmt.Errorf("invalid error severity: %s", e.Severity)
	}

	return nil
}

func (d *ResponseData) Validate() error {
	if d.Model == "" {
		return fmt.Errorf("model is required")
	}

	for i, choice := range d.Choices {
		if err := choice.Validate(); err != nil {
			return fmt.Errorf("invalid choice at index %d: %w", i, err)
		}
	}

	return nil
}

func (c *Choice) Validate() error {
	if c.Index < 0 {
		return fmt.Errorf("choice index cannot be negative")
	}

	if c.Message != nil {
		if err := c.Message.Validate(); err != nil {
			return fmt.Errorf("invalid message: %w", err)
		}
	}

	return nil
}

func (m *ResponseMessage) Validate() error {
	if m.Role == "" {
		return fmt.Errorf("message role is required")
	}

	validRoles := []string{"assistant", "system", "user", "function", "tool"}
	roleValid := false
	for _, role := range validRoles {
		if m.Role == role {
			roleValid = true
			break
		}
	}
	if !roleValid {
		return fmt.Errorf("invalid message role: %s", m.Role)
	}

	return nil
}

func (s *SecurityAnalysis) Validate() error {
	if !isValidThreatLevel(s.ThreatLevel) {
		return fmt.Errorf("invalid threat level: %s", s.ThreatLevel)
	}

	if s.RiskScore < 0 || s.RiskScore > 1 {
		return fmt.Errorf("risk score must be between 0 and 1")
	}

	if s.Confidence < 0 || s.Confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1")
	}

	return nil
}

func (c *ComplianceReport) Validate() error {
	if !isValidComplianceStatus(c.Status) {
		return fmt.Errorf("invalid compliance status: %s", c.Status)
	}

	for i, framework := range c.Frameworks {
		if err := framework.Validate(); err != nil {
			return fmt.Errorf("invalid framework result at index %d: %w", i, err)
		}
	}

	return nil
}

func (f *FrameworkResult) Validate() error {
	if f.Framework == "" {
		return fmt.Errorf("framework name is required")
	}

	if !isValidComplianceStatus(f.Status) {
		return fmt.Errorf("invalid framework status: %s", f.Status)
	}

	if f.Score < 0 || f.Score > 1 {
		return fmt.Errorf("framework score must be between 0 and 1")
	}

	return nil
}

func (r *AIResponse) updateThreatLevel() {
	if len(r.SecurityAnalysis.ThreatsDetected) == 0 {
		r.SecurityAnalysis.ThreatLevel = ThreatLevelNone
		return
	}

	maxLevel := ThreatLevelNone
	for _, threat := range r.SecurityAnalysis.ThreatsDetected {
		switch threat.Severity {
		case "critical":
			maxLevel = ThreatLevelCritical
		case "high":
			if maxLevel != ThreatLevelCritical {
				maxLevel = ThreatLevelHigh
			}
		case "medium":
			if maxLevel != ThreatLevelCritical && maxLevel != ThreatLevelHigh {
				maxLevel = ThreatLevelMedium
			}
		case "low":
			if maxLevel == ThreatLevelNone {
				maxLevel = ThreatLevelLow
			}
		}
	}

	r.SecurityAnalysis.ThreatLevel = maxLevel
}

func isValidResponseStatus(status ResponseStatus) bool {
	validStatuses := []ResponseStatus{StatusSuccess, StatusError, StatusBlocked, StatusFlagged, StatusThrottled}
	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}
	return false
}

func isValidErrorCode(code ErrorCode) bool {
	validCodes := []ErrorCode{
		ErrorCodeInvalidRequest, ErrorCodeUnauthorized, ErrorCodeForbidden, ErrorCodeNotFound,
		ErrorCodeRateLimit, ErrorCodeQuotaExceeded, ErrorCodeModelUnavailable, ErrorCodeThreatDetected,
		ErrorCodeComplianceViolation, ErrorCodeInternalError, ErrorCodeTimeout, ErrorCodeInvalidModel,
		ErrorCodeContentFiltered,
	}
	for _, validCode := range validCodes {
		if code == validCode {
			return true
		}
	}
	return false
}

func isValidErrorSeverity(severity ErrorSeverity) bool {
	validSeverities := []ErrorSeverity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for _, validSeverity := range validSeverities {
		if severity == validSeverity {
			return true
		}
	}
	return false
}

func isValidThreatLevel(level ThreatLevel) bool {
	validLevels := []ThreatLevel{ThreatLevelNone, ThreatLevelLow, ThreatLevelMedium, ThreatLevelHigh, ThreatLevelCritical}
	for _, validLevel := range validLevels {
		if level == validLevel {
			return true
		}
	}
	return false
}

func isValidComplianceStatus(status ComplianceStatus) bool {
	validStatuses := []ComplianceStatus{CompliancePass, ComplianceFail, ComplianceWarn, ComplianceSkip}
	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}
	return false
}

func isRetryableError(code ErrorCode) bool {
	retryableCodes := []ErrorCode{
		ErrorCodeRateLimit, ErrorCodeModelUnavailable, ErrorCodeInternalError, ErrorCodeTimeout,
	}
	for _, retryableCode := range retryableCodes {
		if code == retryableCode {
			return true
		}
	}
	return false
}

func getRetryAfterDuration(code ErrorCode) time.Duration {
	switch code {
	case ErrorCodeRateLimit:
		return time.Minute * 1
	case ErrorCodeQuotaExceeded:
		return time.Hour * 1
	case ErrorCodeModelUnavailable:
		return time.Second * 30
	case ErrorCodeInternalError:
		return time.Second * 10
	case ErrorCodeTimeout:
		return time.Second * 5
	default:
		return time.Second * 30
	}
}

func GetErrorHelpURL(code ErrorCode) string {
	baseURL := "https://docs.exoper.ai/errors/"
	return fmt.Sprintf("%s%s", baseURL, string(code))
}

func CalculateRiskScore(threats []ThreatDetection) float64 {
	if len(threats) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, threat := range threats {
		var severityWeight float64
		switch threat.Severity {
		case "critical":
			severityWeight = 1.0
		case "high":
			severityWeight = 0.8
		case "medium":
			severityWeight = 0.5
		case "low":
			severityWeight = 0.2
		default:
			severityWeight = 0.1
		}
		totalScore += severityWeight * threat.Confidence
	}

	riskScore := totalScore / float64(len(threats))
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	return riskScore
}
