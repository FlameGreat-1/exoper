package request

import (
	"encoding/json"
	"fmt"
	"net"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

type RequestType string
type ModelProvider string
type SecurityLevel string
type ContentType string

const (
	TypeCompletion     RequestType = "completion"
	TypeChat          RequestType = "chat"
	TypeEmbedding     RequestType = "embedding"
	TypeFineTuning    RequestType = "fine_tuning"
	TypeModeration    RequestType = "moderation"
	TypeClassification RequestType = "classification"

	ProviderOpenAI     ModelProvider = "openai"
	ProviderAnthropic  ModelProvider = "anthropic"
	ProviderCohere     ModelProvider = "cohere"
	ProviderHuggingFace ModelProvider = "huggingface"
	ProviderInternal   ModelProvider = "internal"

	SecurityLevelLow      SecurityLevel = "low"
	SecurityLevelMedium   SecurityLevel = "medium"
	SecurityLevelHigh     SecurityLevel = "high"
	SecurityLevelCritical SecurityLevel = "critical"

	ContentTypeText  ContentType = "text"
	ContentTypeImage ContentType = "image"
	ContentTypeAudio ContentType = "audio"
	ContentTypeVideo ContentType = "video"
	ContentTypeMixed ContentType = "mixed"
)

type AIRequest struct {
	ID                uuid.UUID              `json:"id"`
	TenantID          uuid.UUID              `json:"tenant_id"`
	UserID            *uuid.UUID             `json:"user_id,omitempty"`
	SessionID         *uuid.UUID             `json:"session_id,omitempty"`
	TraceID           string                 `json:"trace_id"`
	SpanID            string                 `json:"span_id"`
	Type              RequestType            `json:"type"`
	Provider          ModelProvider          `json:"provider"`
	ModelName         string                 `json:"model_name"`
	SecurityLevel     SecurityLevel          `json:"security_level"`
	ContentType       ContentType            `json:"content_type"`
	Payload           RequestPayload         `json:"payload"`
	Headers           map[string]string      `json:"headers"`
	ClientInfo        ClientInformation      `json:"client_info"`
	SecurityContext   SecurityContext        `json:"security_context"`
	ComplianceContext ComplianceContext      `json:"compliance_context"`
	Metadata          map[string]interface{} `json:"metadata"`
	Timestamp         time.Time              `json:"timestamp"`
	ExpiresAt         *time.Time             `json:"expires_at,omitempty"`
}

type RequestPayload struct {
	Prompt           string                 `json:"prompt,omitempty"`
	Messages         []ChatMessage          `json:"messages,omitempty"`
	SystemPrompt     string                 `json:"system_prompt,omitempty"`
	MaxTokens        *int                   `json:"max_tokens,omitempty"`
	Temperature      *float64               `json:"temperature,omitempty"`
	TopP             *float64               `json:"top_p,omitempty"`
	FrequencyPenalty *float64               `json:"frequency_penalty,omitempty"`
	PresencePenalty  *float64               `json:"presence_penalty,omitempty"`
	Stop             []string               `json:"stop,omitempty"`
	Stream           bool                   `json:"stream"`
	Functions        []FunctionDefinition   `json:"functions,omitempty"`
	FunctionCall     interface{}            `json:"function_call,omitempty"`
	Tools            []ToolDefinition       `json:"tools,omitempty"`
	ToolChoice       interface{}            `json:"tool_choice,omitempty"`
	ResponseFormat   *ResponseFormat        `json:"response_format,omitempty"`
	Seed             *int                   `json:"seed,omitempty"`
	User             string                 `json:"user,omitempty"`
	CustomParameters map[string]interface{} `json:"custom_parameters,omitempty"`
}

type ChatMessage struct {
	Role         string                 `json:"role"`
	Content      string                 `json:"content"`
	Name         string                 `json:"name,omitempty"`
	FunctionCall *FunctionCall          `json:"function_call,omitempty"`
	ToolCalls    []ToolCall             `json:"tool_calls,omitempty"`
	ToolCallID   string                 `json:"tool_call_id,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type FunctionDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ToolDefinition struct {
	Type     string                 `json:"type"`
	Function FunctionDefinition     `json:"function"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type ResponseFormat struct {
	Type   string                 `json:"type"`
	Schema map[string]interface{} `json:"schema,omitempty"`
}

type ClientInformation struct {
	IPAddress     string            `json:"ip_address"`
	UserAgent     string            `json:"user_agent"`
	Referer       string            `json:"referer,omitempty"`
	Origin        string            `json:"origin,omitempty"`
	Country       string            `json:"country,omitempty"`
	Region        string            `json:"region,omitempty"`
	City          string            `json:"city,omitempty"`
	ISP           string            `json:"isp,omitempty"`
	DeviceType    string            `json:"device_type,omitempty"`
	Platform      string            `json:"platform,omitempty"`
	Browser       string            `json:"browser,omitempty"`
	Language      string            `json:"language,omitempty"`
	Timezone      string            `json:"timezone,omitempty"`
	Fingerprint   string            `json:"fingerprint,omitempty"`
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
}

type SecurityContext struct {
	SessionToken         string                 `json:"session_token"`         
	AuthenticationMethod string                 `json:"authentication_method"`
	AuthenticationLevel  string                 `json:"authentication_level"`
	APIKeyID             *uuid.UUID             `json:"api_key_id,omitempty"`
	JWTClaims            map[string]interface{} `json:"jwt_claims,omitempty"`
	Permissions          []string               `json:"permissions"`
	Scopes               []string               `json:"scopes,omitempty"`
	RiskScore            float64                `json:"risk_score"`
	ThreatIndicators     []string               `json:"threat_indicators,omitempty"`
	IPWhitelisted        bool                   `json:"ip_whitelisted"`
	RateLimitRemaining   int                    `json:"rate_limit_remaining"`
	QuotaRemaining       int64                  `json:"quota_remaining"`
	MTLSVerified         bool                   `json:"mtls_verified"`
	CertificateSubject   string                 `json:"certificate_subject,omitempty"`
}

type ComplianceContext struct {
	DataClassification   []string               `json:"data_classification"`
	PIIDetected          bool                   `json:"pii_detected"`
	PIITypes             []string               `json:"pii_types,omitempty"`
	DataResidency        string                 `json:"data_residency"`
	ComplianceFrameworks []string               `json:"compliance_frameworks"`
	ConsentRequired      bool                   `json:"consent_required"`
	ConsentProvided      bool                   `json:"consent_provided"`
	DataRetentionDays    int                    `json:"data_retention_days"`
	EncryptionRequired   bool                   `json:"encryption_required"`
	AuditRequired        bool                   `json:"audit_required"`
	RedactionRules       []RedactionRule        `json:"redaction_rules,omitempty"`
	ComplianceMetadata   map[string]interface{} `json:"compliance_metadata,omitempty"`
}

type RedactionRule struct {
	Type        string `json:"type"`
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement"`
	Enabled     bool   `json:"enabled"`
}

var (
	ipRegex    = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	uuidRegex  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

func NewAIRequest(tenantID uuid.UUID, requestType RequestType, provider ModelProvider, modelName string) *AIRequest {
	return &AIRequest{
		ID:            uuid.New(),
		TenantID:      tenantID,
		TraceID:       generateTraceID(),
		SpanID:        generateSpanID(),
		Type:          requestType,
		Provider:      provider,
		ModelName:     modelName,
		SecurityLevel: SecurityLevelMedium,
		ContentType:   ContentTypeText,
		Headers:       make(map[string]string),
		Metadata:      make(map[string]interface{}),
		Timestamp:     time.Now().UTC(),
	}
}

func (r *AIRequest) Validate() error {
	if r.ID == uuid.Nil {
		return fmt.Errorf("request ID is required")
	}

	if r.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}

	if r.TraceID == "" {
		return fmt.Errorf("trace ID is required")
	}

	if !isValidRequestType(r.Type) {
		return fmt.Errorf("invalid request type: %s", r.Type)
	}

	if !isValidModelProvider(r.Provider) {
		return fmt.Errorf("invalid model provider: %s", r.Provider)
	}

	if r.ModelName == "" {
		return fmt.Errorf("model name is required")
	}

	if !isValidSecurityLevel(r.SecurityLevel) {
		return fmt.Errorf("invalid security level: %s", r.SecurityLevel)
	}

	if !isValidContentType(r.ContentType) {
		return fmt.Errorf("invalid content type: %s", r.ContentType)
	}

	if err := r.Payload.Validate(r.Type); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	if err := r.ClientInfo.Validate(); err != nil {
		return fmt.Errorf("invalid client info: %w", err)
	}

	if err := r.SecurityContext.Validate(); err != nil {
		return fmt.Errorf("invalid security context: %w", err)
	}

	if err := r.ComplianceContext.Validate(); err != nil {
		return fmt.Errorf("invalid compliance context: %w", err)
	}

	if r.ExpiresAt != nil && r.ExpiresAt.Before(time.Now().UTC()) {
		return fmt.Errorf("request has expired")
	}

	return nil
}

func (r *AIRequest) IsExpired() bool {
	return r.ExpiresAt != nil && r.ExpiresAt.Before(time.Now().UTC())
}

func (r *AIRequest) SetExpiration(duration time.Duration) {
	expiresAt := time.Now().UTC().Add(duration)
	r.ExpiresAt = &expiresAt
}

func (r *AIRequest) AddMetadata(key string, value interface{}) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]interface{})
	}
	r.Metadata[key] = value
}

func (r *AIRequest) GetMetadata(key string) (interface{}, bool) {
	if r.Metadata == nil {
		return nil, false
	}
	value, exists := r.Metadata[key]
	return value, exists
}

func (r *AIRequest) HasPermission(permission string) bool {
	for _, perm := range r.SecurityContext.Permissions {
		if perm == permission || perm == "*" {
			return true
		}
	}
	return false
}

func (r *AIRequest) RequiresCompliance() bool {
	return len(r.ComplianceContext.ComplianceFrameworks) > 0 || r.ComplianceContext.PIIDetected
}

func (r *AIRequest) SanitizeForLogging() *AIRequest {
	sanitized := *r
	
	if r.ComplianceContext.PIIDetected {
		sanitized.Payload.Prompt = "[REDACTED - PII DETECTED]"
		for i := range sanitized.Payload.Messages {
			sanitized.Payload.Messages[i].Content = "[REDACTED - PII DETECTED]"
		}
	}

	sanitized.SecurityContext.JWTClaims = nil
	sanitized.Headers = make(map[string]string)
	
	return &sanitized
}

func (p *RequestPayload) Validate(requestType RequestType) error {
	switch requestType {
	case TypeCompletion:
		if p.Prompt == "" {
			return fmt.Errorf("prompt is required for completion requests")
		}
		if len(p.Prompt) > 100000 {
			return fmt.Errorf("prompt exceeds maximum length of 100,000 characters")
		}
	case TypeChat:
		if len(p.Messages) == 0 {
			return fmt.Errorf("messages are required for chat requests")
		}
		for i, msg := range p.Messages {
			if err := msg.Validate(); err != nil {
				return fmt.Errorf("invalid message at index %d: %w", i, err)
			}
		}
	case TypeEmbedding:
		if p.Prompt == "" && len(p.Messages) == 0 {
			return fmt.Errorf("prompt or messages are required for embedding requests")
		}
	}

	if p.MaxTokens != nil && (*p.MaxTokens < 1 || *p.MaxTokens > 32000) {
		return fmt.Errorf("max_tokens must be between 1 and 32,000")
	}

	if p.Temperature != nil && (*p.Temperature < 0 || *p.Temperature > 2) {
		return fmt.Errorf("temperature must be between 0 and 2")
	}

	if p.TopP != nil && (*p.TopP < 0 || *p.TopP > 1) {
		return fmt.Errorf("top_p must be between 0 and 1")
	}

	if p.FrequencyPenalty != nil && (*p.FrequencyPenalty < -2 || *p.FrequencyPenalty > 2) {
		return fmt.Errorf("frequency_penalty must be between -2 and 2")
	}

	if p.PresencePenalty != nil && (*p.PresencePenalty < -2 || *p.PresencePenalty > 2) {
		return fmt.Errorf("presence_penalty must be between -2 and 2")
	}

	for _, function := range p.Functions {
		if err := function.Validate(); err != nil {
			return fmt.Errorf("invalid function definition: %w", err)
		}
	}

	for _, tool := range p.Tools {
		if err := tool.Validate(); err != nil {
			return fmt.Errorf("invalid tool definition: %w", err)
		}
	}

	return nil
}

func (m *ChatMessage) Validate() error {
	if m.Role == "" {
		return fmt.Errorf("message role is required")
	}

	validRoles := []string{"system", "user", "assistant", "function", "tool"}
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

	if m.Content == "" && m.FunctionCall == nil && len(m.ToolCalls) == 0 {
		return fmt.Errorf("message must have content, function_call, or tool_calls")
	}

	if len(m.Content) > 50000 {
		return fmt.Errorf("message content exceeds maximum length of 50,000 characters")
	}

	if m.FunctionCall != nil {
		if err := m.FunctionCall.Validate(); err != nil {
			return fmt.Errorf("invalid function call: %w", err)
		}
	}

	for i, toolCall := range m.ToolCalls {
		if err := toolCall.Validate(); err != nil {
			return fmt.Errorf("invalid tool call at index %d: %w", i, err)
		}
	}

	return nil
}

func (f *FunctionDefinition) Validate() error {
	if f.Name == "" {
		return fmt.Errorf("function name is required")
	}

	if len(f.Name) > 64 {
		return fmt.Errorf("function name exceeds maximum length of 64 characters")
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(f.Name) {
		return fmt.Errorf("function name contains invalid characters")
	}

	if len(f.Description) > 1000 {
		return fmt.Errorf("function description exceeds maximum length of 1,000 characters")
	}

	return nil
}

func (f *FunctionCall) Validate() error {
	if f.Name == "" {
		return fmt.Errorf("function call name is required")
	}

	if len(f.Arguments) > 10000 {
		return fmt.Errorf("function arguments exceed maximum length of 10,000 characters")
	}

	if f.Arguments != "" {
		var args map[string]interface{}
		if err := json.Unmarshal([]byte(f.Arguments), &args); err != nil {
			return fmt.Errorf("invalid function arguments JSON: %w", err)
		}
	}

	return nil
}

func (t *ToolDefinition) Validate() error {
	if t.Type == "" {
		return fmt.Errorf("tool type is required")
	}

	if t.Type != "function" {
		return fmt.Errorf("unsupported tool type: %s", t.Type)
	}

	return t.Function.Validate()
}

func (t *ToolCall) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("tool call ID is required")
	}

	if t.Type == "" {
		return fmt.Errorf("tool call type is required")
	}

	if t.Type != "function" {
		return fmt.Errorf("unsupported tool call type: %s", t.Type)
	}

	return t.Function.Validate()
}

func (c *ClientInformation) Validate() error {
	if c.IPAddress == "" {
		return fmt.Errorf("IP address is required")
	}

	if !isValidIP(c.IPAddress) {
		return fmt.Errorf("invalid IP address: %s", c.IPAddress)
	}

	if c.UserAgent == "" {
		return fmt.Errorf("user agent is required")
	}

	if len(c.UserAgent) > 1000 {
		return fmt.Errorf("user agent exceeds maximum length of 1,000 characters")
	}

	if c.Origin != "" {
		if _, err := url.Parse(c.Origin); err != nil {
			return fmt.Errorf("invalid origin URL: %w", err)
		}
	}

	if c.Referer != "" {
		if _, err := url.Parse(c.Referer); err != nil {
			return fmt.Errorf("invalid referer URL: %w", err)
		}
	}

	return nil
}

func (s *SecurityContext) Validate() error {
	if s.AuthenticationMethod == "" {
		return fmt.Errorf("authentication method is required")
	}

	validMethods := []string{"api_key", "jwt", "mtls", "oauth2", "basic"}
	methodValid := false
	for _, method := range validMethods {
		if s.AuthenticationMethod == method {
			methodValid = true
			break
		}
	}
	if !methodValid {
		return fmt.Errorf("invalid authentication method: %s", s.AuthenticationMethod)
	}

	if s.RiskScore < 0 || s.RiskScore > 1 {
		return fmt.Errorf("risk score must be between 0 and 1")
	}

	if s.RateLimitRemaining < 0 {
		return fmt.Errorf("rate limit remaining cannot be negative")
	}

	if s.QuotaRemaining < 0 {
		return fmt.Errorf("quota remaining cannot be negative")
	}

	return nil
}

func (c *ComplianceContext) Validate() error {
	validFrameworks := []string{"gdpr", "hipaa", "soc2", "iso27001", "fedramp", "ccpa"}
	for _, framework := range c.ComplianceFrameworks {
		frameworkValid := false
		for _, valid := range validFrameworks {
			if framework == valid {
				frameworkValid = true
				break
			}
		}
		if !frameworkValid {
			return fmt.Errorf("invalid compliance framework: %s", framework)
		}
	}

	validResidencies := []string{"us", "eu", "apac", "canada", "uk", "australia"}
	if c.DataResidency != "" {
		residencyValid := false
		for _, valid := range validResidencies {
			if c.DataResidency == valid {
				residencyValid = true
				break
			}
		}
		if !residencyValid {
			return fmt.Errorf("invalid data residency: %s", c.DataResidency)
		}
	}

	if c.DataRetentionDays < 1 || c.DataRetentionDays > 3650 {
		return fmt.Errorf("data retention days must be between 1 and 3,650")
	}

	for i, rule := range c.RedactionRules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("invalid redaction rule at index %d: %w", i, err)
		}
	}

	return nil
}

func (r *RedactionRule) Validate() error {
	if r.Type == "" {
		return fmt.Errorf("redaction rule type is required")
	}

	validTypes := []string{"email", "phone", "ssn", "credit_card", "ip_address", "custom"}
	typeValid := false
	for _, validType := range validTypes {
		if r.Type == validType {
			typeValid = true
			break
		}
	}
	if !typeValid {
		return fmt.Errorf("invalid redaction rule type: %s", r.Type)
	}

	if r.Pattern == "" {
		return fmt.Errorf("redaction rule pattern is required")
	}

	if _, err := regexp.Compile(r.Pattern); err != nil {
		return fmt.Errorf("invalid redaction rule pattern: %w", err)
	}

	return nil
}

func isValidRequestType(requestType RequestType) bool {
	validTypes := []RequestType{TypeCompletion, TypeChat, TypeEmbedding, TypeFineTuning, TypeModeration, TypeClassification}
	for _, validType := range validTypes {
		if requestType == validType {
			return true
		}
	}
	return false
}

func isValidModelProvider(provider ModelProvider) bool {
	validProviders := []ModelProvider{ProviderOpenAI, ProviderAnthropic, ProviderCohere, ProviderHuggingFace, ProviderInternal}
	for _, validProvider := range validProviders {
		if provider == validProvider {
			return true
		}
	}
	return false
}

func isValidSecurityLevel(level SecurityLevel) bool {
	validLevels := []SecurityLevel{SecurityLevelLow, SecurityLevelMedium, SecurityLevelHigh, SecurityLevelCritical}
	for _, validLevel := range validLevels {
		if level == validLevel {
			return true
		}
	}
	return false
}

func isValidContentType(contentType ContentType) bool {
	validTypes := []ContentType{ContentTypeText, ContentTypeImage, ContentTypeAudio, ContentTypeVideo, ContentTypeMixed}
	for _, validType := range validTypes {
		if contentType == validType {
			return true
		}
	}
	return false
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func generateTraceID() string {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return uuid.New().String()
	}
	return fmt.Sprintf("%x", bytes)
}

func generateSpanID() string {
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		return uuid.New().String()[:16]
	}
	return fmt.Sprintf("%x", bytes)
}

func ExtractClientInfo(r *http.Request) ClientInformation {
	clientInfo := ClientInformation{
		IPAddress: getClientIP(r),
		UserAgent: r.UserAgent(),
		Referer:   r.Referer(),
		Origin:    r.Header.Get("Origin"),
		Language:  r.Header.Get("Accept-Language"),
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientInfo.IPAddress = strings.TrimSpace(ips[0])
		}
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		clientInfo.IPAddress = realIP
	}

	return clientInfo
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	if remoteAddr := r.Header.Get("X-Appengine-Remote-Addr"); remoteAddr != "" {
		return remoteAddr
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

func SanitizeHeaders(headers map[string]string) map[string]string {
	sanitized := make(map[string]string)
	sensitiveHeaders := map[string]bool{
		"authorization": true,
		"cookie":        true,
		"x-api-key":     true,
		"x-auth-token":  true,
	}

	for key, value := range headers {
		lowerKey := strings.ToLower(key)
		if sensitiveHeaders[lowerKey] {
			sanitized[key] = "[REDACTED]"
		} else {
			sanitized[key] = value
		}
	}

	return sanitized
}

func ValidateModelName(modelName string, provider ModelProvider) error {
	if modelName == "" {
		return fmt.Errorf("model name is required")
	}

	if len(modelName) > 100 {
		return fmt.Errorf("model name exceeds maximum length of 100 characters")
	}

	switch provider {
	case ProviderOpenAI:
		validModels := []string{"gpt-4", "gpt-4-turbo", "gpt-3.5-turbo", "text-embedding-ada-002", "text-davinci-003"}
		for _, valid := range validModels {
			if strings.HasPrefix(modelName, valid) {
				return nil
			}
		}
		return fmt.Errorf("invalid OpenAI model: %s", modelName)
	case ProviderAnthropic:
		validModels := []string{"claude-3", "claude-2", "claude-instant"}
		for _, valid := range validModels {
			if strings.HasPrefix(modelName, valid) {
				return nil
			}
		}
		return fmt.Errorf("invalid Anthropic model: %s", modelName)
	case ProviderInternal:
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(modelName) {
			return fmt.Errorf("internal model name contains invalid characters")
		}
	}

	return nil
}

