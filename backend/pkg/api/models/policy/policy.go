package policy

import (
	"time"
)

type PolicyType string

const (
	PolicyTypeAccess     PolicyType = "access"
	PolicyTypeModel      PolicyType = "model"
	PolicyTypeRate       PolicyType = "rate"
	PolicyTypeCompliance PolicyType = "compliance"
	PolicyTypeContent    PolicyType = "content"
)

type PolicyStatus string

const (
	PolicyStatusActive   PolicyStatus = "active"
	PolicyStatusInactive PolicyStatus = "inactive"
	PolicyStatusDraft    PolicyStatus = "draft"
	PolicyStatusArchived PolicyStatus = "archived"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type Priority int

const (
	PriorityLow      Priority = 1
	PriorityMedium   Priority = 5
	PriorityHigh     Priority = 10
	PriorityCritical Priority = 15
)

type Policy struct {
	ID          string            `json:"id" db:"id"`
	TenantID    string            `json:"tenant_id" db:"tenant_id"`
	Name        string            `json:"name" db:"name"`
	Description string            `json:"description" db:"description"`
	Type        PolicyType        `json:"type" db:"type"`
	Status      PolicyStatus      `json:"status" db:"status"`
	Priority    Priority          `json:"priority" db:"priority"`
	Effect      Effect            `json:"effect" db:"effect"`
	Version     string            `json:"version" db:"version"`
	Rules       []Rule            `json:"rules" db:"rules"`
	Conditions  []Condition       `json:"conditions" db:"conditions"`
	Metadata    map[string]string `json:"metadata" db:"metadata"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	CreatedBy   string            `json:"created_by" db:"created_by"`
	UpdatedBy   string            `json:"updated_by" db:"updated_by"`
}

type Rule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Resource    string            `json:"resource"`
	Action      string            `json:"action"`
	Effect      Effect            `json:"effect"`
	Conditions  []Condition       `json:"conditions"`
	Metadata    map[string]string `json:"metadata"`
}

type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Type     string      `json:"type"`
}

type Permission struct {
	ID          string            `json:"id" db:"id"`
	TenantID    string            `json:"tenant_id" db:"tenant_id"`
	SubjectID   string            `json:"subject_id" db:"subject_id"`
	SubjectType string            `json:"subject_type" db:"subject_type"`
	Resource    string            `json:"resource" db:"resource"`
	Action      string            `json:"action" db:"action"`
	Effect      Effect            `json:"effect" db:"effect"`
	Constraints map[string]string `json:"constraints" db:"constraints"`
	ExpiresAt   *time.Time        `json:"expires_at" db:"expires_at"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	CreatedBy   string            `json:"created_by" db:"created_by"`
}

type PolicyBundle struct {
	ID          string            `json:"id" db:"id"`
	TenantID    string            `json:"tenant_id" db:"tenant_id"`
	Name        string            `json:"name" db:"name"`
	Description string            `json:"description" db:"description"`
	Version     string            `json:"version" db:"version"`
	Policies    []string          `json:"policies" db:"policies"`
	Status      PolicyStatus      `json:"status" db:"status"`
	Metadata    map[string]string `json:"metadata" db:"metadata"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	CreatedBy   string            `json:"created_by" db:"created_by"`
	UpdatedBy   string            `json:"updated_by" db:"updated_by"`
}

type PolicyDecision struct {
	Allow      bool              `json:"allow"`
	Deny       bool              `json:"deny"`
	Reason     string            `json:"reason"`
	PolicyID   string            `json:"policy_id"`
	RuleID     string            `json:"rule_id"`
	Metadata   map[string]string `json:"metadata"`
	Timestamp  time.Time         `json:"timestamp"`
	RequestID  string            `json:"request_id"`
	TenantID   string            `json:"tenant_id"`
	SubjectID  string            `json:"subject_id"`
	Resource   string            `json:"resource"`
	Action     string            `json:"action"`
	Context    map[string]string `json:"context"`
}

type PolicyEvaluation struct {
	RequestID   string            `json:"request_id"`
	TenantID    string            `json:"tenant_id"`
	SubjectID   string            `json:"subject_id"`
	Resource    string            `json:"resource"`
	Action      string            `json:"action"`
	Context     map[string]string `json:"context"`
	Input       map[string]string `json:"input"`
	Decision    PolicyDecision    `json:"decision"`
	Duration    time.Duration     `json:"duration"`
	Timestamp   time.Time         `json:"timestamp"`
	CacheHit    bool              `json:"cache_hit"`
	PolicyCount int               `json:"policy_count"`
}

type TenantPolicy struct {
	TenantID         string            `json:"tenant_id" db:"tenant_id"`
	PolicyID         string            `json:"policy_id" db:"policy_id"`
	Overrides        map[string]string `json:"overrides" db:"overrides"`
	CustomRules      []Rule            `json:"custom_rules" db:"custom_rules"`
	IsActive         bool              `json:"is_active" db:"is_active"`
	ActivatedAt      *time.Time        `json:"activated_at" db:"activated_at"`
	DeactivatedAt    *time.Time        `json:"deactivated_at" db:"deactivated_at"`
	CreatedAt        time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at" db:"updated_at"`
	CreatedBy        string            `json:"created_by" db:"created_by"`
	UpdatedBy        string            `json:"updated_by" db:"updated_by"`
}

type PolicyAudit struct {
	ID          string            `json:"id" db:"id"`
	PolicyID    string            `json:"policy_id" db:"policy_id"`
	TenantID    string            `json:"tenant_id" db:"tenant_id"`
	Action      string            `json:"action" db:"action"`
	Changes     map[string]string `json:"changes" db:"changes"`
	OldValue    string            `json:"old_value" db:"old_value"`
	NewValue    string            `json:"new_value" db:"new_value"`
	Reason      string            `json:"reason" db:"reason"`
	UserID      string            `json:"user_id" db:"user_id"`
	UserAgent   string            `json:"user_agent" db:"user_agent"`
	IPAddress   string            `json:"ip_address" db:"ip_address"`
	Timestamp   time.Time         `json:"timestamp" db:"timestamp"`
	RequestID   string            `json:"request_id" db:"request_id"`
	SessionID   string            `json:"session_id" db:"session_id"`
}

type PolicyTemplate struct {
	ID          string            `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	Description string            `json:"description" db:"description"`
	Category    string            `json:"category" db:"category"`
	Industry    string            `json:"industry" db:"industry"`
	Compliance  []string          `json:"compliance" db:"compliance"`
	Template    string            `json:"template" db:"template"`
	Variables   map[string]string `json:"variables" db:"variables"`
	Version     string            `json:"version" db:"version"`
	IsPublic    bool              `json:"is_public" db:"is_public"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	CreatedBy   string            `json:"created_by" db:"created_by"`
}
