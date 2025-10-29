package v1

import (
	"context"
	"time"

	"flamo/backend/pkg/api/models/policy"
)

type PolicyService interface {
	CreatePolicy(ctx context.Context, req *CreatePolicyRequest) (*policy.Policy, error)
	GetPolicy(ctx context.Context, req *GetPolicyRequest) (*policy.Policy, error)
	UpdatePolicy(ctx context.Context, req *UpdatePolicyRequest) (*policy.Policy, error)
	DeletePolicy(ctx context.Context, req *DeletePolicyRequest) error
	ListPolicies(ctx context.Context, req *ListPoliciesRequest) (*ListPoliciesResponse, error)
	ActivatePolicy(ctx context.Context, req *ActivatePolicyRequest) error
	DeactivatePolicy(ctx context.Context, req *DeactivatePolicyRequest) error
	ValidatePolicy(ctx context.Context, req *ValidatePolicyRequest) (*ValidatePolicyResponse, error)
}

type DecisionService interface {
	Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error)
	BatchEvaluate(ctx context.Context, req *BatchEvaluateRequest) (*BatchEvaluateResponse, error)
	Explain(ctx context.Context, req *ExplainRequest) (*ExplainResponse, error)
	Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error)
	Compile(ctx context.Context, req *CompileRequest) (*CompileResponse, error)
	GetDecisionHistory(ctx context.Context, req *GetDecisionHistoryRequest) (*GetDecisionHistoryResponse, error)
	ClearCache(ctx context.Context, req *ClearCacheRequest) error
	GetDecisionMetrics(ctx context.Context, tenantID string) (map[string]interface{}, error)
    WarmupCache(ctx context.Context, tenantID string) error
    GetCircuitBreakerState() string
    ResetCircuitBreaker()
    GetRateLimiterStatus() map[string]interface{}
    GetHealthStatus() map[string]interface{}
    IsRateLimited() bool
}

type BundleService interface {
	CreateBundle(ctx context.Context, req *CreateBundleRequest) (*policy.PolicyBundle, error)
	GetBundle(ctx context.Context, req *GetBundleRequest) (*policy.PolicyBundle, error)
	UpdateBundle(ctx context.Context, req *UpdateBundleRequest) (*policy.PolicyBundle, error)
	DeleteBundle(ctx context.Context, req *DeleteBundleRequest) error
	ListBundles(ctx context.Context, req *ListBundlesRequest) (*ListBundlesResponse, error)
	DeployBundle(ctx context.Context, req *DeployBundleRequest) error
}

type TemplateService interface {
	CreateTemplate(ctx context.Context, req *CreateTemplateRequest) (*policy.PolicyTemplate, error)
	GetTemplate(ctx context.Context, req *GetTemplateRequest) (*policy.PolicyTemplate, error)
	ListTemplates(ctx context.Context, req *ListTemplatesRequest) (*ListTemplatesResponse, error)
	InstantiateTemplate(ctx context.Context, req *InstantiateTemplateRequest) (*policy.Policy, error)
}

type LoaderService interface {
	LoadPolicy(ctx context.Context, req *LoadPolicyRequest) error
	LoadBundle(ctx context.Context, req *LoadBundleRequest) error
	UnloadPolicy(ctx context.Context, req *UnloadPolicyRequest) error
	ReloadPolicy(ctx context.Context, req *ReloadPolicyRequest) error
	SyncTenant(ctx context.Context, req *SyncTenantRequest) error
}

type CreatePolicyRequest struct {
	TenantID    string             `json:"tenant_id" validate:"required,uuid"`
	Name        string             `json:"name" validate:"required,max=255"`
	Description string             `json:"description" validate:"max=1000"`
	Type        policy.PolicyType  `json:"type" validate:"required"`
	Priority    policy.Priority    `json:"priority" validate:"required,min=1,max=15"`
	Effect      policy.Effect      `json:"effect" validate:"required"`
	Rules       []policy.Rule      `json:"rules" validate:"required,min=1"`
	Conditions  []policy.Condition `json:"conditions"`
	Metadata    map[string]string  `json:"metadata"`
	CreatedBy   string             `json:"created_by" validate:"required"`
}

type GetPolicyRequest struct {
	ID       string `json:"id" validate:"required,uuid"`
	TenantID string `json:"tenant_id" validate:"required,uuid"`
}

type UpdatePolicyRequest struct {
	ID          string             `json:"id" validate:"required,uuid"`
	TenantID    string             `json:"tenant_id" validate:"required,uuid"`
	Name        string             `json:"name" validate:"required,max=255"`
	Description string             `json:"description" validate:"max=1000"`
	Priority    policy.Priority    `json:"priority" validate:"required,min=1,max=15"`
	Effect      policy.Effect      `json:"effect" validate:"required"`
	Rules       []policy.Rule      `json:"rules" validate:"required,min=1"`
	Conditions  []policy.Condition `json:"conditions"`
	Metadata    map[string]string  `json:"metadata"`
	UpdatedBy   string             `json:"updated_by" validate:"required"`
}

type DeletePolicyRequest struct {
	ID       string `json:"id" validate:"required,uuid"`
	TenantID string `json:"tenant_id" validate:"required,uuid"`
}

type ListPoliciesRequest struct {
	TenantID  string              `json:"tenant_id" validate:"required,uuid"`
	Type      policy.PolicyType   `json:"type"`
	Status    policy.PolicyStatus `json:"status"`
	Limit     int                 `json:"limit" validate:"min=1,max=1000"`
	Offset    int                 `json:"offset" validate:"min=0"`
	SortBy    string              `json:"sort_by"`
	SortOrder string              `json:"sort_order" validate:"oneof=asc desc"`
}

type ListPoliciesResponse struct {
	Policies []policy.Policy `json:"policies"`
	Total    int             `json:"total"`
	Limit    int             `json:"limit"`
	Offset   int             `json:"offset"`
	HasMore  bool            `json:"has_more"`
}

type ActivatePolicyRequest struct {
	ID       string `json:"id" validate:"required,uuid"`
	TenantID string `json:"tenant_id" validate:"required,uuid"`
}

type DeactivatePolicyRequest struct {
	ID       string `json:"id" validate:"required,uuid"`
	TenantID string `json:"tenant_id" validate:"required,uuid"`
}

type ValidatePolicyRequest struct {
	Policy   *policy.Policy `json:"policy" validate:"required"`
	TenantID string         `json:"tenant_id"`
}

type ValidatePolicyResponse struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
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

type GetDecisionHistoryRequest struct {
	TenantID  string    `json:"tenant_id"`
	SubjectID string    `json:"subject_id"`
	Resource  string    `json:"resource"`
	Action    string    `json:"action"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Limit     int       `json:"limit"`
	Offset    int       `json:"offset"`
}

type GetDecisionHistoryResponse struct {
	Evaluations []policy.PolicyEvaluation `json:"evaluations"`
	Total       int                       `json:"total"`
	HasMore     bool                      `json:"has_more"`
}

type ClearCacheRequest struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	PolicyID string `json:"policy_id,omitempty"`
}

type CreateBundleRequest struct {
	TenantID    string            `json:"tenant_id" validate:"required,uuid"`
	Name        string            `json:"name" validate:"required,max=255"`
	Description string            `json:"description" validate:"max=1000"`
	Policies    []string          `json:"policies" validate:"required,min=1"`
	Metadata    map[string]string `json:"metadata"`
	CreatedBy   string            `json:"created_by" validate:"required"`
}

type GetBundleRequest struct {
	ID       string `json:"id" validate:"required,uuid"`
	TenantID string `json:"tenant_id" validate:"required,uuid"`
}

type UpdateBundleRequest struct {
	ID          string            `json:"id" validate:"required,uuid"`
	TenantID    string            `json:"tenant_id" validate:"required,uuid"`
	Name        string            `json:"name" validate:"required,max=255"`
	Description string            `json:"description" validate:"max=1000"`
	Policies    []string          `json:"policies" validate:"required,min=1"`
	Metadata    map[string]string `json:"metadata"`
	UpdatedBy   string            `json:"updated_by" validate:"required"`
}

type DeleteBundleRequest struct {
	ID       string `json:"id" validate:"required,uuid"`
	TenantID string `json:"tenant_id" validate:"required,uuid"`
}

type ListBundlesRequest struct {
	TenantID string              `json:"tenant_id" validate:"required,uuid"`
	Status   policy.PolicyStatus `json:"status"`
	Limit    int                 `json:"limit" validate:"min=1,max=1000"`
	Offset   int                 `json:"offset" validate:"min=0"`
}

type ListBundlesResponse struct {
	Bundles []policy.PolicyBundle `json:"bundles"`
	Total   int                   `json:"total"`
	HasMore bool                  `json:"has_more"`
}

type DeployBundleRequest struct {
	ID       string `json:"id" validate:"required,uuid"`
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	Target   string `json:"target" validate:"required,oneof=opa database"`
}

type CreateTemplateRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Industry    string            `json:"industry"`
	Compliance  []string          `json:"compliance"`
	Template    string            `json:"template"`
	Variables   map[string]string `json:"variables"`
	IsPublic    bool              `json:"is_public"`
	CreatedBy   string            `json:"created_by"`
}

type GetTemplateRequest struct {
	ID string `json:"id"`
}

type ListTemplatesRequest struct {
	Category   string `json:"category"`
	Industry   string `json:"industry"`
	Compliance string `json:"compliance"`
	IsPublic   bool   `json:"is_public"`
	Limit      int    `json:"limit"`
	Offset     int    `json:"offset"`
}

type ListTemplatesResponse struct {
	Templates []policy.PolicyTemplate `json:"templates"`
	Total     int                     `json:"total"`
	HasMore   bool                    `json:"has_more"`
}

type InstantiateTemplateRequest struct {
	TemplateID string            `json:"template_id"`
	TenantID   string            `json:"tenant_id"`
	Name       string            `json:"name"`
	Variables  map[string]string `json:"variables"`
	CreatedBy  string            `json:"created_by"`
}

type LoadPolicyRequest struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	PolicyID string `json:"policy_id" validate:"required,uuid"`
	Priority int    `json:"priority" validate:"min=1,max=15"`
}

type LoadBundleRequest struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	BundleID string `json:"bundle_id" validate:"required,uuid"`
	Priority int    `json:"priority" validate:"min=1,max=15"`
}

type UnloadPolicyRequest struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	PolicyID string `json:"policy_id" validate:"required,uuid"`
}

type ReloadPolicyRequest struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	PolicyID string `json:"policy_id" validate:"required,uuid"`
}

type SyncTenantRequest struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
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
	PolicyID    string          `json:"policy_id"`
	PolicyName  string          `json:"policy_name"`
	Version     string          `json:"version"`
	Priority    policy.Priority `json:"priority"`
	Effect      policy.Effect   `json:"effect"`
	MatchReason string          `json:"match_reason"`
	Rules       []policy.Rule   `json:"rules"`
}

type AppliedRule struct {
	RuleID     string             `json:"rule_id"`
	PolicyID   string             `json:"policy_id"`
	Resource   string             `json:"resource"`
	Action     string             `json:"action"`
	Effect     policy.Effect      `json:"effect"`
	Conditions []policy.Condition `json:"conditions"`
	Metadata   map[string]string  `json:"metadata"`
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
