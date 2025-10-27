package service

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
	GetDecisionHistory(ctx context.Context, req *GetDecisionHistoryRequest) (*GetDecisionHistoryResponse, error)
	ClearCache(ctx context.Context, req *ClearCacheRequest) error
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

type CreatePolicyRequest struct {
	TenantID    string                `json:"tenant_id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Type        policy.PolicyType     `json:"type"`
	Priority    policy.Priority       `json:"priority"`
	Effect      policy.Effect         `json:"effect"`
	Rules       []policy.Rule         `json:"rules"`
	Conditions  []policy.Condition    `json:"conditions"`
	Metadata    map[string]string     `json:"metadata"`
	CreatedBy   string                `json:"created_by"`
}

type GetPolicyRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}

type UpdatePolicyRequest struct {
	ID          string                `json:"id"`
	TenantID    string                `json:"tenant_id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Priority    policy.Priority       `json:"priority"`
	Effect      policy.Effect         `json:"effect"`
	Rules       []policy.Rule         `json:"rules"`
	Conditions  []policy.Condition    `json:"conditions"`
	Metadata    map[string]string     `json:"metadata"`
	UpdatedBy   string                `json:"updated_by"`
}

type DeletePolicyRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}

type ListPoliciesRequest struct {
	TenantID   string            `json:"tenant_id"`
	Type       policy.PolicyType `json:"type"`
	Status     policy.PolicyStatus `json:"status"`
	Limit      int               `json:"limit"`
	Offset     int               `json:"offset"`
	SortBy     string            `json:"sort_by"`
	SortOrder  string            `json:"sort_order"`
}

type ListPoliciesResponse struct {
	Policies   []policy.Policy `json:"policies"`
	Total      int             `json:"total"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
	HasMore    bool            `json:"has_more"`
}

type ActivatePolicyRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}

type DeactivatePolicyRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}

type ValidatePolicyRequest struct {
	Policy   policy.Policy `json:"policy"`
	TenantID string        `json:"tenant_id"`
}

type ValidatePolicyResponse struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

type EvaluateRequest struct {
	TenantID  string            `json:"tenant_id"`
	SubjectID string            `json:"subject_id"`
	Resource  string            `json:"resource"`
	Action    string            `json:"action"`
	Context   map[string]string `json:"context"`
	Input     map[string]string `json:"input"`
	RequestID string            `json:"request_id"`
}

type EvaluateResponse struct {
	Decision policy.PolicyDecision `json:"decision"`
	Cached   bool                  `json:"cached"`
	Duration time.Duration         `json:"duration"`
}

type BatchEvaluateRequest struct {
	Requests []EvaluateRequest `json:"requests"`
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
	TenantID string `json:"tenant_id"`
	PolicyID string `json:"policy_id"`
}

type CreateBundleRequest struct {
	TenantID    string            `json:"tenant_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Policies    []string          `json:"policies"`
	Metadata    map[string]string `json:"metadata"`
	CreatedBy   string            `json:"created_by"`
}

type GetBundleRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}

type UpdateBundleRequest struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Policies    []string          `json:"policies"`
	Metadata    map[string]string `json:"metadata"`
	UpdatedBy   string            `json:"updated_by"`
}

type DeleteBundleRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}

type ListBundlesRequest struct {
	TenantID  string `json:"tenant_id"`
	Status    policy.PolicyStatus `json:"status"`
	Limit     int    `json:"limit"`
	Offset    int    `json:"offset"`
}

type ListBundlesResponse struct {
	Bundles []policy.PolicyBundle `json:"bundles"`
	Total   int                   `json:"total"`
	HasMore bool                  `json:"has_more"`
}

type DeployBundleRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Target   string `json:"target"`
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
