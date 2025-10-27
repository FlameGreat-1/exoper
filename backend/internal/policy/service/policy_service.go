package service

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
	"flamo/backend/internal/policy/storage"
	"flamo/backend/internal/policy/opa"
)

type PolicyService struct {
	policyStore   *storage.PolicyStore
	bundleManager *storage.BundleManager
	opaEngine     *opa.Engine
	opaClient     *opa.Client
	policyLoader  *opa.PolicyLoader
	cache         *opa.Cache
	db            *database.Database
	config        *config.Config
	logger        *zap.Logger
	rateLimiter   *utils.RateLimiter
	metrics       *PolicyServiceMetrics
	mu            sync.RWMutex
}

type PolicyServiceMetrics struct {
	TotalOperations     int64         `json:"total_operations"`
	SuccessfulOps       int64         `json:"successful_operations"`
	FailedOps           int64         `json:"failed_operations"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	PoliciesCreated     int64         `json:"policies_created"`
	PoliciesUpdated     int64         `json:"policies_updated"`
	PoliciesDeleted     int64         `json:"policies_deleted"`
	BundlesCreated      int64         `json:"bundles_created"`
	BundlesDeployed     int64         `json:"bundles_deployed"`
	ValidationErrors    int64         `json:"validation_errors"`
	LastOperationTime   time.Time     `json:"last_operation_time"`
	mu                  sync.RWMutex
}

type CreatePolicyRequest struct {
	TenantID    string                 `json:"tenant_id" validate:"required,uuid"`
	Name        string                 `json:"name" validate:"required,max=255"`
	Description string                 `json:"description" validate:"max=1000"`
	Type        policy.PolicyType      `json:"type" validate:"required"`
	Priority    policy.Priority        `json:"priority" validate:"required,min=1,max=15"`
	Effect      policy.Effect          `json:"effect" validate:"required"`
	Rules       []policy.Rule          `json:"rules" validate:"required,min=1"`
	Conditions  []policy.Condition     `json:"conditions"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedBy   string                 `json:"created_by" validate:"required"`
}

type UpdatePolicyRequest struct {
	ID          string                 `json:"id" validate:"required,uuid"`
	TenantID    string                 `json:"tenant_id" validate:"required,uuid"`
	Name        string                 `json:"name" validate:"required,max=255"`
	Description string                 `json:"description" validate:"max=1000"`
	Priority    policy.Priority        `json:"priority" validate:"required,min=1,max=15"`
	Effect      policy.Effect          `json:"effect" validate:"required"`
	Rules       []policy.Rule          `json:"rules" validate:"required,min=1"`
	Conditions  []policy.Condition     `json:"conditions"`
	Metadata    map[string]interface{} `json:"metadata"`
	UpdatedBy   string                 `json:"updated_by" validate:"required"`
}

type GetPolicyRequest struct {
	ID       string `json:"id" validate:"required,uuid"`
	TenantID string `json:"tenant_id" validate:"required,uuid"`
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
	Policy *policy.Policy `json:"policy" validate:"required"`
}

type ValidatePolicyResponse struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type CreateBundleRequest struct {
	TenantID    string                 `json:"tenant_id" validate:"required,uuid"`
	Name        string                 `json:"name" validate:"required,max=255"`
	Description string                 `json:"description" validate:"max=1000"`
	Policies    []string               `json:"policies" validate:"required,min=1"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedBy   string                 `json:"created_by" validate:"required"`
}

type UpdateBundleRequest struct {
	ID          string                 `json:"id" validate:"required,uuid"`
	TenantID    string                 `json:"tenant_id" validate:"required,uuid"`
	Name        string                 `json:"name" validate:"required,max=255"`
	Description string                 `json:"description" validate:"max=1000"`
	Policies    []string               `json:"policies" validate:"required,min=1"`
	Metadata    map[string]interface{} `json:"metadata"`
	UpdatedBy   string                 `json:"updated_by" validate:"required"`
}

type GetBundleRequest struct {
	ID       string `json:"id" validate:"required,uuid"`
	TenantID string `json:"tenant_id" validate:"required,uuid"`
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

type ClearCacheRequest struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	PolicyID string `json:"policy_id,omitempty"`
}

func NewPolicyService(
	policyStore *storage.PolicyStore,
	bundleManager *storage.BundleManager,
	opaEngine *opa.Engine,
	opaClient *opa.Client,
	policyLoader *opa.PolicyLoader,
	cache *opa.Cache,
	db *database.Database,
	cfg *config.Config,
	logger *zap.Logger,
) *PolicyService {
	rateLimiter := utils.NewRateLimiter(1000.0, 10000)

	return &PolicyService{
		policyStore:   policyStore,
		bundleManager: bundleManager,
		opaEngine:     opaEngine,
		opaClient:     opaClient,
		policyLoader:  policyLoader,
		cache:         cache,
		db:            db,
		config:        cfg,
		logger:        logger,
		rateLimiter:   rateLimiter,
		metrics:       &PolicyServiceMetrics{},
	}
}

func (ps *PolicyService) CreatePolicy(ctx context.Context, req *CreatePolicyRequest) (*policy.Policy, error) {
	start := time.Now()
	defer ps.recordMetrics("create_policy", time.Since(start), nil)

	if !ps.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "create_policy")
	}

	if err := ps.validateCreatePolicyRequest(req); err != nil {
		ps.recordValidationError()
		return nil, err
	}

	pol, err := ps.policyStore.CreatePolicy(ctx, req)
	if err != nil {
		ps.recordFailedOperation()
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to create policy").
			WithTenantID(req.TenantID).
			WithContext("policy_name", req.Name)
	}

	ps.recordSuccessfulOperation()
	ps.metrics.mu.Lock()
	ps.metrics.PoliciesCreated++
	ps.metrics.mu.Unlock()

	ps.logger.Info("Policy created successfully",
		zap.String("policy_id", pol.ID),
		zap.String("tenant_id", req.TenantID),
		zap.String("policy_name", req.Name),
		zap.String("created_by", req.CreatedBy))

	return pol, nil
}

func (ps *PolicyService) GetPolicy(ctx context.Context, req *GetPolicyRequest) (*policy.Policy, error) {
	start := time.Now()
	defer ps.recordMetrics("get_policy", time.Since(start), nil)

	if !ps.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "get_policy")
	}

	if err := ps.validateGetPolicyRequest(req); err != nil {
		ps.recordValidationError()
		return nil, err
	}

	pol, err := ps.policyStore.GetPolicy(ctx, req)
	if err != nil {
		ps.recordFailedOperation()
		return nil, err
	}

	ps.recordSuccessfulOperation()
	return pol, nil
}

func (ps *PolicyService) UpdatePolicy(ctx context.Context, req *UpdatePolicyRequest) (*policy.Policy, error) {
	start := time.Now()
	defer ps.recordMetrics("update_policy", time.Since(start), nil)

	if !ps.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "update_policy")
	}

	if err := ps.validateUpdatePolicyRequest(req); err != nil {
		ps.recordValidationError()
		return nil, err
	}

	pol, err := ps.policyStore.UpdatePolicy(ctx, req)
	if err != nil {
		ps.recordFailedOperation()
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to update policy").
			WithTenantID(req.TenantID).
			WithContext("policy_id", req.ID)
	}

	if pol.Status == policy.PolicyStatusActive {
		if err := ps.policyLoader.ReloadPolicy(ctx, &ReloadPolicyRequest{
			TenantID: req.TenantID,
			PolicyID: req.ID,
		}); err != nil {
			ps.logger.Warn("Failed to reload policy in OPA after update",
				zap.String("policy_id", req.ID),
				zap.String("tenant_id", req.TenantID),
				zap.Error(err))
		}
	}

	ps.recordSuccessfulOperation()
	ps.metrics.mu.Lock()
	ps.metrics.PoliciesUpdated++
	ps.metrics.mu.Unlock()

	ps.logger.Info("Policy updated successfully",
		zap.String("policy_id", req.ID),
		zap.String("tenant_id", req.TenantID),
		zap.String("updated_by", req.UpdatedBy))

	return pol, nil
}

func (ps *PolicyService) DeletePolicy(ctx context.Context, req *DeletePolicyRequest) error {
	start := time.Now()
	defer ps.recordMetrics("delete_policy", time.Since(start), nil)

	if !ps.rateLimiter.Allow() {
		return errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "delete_policy")
	}

	if err := ps.validateDeletePolicyRequest(req); err != nil {
		ps.recordValidationError()
		return err
	}

	existing, err := ps.policyStore.GetPolicy(ctx, &GetPolicyRequest{
		ID:       req.ID,
		TenantID: req.TenantID,
	})
	if err != nil {
		ps.recordFailedOperation()
		return err
	}

	if existing.Status == policy.PolicyStatusActive {
		if err := ps.policyLoader.UnloadPolicy(ctx, &UnloadPolicyRequest{
			TenantID: req.TenantID,
			PolicyID: req.ID,
		}); err != nil {
			ps.logger.Warn("Failed to unload policy from OPA before deletion",
				zap.String("policy_id", req.ID),
				zap.String("tenant_id", req.TenantID),
				zap.Error(err))
		}
	}

	if err := ps.policyStore.DeletePolicy(ctx, req); err != nil {
		ps.recordFailedOperation()
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to delete policy").
			WithTenantID(req.TenantID).
			WithContext("policy_id", req.ID)
	}

	ps.recordSuccessfulOperation()
	ps.metrics.mu.Lock()
	ps.metrics.PoliciesDeleted++
	ps.metrics.mu.Unlock()

	ps.logger.Info("Policy deleted successfully",
		zap.String("policy_id", req.ID),
		zap.String("tenant_id", req.TenantID))

	return nil
}

func (ps *PolicyService) ListPolicies(ctx context.Context, req *ListPoliciesRequest) (*ListPoliciesResponse, error) {
	start := time.Now()
	defer ps.recordMetrics("list_policies", time.Since(start), nil)

	if !ps.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "list_policies")
	}

	if err := ps.validateListPoliciesRequest(req); err != nil {
		ps.recordValidationError()
		return nil, err
	}

	response, err := ps.policyStore.ListPolicies(ctx, req)
	if err != nil {
		ps.recordFailedOperation()
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to list policies").
			WithTenantID(req.TenantID)
	}

	ps.recordSuccessfulOperation()
	return response, nil
}

func (ps *PolicyService) ActivatePolicy(ctx context.Context, req *ActivatePolicyRequest) error {
	start := time.Now()
	defer ps.recordMetrics("activate_policy", time.Since(start), nil)

	if !ps.rateLimiter.Allow() {
		return errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "activate_policy")
	}

	if err := ps.validateActivatePolicyRequest(req); err != nil {
		ps.recordValidationError()
		return err
	}

	if err := ps.policyStore.ActivatePolicy(ctx, req); err != nil {
		ps.recordFailedOperation()
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to activate policy").
			WithTenantID(req.TenantID).
			WithContext("policy_id", req.ID)
	}

	if err := ps.policyLoader.LoadPolicy(ctx, &LoadPolicyRequest{
		TenantID: req.TenantID,
		PolicyID: req.ID,
		Priority: 10,
	}); err != nil {
		ps.logger.Error("Failed to load activated policy to OPA",
			zap.String("policy_id", req.ID),
			zap.String("tenant_id", req.TenantID),
			zap.Error(err))
	}

	ps.recordSuccessfulOperation()

	ps.logger.Info("Policy activated successfully",
		zap.String("policy_id", req.ID),
		zap.String("tenant_id", req.TenantID))

	return nil
}

func (ps *PolicyService) DeactivatePolicy(ctx context.Context, req *DeactivatePolicyRequest) error {
	start := time.Now()
	defer ps.recordMetrics("deactivate_policy", time.Since(start), nil)

	if !ps.rateLimiter.Allow() {
		return errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "deactivate_policy")
	}

	if err := ps.validateDeactivatePolicyRequest(req); err != nil {
		ps.recordValidationError()
		return err
	}

	if err := ps.policyLoader.UnloadPolicy(ctx, &UnloadPolicyRequest{
		TenantID: req.TenantID,
		PolicyID: req.ID,
	}); err != nil {
		ps.logger.Warn("Failed to unload policy from OPA during deactivation",
			zap.String("policy_id", req.ID),
			zap.String("tenant_id", req.TenantID),
			zap.Error(err))
	}

	if err := ps.policyStore.DeactivatePolicy(ctx, req); err != nil {
		ps.recordFailedOperation()
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to deactivate policy").
			WithTenantID(req.TenantID).
			WithContext("policy_id", req.ID)
	}

	ps.recordSuccessfulOperation()

	ps.logger.Info("Policy deactivated successfully",
		zap.String("policy_id", req.ID),
		zap.String("tenant_id", req.TenantID))

	return nil
}

func (ps *PolicyService) ValidatePolicy(ctx context.Context, req *ValidatePolicyRequest) (*ValidatePolicyResponse, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Policy validation completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithContext("operation", "validate_policy")
	}

	if req.Policy == nil {
		return nil, errors.NewValidationError("policy", "Policy is required", req.Policy)
	}

	response, err := ps.policyStore.ValidatePolicy(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to validate policy")
	}

	if ps.opaEngine != nil {
		if err := ps.opaEngine.ValidatePolicy(ctx, req.Policy); err != nil {
			response.Valid = false
			response.Errors = append(response.Errors, fmt.Sprintf("OPA validation failed: %v", err))
		}
	}

	return response, nil
}

func (ps *PolicyService) CreateBundle(ctx context.Context, req *CreateBundleRequest) (*policy.PolicyBundle, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Bundle creation completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "create_bundle")
	}

	if err := ps.validateCreateBundleRequest(req); err != nil {
		return nil, err
	}

	bundle, err := ps.bundleManager.CreateBundle(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to create bundle").
			WithTenantID(req.TenantID).
			WithContext("bundle_name", req.Name)
	}

	ps.logger.Info("Bundle created successfully",
		zap.String("bundle_id", bundle.ID),
		zap.String("tenant_id", req.TenantID),
		zap.String("bundle_name", req.Name),
		zap.Int("policy_count", len(req.Policies)),
		zap.String("created_by", req.CreatedBy))

	return bundle, nil
}

func (ps *PolicyService) GetBundle(ctx context.Context, req *GetBundleRequest) (*policy.PolicyBundle, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Bundle retrieval completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "get_bundle")
	}

	if err := ps.validateGetBundleRequest(req); err != nil {
		return nil, err
	}

	bundle, err := ps.bundleManager.GetBundle(ctx, req)
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

func (ps *PolicyService) UpdateBundle(ctx context.Context, req *UpdateBundleRequest) (*policy.PolicyBundle, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Bundle update completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "update_bundle")
	}

	if err := ps.validateUpdateBundleRequest(req); err != nil {
		return nil, err
	}

	bundle, err := ps.bundleManager.UpdateBundle(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to update bundle").
			WithTenantID(req.TenantID).
			WithContext("bundle_id", req.ID)
	}

	ps.logger.Info("Bundle updated successfully",
		zap.String("bundle_id", req.ID),
		zap.String("tenant_id", req.TenantID),
		zap.String("updated_by", req.UpdatedBy))

	return bundle, nil
}

func (ps *PolicyService) DeleteBundle(ctx context.Context, req *DeleteBundleRequest) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Bundle deletion completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "delete_bundle")
	}

	if err := ps.validateDeleteBundleRequest(req); err != nil {
		return err
	}

	if err := ps.bundleManager.DeleteBundle(ctx, req); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to delete bundle").
			WithTenantID(req.TenantID).
			WithContext("bundle_id", req.ID)
	}

	ps.logger.Info("Bundle deleted successfully",
		zap.String("bundle_id", req.ID),
		zap.String("tenant_id", req.TenantID))

	return nil
}

func (ps *PolicyService) ListBundles(ctx context.Context, req *ListBundlesRequest) (*ListBundlesResponse, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Bundle listing completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return nil, errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "list_bundles")
	}

	if err := ps.validateListBundlesRequest(req); err != nil {
		return nil, err
	}

	response, err := ps.bundleManager.ListBundles(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to list bundles").
			WithTenantID(req.TenantID)
	}

	return response, nil
}

func (ps *PolicyService) DeployBundle(ctx context.Context, req *DeployBundleRequest) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Bundle deployment completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "deploy_bundle")
	}

	if err := ps.validateDeployBundleRequest(req); err != nil {
		return err
	}

	if err := ps.bundleManager.DeployBundle(ctx, req); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to deploy bundle").
			WithTenantID(req.TenantID).
			WithContext("bundle_id", req.ID).
			WithContext("target", req.Target)
	}

	ps.logger.Info("Bundle deployment initiated",
		zap.String("bundle_id", req.ID),
		zap.String("tenant_id", req.TenantID),
		zap.String("target", req.Target))

	return nil
}

func (ps *PolicyService) LoadPolicy(ctx context.Context, req *LoadPolicyRequest) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Policy loading completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "load_policy")
	}

	if err := ps.validateLoadPolicyRequest(req); err != nil {
		return err
	}

	if err := ps.policyLoader.LoadPolicy(ctx, req); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to load policy").
			WithTenantID(req.TenantID).
			WithContext("policy_id", req.PolicyID)
	}

	ps.logger.Info("Policy loaded successfully",
		zap.String("policy_id", req.PolicyID),
		zap.String("tenant_id", req.TenantID))

	return nil
}

func (ps *PolicyService) LoadBundle(ctx context.Context, req *LoadBundleRequest) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Bundle loading completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "load_bundle")
	}

	if err := ps.validateLoadBundleRequest(req); err != nil {
		return err
	}

	if err := ps.policyLoader.LoadBundle(ctx, req); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to load bundle").
			WithTenantID(req.TenantID).
			WithContext("bundle_id", req.BundleID)
	}

	ps.logger.Info("Bundle loaded successfully",
		zap.String("bundle_id", req.BundleID),
		zap.String("tenant_id", req.TenantID))

	return nil
}

func (ps *PolicyService) SyncTenant(ctx context.Context, req *SyncTenantRequest) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Tenant sync completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "sync_tenant")
	}

	if err := ps.validateSyncTenantRequest(req); err != nil {
		return err
	}

	if err := ps.policyLoader.SyncTenant(ctx, req); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to sync tenant").
			WithTenantID(req.TenantID)
	}

	ps.logger.Info("Tenant synced successfully",
		zap.String("tenant_id", req.TenantID))

	return nil
}

func (ps *PolicyService) ClearCache(ctx context.Context, req *ClearCacheRequest) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ps.logger.Debug("Cache clearing completed", zap.Duration("duration", duration))
	}()

	if !ps.rateLimiter.Allow() {
		return errors.NewRateLimitError(time.Minute).
			WithTenantID(req.TenantID).
			WithContext("operation", "clear_cache")
	}

	if err := ps.validateClearCacheRequest(req); err != nil {
		return err
	}

	if err := ps.opaEngine.ClearCache(ctx, req); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to clear cache").
			WithTenantID(req.TenantID)
	}

	ps.logger.Info("Cache cleared successfully",
		zap.String("tenant_id", req.TenantID),
		zap.String("policy_id", req.PolicyID))

	return nil
}

func (ps *PolicyService) validateCreatePolicyRequest(req *CreatePolicyRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.Name == "" {
		return errors.NewValidationError("name", "Policy name is required", req.Name)
	}

	if len(req.Name) > 255 {
		return errors.NewValidationError("name", "Policy name too long", req.Name)
	}

	if req.CreatedBy == "" {
		return errors.NewValidationError("created_by", "Created by is required", req.CreatedBy)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	if len(req.Rules) == 0 {
		return errors.NewValidationError("rules", "Policy must have at least one rule", len(req.Rules))
	}

	if req.Priority < policy.PriorityLow || req.Priority > policy.PriorityCritical {
		return errors.NewValidationError("priority", "Invalid priority value", req.Priority)
	}

	for i, rule := range req.Rules {
		if rule.Resource == "" {
			return errors.NewValidationError("rules", fmt.Sprintf("Rule %d: resource is required", i+1), rule.Resource)
		}
		if rule.Action == "" {
			return errors.NewValidationError("rules", fmt.Sprintf("Rule %d: action is required", i+1), rule.Action)
		}
	}

	return nil
}

func (ps *PolicyService) validateUpdatePolicyRequest(req *UpdatePolicyRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("id", "Policy ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.Name == "" {
		return errors.NewValidationError("name", "Policy name is required", req.Name)
	}

	if len(req.Name) > 255 {
		return errors.NewValidationError("name", "Policy name too long", req.Name)
	}

	if req.UpdatedBy == "" {
		return errors.NewValidationError("updated_by", "Updated by is required", req.UpdatedBy)
	}

	if !utils.IsValidUUID(req.ID) {
		return errors.NewValidationError("id", "Invalid policy ID format", req.ID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	if len(req.Rules) == 0 {
		return errors.NewValidationError("rules", "Policy must have at least one rule", len(req.Rules))
	}

	if req.Priority < policy.PriorityLow || req.Priority > policy.PriorityCritical {
		return errors.NewValidationError("priority", "Invalid priority value", req.Priority)
	}

	return nil
}

func (ps *PolicyService) validateGetPolicyRequest(req *GetPolicyRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("id", "Policy ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if !utils.IsValidUUID(req.ID) {
		return errors.NewValidationError("id", "Invalid policy ID format", req.ID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ps *PolicyService) validateDeletePolicyRequest(req *DeletePolicyRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("id", "Policy ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if !utils.IsValidUUID(req.ID) {
		return errors.NewValidationError("id", "Invalid policy ID format", req.ID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ps *PolicyService) validateListPoliciesRequest(req *ListPoliciesRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	if req.Limit <= 0 {
		req.Limit = 50
	}

	if req.Limit > 1000 {
		req.Limit = 1000
	}

	if req.Offset < 0 {
		req.Offset = 0
	}

	if req.SortOrder != "" && req.SortOrder != "asc" && req.SortOrder != "desc" {
		return errors.NewValidationError("sort_order", "Sort order must be 'asc' or 'desc'", req.SortOrder)
	}

	return nil
}

func (ps *PolicyService) validateActivatePolicyRequest(req *ActivatePolicyRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("id", "Policy ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if !utils.IsValidUUID(req.ID) {
		return errors.NewValidationError("id", "Invalid policy ID format", req.ID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ps *PolicyService) validateDeactivatePolicyRequest(req *DeactivatePolicyRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("id", "Policy ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if !utils.IsValidUUID(req.ID) {
		return errors.NewValidationError("id", "Invalid policy ID format", req.ID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ps *PolicyService) validateCreateBundleRequest(req *CreateBundleRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.Name == "" {
		return errors.NewValidationError("name", "Bundle name is required", req.Name)
	}

	if len(req.Name) > 255 {
		return errors.NewValidationError("name", "Bundle name too long", req.Name)
	}

	if len(req.Policies) == 0 {
		return errors.NewValidationError("policies", "Bundle must contain at least one policy", len(req.Policies))
	}

	if req.CreatedBy == "" {
		return errors.NewValidationError("created_by", "Created by is required", req.CreatedBy)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	for i, policyID := range req.Policies {
		if !utils.IsValidUUID(policyID) {
			return errors.NewValidationError("policies", fmt.Sprintf("Policy %d: invalid UUID format", i+1), policyID)
		}
	}

	return nil
}

func (ps *PolicyService) validateUpdateBundleRequest(req *UpdateBundleRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("id", "Bundle ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.Name == "" {
		return errors.NewValidationError("name", "Bundle name is required", req.Name)
	}

	if len(req.Name) > 255 {
		return errors.NewValidationError("name", "Bundle name too long", req.Name)
	}

	if len(req.Policies) == 0 {
		return errors.NewValidationError("policies", "Bundle must contain at least one policy", len(req.Policies))
	}

	if req.UpdatedBy == "" {
		return errors.NewValidationError("updated_by", "Updated by is required", req.UpdatedBy)
	}

	if !utils.IsValidUUID(req.ID) {
		return errors.NewValidationError("id", "Invalid bundle ID format", req.ID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ps *PolicyService) validateGetBundleRequest(req *GetBundleRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("id", "Bundle ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if !utils.IsValidUUID(req.ID) {
		return errors.NewValidationError("id", "Invalid bundle ID format", req.ID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ps *PolicyService) validateDeleteBundleRequest(req *DeleteBundleRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("id", "Bundle ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if !utils.IsValidUUID(req.ID) {
		return errors.NewValidationError("id", "Invalid bundle ID format", req.ID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ps *PolicyService) validateListBundlesRequest(req *ListBundlesRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	if req.Limit <= 0 {
		req.Limit = 50
	}

	if req.Limit > 1000 {
		req.Limit = 1000
	}

	if req.Offset < 0 {
		req.Offset = 0
	}

	return nil
}

func (ps *PolicyService) validateDeployBundleRequest(req *DeployBundleRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("id", "Bundle ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.Target == "" {
		return errors.NewValidationError("target", "Deployment target is required", req.Target)
	}

	validTargets := []string{"opa", "database"}
	if !utils.Contains(validTargets, req.Target) {
		return errors.NewValidationError("target", "Invalid deployment target", req.Target)
	}

	if !utils.IsValidUUID(req.ID) {
		return errors.NewValidationError("id", "Invalid bundle ID format", req.ID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ps *PolicyService) validateLoadPolicyRequest(req *LoadPolicyRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.PolicyID == "" {
		return errors.NewValidationError("policy_id", "Policy ID is required", req.PolicyID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	if !utils.IsValidUUID(req.PolicyID) {
		return errors.NewValidationError("policy_id", "Invalid policy ID format", req.PolicyID)
	}

	return nil
}

func (ps *PolicyService) validateLoadBundleRequest(req *LoadBundleRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if req.BundleID == "" {
		return errors.NewValidationError("bundle_id", "Bundle ID is required", req.BundleID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	if !utils.IsValidUUID(req.BundleID) {
		return errors.NewValidationError("bundle_id", "Invalid bundle ID format", req.BundleID)
	}

	return nil
}

func (ps *PolicyService) validateSyncTenantRequest(req *SyncTenantRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	return nil
}

func (ps *PolicyService) validateClearCacheRequest(req *ClearCacheRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if !utils.IsValidUUID(req.TenantID) {
		return errors.NewValidationError("tenant_id", "Invalid tenant ID format", req.TenantID)
	}

	if req.PolicyID != "" && !utils.IsValidUUID(req.PolicyID) {
		return errors.NewValidationError("policy_id", "Invalid policy ID format", req.PolicyID)
	}

	return nil
}

func (ps *PolicyService) recordMetrics(operation string, duration time.Duration, err error) {
	ps.logger.Debug("Operation completed",
		zap.String("operation", operation),
		zap.Duration("duration", duration),
		zap.Bool("success", err == nil))
}

func (ps *PolicyService) recordSuccessfulOperation() {
	ps.logger.Debug("Operation completed successfully")
}

func (ps *PolicyService) recordFailedOperation() {
	ps.logger.Debug("Operation failed")
}

func (ps *PolicyService) recordValidationError() {
	ps.logger.Debug("Validation error occurred")
}

func (ps *PolicyService) HealthCheck(ctx context.Context) error {
	if err := ps.policyStore.HealthCheck(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeServiceUnavailable, "Policy store health check failed")
	}

	if err := ps.bundleManager.HealthCheck(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeServiceUnavailable, "Bundle manager health check failed")
	}

	if err := ps.cache.HealthCheck(); err != nil {
		return errors.Wrap(err, errors.ErrCodeServiceUnavailable, "Cache health check failed")
	}

	if !ps.opaEngine.IsHealthy() {
		return errors.NewServiceUnavailable("OPA engine is not healthy")
	}

	if !ps.policyLoader.IsRunning() {
		return errors.NewServiceUnavailable("Policy loader is not running")
	}

	return nil
}

func (ps *PolicyService) GetHealthStatus() map[string]interface{} {
	return map[string]interface{}{
		"policy_store":   ps.policyStore.HealthCheck(context.Background()) == nil,
		"bundle_manager": ps.bundleManager.HealthCheck(context.Background()) == nil,
		"opa_engine":     ps.opaEngine.GetHealthStatus(),
		"opa_client":     ps.opaClient.IsHealthy(context.Background()),
		"policy_loader":  ps.policyLoader.GetHealthStatus(),
		"cache":          ps.cache.GetStats(),
	}
}

func (ps *PolicyService) Close() error {
	ps.logger.Info("Shutting down policy service")

	if err := ps.policyLoader.Close(); err != nil {
		ps.logger.Error("Failed to close policy loader", zap.Error(err))
	}

	if err := ps.opaEngine.Close(); err != nil {
		ps.logger.Error("Failed to close OPA engine", zap.Error(err))
	}

	if err := ps.cache.Close(); err != nil {
		ps.logger.Error("Failed to close cache", zap.Error(err))
	}

	if err := ps.policyStore.Close(); err != nil {
		ps.logger.Error("Failed to close policy store", zap.Error(err))
	}

	if err := ps.bundleManager.Close(); err != nil {
		ps.logger.Error("Failed to close bundle manager", zap.Error(err))
	}

	ps.logger.Info("Policy service shutdown completed")
	return nil
}
