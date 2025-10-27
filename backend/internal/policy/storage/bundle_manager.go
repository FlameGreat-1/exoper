package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	"flamo/backend/pkg/api/models/policy"
	"flamo/backend/internal/policy/service"
)

type BundleManager struct {
	db           *database.Database
	policyStore  *PolicyStore
	config       *config.Config
	logger       *zap.Logger
	cache        *BundleCache
	deployments  map[string]*BundleDeployment
	mu           sync.RWMutex
}

type BundleCache struct {
	bundles map[string]*policy.PolicyBundle
	ttl     time.Duration
	mu      sync.RWMutex
}

type BundleDeployment struct {
	BundleID     string                 `json:"bundle_id"`
	TenantID     string                 `json:"tenant_id"`
	Target       string                 `json:"target"`
	Status       BundleDeploymentStatus `json:"status"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Progress     int                    `json:"progress"`
	TotalSteps   int                    `json:"total_steps"`
	CurrentStep  string                 `json:"current_step"`
	DeployedBy   string                 `json:"deployed_by"`
}

type BundleDeploymentStatus string

const (
	DeploymentStatusPending    BundleDeploymentStatus = "pending"
	DeploymentStatusInProgress BundleDeploymentStatus = "in_progress"
	DeploymentStatusCompleted  BundleDeploymentStatus = "completed"
	DeploymentStatusFailed     BundleDeploymentStatus = "failed"
	DeploymentStatusRolledBack BundleDeploymentStatus = "rolled_back"
)

type BundleFilter struct {
	TenantID string
	Status   policy.PolicyStatus
	Version  string
	Tags     []string
	Search   string
	Limit    int
	Offset   int
	SortBy   string
	SortDesc bool
}

type BundleValidationResult struct {
	Valid            bool                    `json:"valid"`
	Errors           []string                `json:"errors,omitempty"`
	Warnings         []string                `json:"warnings,omitempty"`
	PolicyValidation map[string][]string     `json:"policy_validation,omitempty"`
	Dependencies     []string                `json:"dependencies,omitempty"`
	Conflicts        []BundleConflict        `json:"conflicts,omitempty"`
}

type BundleConflict struct {
	Type        string `json:"type"`
	PolicyID1   string `json:"policy_id_1"`
	PolicyID2   string `json:"policy_id_2"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type BundleMetrics struct {
	TotalBundles    int64 `json:"total_bundles"`
	ActiveBundles   int64 `json:"active_bundles"`
	InactiveBundles int64 `json:"inactive_bundles"`
	DraftBundles    int64 `json:"draft_bundles"`
	ArchivedBundles int64 `json:"archived_bundles"`
	TotalPolicies   int64 `json:"total_policies"`
	Deployments     int64 `json:"deployments"`
}

func NewBundleManager(db *database.Database, policyStore *PolicyStore, cfg *config.Config, logger *zap.Logger) *BundleManager {
	cache := &BundleCache{
		bundles: make(map[string]*policy.PolicyBundle),
		ttl:     30 * time.Minute,
	}

	return &BundleManager{
		db:          db,
		policyStore: policyStore,
		config:      cfg,
		logger:      logger,
		cache:       cache,
		deployments: make(map[string]*BundleDeployment),
	}
}

func (bm *BundleManager) CreateBundle(ctx context.Context, req *service.CreateBundleRequest) (*policy.PolicyBundle, error) {
	if err := bm.validateCreateBundleRequest(req); err != nil {
		return nil, err
	}

	bundleID := uuid.New().String()
	now := time.Now().UTC()

	bundle := &policy.PolicyBundle{
		ID:          bundleID,
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Version:     "1.0.0",
		Policies:    req.Policies,
		Status:      policy.PolicyStatusDraft,
		Metadata:    req.Metadata,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   req.CreatedBy,
		UpdatedBy:   req.CreatedBy,
	}

	if err := bm.validateBundlePolicies(ctx, bundle); err != nil {
		return nil, err
	}

	if err := bm.insertBundle(ctx, bundle); err != nil {
		return nil, errors.NewDatabaseError("create bundle", err).
			WithTenantID(req.TenantID).
			WithContext("bundle_name", req.Name)
	}

	bm.cache.invalidateBundle(bundleID)

	bm.logger.Info("Bundle created successfully",
		zap.String("bundle_id", bundleID),
		zap.String("tenant_id", req.TenantID),
		zap.String("bundle_name", req.Name),
		zap.Int("policy_count", len(req.Policies)))

	return bundle, nil
}

func (bm *BundleManager) GetBundle(ctx context.Context, req *service.GetBundleRequest) (*policy.PolicyBundle, error) {
	if req.ID == "" {
		return nil, errors.NewValidationError("bundle_id", "Bundle ID is required", req.ID)
	}

	if req.TenantID == "" {
		return nil, errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if cached := bm.cache.getBundle(req.ID); cached != nil && cached.TenantID == req.TenantID {
		return cached, nil
	}

	bundle, err := bm.selectBundle(ctx, req.ID, req.TenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("Bundle").
				WithTenantID(req.TenantID).
				WithContext("bundle_id", req.ID)
		}
		return nil, errors.NewDatabaseError("get bundle", err).
			WithTenantID(req.TenantID).
			WithContext("bundle_id", req.ID)
	}

	bm.cache.setBundle(bundle)
	return bundle, nil
}

func (bm *BundleManager) UpdateBundle(ctx context.Context, req *service.UpdateBundleRequest) (*policy.PolicyBundle, error) {
	if err := bm.validateUpdateBundleRequest(req); err != nil {
		return nil, err
	}

	existing, err := bm.GetBundle(ctx, &service.GetBundleRequest{
		ID:       req.ID,
		TenantID: req.TenantID,
	})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	existing.Name = req.Name
	existing.Description = req.Description
	existing.Policies = req.Policies
	existing.Metadata = req.Metadata
	existing.UpdatedAt = now
	existing.UpdatedBy = req.UpdatedBy
	existing.Version = bm.incrementVersion(existing.Version)

	if err := bm.validateBundlePolicies(ctx, existing); err != nil {
		return nil, err
	}

	if err := bm.updateBundle(ctx, existing); err != nil {
		return nil, errors.NewDatabaseError("update bundle", err).
			WithTenantID(req.TenantID).
			WithContext("bundle_id", req.ID)
	}

	bm.cache.invalidateBundle(req.ID)

	bm.logger.Info("Bundle updated successfully",
		zap.String("bundle_id", req.ID),
		zap.String("tenant_id", req.TenantID),
		zap.String("new_version", existing.Version))

	return existing, nil
}

func (bm *BundleManager) DeleteBundle(ctx context.Context, req *service.DeleteBundleRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("bundle_id", "Bundle ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	existing, err := bm.GetBundle(ctx, &service.GetBundleRequest{
		ID:       req.ID,
		TenantID: req.TenantID,
	})
	if err != nil {
		return err
	}

	if existing.Status == policy.PolicyStatusActive {
		return errors.NewConflictError("Cannot delete active bundle. Deactivate first").
			WithTenantID(req.TenantID).
			WithContext("bundle_id", req.ID)
	}

	if err := bm.deleteBundle(ctx, req.ID, req.TenantID); err != nil {
		return errors.NewDatabaseError("delete bundle", err).
			WithTenantID(req.TenantID).
			WithContext("bundle_id", req.ID)
	}

	bm.cache.invalidateBundle(req.ID)

	bm.logger.Info("Bundle deleted successfully",
		zap.String("bundle_id", req.ID),
		zap.String("tenant_id", req.TenantID))

	return nil
}

func (bm *BundleManager) ListBundles(ctx context.Context, req *service.ListBundlesRequest) (*service.ListBundlesResponse, error) {
	if req.TenantID == "" {
		return nil, errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	filter := &BundleFilter{
		TenantID: req.TenantID,
		Status:   req.Status,
		Limit:    req.Limit,
		Offset:   req.Offset,
	}

	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}

	bundles, total, err := bm.selectBundles(ctx, filter)
	if err != nil {
		return nil, errors.NewDatabaseError("list bundles", err).
			WithTenantID(req.TenantID)
	}

	hasMore := (filter.Offset + filter.Limit) < int(total)

	return &service.ListBundlesResponse{
		Bundles: bundles,
		Total:   int(total),
		HasMore: hasMore,
	}, nil
}

func (bm *BundleManager) DeployBundle(ctx context.Context, req *service.DeployBundleRequest) error {
	if err := bm.validateDeployBundleRequest(req); err != nil {
		return err
	}

	bundle, err := bm.GetBundle(ctx, &service.GetBundleRequest{
		ID:       req.ID,
		TenantID: req.TenantID,
	})
	if err != nil {
		return err
	}

	if bundle.Status != policy.PolicyStatusActive {
		return errors.NewConflictError("Only active bundles can be deployed").
			WithTenantID(req.TenantID).
			WithContext("bundle_id", req.ID).
			WithContext("bundle_status", string(bundle.Status))
	}

	deploymentID := uuid.New().String()
	deployment := &BundleDeployment{
		BundleID:    req.ID,
		TenantID:    req.TenantID,
		Target:      req.Target,
		Status:      DeploymentStatusPending,
		StartedAt:   time.Now().UTC(),
		Progress:    0,
		TotalSteps:  len(bundle.Policies) + 2,
		CurrentStep: "Initializing deployment",
		DeployedBy:  "system",
	}

	bm.mu.Lock()
	bm.deployments[deploymentID] = deployment
	bm.mu.Unlock()

	go bm.executeDeployment(ctx, deploymentID, bundle)

	bm.logger.Info("Bundle deployment started",
		zap.String("deployment_id", deploymentID),
		zap.String("bundle_id", req.ID),
		zap.String("tenant_id", req.TenantID),
		zap.String("target", req.Target))

	return nil
}

func (bm *BundleManager) ValidateBundle(ctx context.Context, bundle *policy.PolicyBundle) (*BundleValidationResult, error) {
	result := &BundleValidationResult{
		Valid:            true,
		Errors:           []string{},
		Warnings:         []string{},
		PolicyValidation: make(map[string][]string),
		Dependencies:     []string{},
		Conflicts:        []BundleConflict{},
	}

	if bundle.Name == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Bundle name is required")
	}

	if len(bundle.Policies) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "Bundle must contain at least one policy")
	}

	if len(bundle.Policies) > 100 {
		result.Warnings = append(result.Warnings, "Bundle contains many policies, consider splitting")
	}

	for _, policyID := range bundle.Policies {
		pol, err := bm.policyStore.GetPolicy(ctx, &service.GetPolicyRequest{
			ID:       policyID,
			TenantID: bundle.TenantID,
		})
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Policy %s not found or inaccessible", policyID))
			continue
		}

		policyValidation := bm.validatePolicyForBundle(pol)
		if len(policyValidation) > 0 {
			result.PolicyValidation[policyID] = policyValidation
			if bm.containsCriticalErrors(policyValidation) {
				result.Valid = false
			}
		}
	}

	conflicts := bm.detectPolicyConflicts(ctx, bundle)
	result.Conflicts = conflicts
	if len(conflicts) > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Found %d potential policy conflicts", len(conflicts)))
	}

	return result, nil
}


func (bm *BundleManager) executeDeployment(ctx context.Context, deploymentID string, bundle *policy.PolicyBundle) {
	bm.mu.Lock()
	deployment := bm.deployments[deploymentID]
	bm.mu.Unlock()

	if deployment == nil {
		return
	}

	deployment.Status = DeploymentStatusInProgress
	deployment.CurrentStep = "Validating bundle"
	deployment.Progress = 1

	validation, err := bm.ValidateBundle(ctx, bundle)
	if err != nil || !validation.Valid {
		bm.failDeployment(deployment, fmt.Sprintf("Bundle validation failed: %v", err))
		return
	}

	deployment.CurrentStep = "Deploying policies"
	deployment.Progress = 2

	for i, policyID := range bundle.Policies {
		pol, err := bm.policyStore.GetPolicy(ctx, &service.GetPolicyRequest{
			ID:       policyID,
			TenantID: bundle.TenantID,
		})
		if err != nil {
			bm.failDeployment(deployment, fmt.Sprintf("Failed to get policy %s: %v", policyID, err))
			return
		}

		if err := bm.deployPolicy(ctx, pol, deployment.Target); err != nil {
			bm.failDeployment(deployment, fmt.Sprintf("Failed to deploy policy %s: %v", policyID, err))
			return
		}

		deployment.Progress = 2 + i + 1
		deployment.CurrentStep = fmt.Sprintf("Deployed policy %s", pol.Name)

		bm.logger.Debug("Policy deployed in bundle",
			zap.String("deployment_id", deploymentID),
			zap.String("policy_id", policyID),
			zap.String("policy_name", pol.Name))
	}

	deployment.Status = DeploymentStatusCompleted
	deployment.CurrentStep = "Deployment completed"
	deployment.Progress = deployment.TotalSteps
	now := time.Now().UTC()
	deployment.CompletedAt = &now

	bm.logger.Info("Bundle deployment completed successfully",
		zap.String("deployment_id", deploymentID),
		zap.String("bundle_id", bundle.ID),
		zap.String("tenant_id", bundle.TenantID),
		zap.Duration("duration", time.Since(deployment.StartedAt)))
}

func (bm *BundleManager) failDeployment(deployment *BundleDeployment, errorMsg string) {
	deployment.Status = DeploymentStatusFailed
	deployment.Error = errorMsg
	now := time.Now().UTC()
	deployment.CompletedAt = &now

	bm.logger.Error("Bundle deployment failed",
		zap.String("bundle_id", deployment.BundleID),
		zap.String("tenant_id", deployment.TenantID),
		zap.String("error", errorMsg))
}

func (bm *BundleManager) deployPolicy(ctx context.Context, pol *policy.Policy, target string) error {
	switch target {
	case "opa":
		return bm.deployToOPA(ctx, pol)
	case "database":
		return bm.deployToDatabase(ctx, pol)
	default:
		return errors.NewValidationError("target", "Unsupported deployment target", target)
	}
}

func (bm *BundleManager) deployToOPA(ctx context.Context, pol *policy.Policy) error {
	return nil
}

func (bm *BundleManager) deployToDatabase(ctx context.Context, pol *policy.Policy) error {
	return bm.policyStore.ActivatePolicy(ctx, &service.ActivatePolicyRequest{
		ID:       pol.ID,
		TenantID: pol.TenantID,
	})
}

func (bm *BundleManager) GetDeploymentStatus(deploymentID string) *BundleDeployment {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	deployment := bm.deployments[deploymentID]
	if deployment == nil {
		return nil
	}

	deploymentCopy := *deployment
	return &deploymentCopy
}

func (bm *BundleManager) insertBundle(ctx context.Context, bundle *policy.PolicyBundle) error {
	policiesJSON, _ := json.Marshal(bundle.Policies)
	metadataJSON, _ := json.Marshal(bundle.Metadata)

	query := `
		INSERT INTO policy_bundles (
			id, tenant_id, name, description, version, policies, status, metadata,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := bm.db.Exec(ctx, query,
		bundle.ID, bundle.TenantID, bundle.Name, bundle.Description, bundle.Version,
		policiesJSON, bundle.Status, metadataJSON, bundle.CreatedAt, bundle.UpdatedAt,
		bundle.CreatedBy, bundle.UpdatedBy)

	return err
}

func (bm *BundleManager) selectBundle(ctx context.Context, bundleID, tenantID string) (*policy.PolicyBundle, error) {
	query := `
		SELECT id, tenant_id, name, description, version, policies, status, metadata,
			   created_at, updated_at, created_by, updated_by
		FROM policy_bundles 
		WHERE id = $1 AND tenant_id = $2`

	var bundle policy.PolicyBundle
	var policiesJSON, metadataJSON []byte

	err := bm.db.QueryRow(ctx, query, bundleID, tenantID).Scan(
		&bundle.ID, &bundle.TenantID, &bundle.Name, &bundle.Description, &bundle.Version,
		&policiesJSON, &bundle.Status, &metadataJSON, &bundle.CreatedAt, &bundle.UpdatedAt,
		&bundle.CreatedBy, &bundle.UpdatedBy,
	)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(policiesJSON, &bundle.Policies)
	json.Unmarshal(metadataJSON, &bundle.Metadata)

	return &bundle, nil
}

func (bm *BundleManager) updateBundle(ctx context.Context, bundle *policy.PolicyBundle) error {
	policiesJSON, _ := json.Marshal(bundle.Policies)
	metadataJSON, _ := json.Marshal(bundle.Metadata)

	query := `
		UPDATE policy_bundles SET 
			name = $1, description = $2, version = $3, policies = $4, metadata = $5,
			updated_at = $6, updated_by = $7
		WHERE id = $8 AND tenant_id = $9`

	_, err := bm.db.Exec(ctx, query,
		bundle.Name, bundle.Description, bundle.Version, policiesJSON, metadataJSON,
		bundle.UpdatedAt, bundle.UpdatedBy, bundle.ID, bundle.TenantID)

	return err
}

func (bm *BundleManager) deleteBundle(ctx context.Context, bundleID, tenantID string) error {
	query := `DELETE FROM policy_bundles WHERE id = $1 AND tenant_id = $2`
	_, err := bm.db.Exec(ctx, query, bundleID, tenantID)
	return err
}

func (bm *BundleManager) selectBundles(ctx context.Context, filter *BundleFilter) ([]policy.PolicyBundle, int64, error) {
	whereClause := []string{"tenant_id = $1"}
	args := []interface{}{filter.TenantID}
	argIndex := 2

	if filter.Status != "" {
		whereClause = append(whereClause, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, filter.Status)
		argIndex++
	}

	if filter.Version != "" {
		whereClause = append(whereClause, fmt.Sprintf("version = $%d", argIndex))
		args = append(args, filter.Version)
		argIndex++
	}

	if filter.Search != "" {
		whereClause = append(whereClause, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM policy_bundles WHERE %s", strings.Join(whereClause, " AND "))
	var total int64
	err := bm.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	orderBy := "created_at"
	if filter.SortBy != "" {
		orderBy = filter.SortBy
	}
	if filter.SortDesc {
		orderBy += " DESC"
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, description, version, policies, status, metadata,
			   created_at, updated_at, created_by, updated_by
		FROM policy_bundles 
		WHERE %s 
		ORDER BY %s 
		LIMIT $%d OFFSET $%d`,
		strings.Join(whereClause, " AND "), orderBy, argIndex, argIndex+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := bm.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Rows.Close()

	var bundles []policy.PolicyBundle
	for rows.Rows.Next() {
		var bundle policy.PolicyBundle
		var policiesJSON, metadataJSON []byte

		err := rows.Rows.Scan(
			&bundle.ID, &bundle.TenantID, &bundle.Name, &bundle.Description, &bundle.Version,
			&policiesJSON, &bundle.Status, &metadataJSON, &bundle.CreatedAt, &bundle.UpdatedAt,
			&bundle.CreatedBy, &bundle.UpdatedBy,
		)
		if err != nil {
			return nil, 0, err
		}

		json.Unmarshal(policiesJSON, &bundle.Policies)
		json.Unmarshal(metadataJSON, &bundle.Metadata)

		bundles = append(bundles, bundle)
	}

	return bundles, total, nil
}

func (bm *BundleManager) validateCreateBundleRequest(req *service.CreateBundleRequest) error {
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

	return nil
}

func (bm *BundleManager) validateUpdateBundleRequest(req *service.UpdateBundleRequest) error {
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

func (bm *BundleManager) validateDeployBundleRequest(req *service.DeployBundleRequest) error {
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

	return nil
}

func (bm *BundleManager) validateBundlePolicies(ctx context.Context, bundle *policy.PolicyBundle) error {
	for _, policyID := range bundle.Policies {
		if !utils.IsValidUUID(policyID) {
			return errors.NewValidationError("policies", "Invalid policy ID format", policyID)
		}

		_, err := bm.policyStore.GetPolicy(ctx, &service.GetPolicyRequest{
			ID:       policyID,
			TenantID: bundle.TenantID,
		})
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeValidationError, "Policy validation failed").
				WithContext("policy_id", policyID)
		}
	}

	return nil
}

func (bm *BundleManager) validatePolicyForBundle(pol *policy.Policy) []string {
	var issues []string

	if pol.Status != policy.PolicyStatusActive && pol.Status != policy.PolicyStatusDraft {
		issues = append(issues, "Policy must be active or draft")
	}

	if len(pol.Rules) == 0 {
		issues = append(issues, "Policy must have at least one rule")
	}

	return issues
}

func (bm *BundleManager) containsCriticalErrors(validationErrors []string) bool {
	for _, err := range validationErrors {
		if strings.Contains(strings.ToLower(err), "must") {
			return true
		}
	}
	return false
}

func (bm *BundleManager) detectPolicyConflicts(ctx context.Context, bundle *policy.PolicyBundle) []BundleConflict {
	var conflicts []BundleConflict

	policies := make([]*policy.Policy, 0, len(bundle.Policies))
	for _, policyID := range bundle.Policies {
		pol, err := bm.policyStore.GetPolicy(ctx, &service.GetPolicyRequest{
			ID:       policyID,
			TenantID: bundle.TenantID,
		})
		if err == nil {
			policies = append(policies, pol)
		}
	}

	for i, pol1 := range policies {
		for j, pol2 := range policies {
			if i >= j {
				continue
			}

			if conflict := bm.checkPolicyConflict(pol1, pol2); conflict != nil {
				conflicts = append(conflicts, *conflict)
			}
		}
	}

	return conflicts
}

func (bm *BundleManager) checkPolicyConflict(pol1, pol2 *policy.Policy) *BundleConflict {
	for _, rule1 := range pol1.Rules {
		for _, rule2 := range pol2.Rules {
			if rule1.Resource == rule2.Resource && rule1.Action == rule2.Action {
				if rule1.Effect != rule2.Effect {
					return &BundleConflict{
						Type:        "effect_conflict",
						PolicyID1:   pol1.ID,
						PolicyID2:   pol2.ID,
						Resource:    rule1.Resource,
						Action:      rule1.Action,
						Description: fmt.Sprintf("Conflicting effects: %s vs %s", rule1.Effect, rule2.Effect),
					}
				}
			}
		}
	}

	return nil
}

func (bm *BundleManager) incrementVersion(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return "1.0.1"
	}

	patch := utils.SafeStringToInt(parts[2], 0)
	return fmt.Sprintf("%s.%s.%d", parts[0], parts[1], patch+1)
}

func (bc *BundleCache) getBundle(bundleID string) *policy.PolicyBundle {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.bundles[bundleID]
}

func (bc *BundleCache) setBundle(bundle *policy.PolicyBundle) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.bundles[bundle.ID] = bundle
}

func (bc *BundleCache) invalidateBundle(bundleID string) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	delete(bc.bundles, bundleID)
}

func (bm *BundleManager) GetBundleMetrics(ctx context.Context, tenantID string) (*BundleMetrics, error) {
	if tenantID == "" {
		return nil, errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID)
	}

	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
			COUNT(CASE WHEN status = 'inactive' THEN 1 END) as inactive,
			COUNT(CASE WHEN status = 'draft' THEN 1 END) as draft,
			COUNT(CASE WHEN status = 'archived' THEN 1 END) as archived,
			COALESCE(SUM(jsonb_array_length(policies)), 0) as total_policies
		FROM policy_bundles 
		WHERE tenant_id = $1`

	var metrics BundleMetrics
	err := bm.db.QueryRow(ctx, query, tenantID).Scan(
		&metrics.TotalBundles,
		&metrics.ActiveBundles,
		&metrics.InactiveBundles,
		&metrics.DraftBundles,
		&metrics.ArchivedBundles,
		&metrics.TotalPolicies,
	)

	if err != nil {
		return nil, errors.NewDatabaseError("get bundle metrics", err).
			WithTenantID(tenantID)
	}

	bm.mu.RLock()
	metrics.Deployments = int64(len(bm.deployments))
	bm.mu.RUnlock()

	return &metrics, nil
}

func (bm *BundleManager) HealthCheck(ctx context.Context) error {
	query := "SELECT 1"
	_, err := bm.db.QueryRow(ctx, query).Scan(new(int))
	return err
}

func (bm *BundleManager) Close() error {
	bm.cache.bundles = make(map[string]*policy.PolicyBundle)
	bm.deployments = make(map[string]*BundleDeployment)
	return nil
}
