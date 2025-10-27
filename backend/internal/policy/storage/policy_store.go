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

type PolicyStore struct {
	db     *database.Database
	config *config.Config
	logger *zap.Logger
	cache  *PolicyCache
	mu     sync.RWMutex
}

type PolicyCache struct {
	policies map[string]*policy.Policy
	bundles  map[string]*policy.PolicyBundle
	ttl      time.Duration
	mu       sync.RWMutex
}

type PolicyFilter struct {
	TenantID string
	Type     policy.PolicyType
	Status   policy.PolicyStatus
	Priority policy.Priority
	Tags     []string
	Search   string
	Limit    int
	Offset   int
	SortBy   string
	SortDesc bool
}

type PolicyMetrics struct {
	TotalPolicies    int64 `json:"total_policies"`
	ActivePolicies   int64 `json:"active_policies"`
	InactivePolicies int64 `json:"inactive_policies"`
	DraftPolicies    int64 `json:"draft_policies"`
	ArchivedPolicies int64 `json:"archived_policies"`
}

func NewPolicyStore(db *database.Database, cfg *config.Config, logger *zap.Logger) *PolicyStore {
	cache := &PolicyCache{
		policies: make(map[string]*policy.Policy),
		bundles:  make(map[string]*policy.PolicyBundle),
		ttl:      30 * time.Minute,
	}

	return &PolicyStore{
		db:     db,
		config: cfg,
		logger: logger,
		cache:  cache,
	}
}

func (ps *PolicyStore) CreatePolicy(ctx context.Context, req *service.CreatePolicyRequest) (*policy.Policy, error) {
	if err := ps.validateCreateRequest(req); err != nil {
		return nil, err
	}

	policyID := uuid.New().String()
	now := time.Now().UTC()

	pol := &policy.Policy{
		ID:          policyID,
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Status:      policy.PolicyStatusDraft,
		Priority:    req.Priority,
		Effect:      req.Effect,
		Version:     "1.0.0",
		Rules:       req.Rules,
		Conditions:  req.Conditions,
		Metadata:    req.Metadata,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   req.CreatedBy,
		UpdatedBy:   req.CreatedBy,
	}

	if err := ps.insertPolicy(ctx, pol); err != nil {
		return nil, errors.NewDatabaseError("create policy", err).
			WithTenantID(req.TenantID).
			WithContext("policy_name", req.Name)
	}

	ps.cache.invalidatePolicy(policyID)

	ps.logger.Info("Policy created successfully",
		zap.String("policy_id", policyID),
		zap.String("tenant_id", req.TenantID),
		zap.String("policy_name", req.Name),
		zap.String("policy_type", string(req.Type)))

	return pol, nil
}

func (ps *PolicyStore) GetPolicy(ctx context.Context, req *service.GetPolicyRequest) (*policy.Policy, error) {
	if req.ID == "" {
		return nil, errors.NewValidationError("policy_id", "Policy ID is required", req.ID)
	}

	if req.TenantID == "" {
		return nil, errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	if cached := ps.cache.getPolicy(req.ID); cached != nil && cached.TenantID == req.TenantID {
		return cached, nil
	}

	pol, err := ps.selectPolicy(ctx, req.ID, req.TenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("Policy").
				WithTenantID(req.TenantID).
				WithContext("policy_id", req.ID)
		}
		return nil, errors.NewDatabaseError("get policy", err).
			WithTenantID(req.TenantID).
			WithContext("policy_id", req.ID)
	}

	ps.cache.setPolicy(pol)
	return pol, nil
}

func (ps *PolicyStore) UpdatePolicy(ctx context.Context, req *service.UpdatePolicyRequest) (*policy.Policy, error) {
	if err := ps.validateUpdateRequest(req); err != nil {
		return nil, err
	}

	existing, err := ps.GetPolicy(ctx, &service.GetPolicyRequest{
		ID:       req.ID,
		TenantID: req.TenantID,
	})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	existing.Name = req.Name
	existing.Description = req.Description
	existing.Priority = req.Priority
	existing.Effect = req.Effect
	existing.Rules = req.Rules
	existing.Conditions = req.Conditions
	existing.Metadata = req.Metadata
	existing.UpdatedAt = now
	existing.UpdatedBy = req.UpdatedBy
	existing.Version = ps.incrementVersion(existing.Version)

	if err := ps.updatePolicy(ctx, existing); err != nil {
		return nil, errors.NewDatabaseError("update policy", err).
			WithTenantID(req.TenantID).
			WithContext("policy_id", req.ID)
	}

	ps.cache.invalidatePolicy(req.ID)

	ps.logger.Info("Policy updated successfully",
		zap.String("policy_id", req.ID),
		zap.String("tenant_id", req.TenantID),
		zap.String("new_version", existing.Version))

	return existing, nil
}

func (ps *PolicyStore) DeletePolicy(ctx context.Context, req *service.DeletePolicyRequest) error {
	if req.ID == "" {
		return errors.NewValidationError("policy_id", "Policy ID is required", req.ID)
	}

	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	existing, err := ps.GetPolicy(ctx, &service.GetPolicyRequest{
		ID:       req.ID,
		TenantID: req.TenantID,
	})
	if err != nil {
		return err
	}

	if existing.Status == policy.PolicyStatusActive {
		return errors.NewConflictError("Cannot delete active policy. Deactivate first").
			WithTenantID(req.TenantID).
			WithContext("policy_id", req.ID)
	}

	if err := ps.deletePolicy(ctx, req.ID, req.TenantID); err != nil {
		return errors.NewDatabaseError("delete policy", err).
			WithTenantID(req.TenantID).
			WithContext("policy_id", req.ID)
	}

	ps.cache.invalidatePolicy(req.ID)

	ps.logger.Info("Policy deleted successfully",
		zap.String("policy_id", req.ID),
		zap.String("tenant_id", req.TenantID))

	return nil
}

func (ps *PolicyStore) ListPolicies(ctx context.Context, req *service.ListPoliciesRequest) (*service.ListPoliciesResponse, error) {
	if req.TenantID == "" {
		return nil, errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	filter := &PolicyFilter{
		TenantID: req.TenantID,
		Type:     req.Type,
		Status:   req.Status,
		Limit:    req.Limit,
		Offset:   req.Offset,
		SortBy:   req.SortBy,
		SortDesc: req.SortOrder == "desc",
	}

	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}

	policies, total, err := ps.selectPolicies(ctx, filter)
	if err != nil {
		return nil, errors.NewDatabaseError("list policies", err).
			WithTenantID(req.TenantID)
	}

	hasMore := (filter.Offset + filter.Limit) < int(total)

	return &service.ListPoliciesResponse{
		Policies: policies,
		Total:    int(total),
		Limit:    filter.Limit,
		Offset:   filter.Offset,
		HasMore:  hasMore,
	}, nil
}

func (ps *PolicyStore) ActivatePolicy(ctx context.Context, req *service.ActivatePolicyRequest) error {
	return ps.updatePolicyStatus(ctx, req.ID, req.TenantID, policy.PolicyStatusActive)
}

func (ps *PolicyStore) DeactivatePolicy(ctx context.Context, req *service.DeactivatePolicyRequest) error {
	return ps.updatePolicyStatus(ctx, req.ID, req.TenantID, policy.PolicyStatusInactive)
}

func (ps *PolicyStore) ValidatePolicy(ctx context.Context, req *service.ValidatePolicyRequest) (*service.ValidatePolicyResponse, error) {
	result := &service.ValidatePolicyResponse{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	if req.Policy.Name == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Policy name is required")
	}

	if len(req.Policy.Rules) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "Policy must have at least one rule")
	}

	for i, rule := range req.Policy.Rules {
		if rule.Resource == "" {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Rule %d: resource is required", i+1))
		}
		if rule.Action == "" {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Rule %d: action is required", i+1))
		}
	}

	if req.Policy.Priority < policy.PriorityLow || req.Policy.Priority > policy.PriorityCritical {
		result.Warnings = append(result.Warnings, "Policy priority should be between 1 and 15")
	}

	return result, nil
}

func (ps *PolicyStore) updatePolicyStatus(ctx context.Context, policyID, tenantID string, status policy.PolicyStatus) error {
	if policyID == "" {
		return errors.NewValidationError("policy_id", "Policy ID is required", policyID)
	}

	if tenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID)
	}

	existing, err := ps.GetPolicy(ctx, &service.GetPolicyRequest{
		ID:       policyID,
		TenantID: tenantID,
	})
	if err != nil {
		return err
	}

	if existing.Status == status {
		return nil
	}

	query := `UPDATE policies SET status = $1, updated_at = $2 WHERE id = $3 AND tenant_id = $4`
	_, err = ps.db.Exec(ctx, query, status, time.Now().UTC(), policyID, tenantID)
	if err != nil {
		return errors.NewDatabaseError("update policy status", err).
			WithTenantID(tenantID).
			WithContext("policy_id", policyID).
			WithContext("status", string(status))
	}

	ps.cache.invalidatePolicy(policyID)

	ps.logger.Info("Policy status updated",
		zap.String("policy_id", policyID),
		zap.String("tenant_id", tenantID),
		zap.String("old_status", string(existing.Status)),
		zap.String("new_status", string(status)))

	return nil
}

func (ps *PolicyStore) GetPolicyMetrics(ctx context.Context, tenantID string) (*PolicyMetrics, error) {
	if tenantID == "" {
		return nil, errors.NewValidationError("tenant_id", "Tenant ID is required", tenantID)
	}

	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
			COUNT(CASE WHEN status = 'inactive' THEN 1 END) as inactive,
			COUNT(CASE WHEN status = 'draft' THEN 1 END) as draft,
			COUNT(CASE WHEN status = 'archived' THEN 1 END) as archived
		FROM policies 
		WHERE tenant_id = $1`

	var metrics PolicyMetrics
	err := ps.db.QueryRow(ctx, query, tenantID).Scan(
		&metrics.TotalPolicies,
		&metrics.ActivePolicies,
		&metrics.InactivePolicies,
		&metrics.DraftPolicies,
		&metrics.ArchivedPolicies,
	)

	if err != nil {
		return nil, errors.NewDatabaseError("get policy metrics", err).
			WithTenantID(tenantID)
	}

	return &metrics, nil
}

func (ps *PolicyStore) insertPolicy(ctx context.Context, pol *policy.Policy) error {
	rulesJSON, _ := json.Marshal(pol.Rules)
	conditionsJSON, _ := json.Marshal(pol.Conditions)
	metadataJSON, _ := json.Marshal(pol.Metadata)

	query := `
		INSERT INTO policies (
			id, tenant_id, name, description, type, status, priority, effect, version,
			rules, conditions, metadata, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	_, err := ps.db.Exec(ctx, query,
		pol.ID, pol.TenantID, pol.Name, pol.Description, pol.Type, pol.Status,
		pol.Priority, pol.Effect, pol.Version, rulesJSON, conditionsJSON,
		metadataJSON, pol.CreatedAt, pol.UpdatedAt, pol.CreatedBy, pol.UpdatedBy)

	return err
}

func (ps *PolicyStore) selectPolicy(ctx context.Context, policyID, tenantID string) (*policy.Policy, error) {
	query := `
		SELECT id, tenant_id, name, description, type, status, priority, effect, version,
			   rules, conditions, metadata, created_at, updated_at, created_by, updated_by
		FROM policies 
		WHERE id = $1 AND tenant_id = $2`

	var pol policy.Policy
	var rulesJSON, conditionsJSON, metadataJSON []byte

	err := ps.db.QueryRow(ctx, query, policyID, tenantID).Scan(
		&pol.ID, &pol.TenantID, &pol.Name, &pol.Description, &pol.Type, &pol.Status,
		&pol.Priority, &pol.Effect, &pol.Version, &rulesJSON, &conditionsJSON,
		&metadataJSON, &pol.CreatedAt, &pol.UpdatedAt, &pol.CreatedBy, &pol.UpdatedBy,
	)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(rulesJSON, &pol.Rules)
	json.Unmarshal(conditionsJSON, &pol.Conditions)
	json.Unmarshal(metadataJSON, &pol.Metadata)

	return &pol, nil
}

func (ps *PolicyStore) updatePolicy(ctx context.Context, pol *policy.Policy) error {
	rulesJSON, _ := json.Marshal(pol.Rules)
	conditionsJSON, _ := json.Marshal(pol.Conditions)
	metadataJSON, _ := json.Marshal(pol.Metadata)

	query := `
		UPDATE policies SET 
			name = $1, description = $2, priority = $3, effect = $4, version = $5,
			rules = $6, conditions = $7, metadata = $8, updated_at = $9, updated_by = $10
		WHERE id = $11 AND tenant_id = $12`

	_, err := ps.db.Exec(ctx, query,
		pol.Name, pol.Description, pol.Priority, pol.Effect, pol.Version,
		rulesJSON, conditionsJSON, metadataJSON, pol.UpdatedAt, pol.UpdatedBy,
		pol.ID, pol.TenantID)

	return err
}

func (ps *PolicyStore) deletePolicy(ctx context.Context, policyID, tenantID string) error {
	query := `DELETE FROM policies WHERE id = $1 AND tenant_id = $2`
	_, err := ps.db.Exec(ctx, query, policyID, tenantID)
	return err
}

func (ps *PolicyStore) selectPolicies(ctx context.Context, filter *PolicyFilter) ([]policy.Policy, int64, error) {
	whereClause := []string{"tenant_id = $1"}
	args := []interface{}{filter.TenantID}
	argIndex := 2

	if filter.Type != "" {
		whereClause = append(whereClause, fmt.Sprintf("type = $%d", argIndex))
		args = append(args, filter.Type)
		argIndex++
	}

	if filter.Status != "" {
		whereClause = append(whereClause, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, filter.Status)
		argIndex++
	}

	if filter.Search != "" {
		whereClause = append(whereClause, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM policies WHERE %s", strings.Join(whereClause, " AND "))
	var total int64
	err := ps.db.QueryRow(ctx, countQuery, args...).Scan(&total)
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
		SELECT id, tenant_id, name, description, type, status, priority, effect, version,
			   rules, conditions, metadata, created_at, updated_at, created_by, updated_by
		FROM policies 
		WHERE %s 
		ORDER BY %s 
		LIMIT $%d OFFSET $%d`,
		strings.Join(whereClause, " AND "), orderBy, argIndex, argIndex+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := ps.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Rows.Close()

	var policies []policy.Policy
	for rows.Rows.Next() {
		var pol policy.Policy
		var rulesJSON, conditionsJSON, metadataJSON []byte

		err := rows.Rows.Scan(
			&pol.ID, &pol.TenantID, &pol.Name, &pol.Description, &pol.Type, &pol.Status,
			&pol.Priority, &pol.Effect, &pol.Version, &rulesJSON, &conditionsJSON,
			&metadataJSON, &pol.CreatedAt, &pol.UpdatedAt, &pol.CreatedBy, &pol.UpdatedBy,
		)
		if err != nil {
			return nil, 0, err
		}

		json.Unmarshal(rulesJSON, &pol.Rules)
		json.Unmarshal(conditionsJSON, &pol.Conditions)
		json.Unmarshal(metadataJSON, &pol.Metadata)

		policies = append(policies, pol)
	}

	return policies, total, nil
}

func (ps *PolicyStore) validateCreateRequest(req *service.CreatePolicyRequest) error {
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

	return nil
}

func (ps *PolicyStore) validateUpdateRequest(req *service.UpdatePolicyRequest) error {
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

	return nil
}

func (ps *PolicyStore) incrementVersion(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return "1.0.1"
	}

	patch := utils.SafeStringToInt(parts[2], 0)
	return fmt.Sprintf("%s.%s.%d", parts[0], parts[1], patch+1)
}

func (pc *PolicyCache) getPolicy(policyID string) *policy.Policy {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.policies[policyID]
}

func (pc *PolicyCache) setPolicy(pol *policy.Policy) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.policies[pol.ID] = pol
}

func (pc *PolicyCache) invalidatePolicy(policyID string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	delete(pc.policies, policyID)
}

func (pc *PolicyCache) clear() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.policies = make(map[string]*policy.Policy)
	pc.bundles = make(map[string]*policy.PolicyBundle)
}

func (ps *PolicyStore) Close() error {
	ps.cache.clear()
	return nil
}

func (ps *PolicyStore) HealthCheck(ctx context.Context) error {
	query := "SELECT 1"
	_, err := ps.db.QueryRow(ctx, query).Scan(new(int))
	return err
}
