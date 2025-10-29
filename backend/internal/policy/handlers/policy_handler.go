package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"exoper/backend/internal/common/config"
	"exoper/backend/internal/common/errors"
	"exoper/backend/internal/common/utils"
	"exoper/backend/pkg/api/models/policy"
	v1 "exoper/backend/pkg/api/policy/v1"
)

type PolicyHandler struct {
	policyService   v1.PolicyService
	bundleService   v1.BundleService
	loaderService   v1.LoaderService
	decisionService v1.DecisionService
	config          *config.Config
	logger          *zap.Logger
	rateLimiter     *utils.RateLimiter
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
	Name        string                 `json:"name" validate:"required,max=255"`
	Description string                 `json:"description" validate:"max=1000"`
	Priority    policy.Priority        `json:"priority" validate:"required,min=1,max=15"`
	Effect      policy.Effect          `json:"effect" validate:"required"`
	Rules       []policy.Rule          `json:"rules" validate:"required,min=1"`
	Conditions  []policy.Condition     `json:"conditions"`
	Metadata    map[string]interface{} `json:"metadata"`
	UpdatedBy   string                 `json:"updated_by" validate:"required"`
}

type PolicyResponse struct {
	Policy *policy.Policy `json:"policy"`
}

type ListPoliciesResponse struct {
	Policies []policy.Policy `json:"policies"`
	Total    int             `json:"total"`
	Limit    int             `json:"limit"`
	Offset   int             `json:"offset"`
	HasMore  bool            `json:"has_more"`
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
	Name        string                 `json:"name" validate:"required,max=255"`
	Description string                 `json:"description" validate:"max=1000"`
	Policies    []string               `json:"policies" validate:"required,min=1"`
	Metadata    map[string]interface{} `json:"metadata"`
	UpdatedBy   string                 `json:"updated_by" validate:"required"`
}

type BundleResponse struct {
	Bundle *policy.PolicyBundle `json:"bundle"`
}

type ListBundlesResponse struct {
	Bundles []policy.PolicyBundle `json:"bundles"`
	Total   int                   `json:"total"`
	HasMore bool                  `json:"has_more"`
}

type DeployBundleRequest struct {
	Target string `json:"target" validate:"required,oneof=opa database"`
}

type ErrorResponse struct {
	Error   string                 `json:"error"`
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

func NewPolicyHandler(
	policyService v1.PolicyService,
	bundleService v1.BundleService,
	loaderService v1.LoaderService,
	decisionService v1.DecisionService,
	cfg *config.Config,
	logger *zap.Logger,
) *PolicyHandler {
	rateLimiter := utils.NewRateLimiter(1000.0, 10000)

	return &PolicyHandler{
		policyService:   policyService,
		bundleService:   bundleService,
		loaderService:   loaderService,
		decisionService: decisionService,
		config:          cfg,
		logger:          logger,
		rateLimiter:     rateLimiter,
	}
}

func (h *PolicyHandler) convertMetadata(metadata map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range metadata {
		if str, ok := v.(string); ok {
			result[k] = str
		}
	}
	return result
}

func (h *PolicyHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	var req CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" || req.Name == "" || req.CreatedBy == "" {
		h.writeErrorResponse(w, errors.NewValidationError("validation", "Required fields missing", "tenant_id, name, and created_by are required"), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.CreatePolicyRequest{
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Priority:    req.Priority,
		Effect:      req.Effect,
		Rules:       req.Rules,
		Conditions:  req.Conditions,
		Metadata:    h.convertMetadata(req.Metadata),
		CreatedBy:   req.CreatedBy,
	}

	pol, err := h.policyService.CreatePolicy(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	response := &PolicyResponse{Policy: pol}
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode create policy response", zap.Error(err))
		return
	}

	h.logger.Info("Policy created successfully",
		zap.String("policy_id", pol.ID),
		zap.String("tenant_id", req.TenantID),
		zap.String("policy_name", req.Name),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	policyID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")

	if policyID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("id", "Policy ID is required", policyID), http.StatusBadRequest)
		return
	}

	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.GetPolicyRequest{
		ID:       policyID,
		TenantID: tenantID,
	}

	pol, err := h.policyService.GetPolicy(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	response := &PolicyResponse{Policy: pol}
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode get policy response", zap.Error(err))
		return
	}

	h.logger.Debug("Policy retrieved successfully",
		zap.String("policy_id", policyID),
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	policyID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")

	if policyID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("id", "Policy ID is required", policyID), http.StatusBadRequest)
		return
	}

	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	var req UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.UpdatedBy == "" {
		h.writeErrorResponse(w, errors.NewValidationError("validation", "Required fields missing", "name and updated_by are required"), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.UpdatePolicyRequest{
		ID:          policyID,
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		Effect:      req.Effect,
		Rules:       req.Rules,
		Conditions:  req.Conditions,
		Metadata:    h.convertMetadata(req.Metadata),
		UpdatedBy:   req.UpdatedBy,
	}

	pol, err := h.policyService.UpdatePolicy(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	response := &PolicyResponse{Policy: pol}
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode update policy response", zap.Error(err))
		return
	}

	h.logger.Info("Policy updated successfully",
		zap.String("policy_id", policyID),
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	policyID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")

	if policyID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("id", "Policy ID is required", policyID), http.StatusBadRequest)
		return
	}

	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.DeletePolicyRequest{
		ID:       policyID,
		TenantID: tenantID,
	}

	if err := h.policyService.DeletePolicy(ctx, serviceReq); err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)

	h.logger.Info("Policy deleted successfully",
		zap.String("policy_id", policyID),
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	policyType := query.Get("type")
	status := query.Get("status")
	sortBy := query.Get("sort_by")
	sortOrder := query.Get("sort_order")

	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	serviceReq := &v1.ListPoliciesRequest{
		TenantID:  tenantID,
		Type:      policy.PolicyType(policyType),
		Status:    policy.PolicyStatus(status),
		Limit:     limit,
		Offset:    offset,
		SortBy:    sortBy,
		SortOrder: sortOrder,
	}

	response, err := h.policyService.ListPolicies(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	listResponse := &ListPoliciesResponse{
		Policies: response.Policies,
		Total:    response.Total,
		Limit:    response.Limit,
		Offset:   response.Offset,
		HasMore:  response.HasMore,
	}

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(listResponse); err != nil {
		h.logger.Error("Failed to encode list policies response", zap.Error(err))
		return
	}

	h.logger.Debug("Policies listed successfully",
		zap.String("tenant_id", tenantID),
		zap.Int("count", len(response.Policies)),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) ActivatePolicy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	policyID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")

	if policyID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("id", "Policy ID is required", policyID), http.StatusBadRequest)
		return
	}

	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.ActivatePolicyRequest{
		ID:       policyID,
		TenantID: tenantID,
	}

	if err := h.policyService.ActivatePolicy(ctx, serviceReq); err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"message":   "Policy activated successfully",
		"policy_id": policyID,
		"status":    "active",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode activate policy response", zap.Error(err))
		return
	}

	h.logger.Info("Policy activated successfully",
		zap.String("policy_id", policyID),
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) DeactivatePolicy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	policyID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")

	if policyID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("id", "Policy ID is required", policyID), http.StatusBadRequest)
		return
	}

	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.DeactivatePolicyRequest{
		ID:       policyID,
		TenantID: tenantID,
	}

	if err := h.policyService.DeactivatePolicy(ctx, serviceReq); err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"message":   "Policy deactivated successfully",
		"policy_id": policyID,
		"status":    "inactive",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode deactivate policy response", zap.Error(err))
		return
	}

	h.logger.Info("Policy deactivated successfully",
		zap.String("policy_id", policyID),
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) ValidatePolicy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	var req ValidatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if req.Policy == nil {
		h.writeErrorResponse(w, errors.NewValidationError("policy", "Policy is required", "policy field cannot be null"), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.ValidatePolicyRequest{
		Policy: req.Policy,
	}

	validationResult, err := h.policyService.ValidatePolicy(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	response := &ValidatePolicyResponse{
		Valid:    validationResult.Valid,
		Errors:   validationResult.Errors,
		Warnings: validationResult.Warnings,
	}

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode validate policy response", zap.Error(err))
		return
	}

	h.logger.Debug("Policy validation completed",
		zap.Bool("valid", validationResult.Valid),
		zap.Int("errors", len(validationResult.Errors)),
		zap.Int("warnings", len(validationResult.Warnings)),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) CreateBundle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	var req CreateBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if req.TenantID == "" || req.Name == "" || req.CreatedBy == "" || len(req.Policies) == 0 {
		h.writeErrorResponse(w, errors.NewValidationError("validation", "Required fields missing", "tenant_id, name, created_by, and policies are required"), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.CreateBundleRequest{
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Policies:    req.Policies,
		Metadata:    h.convertMetadata(req.Metadata),
		CreatedBy:   req.CreatedBy,
	}

	bundle, err := h.bundleService.CreateBundle(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	response := &BundleResponse{Bundle: bundle}
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode create bundle response", zap.Error(err))
		return
	}

	h.logger.Info("Bundle created successfully",
		zap.String("bundle_id", bundle.ID),
		zap.String("tenant_id", req.TenantID),
		zap.String("bundle_name", req.Name),
		zap.Int("policy_count", len(req.Policies)),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) GetBundle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	bundleID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")

	if bundleID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("id", "Bundle ID is required", bundleID), http.StatusBadRequest)
		return
	}

	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.GetBundleRequest{
		ID:       bundleID,
		TenantID: tenantID,
	}

	bundle, err := h.bundleService.GetBundle(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	response := &BundleResponse{Bundle: bundle}
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode get bundle response", zap.Error(err))
		return
	}

	h.logger.Debug("Bundle retrieved successfully",
		zap.String("bundle_id", bundleID),
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) UpdateBundle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	bundleID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")

	if bundleID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("id", "Bundle ID is required", bundleID), http.StatusBadRequest)
		return
	}

	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	var req UpdateBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.UpdatedBy == "" || len(req.Policies) == 0 {
		h.writeErrorResponse(w, errors.NewValidationError("validation", "Required fields missing", "name, updated_by, and policies are required"), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.UpdateBundleRequest{
		ID:          bundleID,
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Policies:    req.Policies,
		Metadata:    h.convertMetadata(req.Metadata),
		UpdatedBy:   req.UpdatedBy,
	}

	bundle, err := h.bundleService.UpdateBundle(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	response := &BundleResponse{Bundle: bundle}
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode update bundle response", zap.Error(err))
		return
	}

	h.logger.Info("Bundle updated successfully",
		zap.String("bundle_id", bundleID),
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) DeleteBundle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	bundleID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")

	if bundleID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("id", "Bundle ID is required", bundleID), http.StatusBadRequest)
		return
	}

	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.DeleteBundleRequest{
		ID:       bundleID,
		TenantID: tenantID,
	}

	if err := h.bundleService.DeleteBundle(ctx, serviceReq); err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)

	h.logger.Info("Bundle deleted successfully",
		zap.String("bundle_id", bundleID),
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) ListBundles(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	status := query.Get("status")

	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	serviceReq := &v1.ListBundlesRequest{
		TenantID: tenantID,
		Status:   policy.PolicyStatus(status),
		Limit:    limit,
		Offset:   offset,
	}

	response, err := h.bundleService.ListBundles(ctx, serviceReq)
	if err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	listResponse := &ListBundlesResponse{
		Bundles: response.Bundles,
		Total:   response.Total,
		HasMore: response.HasMore,
	}

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(listResponse); err != nil {
		h.logger.Error("Failed to encode list bundles response", zap.Error(err))
		return
	}

	h.logger.Debug("Bundles listed successfully",
		zap.String("tenant_id", tenantID),
		zap.Int("count", len(response.Bundles)),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) DeployBundle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	bundleID := vars["id"]
	tenantID := r.Header.Get("X-Tenant-ID")

	if bundleID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("id", "Bundle ID is required", bundleID), http.StatusBadRequest)
		return
	}

	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	var req DeployBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("body", "Invalid JSON body", err.Error()), http.StatusBadRequest)
		return
	}

	if req.Target == "" {
		h.writeErrorResponse(w, errors.NewValidationError("target", "Target is required", "target must be 'opa' or 'database'"), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.DeployBundleRequest{
		ID:       bundleID,
		TenantID: tenantID,
		Target:   req.Target,
	}

	if err := h.bundleService.DeployBundle(ctx, serviceReq); err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)

	response := map[string]interface{}{
		"message":   "Bundle deployment initiated",
		"bundle_id": bundleID,
		"target":    req.Target,
		"status":    "deploying",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode deploy bundle response", zap.Error(err))
		return
	}

	h.logger.Info("Bundle deployment initiated",
		zap.String("bundle_id", bundleID),
		zap.String("tenant_id", tenantID),
		zap.String("target", req.Target),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) SyncTenant(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	serviceReq := &v1.SyncTenantRequest{
		TenantID: tenantID,
	}

	if err := h.loaderService.SyncTenant(ctx, serviceReq); err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)

	response := map[string]interface{}{
		"message":   "Tenant sync initiated",
		"tenant_id": tenantID,
		"status":    "syncing",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode sync tenant response", zap.Error(err))
		return
	}

	h.logger.Info("Tenant sync initiated",
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) ClearCache(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if !h.rateLimiter.Allow() {
		h.writeErrorResponse(w, errors.NewRateLimitError(time.Minute), http.StatusTooManyRequests)
		return
	}

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("tenant_id", "Tenant ID header is required", tenantID), http.StatusBadRequest)
		return
	}

	query := r.URL.Query()
	policyID := query.Get("policy_id")

	serviceReq := &v1.ClearCacheRequest{
		TenantID: tenantID,
		PolicyID: policyID,
	}

	if err := h.decisionService.ClearCache(ctx, serviceReq); err != nil {
		h.writeErrorResponse(w, err, h.getStatusCodeFromError(err))
		return
	}

	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"message":   "Cache cleared successfully",
		"tenant_id": tenantID,
	}

	if policyID != "" {
		response["policy_id"] = policyID
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode clear cache response", zap.Error(err))
		return
	}

	h.logger.Info("Cache cleared successfully",
		zap.String("tenant_id", tenantID),
		zap.String("policy_id", policyID),
		zap.Duration("duration", time.Since(start)))
}

func (h *PolicyHandler) writeErrorResponse(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := &ErrorResponse{
		Error:   err.Error(),
		Code:    h.getErrorCode(err),
		Message: h.getErrorMessage(err),
		Details: h.getErrorDetails(err),
	}

	if encodeErr := json.NewEncoder(w).Encode(errorResponse); encodeErr != nil {
		h.logger.Error("Failed to encode error response", 
			zap.Error(encodeErr),
			zap.Error(err))
	}

	h.logger.Error("Request failed",
		zap.Error(err),
		zap.Int("status_code", statusCode),
		zap.String("error_code", errorResponse.Code))
}

func (h *PolicyHandler) getStatusCodeFromError(err error) int {
	if errors.IsAppError(err) {
		return errors.GetHTTPStatus(err)
	}
	return http.StatusInternalServerError
}

func (h *PolicyHandler) getErrorCode(err error) string {
	if appErr, ok := err.(*errors.AppError); ok {
		return string(appErr.Code)
	}
	return "INTERNAL_ERROR"
}

func (h *PolicyHandler) getErrorMessage(err error) string {
	if appErr, ok := err.(*errors.AppError); ok {
		return appErr.Message
	}
	return err.Error()
}

func (h *PolicyHandler) getErrorDetails(err error) map[string]interface{} {
	if appErr, ok := err.(*errors.AppError); ok {
		return appErr.Context
	}
	return nil
}

func (h *PolicyHandler) RegisterRoutes(router *mux.Router) {
	apiRouter := router.PathPrefix("/api/v1").Subrouter()

	apiRouter.HandleFunc("/policies", h.CreatePolicy).Methods("POST")
	apiRouter.HandleFunc("/policies", h.ListPolicies).Methods("GET")
	apiRouter.HandleFunc("/policies/{id}", h.GetPolicy).Methods("GET")
	apiRouter.HandleFunc("/policies/{id}", h.UpdatePolicy).Methods("PUT")
	apiRouter.HandleFunc("/policies/{id}", h.DeletePolicy).Methods("DELETE")
	apiRouter.HandleFunc("/policies/{id}/activate", h.ActivatePolicy).Methods("POST")
	apiRouter.HandleFunc("/policies/{id}/deactivate", h.DeactivatePolicy).Methods("POST")
	apiRouter.HandleFunc("/policies/validate", h.ValidatePolicy).Methods("POST")

	apiRouter.HandleFunc("/bundles", h.CreateBundle).Methods("POST")
	apiRouter.HandleFunc("/bundles", h.ListBundles).Methods("GET")
	apiRouter.HandleFunc("/bundles/{id}", h.GetBundle).Methods("GET")
	apiRouter.HandleFunc("/bundles/{id}", h.UpdateBundle).Methods("PUT")
	apiRouter.HandleFunc("/bundles/{id}", h.DeleteBundle).Methods("DELETE")
	apiRouter.HandleFunc("/bundles/{id}/deploy", h.DeployBundle).Methods("POST")

	apiRouter.HandleFunc("/sync", h.SyncTenant).Methods("POST")
	apiRouter.HandleFunc("/cache/clear", h.ClearCache).Methods("POST")

	h.logger.Info("Policy handler routes registered",
		zap.Strings("endpoints", []string{
			"POST /api/v1/policies",
			"GET /api/v1/policies",
			"GET /api/v1/policies/{id}",
			"PUT /api/v1/policies/{id}",
			"DELETE /api/v1/policies/{id}",
			"POST /api/v1/policies/{id}/activate",
			"POST /api/v1/policies/{id}/deactivate",
			"POST /api/v1/policies/validate",
			"POST /api/v1/bundles",
			"GET /api/v1/bundles",
			"GET /api/v1/bundles/{id}",
			"PUT /api/v1/bundles/{id}",
			"DELETE /api/v1/bundles/{id}",
			"POST /api/v1/bundles/{id}/deploy",
			"POST /api/v1/sync",
			"POST /api/v1/cache/clear",
		}))
}

func (h *PolicyHandler) Shutdown(ctx context.Context) error {
	h.logger.Info("Policy handler shutting down")
	return nil
}
