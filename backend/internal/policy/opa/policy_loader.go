package opa

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	"flamo/backend/pkg/api/models/policy"
	"flamo/backend/internal/policy/service"
	"flamo/backend/internal/policy/storage"
)

type PolicyLoader struct {
	client        *Client
	policyStore   *storage.PolicyStore
	bundleManager *storage.BundleManager
	db            *database.Database
	config        *config.Config
	logger        *zap.Logger
	loadQueue     chan *LoadRequest
	workers       []*LoadWorker
	metrics       *LoaderMetrics
	mu            sync.RWMutex
	isRunning     bool
	stopChan      chan struct{}
}

type LoadRequest struct {
	Type      LoadRequestType            `json:"type"`
	TenantID  string                     `json:"tenant_id"`
	PolicyID  string                     `json:"policy_id,omitempty"`
	BundleID  string                     `json:"bundle_id,omitempty"`
	Priority  LoadPriority               `json:"priority"`
	Context   map[string]interface{}     `json:"context,omitempty"`
	Callback  func(*LoadResult)          `json:"-"`
	CreatedAt time.Time                  `json:"created_at"`
	RequestID string                     `json:"request_id"`
}

type LoadRequestType string

const (
	LoadTypePolicy       LoadRequestType = "policy"
	LoadTypeBundle       LoadRequestType = "bundle"
	LoadTypeTenantSync   LoadRequestType = "tenant_sync"
	LoadTypeFullSync     LoadRequestType = "full_sync"
	LoadTypeUnload       LoadRequestType = "unload"
	LoadTypeReload       LoadRequestType = "reload"
)

type LoadPriority int

const (
	PriorityLow    LoadPriority = 1
	PriorityNormal LoadPriority = 5
	PriorityHigh   LoadPriority = 10
	PriorityCritical LoadPriority = 15
)

type LoadResult struct {
	RequestID     string                 `json:"request_id"`
	Type          LoadRequestType        `json:"type"`
	Success       bool                   `json:"success"`
	Error         string                 `json:"error,omitempty"`
	Duration      time.Duration          `json:"duration"`
	PoliciesLoaded int                   `json:"policies_loaded"`
	PoliciesFailed int                   `json:"policies_failed"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
}

type LoadWorker struct {
	id       int
	loader   *PolicyLoader
	stopChan chan struct{}
	logger   *zap.Logger
}

type LoaderMetrics struct {
	TotalRequests      int64         `json:"total_requests"`
	SuccessfulLoads    int64         `json:"successful_loads"`
	FailedLoads        int64         `json:"failed_loads"`
	AverageLoadTime    time.Duration `json:"average_load_time"`
	QueueSize          int           `json:"queue_size"`
	ActiveWorkers      int           `json:"active_workers"`
	PoliciesLoaded     int64         `json:"policies_loaded"`
	BundlesLoaded      int64         `json:"bundles_loaded"`
	LastLoadTime       time.Time     `json:"last_load_time"`
	mu                 sync.RWMutex
}

type PolicyTemplate struct {
	TenantID     string                 `json:"tenant_id"`
	PolicyID     string                 `json:"policy_id"`
	PackageName  string                 `json:"package_name"`
	Rules        []string               `json:"rules"`
	Data         map[string]interface{} `json:"data,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

func NewPolicyLoader(client *Client, policyStore *storage.PolicyStore, bundleManager *storage.BundleManager, db *database.Database, cfg *config.Config, logger *zap.Logger) *PolicyLoader {
	loader := &PolicyLoader{
		client:        client,
		policyStore:   policyStore,
		bundleManager: bundleManager,
		db:            db,
		config:        cfg,
		logger:        logger,
		loadQueue:     make(chan *LoadRequest, 10000),
		metrics:       &LoaderMetrics{},
		stopChan:      make(chan struct{}),
	}

	workerCount := 5
	if cfg.Gateway.MaxConcurrentRequests > 0 {
		workerCount = cfg.Gateway.MaxConcurrentRequests / 10
		if workerCount < 1 {
			workerCount = 1
		}
		if workerCount > 20 {
			workerCount = 20
		}
	}

	loader.workers = make([]*LoadWorker, workerCount)
	for i := 0; i < workerCount; i++ {
		loader.workers[i] = &LoadWorker{
			id:       i,
			loader:   loader,
			stopChan: make(chan struct{}),
			logger:   logger.With(zap.Int("worker_id", i)),
		}
	}

	return loader
}

func (pl *PolicyLoader) Start() error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	if pl.isRunning {
		return errors.NewConflictError("Policy loader is already running")
	}

	for _, worker := range pl.workers {
		go worker.start()
	}

	pl.isRunning = true
	pl.metrics.ActiveWorkers = len(pl.workers)

	pl.logger.Info("Policy loader started",
		zap.Int("worker_count", len(pl.workers)),
		zap.Int("queue_capacity", cap(pl.loadQueue)))

	return nil
}

func (pl *PolicyLoader) Stop() error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	if !pl.isRunning {
		return nil
	}

	close(pl.stopChan)

	for _, worker := range pl.workers {
		close(worker.stopChan)
	}

	pl.isRunning = false
	pl.metrics.ActiveWorkers = 0

	pl.logger.Info("Policy loader stopped")
	return nil
}

func (pl *PolicyLoader) LoadPolicy(ctx context.Context, req *service.LoadPolicyRequest) error {
	if err := pl.validateLoadPolicyRequest(req); err != nil {
		return err
	}

	loadReq := &LoadRequest{
		Type:      LoadTypePolicy,
		TenantID:  req.TenantID,
		PolicyID:  req.PolicyID,
		Priority:  PriorityNormal,
		CreatedAt: time.Now().UTC(),
		RequestID: utils.GenerateRequestID(),
	}

	if req.Priority > 0 {
		loadReq.Priority = LoadPriority(req.Priority)
	}

	return pl.enqueueRequest(loadReq)
}

func (pl *PolicyLoader) LoadBundle(ctx context.Context, req *service.LoadBundleRequest) error {
	if err := pl.validateLoadBundleRequest(req); err != nil {
		return err
	}

	loadReq := &LoadRequest{
		Type:      LoadTypeBundle,
		TenantID:  req.TenantID,
		BundleID:  req.BundleID,
		Priority:  PriorityNormal,
		CreatedAt: time.Now().UTC(),
		RequestID: utils.GenerateRequestID(),
	}

	if req.Priority > 0 {
		loadReq.Priority = LoadPriority(req.Priority)
	}

	return pl.enqueueRequest(loadReq)
}

func (pl *PolicyLoader) SyncTenant(ctx context.Context, req *service.SyncTenantRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id", "Tenant ID is required", req.TenantID)
	}

	loadReq := &LoadRequest{
		Type:      LoadTypeTenantSync,
		TenantID:  req.TenantID,
		Priority:  PriorityHigh,
		CreatedAt: time.Now().UTC(),
		RequestID: utils.GenerateRequestID(),
	}

	return pl.enqueueRequest(loadReq)
}

func (pl *PolicyLoader) FullSync(ctx context.Context) error {
	loadReq := &LoadRequest{
		Type:      LoadTypeFullSync,
		Priority:  PriorityCritical,
		CreatedAt: time.Now().UTC(),
		RequestID: utils.GenerateRequestID(),
	}

	return pl.enqueueRequest(loadReq)
}

func (pl *PolicyLoader) UnloadPolicy(ctx context.Context, req *service.UnloadPolicyRequest) error {
	if err := pl.validateUnloadPolicyRequest(req); err != nil {
		return err
	}

	loadReq := &LoadRequest{
		Type:      LoadTypeUnload,
		TenantID:  req.TenantID,
		PolicyID:  req.PolicyID,
		Priority:  PriorityNormal,
		CreatedAt: time.Now().UTC(),
		RequestID: utils.GenerateRequestID(),
	}

	return pl.enqueueRequest(loadReq)
}

func (pl *PolicyLoader) ReloadPolicy(ctx context.Context, req *service.ReloadPolicyRequest) error {
	if err := pl.validateReloadPolicyRequest(req); err != nil {
		return err
	}

	loadReq := &LoadRequest{
		Type:      LoadTypeReload,
		TenantID:  req.TenantID,
		PolicyID:  req.PolicyID,
		Priority:  PriorityHigh,
		CreatedAt: time.Now().UTC(),
		RequestID: utils.GenerateRequestID(),
	}

	return pl.enqueueRequest(loadReq)
}

func (pl *PolicyLoader) enqueueRequest(req *LoadRequest) error {
	pl.mu.RLock()
	if !pl.isRunning {
		pl.mu.RUnlock()
		return errors.NewServiceUnavailable("Policy loader is not running")
	}
	pl.mu.RUnlock()

	select {
	case pl.loadQueue <- req:
		pl.metrics.mu.Lock()
		pl.metrics.TotalRequests++
		pl.metrics.QueueSize = len(pl.loadQueue)
		pl.metrics.mu.Unlock()

		pl.logger.Debug("Load request enqueued",
			zap.String("request_id", req.RequestID),
			zap.String("type", string(req.Type)),
			zap.String("tenant_id", req.TenantID),
			zap.Int("priority", int(req.Priority)))

		return nil
	default:
		return errors.NewServiceUnavailable("Load queue is full")
	}
}

func (w *LoadWorker) start() {
	w.logger.Info("Load worker started")

	for {
		select {
		case req := <-w.loader.loadQueue:
			w.processRequest(req)
		case <-w.stopChan:
			w.logger.Info("Load worker stopped")
			return
		}
	}
}

func (w *LoadWorker) processRequest(req *LoadRequest) {
	start := time.Now()
	ctx := context.Background()

	w.logger.Debug("Processing load request",
		zap.String("request_id", req.RequestID),
		zap.String("type", string(req.Type)),
		zap.String("tenant_id", req.TenantID))

	result := &LoadResult{
		RequestID: req.RequestID,
		Type:      req.Type,
		Timestamp: time.Now().UTC(),
		Metadata:  make(map[string]interface{}),
	}

	switch req.Type {
	case LoadTypePolicy:
		w.processLoadPolicy(ctx, req, result)
	case LoadTypeBundle:
		w.processLoadBundle(ctx, req, result)
	case LoadTypeTenantSync:
		w.processTenantSync(ctx, req, result)
	case LoadTypeFullSync:
		w.processFullSync(ctx, req, result)
	case LoadTypeUnload:
		w.processUnloadPolicy(ctx, req, result)
	case LoadTypeReload:
		w.processReloadPolicy(ctx, req, result)
	default:
		result.Success = false
		result.Error = fmt.Sprintf("Unknown load request type: %s", req.Type)
	}

	result.Duration = time.Since(start)

	w.loader.recordMetrics(result)

	if req.Callback != nil {
		req.Callback(result)
	}

	w.logger.Debug("Load request processed",
		zap.String("request_id", req.RequestID),
		zap.Bool("success", result.Success),
		zap.Duration("duration", result.Duration),
		zap.Int("policies_loaded", result.PoliciesLoaded))
}

func (w *LoadWorker) processLoadPolicy(ctx context.Context, req *LoadRequest, result *LoadResult) {
	pol, err := w.loader.policyStore.GetPolicy(ctx, &service.GetPolicyRequest{
		ID:       req.PolicyID,
		TenantID: req.TenantID,
	})
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to get policy: %v", err)
		return
	}

	if pol.Status != policy.PolicyStatusActive {
		result.Success = false
		result.Error = fmt.Sprintf("Policy is not active: %s", pol.Status)
		return
	}

	template := w.generatePolicyTemplate(pol)
	regoPolicy := w.generateRegoPolicy(template)

	policyDoc := &PolicyDocument{
		ID:      pol.ID,
		Path:    fmt.Sprintf("tenants/%s/policies/%s", pol.TenantID, pol.ID),
		Content: regoPolicy,
		Metadata: map[string]interface{}{
			"tenant_id":   pol.TenantID,
			"policy_name": pol.Name,
			"version":     pol.Version,
			"priority":    pol.Priority,
			"loaded_at":   time.Now().UTC(),
		},
	}

	if err := w.loader.client.UploadPolicy(ctx, policyDoc); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to upload policy to OPA: %v", err)
		return
	}

	result.Success = true
	result.PoliciesLoaded = 1
	result.Metadata["policy_name"] = pol.Name
	result.Metadata["policy_version"] = pol.Version
}

func (w *LoadWorker) processLoadBundle(ctx context.Context, req *LoadRequest, result *LoadResult) {
	bundle, err := w.loader.bundleManager.GetBundle(ctx, &service.GetBundleRequest{
		ID:       req.BundleID,
		TenantID: req.TenantID,
	})
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to get bundle: %v", err)
		return
	}

	if bundle.Status != policy.PolicyStatusActive {
		result.Success = false
		result.Error = fmt.Sprintf("Bundle is not active: %s", bundle.Status)
		return
	}

	loaded := 0
	failed := 0

	for _, policyID := range bundle.Policies {
		pol, err := w.loader.policyStore.GetPolicy(ctx, &service.GetPolicyRequest{
			ID:       policyID,
			TenantID: req.TenantID,
		})
		if err != nil {
			failed++
			w.logger.Error("Failed to get policy from bundle",
				zap.String("policy_id", policyID),
				zap.String("bundle_id", req.BundleID),
				zap.Error(err))
			continue
		}

		if pol.Status != policy.PolicyStatusActive {
			failed++
			continue
		}

		template := w.generatePolicyTemplate(pol)
		regoPolicy := w.generateRegoPolicy(template)

		policyDoc := &PolicyDocument{
			ID:      pol.ID,
			Path:    fmt.Sprintf("tenants/%s/policies/%s", pol.TenantID, pol.ID),
			Content: regoPolicy,
			Metadata: map[string]interface{}{
				"tenant_id":   pol.TenantID,
				"policy_name": pol.Name,
				"version":     pol.Version,
				"bundle_id":   req.BundleID,
				"bundle_name": bundle.Name,
				"loaded_at":   time.Now().UTC(),
			},
		}

		if err := w.loader.client.UploadPolicy(ctx, policyDoc); err != nil {
			failed++
			w.logger.Error("Failed to upload policy to OPA",
				zap.String("policy_id", policyID),
				zap.String("bundle_id", req.BundleID),
				zap.Error(err))
		} else {
			loaded++
		}
	}

	result.Success = failed == 0
	result.PoliciesLoaded = loaded
	result.PoliciesFailed = failed
	result.Metadata["bundle_name"] = bundle.Name
	result.Metadata["bundle_version"] = bundle.Version

	if failed > 0 {
		result.Error = fmt.Sprintf("Failed to load %d out of %d policies", failed, len(bundle.Policies))
	}
}

func (w *LoadWorker) processTenantSync(ctx context.Context, req *LoadRequest, result *LoadResult) {
	policies, _, err := w.loader.policyStore.ListPolicies(ctx, &service.ListPoliciesRequest{
		TenantID: req.TenantID,
		Status:   policy.PolicyStatusActive,
		Limit:    1000,
		Offset:   0,
	})
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to list tenant policies: %v", err)
		return
	}

	loaded := 0
	failed := 0

	for _, pol := range policies.Policies {
		template := w.generatePolicyTemplate(&pol)
		regoPolicy := w.generateRegoPolicy(template)

		policyDoc := &PolicyDocument{
			ID:      pol.ID,
			Path:    fmt.Sprintf("tenants/%s/policies/%s", pol.TenantID, pol.ID),
			Content: regoPolicy,
			Metadata: map[string]interface{}{
				"tenant_id":   pol.TenantID,
				"policy_name": pol.Name,
				"version":     pol.Version,
				"sync_type":   "tenant_sync",
				"loaded_at":   time.Now().UTC(),
			},
		}

		if err := w.loader.client.UploadPolicy(ctx, policyDoc); err != nil {
			failed++
			w.logger.Error("Failed to sync policy for tenant",
				zap.String("policy_id", pol.ID),
				zap.String("tenant_id", req.TenantID),
				zap.Error(err))
		} else {
			loaded++
		}
	}

	result.Success = failed == 0
	result.PoliciesLoaded = loaded
	result.PoliciesFailed = failed
	result.Metadata["tenant_id"] = req.TenantID
	result.Metadata["total_policies"] = len(policies.Policies)

	if failed > 0 {
		result.Error = fmt.Sprintf("Failed to sync %d out of %d policies", failed, len(policies.Policies))
	}
}

func (w *LoadWorker) processFullSync(ctx context.Context, req *LoadRequest, result *LoadResult) {
	tenants, err := w.getActiveTenants(ctx)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to get active tenants: %v", err)
		return
	}

	totalLoaded := 0
	totalFailed := 0

	for _, tenantID := range tenants {
		policies, _, err := w.loader.policyStore.ListPolicies(ctx, &service.ListPoliciesRequest{
			TenantID: tenantID,
			Status:   policy.PolicyStatusActive,
			Limit:    1000,
			Offset:   0,
		})
		if err != nil {
			w.logger.Error("Failed to list policies for tenant during full sync",
				zap.String("tenant_id", tenantID),
				zap.Error(err))
			continue
		}

		for _, pol := range policies.Policies {
			template := w.generatePolicyTemplate(&pol)
			regoPolicy := w.generateRegoPolicy(template)

			policyDoc := &PolicyDocument{
				ID:      pol.ID,
				Path:    fmt.Sprintf("tenants/%s/policies/%s", pol.TenantID, pol.ID),
				Content: regoPolicy,
				Metadata: map[string]interface{}{
					"tenant_id":   pol.TenantID,
					"policy_name": pol.Name,
					"version":     pol.Version,
					"sync_type":   "full_sync",
					"loaded_at":   time.Now().UTC(),
				},
			}

			if err := w.loader.client.UploadPolicy(ctx, policyDoc); err != nil {
				totalFailed++
				w.logger.Error("Failed to sync policy during full sync",
					zap.String("policy_id", pol.ID),
					zap.String("tenant_id", tenantID),
					zap.Error(err))
			} else {
				totalLoaded++
			}
		}
	}

	result.Success = totalFailed == 0
	result.PoliciesLoaded = totalLoaded
	result.PoliciesFailed = totalFailed
	result.Metadata["tenants_synced"] = len(tenants)
	result.Metadata["total_policies"] = totalLoaded + totalFailed

	if totalFailed > 0 {
		result.Error = fmt.Sprintf("Failed to sync %d out of %d policies across %d tenants", totalFailed, totalLoaded+totalFailed, len(tenants))
	}
}

func (w *LoadWorker) processUnloadPolicy(ctx context.Context, req *LoadRequest, result *LoadResult) {
	if err := w.loader.client.DeletePolicy(ctx, req.PolicyID); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to unload policy from OPA: %v", err)
		return
	}

	result.Success = true
	result.Metadata["policy_id"] = req.PolicyID
	result.Metadata["tenant_id"] = req.TenantID
}

func (w *LoadWorker) processReloadPolicy(ctx context.Context, req *LoadRequest, result *LoadResult) {
	if err := w.loader.client.DeletePolicy(ctx, req.PolicyID); err != nil {
		w.logger.Warn("Failed to delete policy during reload, continuing with upload",
			zap.String("policy_id", req.PolicyID),
			zap.Error(err))
	}

	pol, err := w.loader.policyStore.GetPolicy(ctx, &service.GetPolicyRequest{
		ID:       req.PolicyID,
		TenantID: req.TenantID,
	})
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to get policy for reload: %v", err)
		return
	}

	if pol.Status != policy.PolicyStatusActive {
		result.Success = false
		result.Error = fmt.Sprintf("Policy is not active: %s", pol.Status)
		return
	}

	template := w.generatePolicyTemplate(pol)
	regoPolicy := w.generateRegoPolicy(template)

	policyDoc := &PolicyDocument{
		ID:      pol.ID,
		Path:    fmt.Sprintf("tenants/%s/policies/%s", pol.TenantID, pol.ID),
		Content: regoPolicy,
		Metadata: map[string]interface{}{
			"tenant_id":   pol.TenantID,
			"policy_name": pol.Name,
			"version":     pol.Version,
			"reload_type": "policy_reload",
			"loaded_at":   time.Now().UTC(),
		},
	}

	if err := w.loader.client.UploadPolicy(ctx, policyDoc); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to reload policy to OPA: %v", err)
		return
	}

	result.Success = true
	result.PoliciesLoaded = 1
	result.Metadata["policy_name"] = pol.Name
	result.Metadata["policy_version"] = pol.Version
}

func (w *LoadWorker) generatePolicyTemplate(pol *policy.Policy) *PolicyTemplate {
	packageName := fmt.Sprintf("tenants.%s.policies.%s", pol.TenantID, strings.ReplaceAll(pol.ID, "-", "_"))

	rules := make([]string, 0, len(pol.Rules))
	for i, rule := range pol.Rules {
		ruleStr := fmt.Sprintf(`rule_%d {
    input.resource == "%s"
    input.action == "%s"`, i, rule.Resource, rule.Action)

		for _, condition := range rule.Conditions {
			ruleStr += fmt.Sprintf(`
    input.%s %s %v`, condition.Field, condition.Operator, condition.Value)
		}

		ruleStr += "\n}"
		rules = append(rules, ruleStr)
	}

	return &PolicyTemplate{
		TenantID:    pol.TenantID,
		PolicyID:    pol.ID,
		PackageName: packageName,
		Rules:       rules,
		Data: map[string]interface{}{
			"policy_id":   pol.ID,
			"policy_name": pol.Name,
			"version":     pol.Version,
			"priority":    pol.Priority,
			"effect":      pol.Effect,
		},
		Metadata: map[string]interface{}{
			"created_at": pol.CreatedAt,
			"updated_at": pol.UpdatedAt,
			"created_by": pol.CreatedBy,
			"updated_by": pol.UpdatedBy,
		},
	}
}

func (w *LoadWorker) generateRegoPolicy(template *PolicyTemplate) string {
	rego := fmt.Sprintf(`package %s

import future.keywords.if
import future.keywords.in

default allow := false
default deny := false

allow if {
    input.tenant_id == "%s"
    policy_matches
}

deny if {
    input.tenant_id == "%s"
    not policy_matches
}

policy_matches if {
    some rule in rules
    rule
}

rules := [
`, template.PackageName, template.TenantID, template.TenantID)

	for i, rule := range template.Rules {
		if i > 0 {
			rego += ",\n"
		}
		rego += fmt.Sprintf("    %s", rule)
	}

	rego += "\n]\n\n"

	for i, rule := range template.Rules {
		rego += fmt.Sprintf("%s\n\n", rule)
		_ = i
	}

	rego += fmt.Sprintf(`policy_data := {
    "id": "%s",
    "name": "%s",
    "version": "%s",
    "priority": %d,
    "effect": "%s"
}

metadata := %s
`,
		template.Data["policy_id"],
		template.Data["policy_name"],
		template.Data["version"],
		template.Data["priority"],
		template.Data["effect"],
		utils.CoalesceString(utils.ToJSONIndent(template.Metadata)))

	return rego
}

func (w *LoadWorker) getActiveTenants(ctx context.Context) ([]string, error) {
	query := "SELECT DISTINCT tenant_id FROM policies WHERE status = 'active'"

	rows, err := w.loader.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Rows.Close()

	var tenants []string
	for rows.Rows.Next() {
		var tenantID string
		if err := rows.Rows.Scan(&tenantID); err != nil {
			continue
		}
		tenants = append(tenants, tenantID)
	}

	return tenants, nil
}

func (pl *PolicyLoader) recordMetrics(result *LoadResult) {
	pl.metrics.mu.Lock()
	defer pl.metrics.mu.Unlock()

	if result.Success {
		pl.metrics.SuccessfulLoads++
		pl.metrics.PoliciesLoaded += int64(result.PoliciesLoaded)
		
		if result.Type == LoadTypeBundle {
			pl.metrics.BundlesLoaded++
		}
	} else {
		pl.metrics.FailedLoads++
	}

	if pl.metrics.SuccessfulLoads > 0 {
		totalDuration := time.Duration(pl.metrics.SuccessfulLoads-1) * pl.metrics.AverageLoadTime
		pl.metrics.AverageLoadTime = (totalDuration + result.Duration) / time.Duration(pl.metrics.SuccessfulLoads)
	} else {
		pl.metrics.AverageLoadTime = result.Duration
	}

	pl.metrics.LastLoadTime = result.Timestamp
	pl.metrics.QueueSize = len(pl.loadQueue)
}

func (pl *PolicyLoader) validateLoadPolicyRequest(req *service.LoadPolicyRequest) error {
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

func (pl *PolicyLoader) validateLoadBundleRequest(req *service.LoadBundleRequest) error {
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

func (pl *PolicyLoader) validateUnloadPolicyRequest(req *service.UnloadPolicyRequest) error {
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

func (pl *PolicyLoader) validateReloadPolicyRequest(req *service.ReloadPolicyRequest) error {
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

func (pl *PolicyLoader) GetMetrics() *LoaderMetrics {
	pl.metrics.mu.RLock()
	defer pl.metrics.mu.RUnlock()

	metrics := *pl.metrics
	metrics.QueueSize = len(pl.loadQueue)
	
	pl.mu.RLock()
	metrics.ActiveWorkers = len(pl.workers)
	pl.mu.RUnlock()

	return &metrics
}

func (pl *PolicyLoader) GetQueueStatus() map[string]interface{} {
	pl.metrics.mu.RLock()
	defer pl.metrics.mu.RUnlock()

	return map[string]interface{}{
		"queue_size":     len(pl.loadQueue),
		"queue_capacity": cap(pl.loadQueue),
		"utilization":    float64(len(pl.loadQueue)) / float64(cap(pl.loadQueue)) * 100,
		"active_workers": pl.metrics.ActiveWorkers,
		"total_requests": pl.metrics.TotalRequests,
	}
}

func (pl *PolicyLoader) GetHealthStatus() map[string]interface{} {
	pl.mu.RLock()
	isRunning := pl.isRunning
	pl.mu.RUnlock()

	metrics := pl.GetMetrics()
	queueStatus := pl.GetQueueStatus()

	return map[string]interface{}{
		"running": isRunning,
		"healthy": isRunning && metrics.ActiveWorkers > 0,
		"metrics": map[string]interface{}{
			"total_requests":     metrics.TotalRequests,
			"successful_loads":   metrics.SuccessfulLoads,
			"failed_loads":       metrics.FailedLoads,
			"average_load_time":  metrics.AverageLoadTime.Milliseconds(),
			"policies_loaded":    metrics.PoliciesLoaded,
			"bundles_loaded":     metrics.BundlesLoaded,
			"last_load_time":     metrics.LastLoadTime,
		},
		"queue": queueStatus,
	}
}

func (pl *PolicyLoader) IsRunning() bool {
	pl.mu.RLock()
	defer pl.mu.RUnlock()
	return pl.isRunning
}

func (pl *PolicyLoader) GetWorkerCount() int {
	pl.mu.RLock()
	defer pl.mu.RUnlock()
	return len(pl.workers)
}

func (pl *PolicyLoader) ClearQueue() int {
	cleared := 0
	
	for {
		select {
		case <-pl.loadQueue:
			cleared++
		default:
			pl.metrics.mu.Lock()
			pl.metrics.QueueSize = len(pl.loadQueue)
			pl.metrics.mu.Unlock()
			return cleared
		}
	}
}

func (pl *PolicyLoader) HealthCheck() error {
	pl.mu.RLock()
	isRunning := pl.isRunning
	workerCount := len(pl.workers)
	pl.mu.RUnlock()

	if !isRunning {
		return errors.NewServiceUnavailable("Policy loader is not running")
	}

	if workerCount == 0 {
		return errors.NewServiceUnavailable("No active workers")
	}

	queueSize := len(pl.loadQueue)
	queueCapacity := cap(pl.loadQueue)
	
	if float64(queueSize)/float64(queueCapacity) > 0.9 {
		return errors.NewServiceUnavailable("Load queue is nearly full")
	}

	return nil
}

func (pl *PolicyLoader) Close() error {
	pl.logger.Info("Shutting down policy loader")

	if err := pl.Stop(); err != nil {
		pl.logger.Error("Failed to stop policy loader", zap.Error(err))
	}

	pl.ClearQueue()

	pl.logger.Info("Policy loader shutdown completed")
	return nil
}
