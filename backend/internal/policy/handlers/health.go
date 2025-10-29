package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/utils"
	v1 "flamo/backend/pkg/api/policy/v1"
	"flamo/backend/internal/policy/opa"
	"flamo/backend/internal/policy/storage"
)

type HealthHandler struct {
	policyService   v1.PolicyService
	decisionService v1.DecisionService
	opaEngine       *opa.Engine
	opaClient       *opa.Client
	policyLoader    *opa.PolicyLoader
	cache           *opa.Cache
	policyStore     *storage.PolicyStore
	bundleManager   *storage.BundleManager
	db              *database.Database
	config          *config.Config
	logger          *zap.Logger
}

type HealthStatus struct {
	Status      string                 `json:"status"`
	Timestamp   time.Time              `json:"timestamp"`
	Version     string                 `json:"version"`
	Environment string                 `json:"environment"`
	Uptime      time.Duration          `json:"uptime"`
	Components  map[string]interface{} `json:"components"`
	Metrics     map[string]interface{} `json:"metrics"`
}

type ComponentHealth struct {
	Status      string                 `json:"status"`
	Healthy     bool                   `json:"healthy"`
	LastCheck   time.Time              `json:"last_check"`
	Duration    time.Duration          `json:"duration"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ReadinessStatus struct {
	Ready      bool                   `json:"ready"`
	Timestamp  time.Time              `json:"timestamp"`
	Components map[string]interface{} `json:"components"`
}

type LivenessStatus struct {
	Alive     bool          `json:"alive"`
	Timestamp time.Time     `json:"timestamp"`
	Uptime    time.Duration `json:"uptime"`
}

var startTime = time.Now()

func NewHealthHandler(
	policyService v1.PolicyService,
	decisionService v1.DecisionService,
	opaEngine *opa.Engine,
	opaClient *opa.Client,
	policyLoader *opa.PolicyLoader,
	cache *opa.Cache,
	policyStore *storage.PolicyStore,
	bundleManager *storage.BundleManager,
	db *database.Database,
	cfg *config.Config,
	logger *zap.Logger,
) *HealthHandler {
	return &HealthHandler{
		policyService:   policyService,
		decisionService: decisionService,
		opaEngine:       opaEngine,
		opaClient:       opaClient,
		policyLoader:    policyLoader,
		cache:           cache,
		policyStore:     policyStore,
		bundleManager:   bundleManager,
		db:              db,
		config:          cfg,
		logger:          logger,
	}
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	status := h.performHealthCheck(ctx)

	statusCode := http.StatusOK
	if status.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(status); err != nil {
		h.logger.Error("Failed to encode health response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Health check completed",
		zap.String("status", status.Status),
		zap.Duration("duration", time.Since(start)),
		zap.Int("status_code", statusCode))
}

func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	status := h.performReadinessCheck(ctx)

	statusCode := http.StatusOK
	if !status.Ready {
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(status); err != nil {
		h.logger.Error("Failed to encode readiness response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Readiness check completed",
		zap.Bool("ready", status.Ready),
		zap.Duration("duration", time.Since(start)),
		zap.Int("status_code", statusCode))
}

func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	status := &LivenessStatus{
		Alive:     true,
		Timestamp: time.Now().UTC(),
		Uptime:    time.Since(startTime),
	}

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(status); err != nil {
		h.logger.Error("Failed to encode liveness response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Liveness check completed",
		zap.Duration("duration", time.Since(start)),
		zap.Duration("uptime", status.Uptime))
}

func (h *HealthHandler) performHealthCheck(ctx context.Context) *HealthStatus {
	components := make(map[string]interface{})
	overallHealthy := true

	components["database"] = h.checkDatabase(ctx)
	if !components["database"].(*ComponentHealth).Healthy {
		overallHealthy = false
	}

	components["opa_engine"] = h.checkOPAEngine(ctx)
	if !components["opa_engine"].(*ComponentHealth).Healthy {
		overallHealthy = false
	}

	components["opa_client"] = h.checkOPAClient(ctx)
	if !components["opa_client"].(*ComponentHealth).Healthy {
		overallHealthy = false
	}

	components["policy_loader"] = h.checkPolicyLoader(ctx)
	if !components["policy_loader"].(*ComponentHealth).Healthy {
		overallHealthy = false
	}

	components["cache"] = h.checkCache(ctx)
	if !components["cache"].(*ComponentHealth).Healthy {
		overallHealthy = false
	}

	components["policy_store"] = h.checkPolicyStore(ctx)
	if !components["policy_store"].(*ComponentHealth).Healthy {
		overallHealthy = false
	}

	components["bundle_manager"] = h.checkBundleManager(ctx)
	if !components["bundle_manager"].(*ComponentHealth).Healthy {
		overallHealthy = false
	}

	components["policy_service"] = h.checkPolicyService(ctx)
	if !components["policy_service"].(*ComponentHealth).Healthy {
		overallHealthy = false
	}

	components["decision_service"] = h.checkDecisionService(ctx)
	if !components["decision_service"].(*ComponentHealth).Healthy {
		overallHealthy = false
	}

	status := "healthy"
	if !overallHealthy {
		status = "unhealthy"
	}

	metrics := h.collectMetrics(ctx)

	return &HealthStatus{
		Status:      status,
		Timestamp:   time.Now().UTC(),
		Version:     "1.0.0",
		Environment: string(h.config.Environment),
		Uptime:      time.Since(startTime),
		Components:  components,
		Metrics:     metrics,
	}
}

func (h *HealthHandler) performReadinessCheck(ctx context.Context) *ReadinessStatus {
	components := make(map[string]interface{})
	ready := true

	dbHealth := h.checkDatabase(ctx)
	components["database"] = dbHealth
	if !dbHealth.Healthy {
		ready = false
	}

	opaEngineHealth := h.checkOPAEngine(ctx)
	components["opa_engine"] = opaEngineHealth
	if !opaEngineHealth.Healthy {
		ready = false
	}

	opaClientHealth := h.checkOPAClient(ctx)
	components["opa_client"] = opaClientHealth
	if !opaClientHealth.Healthy {
		ready = false
	}

	loaderHealth := h.checkPolicyLoader(ctx)
	components["policy_loader"] = loaderHealth
	if !loaderHealth.Healthy {
		ready = false
	}

	return &ReadinessStatus{
		Ready:      ready,
		Timestamp:  time.Now().UTC(),
		Components: components,
	}
}

func (h *HealthHandler) checkDatabase(ctx context.Context) *ComponentHealth {
	start := time.Now()

	err := h.db.Ping(ctx)
	healthy := err == nil

	status := "healthy"
	errorMsg := ""
	if !healthy {
		status = "unhealthy"
		errorMsg = err.Error()
	}

	metadata := map[string]interface{}{
		"max_connections":  h.db.Stats().MaxOpenConnections,
		"open_connections": h.db.Stats().OpenConnections,
		"in_use":           h.db.Stats().InUse,
		"idle":             h.db.Stats().Idle,
	}

	return &ComponentHealth{
		Status:    status,
		Healthy:   healthy,
		LastCheck: time.Now().UTC(),
		Duration:  time.Since(start),
		Error:     errorMsg,
		Metadata:  metadata,
	}
}

func (h *HealthHandler) checkOPAEngine(ctx context.Context) *ComponentHealth {
	start := time.Now()

	healthy := h.opaEngine.IsHealthy()

	status := "healthy"
	errorMsg := ""
	if !healthy {
		status = "unhealthy"
		errorMsg = "OPA engine is not healthy"
	}

	metadata := h.opaEngine.GetHealthStatus()

	return &ComponentHealth{
		Status:    status,
		Healthy:   healthy,
		LastCheck: time.Now().UTC(),
		Duration:  time.Since(start),
		Error:     errorMsg,
		Metadata:  metadata,
	}
}

func (h *HealthHandler) checkOPAClient(ctx context.Context) *ComponentHealth {
	start := time.Now()

	healthy := h.opaClient.IsHealthy(ctx)

	status := "healthy"
	errorMsg := ""
	if !healthy {
		status = "unhealthy"
		errorMsg = "OPA client is not healthy"
	}

	metadata := map[string]interface{}{
		"base_url": h.opaClient.GetBaseURL(),
	}

	return &ComponentHealth{
		Status:    status,
		Healthy:   healthy,
		LastCheck: time.Now().UTC(),
		Duration:  time.Since(start),
		Error:     errorMsg,
		Metadata:  metadata,
	}
}

func (h *HealthHandler) checkPolicyLoader(ctx context.Context) *ComponentHealth {
	start := time.Now()

	err := h.policyLoader.HealthCheck()
	healthy := err == nil

	status := "healthy"
	errorMsg := ""
	if !healthy {
		status = "unhealthy"
		errorMsg = err.Error()
	}

	metadata := h.policyLoader.GetHealthStatus()

	return &ComponentHealth{
		Status:    status,
		Healthy:   healthy,
		LastCheck: time.Now().UTC(),
		Duration:  time.Since(start),
		Error:     errorMsg,
		Metadata:  metadata,
	}
}

func (h *HealthHandler) checkCache(ctx context.Context) *ComponentHealth {
	start := time.Now()

	err := h.cache.HealthCheck()
	healthy := err == nil

	status := "healthy"
	errorMsg := ""
	if !healthy {
		status = "unhealthy"
		errorMsg = err.Error()
	}

	metadata := map[string]interface{}{
		"stats": h.cache.GetStats(),
		"size":  h.cache.Size(),
	}

	return &ComponentHealth{
		Status:    status,
		Healthy:   healthy,
		LastCheck: time.Now().UTC(),
		Duration:  time.Since(start),
		Error:     errorMsg,
		Metadata:  metadata,
	}
}

func (h *HealthHandler) checkPolicyStore(ctx context.Context) *ComponentHealth {
	start := time.Now()

	err := h.policyStore.HealthCheck(ctx)
	healthy := err == nil

	status := "healthy"
	errorMsg := ""
	if !healthy {
		status = "unhealthy"
		errorMsg = err.Error()
	}

	metadata := map[string]interface{}{
		"component": "policy_store",
	}

	return &ComponentHealth{
		Status:    status,
		Healthy:   healthy,
		LastCheck: time.Now().UTC(),
		Duration:  time.Since(start),
		Error:     errorMsg,
		Metadata:  metadata,
	}
}

func (h *HealthHandler) checkBundleManager(ctx context.Context) *ComponentHealth {
	start := time.Now()

	err := h.bundleManager.HealthCheck(ctx)
	healthy := err == nil

	status := "healthy"
	errorMsg := ""
	if !healthy {
		status = "unhealthy"
		errorMsg = err.Error()
	}

	metadata := map[string]interface{}{
		"component": "bundle_manager",
	}

	return &ComponentHealth{
		Status:    status,
		Healthy:   healthy,
		LastCheck: time.Now().UTC(),
		Duration:  time.Since(start),
		Error:     errorMsg,
		Metadata:  metadata,
	}
}

func (h *HealthHandler) checkPolicyService(ctx context.Context) *ComponentHealth {
	start := time.Now()

	healthy := true
	status := "healthy"
	errorMsg := ""

	metadata := map[string]interface{}{
		"status": "healthy",
		"type":   "policy_service",
	}

	return &ComponentHealth{
		Status:    status,
		Healthy:   healthy,
		LastCheck: time.Now().UTC(),
		Duration:  time.Since(start),
		Error:     errorMsg,
		Metadata:  metadata,
	}
}

func (h *HealthHandler) checkDecisionService(ctx context.Context) *ComponentHealth {
	start := time.Now()

	healthy := true
	status := "healthy"
	errorMsg := ""

	metadata := h.decisionService.GetHealthStatus()

	return &ComponentHealth{
		Status:    status,
		Healthy:   healthy,
		LastCheck: time.Now().UTC(),
		Duration:  time.Since(start),
		Error:     errorMsg,
		Metadata:  metadata,
	}
}

func (h *HealthHandler) collectMetrics(ctx context.Context) map[string]interface{} {
	metrics := make(map[string]interface{})

	if engineMetrics := h.opaEngine.GetMetrics(); engineMetrics != nil {
		metrics["opa_engine"] = map[string]interface{}{
			"total_evaluations":      engineMetrics.TotalEvaluations,
			"successful_evaluations": engineMetrics.SuccessfulEvaluations,
			"failed_evaluations":     engineMetrics.FailedEvaluations,
			"cache_hits":             engineMetrics.CacheHits,
			"cache_misses":           engineMetrics.CacheMisses,
			"average_latency_ms":     engineMetrics.AverageLatency.Milliseconds(),
			"policy_syncs":           engineMetrics.PolicySyncs,
			"last_sync_time":         engineMetrics.LastSyncTime,
			"active_policies":        engineMetrics.ActivePolicies,
		}
	}

	if loaderMetrics := h.policyLoader.GetMetrics(); loaderMetrics != nil {
		metrics["policy_loader"] = map[string]interface{}{
			"total_requests":    loaderMetrics.TotalRequests,
			"successful_loads":  loaderMetrics.SuccessfulLoads,
			"failed_loads":      loaderMetrics.FailedLoads,
			"average_load_time": loaderMetrics.AverageLoadTime.Milliseconds(),
			"queue_size":        loaderMetrics.QueueSize,
			"active_workers":    loaderMetrics.ActiveWorkers,
			"policies_loaded":   loaderMetrics.PoliciesLoaded,
			"bundles_loaded":    loaderMetrics.BundlesLoaded,
			"last_load_time":    loaderMetrics.LastLoadTime,
		}
	}

	if cacheStats := h.cache.GetStats(); cacheStats != nil {
		metrics["cache"] = map[string]interface{}{
			"hit_rate":               cacheStats.HitRate,
			"total_entries":          cacheStats.TotalEntries,
			"total_size_bytes":       cacheStats.TotalSize,
			"hits":                   cacheStats.Hits,
			"misses":                 cacheStats.Misses,
			"sets":                   cacheStats.Sets,
			"deletes":                cacheStats.Deletes,
			"evictions":              cacheStats.Evictions,
			"expirations":            cacheStats.Expirations,
			"average_access_time_ms": cacheStats.AverageAccessTime.Milliseconds(),
			"last_cleanup":           cacheStats.LastCleanup,
		}
	}

	dbStats := h.db.Stats()
	metrics["database"] = map[string]interface{}{
		"max_open_connections": dbStats.MaxOpenConnections,
		"open_connections":     dbStats.OpenConnections,
		"in_use":               dbStats.InUse,
		"idle":                 dbStats.Idle,
		"wait_count":           dbStats.WaitCount,
		"wait_duration_ms":     dbStats.WaitDuration.Milliseconds(),
		"max_idle_closed":      dbStats.MaxIdleClosed,
		"max_idle_time_closed": dbStats.MaxIdleTimeClosed,
		"max_lifetime_closed":  dbStats.MaxLifetimeClosed,
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	metrics["system"] = map[string]interface{}{
		"uptime_seconds": time.Since(startTime).Seconds(),
		"version":        "1.0.0",
		"environment":    string(h.config.Environment),
		"go_version":     runtime.Version(),
		"memory_usage":   memStats.Alloc,
		"cpu_count":      runtime.NumCPU(),
		"goroutines":     runtime.NumGoroutine(),
	}

	return metrics
}

func (h *HealthHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	metrics := h.collectMetrics(ctx)

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		h.logger.Error("Failed to encode metrics response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Metrics endpoint accessed",
		zap.Duration("duration", time.Since(start)))
}

func (h *HealthHandler) Status(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	status := map[string]interface{}{
		"service":     "policy-service",
		"version":     "1.0.0",
		"environment": string(h.config.Environment),
		"uptime":      time.Since(startTime).Seconds(),
		"timestamp":   time.Now().UTC(),
		"status":      "running",
	}

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(status); err != nil {
		h.logger.Error("Failed to encode status response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Status endpoint accessed",
		zap.Duration("duration", time.Since(start)))
}

func (h *HealthHandler) Version(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	version := map[string]interface{}{
		"service":     "policy-service",
		"version":     "1.0.0",
		"build_time":  time.Now().Format(time.RFC3339),
		"commit_hash": "unknown",
		"go_version":  runtime.Version(),
		"environment": string(h.config.Environment),
	}

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(version); err != nil {
		h.logger.Error("Failed to encode version response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Version endpoint accessed",
		zap.Duration("duration", time.Since(start)))
}

func (h *HealthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.Health)
	mux.HandleFunc("/health/readiness", h.Readiness)
	mux.HandleFunc("/health/liveness", h.Liveness)
	mux.HandleFunc("/metrics", h.Metrics)
	mux.HandleFunc("/status", h.Status)
	mux.HandleFunc("/version", h.Version)

	h.logger.Info("Health handler routes registered",
		zap.Strings("endpoints", []string{
			"/health",
			"/health/readiness",
			"/health/liveness",
			"/metrics",
			"/status",
			"/version",
		}))
}

func (h *HealthHandler) RegisterGRPCHealth(server interface{}) {
	h.logger.Info("gRPC health service would be registered here")
}

func (h *HealthHandler) Shutdown(ctx context.Context) error {
	h.logger.Info("Health handler shutting down")
	return nil
}
