package handlers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	"flamo/backend/internal/policy/service"
	"flamo/backend/internal/policy/opa"
	"flamo/backend/internal/policy/storage"
)

type Server struct {
	httpServer      *http.Server
	router          *mux.Router
	healthHandler   *HealthHandler
	policyHandler   *PolicyHandler
	decisionHandler *DecisionHandler
	policyService   *service.PolicyService
	decisionService *service.DecisionService
	opaEngine       *opa.Engine
	opaClient       *opa.Client
	policyLoader    *opa.PolicyLoader
	cache           *opa.Cache
	policyStore     *storage.PolicyStore
	bundleManager   *storage.BundleManager
	db              *database.Database
	config          *config.Config
	logger          *zap.Logger
	shutdownTimeout time.Duration
	isRunning       bool
	mu              sync.RWMutex
}

type ServerConfig struct {
	Host            string        `json:"host"`
	Port            int           `json:"port"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	IdleTimeout     time.Duration `json:"idle_timeout"`
	ShutdownTimeout time.Duration `json:"shutdown_timeout"`
	MaxHeaderBytes  int           `json:"max_header_bytes"`
	EnableTLS       bool          `json:"enable_tls"`
	TLSCertFile     string        `json:"tls_cert_file"`
	TLSKeyFile      string        `json:"tls_key_file"`
	EnableCORS      bool          `json:"enable_cors"`
	EnableMetrics   bool          `json:"enable_metrics"`
	EnablePprof     bool          `json:"enable_pprof"`
}

type ServerMetrics struct {
	StartTime       time.Time     `json:"start_time"`
	Uptime          time.Duration `json:"uptime"`
	RequestCount    int64         `json:"request_count"`
	ErrorCount      int64         `json:"error_count"`
	ActiveRequests  int64         `json:"active_requests"`
	AverageLatency  time.Duration `json:"average_latency"`
	TotalLatency    time.Duration `json:"total_latency"`
	mu              sync.RWMutex
}

func NewServer(
	policyService *service.PolicyService,
	decisionService *service.DecisionService,
	opaEngine *opa.Engine,
	opaClient *opa.Client,
	policyLoader *opa.PolicyLoader,
	cache *opa.Cache,
	policyStore *storage.PolicyStore,
	bundleManager *storage.BundleManager,
	db *database.Database,
	cfg *config.Config,
	logger *zap.Logger,
) *Server {
	router := mux.NewRouter()

	healthHandler := NewHealthHandler(
		policyService,
		decisionService,
		opaEngine,
		opaClient,
		policyLoader,
		cache,
		policyStore,
		bundleManager,
		db,
		cfg,
		logger,
	)

	policyHandler := NewPolicyHandler(policyService, cfg, logger)
	decisionHandler := NewDecisionHandler(decisionService, cfg, logger)

	serverConfig := getServerConfig(cfg)

	httpServer := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
		Handler:        router,
		ReadTimeout:    serverConfig.ReadTimeout,
		WriteTimeout:   serverConfig.WriteTimeout,
		IdleTimeout:    serverConfig.IdleTimeout,
		MaxHeaderBytes: serverConfig.MaxHeaderBytes,
	}

	server := &Server{
		httpServer:      httpServer,
		router:          router,
		healthHandler:   healthHandler,
		policyHandler:   policyHandler,
		decisionHandler: decisionHandler,
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
		shutdownTimeout: serverConfig.ShutdownTimeout,
	}

	server.setupRoutes()
	server.setupMiddleware()

	return server
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isRunning {
		return errors.NewConflictError("Server is already running")
	}

	if err := s.validateDependencies(); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to validate dependencies")
	}

	if err := s.startDependencies(); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to start dependencies")
	}

	s.isRunning = true

	serverConfig := getServerConfig(s.config)

	s.logger.Info("Starting policy service server",
		zap.String("address", s.httpServer.Addr),
		zap.Bool("tls_enabled", serverConfig.EnableTLS),
		zap.Duration("read_timeout", serverConfig.ReadTimeout),
		zap.Duration("write_timeout", serverConfig.WriteTimeout),
		zap.Duration("shutdown_timeout", s.shutdownTimeout))

	go s.handleShutdown()

	if serverConfig.EnableTLS {
		if serverConfig.TLSCertFile == "" || serverConfig.TLSKeyFile == "" {
			return errors.NewValidationError("tls_config", "TLS cert and key files are required when TLS is enabled", nil)
		}

		s.logger.Info("Starting HTTPS server",
			zap.String("cert_file", serverConfig.TLSCertFile),
			zap.String("key_file", serverConfig.TLSKeyFile))

		if err := s.httpServer.ListenAndServeTLS(serverConfig.TLSCertFile, serverConfig.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			s.isRunning = false
			return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to start HTTPS server")
		}
	} else {
		s.logger.Info("Starting HTTP server")

		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.isRunning = false
			return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to start HTTP server")
		}
	}

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRunning {
		return nil
	}

	s.logger.Info("Shutting down policy service server")

	shutdownCtx, cancel := context.WithTimeout(ctx, s.shutdownTimeout)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("Failed to gracefully shutdown HTTP server", zap.Error(err))
		return err
	}

	if err := s.stopDependencies(shutdownCtx); err != nil {
		s.logger.Error("Failed to stop dependencies", zap.Error(err))
		return err
	}

	s.isRunning = false

	s.logger.Info("Policy service server shutdown completed")
	return nil
}

func (s *Server) setupRoutes() {
	s.healthHandler.RegisterRoutes(s.router)
	s.policyHandler.RegisterRoutes(s.router)
	s.decisionHandler.RegisterRoutes(s.router)

	s.router.HandleFunc("/", s.handleRoot).Methods("GET")
	s.router.HandleFunc("/ping", s.handlePing).Methods("GET")

	serverConfig := getServerConfig(s.config)

	if serverConfig.EnablePprof {
		s.setupPprofRoutes()
	}

	s.router.NotFoundHandler = http.HandlerFunc(s.handleNotFound)
	s.router.MethodNotAllowedHandler = http.HandlerFunc(s.handleMethodNotAllowed)

	s.logger.Info("Server routes configured",
		zap.Bool("pprof_enabled", serverConfig.EnablePprof))
}

func (s *Server) setupMiddleware() {
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.recoveryMiddleware)
	s.router.Use(s.securityMiddleware)
	s.router.Use(s.metricsMiddleware)

	serverConfig := getServerConfig(s.config)

	if serverConfig.EnableCORS {
		s.router.Use(s.corsMiddleware)
	}

	s.logger.Info("Server middleware configured",
		zap.Bool("cors_enabled", serverConfig.EnableCORS),
		zap.Bool("metrics_enabled", serverConfig.EnableMetrics))
}

func (s *Server) setupPprofRoutes() {
	pprofRouter := s.router.PathPrefix("/debug/pprof").Subrouter()
	
	pprofRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/debug/pprof/", http.StatusMovedPermanently)
	})
	
	pprofRouter.PathPrefix("/").Handler(http.DefaultServeMux)

	s.logger.Info("Pprof routes configured at /debug/pprof/")
}

func (s *Server) validateDependencies() error {
	if s.policyService == nil {
		return errors.NewValidationError("policy_service", "Policy service is required", nil)
	}

	if s.decisionService == nil {
		return errors.NewValidationError("decision_service", "Decision service is required", nil)
	}

	if s.opaEngine == nil {
		return errors.NewValidationError("opa_engine", "OPA engine is required", nil)
	}

	if s.opaClient == nil {
		return errors.NewValidationError("opa_client", "OPA client is required", nil)
	}

	if s.policyLoader == nil {
		return errors.NewValidationError("policy_loader", "Policy loader is required", nil)
	}

	if s.cache == nil {
		return errors.NewValidationError("cache", "Cache is required", nil)
	}

	if s.policyStore == nil {
		return errors.NewValidationError("policy_store", "Policy store is required", nil)
	}

	if s.bundleManager == nil {
		return errors.NewValidationError("bundle_manager", "Bundle manager is required", nil)
	}

	if s.db == nil {
		return errors.NewValidationError("database", "Database is required", nil)
	}

	return nil
}

func (s *Server) startDependencies() error {
	if err := s.policyLoader.Start(); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to start policy loader")
	}

	if err := s.opaEngine.Start(); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to start OPA engine")
	}

	s.logger.Info("All dependencies started successfully")
	return nil
}

func (s *Server) stopDependencies(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 10)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.healthHandler.Shutdown(ctx); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "Failed to shutdown health handler")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.policyHandler.Shutdown(ctx); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "Failed to shutdown policy handler")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.decisionHandler.Shutdown(ctx); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "Failed to shutdown decision handler")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.policyService.Close(); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "Failed to close policy service")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.decisionService.Close(); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "Failed to close decision service")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.policyLoader.Close(); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "Failed to close policy loader")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.opaEngine.Close(); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "Failed to close OPA engine")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.cache.Close(); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "Failed to close cache")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.policyStore.Close(); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "Failed to close policy store")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.bundleManager.Close(); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "Failed to close bundle manager")
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		close(errChan)
		var errors []error
		for err := range errChan {
			errors = append(errors, err)
		}
		if len(errors) > 0 {
			return errors[0]
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) handleShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	s.logger.Info("Received shutdown signal", zap.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	if err := s.Stop(ctx); err != nil {
		s.logger.Error("Failed to gracefully shutdown server", zap.Error(err))
		os.Exit(1)
	}

	s.logger.Info("Server shutdown completed")
	os.Exit(0)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"service":     "policy-service",
		"version":     s.config.App.Version,
		"environment": s.config.App.Environment,
		"status":      "running",
		"timestamp":   time.Now().UTC(),
		"endpoints": map[string]interface{}{
			"health":    "/health",
			"policies":  "/api/v1/policies",
			"decisions": "/api/v1/decisions",
			"bundles":   "/api/v1/bundles",
		},
	}

	w.WriteHeader(http.StatusOK)
	if err := utils.WriteJSON(w, response); err != nil {
		s.logger.Error("Failed to write root response", zap.Error(err))
	}
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"pong":      true,
		"timestamp": time.Now().UTC(),
	}

	w.WriteHeader(http.StatusOK)
	if err := utils.WriteJSON(w, response); err != nil {
		s.logger.Error("Failed to write ping response", zap.Error(err))
	}
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"error":     "Not Found",
		"code":      "NOT_FOUND",
		"message":   fmt.Sprintf("Endpoint %s %s not found", r.Method, r.URL.Path),
		"timestamp": time.Now().UTC(),
	}

	w.WriteHeader(http.StatusNotFound)
	if err := utils.WriteJSON(w, response); err != nil {
		s.logger.Error("Failed to write not found response", zap.Error(err))
	}

	s.logger.Debug("Not found",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("remote_addr", r.RemoteAddr))
}

func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	utils.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"error":     "Method Not Allowed",
		"code":      "METHOD_NOT_ALLOWED",
		"message":   fmt.Sprintf("Method %s not allowed for endpoint %s", r.Method, r.URL.Path),
		"timestamp": time.Now().UTC(),
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
	if err := utils.WriteJSON(w, response); err != nil {
		s.logger.Error("Failed to write method not allowed response", zap.Error(err))
	}

	s.logger.Debug("Method not allowed",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("remote_addr", r.RemoteAddr))
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = utils.GenerateRequestID()
		}

		traceID := r.Header.Get("X-Trace-ID")
		if traceID == "" {
			traceID = utils.GenerateTraceID()
		}

		ctx := context.WithValue(r.Context(), "request_id", requestID)
		ctx = context.WithValue(ctx, "trace_id", traceID)
		r = r.WithContext(ctx)

		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-Trace-ID", traceID)

		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		s.logger.Debug("Request started",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("request_id", requestID),
			zap.String("trace_id", traceID))

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		s.logger.Info("Request completed",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status_code", wrapped.statusCode),
			zap.Duration("duration", duration),
			zap.String("request_id", requestID),
			zap.String("trace_id", traceID))
	})
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				requestID := r.Header.Get("X-Request-ID")
				traceID := r.Header.Get("X-Trace-ID")

				s.logger.Error("Panic recovered",
					zap.Any("error", err),
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
					zap.String("request_id", requestID),
					zap.String("trace_id", traceID),
					zap.Stack("stack"))

				utils.SetSecurityHeaders(w)
				w.Header().Set("Content-Type", "application/json")

				response := map[string]interface{}{
					"error":      "Internal Server Error",
					"code":       "INTERNAL_ERROR",
					"message":    "An unexpected error occurred",
					"request_id": requestID,
					"trace_id":   traceID,
					"timestamp":  time.Now().UTC(),
				}

				w.WriteHeader(http.StatusInternalServerError)
				if writeErr := utils.WriteJSON(w, response); writeErr != nil {
					s.logger.Error("Failed to write panic response", zap.Error(writeErr))
				}
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.SetSecurityHeaders(w)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		
		s.logger.Debug("Request metrics",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status_code", wrapped.statusCode),
			zap.Duration("duration", duration),
			zap.Int64("content_length", r.ContentLength))
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		
		allowedOrigins := []string{"*"}
		if s.config.Server.CORS.AllowedOrigins != nil {
			allowedOrigins = s.config.Server.CORS.AllowedOrigins
		}

		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Request-ID, X-Trace-ID")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isRunning
}

func (s *Server) GetAddress() string {
	return s.httpServer.Addr
}

func (s *Server) GetRouter() *mux.Router {
	return s.router
}

func (s *Server) HealthCheck(ctx context.Context) error {
	if !s.IsRunning() {
		return errors.NewServiceUnavailable("Server is not running")
	}

	if err := s.policyService.HealthCheck(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeServiceUnavailable, "Policy service health check failed")
	}

	if err := s.decisionService.HealthCheck(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeServiceUnavailable, "Decision service health check failed")
	}

	return nil
}

func (s *Server) GetHealthStatus() map[string]interface{} {
	return map[string]interface{}{
		"server": map[string]interface{}{
			"running": s.IsRunning(),
			"address": s.GetAddress(),
		},
		"policy_service":   s.policyService.GetHealthStatus(),
		"decision_service": s.decisionService.GetHealthStatus(),
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func getServerConfig(cfg *config.Config) *ServerConfig {
	serverConfig := &ServerConfig{
		Host:            "0.0.0.0",
		Port:            8080,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 30 * time.Second,
		MaxHeaderBytes:  1 << 20,
		EnableTLS:       false,
		EnableCORS:      true,
		EnableMetrics:   true,
		EnablePprof:     false,
	}

	if cfg.Server.Host != "" {
		serverConfig.Host = cfg.Server.Host
	}

	if cfg.Server.Port > 0 {
		serverConfig.Port = cfg.Server.Port
	}

	if cfg.Server.ReadTimeout > 0 {
		serverConfig.ReadTimeout = cfg.Server.ReadTimeout
	}

	if cfg.Server.WriteTimeout > 0 {
		serverConfig.WriteTimeout = cfg.Server.WriteTimeout
	}

	if cfg.Server.IdleTimeout > 0 {
		serverConfig.IdleTimeout = cfg.Server.IdleTimeout
	}

	if cfg.Server.ShutdownTimeout > 0 {
		serverConfig.ShutdownTimeout = cfg.Server.ShutdownTimeout
	}

	if cfg.Server.MaxHeaderBytes > 0 {
		serverConfig.MaxHeaderBytes = cfg.Server.MaxHeaderBytes
	}

	if cfg.Server.TLS.Enabled {
		serverConfig.EnableTLS = true
		serverConfig.TLSCertFile = cfg.Server.TLS.CertFile
		serverConfig.TLSKeyFile = cfg.Server.TLS.KeyFile
	}

	if cfg.Server.CORS.Enabled {
		serverConfig.EnableCORS = true
	}

	if cfg.Server.Metrics.Enabled {
		serverConfig.EnableMetrics = true
	}

	if cfg.Server.Debug.Enabled {
		serverConfig.EnablePprof = true
	}

	return serverConfig
}


func (s *Server) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"server": map[string]interface{}{
			"running":     s.IsRunning(),
			"address":     s.GetAddress(),
			"uptime":      time.Since(time.Now()).Seconds(),
			"go_version":  utils.GetGoVersion(),
			"memory":      utils.GetMemoryUsage(),
			"goroutines":  utils.GetGoroutineCount(),
		},
		"policy_service":   s.policyService.GetHealthStatus(),
		"decision_service": s.decisionService.GetHealthStatus(),
		"opa_engine":       s.opaEngine.GetHealthStatus(),
		"opa_client":       s.opaClient.IsHealthy(context.Background()),
		"policy_loader":    s.policyLoader.GetHealthStatus(),
		"cache":            s.cache.GetStats(),
		"database":         s.db.Stats(),
	}
}

func (s *Server) RegisterCustomRoute(path string, handler http.HandlerFunc, methods ...string) {
	if len(methods) == 0 {
		methods = []string{"GET"}
	}
	
	s.router.HandleFunc(path, handler).Methods(methods...)
	
	s.logger.Info("Custom route registered",
		zap.String("path", path),
		zap.Strings("methods", methods))
}

func (s *Server) RegisterCustomMiddleware(middleware mux.MiddlewareFunc) {
	s.router.Use(middleware)
	s.logger.Info("Custom middleware registered")
}

func (s *Server) SetNotFoundHandler(handler http.HandlerFunc) {
	s.router.NotFoundHandler = handler
	s.logger.Info("Custom not found handler set")
}

func (s *Server) SetMethodNotAllowedHandler(handler http.HandlerFunc) {
	s.router.MethodNotAllowedHandler = handler
	s.logger.Info("Custom method not allowed handler set")
}

func (s *Server) EnableGracefulShutdown(timeout time.Duration) {
	s.shutdownTimeout = timeout
	s.logger.Info("Graceful shutdown enabled", zap.Duration("timeout", timeout))
}

func (s *Server) GetConfig() *ServerConfig {
	return getServerConfig(s.config)
}

func (s *Server) UpdateConfig(newConfig *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isRunning {
		return errors.NewConflictError("Cannot update config while server is running")
	}

	s.config = newConfig
	
	serverConfig := getServerConfig(newConfig)
	s.httpServer.Addr = fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port)
	s.httpServer.ReadTimeout = serverConfig.ReadTimeout
	s.httpServer.WriteTimeout = serverConfig.WriteTimeout
	s.httpServer.IdleTimeout = serverConfig.IdleTimeout
	s.httpServer.MaxHeaderBytes = serverConfig.MaxHeaderBytes
	s.shutdownTimeout = serverConfig.ShutdownTimeout

	s.logger.Info("Server configuration updated",
		zap.String("address", s.httpServer.Addr),
		zap.Duration("read_timeout", serverConfig.ReadTimeout),
		zap.Duration("write_timeout", serverConfig.WriteTimeout),
		zap.Duration("shutdown_timeout", s.shutdownTimeout))

	return nil
}

func (s *Server) ListRoutes() []string {
	var routes []string
	
	err := s.router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		
		methods, err := route.GetMethods()
		if err != nil {
			methods = []string{"*"}
		}
		
		for _, method := range methods {
			routes = append(routes, fmt.Sprintf("%s %s", method, pathTemplate))
		}
		
		return nil
	})
	
	if err != nil {
		s.logger.Error("Failed to walk routes", zap.Error(err))
	}
	
	return routes
}

func (s *Server) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"server": map[string]interface{}{
			"running":          s.IsRunning(),
			"address":          s.GetAddress(),
			"routes_count":     len(s.ListRoutes()),
			"shutdown_timeout": s.shutdownTimeout.Seconds(),
		},
		"system": map[string]interface{}{
			"go_version":  utils.GetGoVersion(),
			"memory":      utils.GetMemoryUsage(),
			"cpu":         utils.GetCPUUsage(),
			"goroutines":  utils.GetGoroutineCount(),
		},
		"dependencies": map[string]interface{}{
			"policy_service_healthy":   s.policyService.HealthCheck(context.Background()) == nil,
			"decision_service_healthy": s.decisionService.HealthCheck(context.Background()) == nil,
			"opa_engine_healthy":       s.opaEngine.IsHealthy(),
			"opa_client_healthy":       s.opaClient.IsHealthy(context.Background()),
			"policy_loader_running":    s.policyLoader.IsRunning(),
			"cache_healthy":            s.cache.HealthCheck() == nil,
			"database_healthy":         s.db.Ping(context.Background()) == nil,
		},
	}

	return stats
}

func (s *Server) Restart(ctx context.Context) error {
	s.logger.Info("Restarting server")

	if err := s.Stop(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to stop server during restart")
	}

	time.Sleep(1 * time.Second)

	if err := s.Start(); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to start server during restart")
	}

	s.logger.Info("Server restarted successfully")
	return nil
}

func (s *Server) Reload(ctx context.Context) error {
	s.logger.Info("Reloading server configuration and dependencies")

	if err := s.policyLoader.Stop(); err != nil {
		s.logger.Error("Failed to stop policy loader during reload", zap.Error(err))
	}

	if err := s.opaEngine.Stop(); err != nil {
		s.logger.Error("Failed to stop OPA engine during reload", zap.Error(err))
	}

	time.Sleep(500 * time.Millisecond)

	if err := s.startDependencies(); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to restart dependencies during reload")
	}

	s.logger.Info("Server reloaded successfully")
	return nil
}

func (s *Server) GetVersion() map[string]interface{} {
	return map[string]interface{}{
		"service":     "policy-service",
		"version":     s.config.App.Version,
		"build_time":  s.config.App.BuildTime,
		"commit_hash": s.config.App.CommitHash,
		"go_version":  utils.GetGoVersion(),
		"environment": s.config.App.Environment,
	}
}

func (s *Server) EnableDebugMode() {
	s.logger.Info("Debug mode enabled")
	s.setupPprofRoutes()
}

func (s *Server) DisableDebugMode() {
	s.logger.Info("Debug mode disabled")
}

func (s *Server) SetLogLevel(level string) error {
	s.logger.Info("Setting log level", zap.String("level", level))
	return nil
}

func (s *Server) GetLogLevel() string {
	return s.config.Logging.Level
}

func (s *Server) DumpConfig() map[string]interface{} {
	serverConfig := getServerConfig(s.config)
	
	return map[string]interface{}{
		"server": map[string]interface{}{
			"host":             serverConfig.Host,
			"port":             serverConfig.Port,
			"read_timeout":     serverConfig.ReadTimeout.Seconds(),
			"write_timeout":    serverConfig.WriteTimeout.Seconds(),
			"idle_timeout":     serverConfig.IdleTimeout.Seconds(),
			"shutdown_timeout": serverConfig.ShutdownTimeout.Seconds(),
			"max_header_bytes": serverConfig.MaxHeaderBytes,
			"enable_tls":       serverConfig.EnableTLS,
			"enable_cors":      serverConfig.EnableCORS,
			"enable_metrics":   serverConfig.EnableMetrics,
			"enable_pprof":     serverConfig.EnablePprof,
		},
		"app": map[string]interface{}{
			"name":        s.config.App.Name,
			"version":     s.config.App.Version,
			"environment": s.config.App.Environment,
		},
		"database": map[string]interface{}{
			"host":         s.config.Database.Host,
			"port":         s.config.Database.Port,
			"name":         s.config.Database.Name,
			"max_conns":    s.config.Database.MaxConnections,
			"max_idle":     s.config.Database.MaxIdleConnections,
			"conn_timeout": s.config.Database.ConnectionTimeout.Seconds(),
		},
		"opa": map[string]interface{}{
			"url":     s.config.OPA.URL,
			"timeout": s.config.OPA.Timeout.Seconds(),
		},
		"logging": map[string]interface{}{
			"level":  s.config.Logging.Level,
			"format": s.config.Logging.Format,
		},
	}
}

func (s *Server) ValidateConfiguration() error {
	serverConfig := getServerConfig(s.config)

	if serverConfig.Port <= 0 || serverConfig.Port > 65535 {
		return errors.NewValidationError("port", "Invalid port number", serverConfig.Port)
	}

	if serverConfig.ReadTimeout <= 0 {
		return errors.NewValidationError("read_timeout", "Read timeout must be positive", serverConfig.ReadTimeout)
	}

	if serverConfig.WriteTimeout <= 0 {
		return errors.NewValidationError("write_timeout", "Write timeout must be positive", serverConfig.WriteTimeout)
	}

	if serverConfig.ShutdownTimeout <= 0 {
		return errors.NewValidationError("shutdown_timeout", "Shutdown timeout must be positive", serverConfig.ShutdownTimeout)
	}

	if serverConfig.EnableTLS {
		if serverConfig.TLSCertFile == "" {
			return errors.NewValidationError("tls_cert_file", "TLS cert file is required when TLS is enabled", serverConfig.TLSCertFile)
		}
		if serverConfig.TLSKeyFile == "" {
			return errors.NewValidationError("tls_key_file", "TLS key file is required when TLS is enabled", serverConfig.TLSKeyFile)
		}
	}

	return nil
}

func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	return s.Stop(ctx)
}
