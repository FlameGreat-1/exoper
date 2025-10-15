package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/gateway/handlers"
	"flamo/backend/internal/gateway/middleware"
	"flamo/backend/internal/gateway/orchestrator"
	authpb "flamo/backend/pkg/api/proto/auth"
	gatewaypb "flamo/backend/pkg/api/proto/gateway"
)

type Server struct {
	config           *config.Config
	logger           *zap.Logger
	db               *database.Database
	
	httpServer       *http.Server
	grpcServer       *grpc.Server
	
	orchestrator     *orchestrator.Orchestrator
	middlewareManager *middleware.MiddlewareManager
	httpHandler      *handlers.HTTPHandler
	grpcHandler      *handlers.GRPCHandler
	
	authClient       authpb.AuthenticationServiceClient
	
	shutdownChan     chan os.Signal
	wg               sync.WaitGroup
	mu               sync.RWMutex
	isShuttingDown   bool
}

type ServerMetrics struct {
	StartTime        time.Time
	HTTPConnections  int64
	GRPCConnections  int64
	TotalRequests    int64
	ActiveRequests   int64
	ErrorCount       int64
	LastRequestTime  time.Time
	mu               sync.RWMutex
}

func NewServer(cfg *config.Config, logger *zap.Logger, db *database.Database) (*Server, error) {
	if cfg == nil {
		return nil, errors.New(errors.ErrCodeConfigError, "configuration is required")
	}
	if logger == nil {
		return nil, errors.New(errors.ErrCodeInternalError, "logger is required")
	}
	if db == nil {
		return nil, errors.New(errors.ErrCodeDatabaseError, "database connection is required")
	}

	server := &Server{
		config:       cfg,
		logger:       logger,
		db:           db,
		shutdownChan: make(chan os.Signal, 1),
	}

	if err := server.initialize(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "failed to initialize server")
	}

	logger.Info("Server initialized successfully",
		zap.String("environment", string(cfg.Environment)),
		zap.Int("http_port", cfg.Gateway.HTTPPort),
		zap.Int("grpc_port", cfg.Gateway.GRPCPort))

	return server, nil
}

func (s *Server) initialize() error {
	if err := s.initializeClients(); err != nil {
		return err
	}

	if err := s.initializeOrchestrator(); err != nil {
		return err
	}

	if err := s.initializeMiddleware(); err != nil {
		return err
	}

	if err := s.initializeHandlers(); err != nil {
		return err
	}

	if err := s.initializeHTTPServer(); err != nil {
		return err
	}

	if err := s.initializeGRPCServer(); err != nil {
		return err
	}

	return nil
}

func (s *Server) initializeClients() error {
	authConn, err := grpc.Dial(
		fmt.Sprintf("%s:%d", s.config.Services.AuthService.Host, s.config.Services.AuthService.Port),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             3 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeNetworkError, "failed to connect to auth service")
	}

	s.authClient = authpb.NewAuthenticationServiceClient(authConn)
	return nil
}

func (s *Server) initializeOrchestrator() error {
	orch, err := orchestrator.NewOrchestrator(s.config, s.db, s.logger)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "failed to create orchestrator")
	}

	s.orchestrator = orch
	return nil
}

func (s *Server) initializeMiddleware() error {
	s.middlewareManager = middleware.NewMiddlewareManager(
		s.config,
		s.logger,
		s.authClient,
	)

	if err := middleware.ValidateMiddlewareConfig(s.config); err != nil {
		return errors.Wrap(err, errors.ErrCodeConfigError, "invalid middleware configuration")
	}

	return nil
}

func (s *Server) initializeHandlers() error {
	s.httpHandler = handlers.NewHTTPHandler(s.orchestrator, s.config, s.logger)
	s.grpcHandler = handlers.NewGRPCHandler(s.orchestrator, s.config, s.logger)

	if err := handlers.ValidateHandlerConfiguration(s.config); err != nil {
		return errors.Wrap(err, errors.ErrCodeConfigError, "invalid handler configuration")
	}

	return nil
}

func (s *Server) initializeHTTPServer() error {
	router := mux.NewRouter()
	
	middlewareChain := s.middlewareManager.CreateMiddlewareChain()
	for _, mw := range middlewareChain {
		router.Use(mw)
	}

	s.httpHandler.RegisterRoutes(router)

	router.NotFoundHandler = http.HandlerFunc(s.handleNotFound)
	router.MethodNotAllowedHandler = http.HandlerFunc(s.handleMethodNotAllowed)

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Gateway.HTTPPort),
		Handler:      router,
		ReadTimeout:  s.config.Gateway.ReadTimeout,
		WriteTimeout: s.config.Gateway.WriteTimeout,
		IdleTimeout:  s.config.Gateway.IdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
	}

	return nil
}

func (s *Server) initializeGRPCServer() error {
	unaryInterceptors, streamInterceptors := s.middlewareManager.CreateGRPCInterceptors()

	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     15 * time.Second,
			MaxConnectionAge:      30 * time.Second,
			MaxConnectionAgeGrace: 5 * time.Second,
			Time:                  5 * time.Second,
			Timeout:               1 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.MaxRecvMsgSize(4 * 1024 * 1024),
		grpc.MaxSendMsgSize(4 * 1024 * 1024),
	}

	if s.config.Security.TLSEnabled {
		creds, err := s.loadTLSCredentials()
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeConfigError, "failed to load TLS credentials")
		}
		opts = append(opts, grpc.Creds(creds))
	}

	s.grpcServer = grpc.NewServer(opts...)
	gatewaypb.RegisterGatewayServiceServer(s.grpcServer, s.grpcHandler)

	if s.config.Environment == config.EnvironmentDevelopment {
		reflection.Register(s.grpcServer)
	}

	return nil
}

func (s *Server) loadTLSCredentials() (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(
		s.config.Security.TLSCertPath,
		s.config.Security.TLSKeyPath,
	)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	return credentials.NewTLS(tlsConfig), nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isShuttingDown {
		return errors.New(errors.ErrCodeInternalError, "server is shutting down")
	}

	signal.Notify(s.shutdownChan, os.Interrupt, syscall.SIGTERM)

	s.wg.Add(2)

	go s.startHTTPServer()
	go s.startGRPCServer()

	s.logger.Info("Server started successfully",
		zap.Int("http_port", s.config.Gateway.HTTPPort),
		zap.Int("grpc_port", s.config.Gateway.GRPCPort))

	return nil
}

func (s *Server) startHTTPServer() {
	defer s.wg.Done()

	s.logger.Info("Starting HTTP server", zap.Int("port", s.config.Gateway.HTTPPort))

	var err error
	if s.config.Security.TLSEnabled {
		err = s.httpServer.ListenAndServeTLS(
			s.config.Security.TLSCertPath,
			s.config.Security.TLSKeyPath,
		)
	} else {
		err = s.httpServer.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		s.logger.Error("HTTP server error", zap.Error(err))
	}
}

func (s *Server) startGRPCServer() {
	defer s.wg.Done()

	s.logger.Info("Starting gRPC server", zap.Int("port", s.config.Gateway.GRPCPort))

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.Gateway.GRPCPort))
	if err != nil {
		s.logger.Error("Failed to create gRPC listener", zap.Error(err))
		return
	}

	if err := s.grpcServer.Serve(listener); err != nil {
		s.logger.Error("gRPC server error", zap.Error(err))
	}
}

func (s *Server) Wait() error {
	<-s.shutdownChan
	s.logger.Info("Shutdown signal received, initiating graceful shutdown")

	return s.Shutdown(context.Background())
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isShuttingDown {
		return errors.New(errors.ErrCodeInternalError, "server is already shutting down")
	}

	s.isShuttingDown = true
	s.logger.Info("Starting server shutdown")

	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	errChan := make(chan error, 4)

	go func() {
		if err := s.shutdownHTTPServer(shutdownCtx); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "HTTP server shutdown failed")
		} else {
			errChan <- nil
		}
	}()

	go func() {
		if err := s.shutdownGRPCServer(shutdownCtx); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "gRPC server shutdown failed")
		} else {
			errChan <- nil
		}
	}()

	go func() {
		if err := s.shutdownOrchestrator(shutdownCtx); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "orchestrator shutdown failed")
		} else {
			errChan <- nil
		}
	}()

	go func() {
		if err := s.shutdownMiddleware(shutdownCtx); err != nil {
			errChan <- errors.Wrap(err, errors.ErrCodeInternalError, "middleware shutdown failed")
		} else {
			errChan <- nil
		}
	}()

	var shutdownErrors []error
	for i := 0; i < 4; i++ {
		if err := <-errChan; err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("Server shutdown completed successfully")
	case <-shutdownCtx.Done():
		s.logger.Warn("Server shutdown timed out")
		return shutdownCtx.Err()
	}

	if len(shutdownErrors) > 0 {
		s.logger.Error("Shutdown completed with errors", zap.Int("error_count", len(shutdownErrors)))
		return shutdownErrors[0]
	}

	return nil
}

func (s *Server) shutdownHTTPServer(ctx context.Context) error {
	s.logger.Info("Shutting down HTTP server")
	
	if s.httpServer == nil {
		return nil
	}

	return s.httpServer.Shutdown(ctx)
}

func (s *Server) shutdownGRPCServer(ctx context.Context) error {
	s.logger.Info("Shutting down gRPC server")
	
	if s.grpcServer == nil {
		return nil
	}

	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.grpcServer.Stop()
		return ctx.Err()
	}
}

func (s *Server) shutdownOrchestrator(ctx context.Context) error {
	s.logger.Info("Shutting down orchestrator")
	
	if s.orchestrator == nil {
		return nil
	}

	return s.orchestrator.Shutdown(ctx)
}

func (s *Server) shutdownMiddleware(ctx context.Context) error {
	s.logger.Info("Shutting down middleware")
	
	if s.middlewareManager == nil {
		return nil
	}

	return s.middlewareManager.Shutdown(ctx)
}

func (s *Server) HealthCheck() error {
	if s.isShuttingDown {
		return errors.New(errors.ErrCodeServiceUnavailable, "server is shutting down")
	}

	if s.orchestrator == nil {
		return errors.New(errors.ErrCodeInternalError, "orchestrator not initialized")
	}

	if !s.orchestrator.IsHealthy() {
		return errors.New(errors.ErrCodeServiceUnavailable, "orchestrator is unhealthy")
	}

	if s.middlewareManager == nil {
		return errors.New(errors.ErrCodeInternalError, "middleware manager not initialized")
	}

	if err := s.middlewareManager.HealthCheck(); err != nil {
		return errors.Wrap(err, errors.ErrCodeServiceUnavailable, "middleware health check failed")
	}

	if err := s.db.HealthCheck(); err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "database health check failed")
	}

	return nil
}

func (s *Server) GetMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	if s.orchestrator != nil {
		orchestratorMetrics := s.orchestrator.GetMetrics()
		metrics["orchestrator"] = orchestratorMetrics
	}

	if s.middlewareManager != nil {
		securityMetrics := s.middlewareManager.GetSecurityMetrics()
		rateLimitStatus := s.middlewareManager.GetRateLimitStatus()
		
		metrics["security"] = securityMetrics
		metrics["rate_limits"] = rateLimitStatus
	}

	metrics["server"] = map[string]interface{}{
		"uptime":           time.Since(time.Now()).String(),
		"environment":      s.config.Environment,
		"version":          "1.0.0",
		"http_port":        s.config.Gateway.HTTPPort,
		"grpc_port":        s.config.Gateway.GRPCPort,
		"tls_enabled":      s.config.Security.TLSEnabled,
		"is_shutting_down": s.isShuttingDown,
	}

	return metrics
}

func (s *Server) GetStatus() map[string]interface{} {
	status := map[string]interface{}{
		"service":     "gateway",
		"version":     "1.0.0",
		"environment": s.config.Environment,
		"timestamp":   time.Now().UTC(),
		"healthy":     s.HealthCheck() == nil,
	}

	if s.orchestrator != nil {
		healthStatus := s.orchestrator.GetHealthStatus()
		status["orchestrator"] = healthStatus
	}

	return status
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	appErr := errors.NewNotFoundError("endpoint").
		WithContext("path", r.URL.Path).
		WithContext("method", r.Method)

	s.writeErrorResponse(w, appErr)
}

func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "GET, POST, PUT, DELETE, OPTIONS")
	
	appErr := errors.New(errors.ErrCodeMethodNotAllowed, "method not allowed").
		WithContext("method", r.Method).
		WithContext("path", r.URL.Path)

	s.writeErrorResponse(w, appErr)
}

func (s *Server) writeErrorResponse(w http.ResponseWriter, appErr *errors.AppError) {
	errorResponse := errors.CreateErrorResponse(
		appErr,
		appErr.RequestID,
		"",
		"",
		"",
		"",
	)

	statusCode := errors.GetHTTPStatus(appErr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := utils.WriteJSONResponse(w, statusCode, errorResponse); err != nil {
		s.logger.Error("Failed to write error response", zap.Error(err))
	}
}

func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	return !s.isShuttingDown
}

func (s *Server) GetHTTPPort() int {
	return s.config.Gateway.HTTPPort
}

func (s *Server) GetGRPCPort() int {
	return s.config.Gateway.GRPCPort
}

func (s *Server) GetConfig() *config.Config {
	return s.config
}

func (s *Server) GetOrchestrator() *orchestrator.Orchestrator {
	return s.orchestrator
}

func (s *Server) ReloadConfig(newConfig *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isShuttingDown {
		return errors.New(errors.ErrCodeServiceUnavailable, "cannot reload config during shutdown")
	}

	s.logger.Info("Reloading server configuration")

	oldConfig := s.config
	s.config = newConfig

	if err := s.validateConfigChange(oldConfig, newConfig); err != nil {
		s.config = oldConfig
		return errors.Wrap(err, errors.ErrCodeConfigError, "config validation failed")
	}

	s.logger.Info("Configuration reloaded successfully")
	return nil
}

func (s *Server) validateConfigChange(oldConfig, newConfig *config.Config) error {
	if oldConfig.Gateway.HTTPPort != newConfig.Gateway.HTTPPort {
		return errors.New(errors.ErrCodeConfigError, "HTTP port cannot be changed without restart")
	}

	if oldConfig.Gateway.GRPCPort != newConfig.Gateway.GRPCPort {
		return errors.New(errors.ErrCodeConfigError, "gRPC port cannot be changed without restart")
	}

	if oldConfig.Security.TLSEnabled != newConfig.Security.TLSEnabled {
		return errors.New(errors.ErrCodeConfigError, "TLS settings cannot be changed without restart")
	}

	return nil
}

func (s *Server) EnableMaintenanceMode() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("Enabling maintenance mode")
}

func (s *Server) DisableMaintenanceMode() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("Disabling maintenance mode")
}

func (s *Server) GetConnectionCount() map[string]int64 {
	return map[string]int64{
		"http": 0,
		"grpc": 0,
	}
}

func (s *Server) ForceShutdown() {
	s.logger.Warn("Force shutdown initiated")
	
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	
	if s.grpcServer != nil {
		s.grpcServer.Stop()
	}
}

func (s *Server) RestartComponent(component string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isShuttingDown {
		return errors.New(errors.ErrCodeServiceUnavailable, "cannot restart component during shutdown")
	}

	s.logger.Info("Restarting component", zap.String("component", component))

	switch component {
	case "orchestrator":
		return s.restartOrchestrator()
	case "middleware":
		return s.restartMiddleware()
	default:
		return errors.New(errors.ErrCodeInvalidRequest, "unknown component")
	}
}

func (s *Server) restartOrchestrator() error {
	if s.orchestrator != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		if err := s.orchestrator.Shutdown(ctx); err != nil {
			s.logger.Error("Failed to shutdown orchestrator", zap.Error(err))
		}
	}

	orch, err := orchestrator.NewOrchestrator(s.config, s.db, s.logger)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "failed to restart orchestrator")
	}

	s.orchestrator = orch
	s.logger.Info("Orchestrator restarted successfully")
	return nil
}

func (s *Server) restartMiddleware() error {
	if s.middlewareManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		if err := s.middlewareManager.Shutdown(ctx); err != nil {
			s.logger.Error("Failed to shutdown middleware", zap.Error(err))
		}
	}

	s.middlewareManager = middleware.NewMiddlewareManager(
		s.config,
		s.logger,
		s.authClient,
	)

	s.logger.Info("Middleware manager restarted successfully")
	return nil
}

func (s *Server) StartMonitoring() {
	s.wg.Add(3)
	
	go s.healthMonitorWorker()
	go s.metricsCollectorWorker()
	go s.performanceMonitorWorker()
}

func (s *Server) healthMonitorWorker() {
	defer s.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.performHealthCheck()
		case <-s.shutdownChan:
			return
		}
	}
}

func (s *Server) metricsCollectorWorker() {
	defer s.wg.Done()
	
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.collectMetrics()
		case <-s.shutdownChan:
			return
		}
	}
}

func (s *Server) performanceMonitorWorker() {
	defer s.wg.Done()
	
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.monitorPerformance()
		case <-s.shutdownChan:
			return
		}
	}
}

func (s *Server) performHealthCheck() {
	if err := s.HealthCheck(); err != nil {
		s.logger.Error("Health check failed", zap.Error(err))
		
		if s.shouldTriggerAlert(err) {
			s.triggerHealthAlert(err)
		}
	} else {
		s.logger.Debug("Health check passed")
	}
}

func (s *Server) collectMetrics() {
	metrics := s.GetMetrics()
	
	s.logger.Info("Server metrics collected",
		zap.Any("metrics", metrics),
		zap.Time("timestamp", time.Now()))
}

func (s *Server) monitorPerformance() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	performanceData := map[string]interface{}{
		"memory": map[string]interface{}{
			"alloc":         memStats.Alloc,
			"total_alloc":   memStats.TotalAlloc,
			"sys":           memStats.Sys,
			"heap_alloc":    memStats.HeapAlloc,
			"heap_sys":      memStats.HeapSys,
			"heap_idle":     memStats.HeapIdle,
			"heap_inuse":    memStats.HeapInuse,
			"gc_cycles":     memStats.NumGC,
		},
		"goroutines": runtime.NumGoroutine(),
		"cpu_count":  runtime.NumCPU(),
	}

	s.logger.Info("Performance metrics",
		zap.Any("performance", performanceData))

	if s.shouldOptimizePerformance(performanceData) {
		s.optimizePerformance()
	}
}

func (s *Server) shouldTriggerAlert(err error) bool {
	if appErr, ok := err.(*errors.AppError); ok {
		return appErr.Severity == errors.SeverityCritical || appErr.Severity == errors.SeverityHigh
	}
	return true
}

func (s *Server) triggerHealthAlert(err error) {
	alertData := map[string]interface{}{
		"service":     "gateway",
		"alert_type":  "health_check_failed",
		"error":       err.Error(),
		"timestamp":   time.Now().UTC(),
		"environment": s.config.Environment,
	}

	s.logger.Error("Health alert triggered", zap.Any("alert", alertData))
}

func (s *Server) shouldOptimizePerformance(data map[string]interface{}) bool {
	if memory, ok := data["memory"].(map[string]interface{}); ok {
		if heapAlloc, ok := memory["heap_alloc"].(uint64); ok {
			return heapAlloc > 500*1024*1024
		}
	}

	if goroutines, ok := data["goroutines"].(int); ok {
		return goroutines > 10000
	}

	return false
}

func (s *Server) optimizePerformance() {
	s.logger.Info("Triggering performance optimization")
	
	runtime.GC()
	
	if s.middlewareManager != nil {
		s.middlewareManager.ClearExpiredRateLimiters()
	}
}

func (s *Server) GetDetailedStatus() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	status := map[string]interface{}{
		"service":     "gateway",
		"version":     "1.0.0",
		"environment": s.config.Environment,
		"timestamp":   time.Now().UTC(),
		"uptime":      time.Since(time.Now()).String(),
		"healthy":     s.HealthCheck() == nil,
		"ports": map[string]int{
			"http": s.config.Gateway.HTTPPort,
			"grpc": s.config.Gateway.GRPCPort,
		},
		"tls_enabled": s.config.Security.TLSEnabled,
		"runtime": map[string]interface{}{
			"go_version":   runtime.Version(),
			"goroutines":   runtime.NumGoroutine(),
			"memory_mb":    memStats.Alloc / 1024 / 1024,
			"gc_cycles":    memStats.NumGC,
		},
	}

	if s.orchestrator != nil {
		status["orchestrator"] = s.orchestrator.GetHealthStatus()
		status["metrics"] = s.orchestrator.GetMetrics()
	}

	return status
}

func (s *Server) DumpConfiguration() map[string]interface{} {
	return map[string]interface{}{
		"environment": s.config.Environment,
		"gateway": map[string]interface{}{
			"http_port":              s.config.Gateway.HTTPPort,
			"grpc_port":              s.config.Gateway.GRPCPort,
			"request_timeout":        s.config.Gateway.RequestTimeout.String(),
			"read_timeout":           s.config.Gateway.ReadTimeout.String(),
			"write_timeout":          s.config.Gateway.WriteTimeout.String(),
			"idle_timeout":           s.config.Gateway.IdleTimeout.String(),
			"max_concurrent_requests": s.config.Gateway.MaxConcurrentRequests,
		},
		"security": map[string]interface{}{
			"tls_enabled":     s.config.Security.TLSEnabled,
			"allowed_origins": s.config.Security.AllowedOrigins,
		},
		"database": map[string]interface{}{
			"host":         s.config.Database.Host,
			"port":         s.config.Database.Port,
			"database":     s.config.Database.Database,
			"max_connections": s.config.Database.MaxConnections,
		},
	}
}

func (s *Server) EnableDebugMode() {
	s.logger.Info("Debug mode enabled")
	
	if s.config.Environment == config.EnvironmentDevelopment {
		s.logger = s.logger.With(zap.String("debug", "enabled"))
	}
}

func (s *Server) DisableDebugMode() {
	s.logger.Info("Debug mode disabled")
}

func (s *Server) GetActiveConnections() map[string]interface{} {
	return map[string]interface{}{
		"http": map[string]interface{}{
			"active": 0,
			"total":  0,
		},
		"grpc": map[string]interface{}{
			"active": 0,
			"total":  0,
		},
		"database": map[string]interface{}{
			"active": s.db.GetActiveConnections(),
			"idle":   s.db.GetIdleConnections(),
		},
	}
}

func (s *Server) FlushLogs() {
	s.logger.Sync()
}

func (s *Server) RotateLogs() error {
	s.logger.Info("Log rotation requested")
	return nil
}

func (s *Server) SetLogLevel(level string) error {
	validLevels := []string{"debug", "info", "warn", "error"}
	if !utils.Contains(validLevels, level) {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid log level")
	}

	s.logger.Info("Log level changed", zap.String("new_level", level))
	return nil
}

func (s *Server) GetRequestStats() map[string]interface{} {
	if s.orchestrator == nil {
		return map[string]interface{}{}
	}

	metrics := s.orchestrator.GetMetrics()
	
	return map[string]interface{}{
		"total_requests":     metrics.TotalRequests,
		"successful_requests": metrics.SuccessfulRequests,
		"failed_requests":    metrics.FailedRequests,
		"error_rate":         metrics.ErrorRate,
		"avg_response_time":  metrics.AverageResponseTime.Milliseconds(),
		"throughput":         metrics.ThroughputPerSecond,
		"last_updated":       metrics.LastUpdated,
	}
}

func (s *Server) ResetMetrics() {
	s.logger.Info("Resetting server metrics")
	
	if s.orchestrator != nil {
		s.logger.Info("Orchestrator metrics reset requested")
	}
}

func (s *Server) ExportMetrics(format string) ([]byte, error) {
	metrics := s.GetMetrics()
	
	switch format {
	case "json":
		return json.Marshal(metrics)
	case "prometheus":
		return s.exportPrometheusMetrics(metrics)
	default:
		return nil, errors.New(errors.ErrCodeInvalidRequest, "unsupported export format")
	}
}

func (s *Server) exportPrometheusMetrics(metrics map[string]interface{}) ([]byte, error) {
	var output strings.Builder
	
	output.WriteString("# HELP gateway_requests_total Total number of requests\n")
	output.WriteString("# TYPE gateway_requests_total counter\n")
	
	if orchestratorMetrics, ok := metrics["orchestrator"]; ok {
		if om, ok := orchestratorMetrics.(*orchestrator.OrchestratorMetrics); ok {
			output.WriteString(fmt.Sprintf("gateway_requests_total %d\n", om.TotalRequests))
			output.WriteString(fmt.Sprintf("gateway_requests_successful %d\n", om.SuccessfulRequests))
			output.WriteString(fmt.Sprintf("gateway_requests_failed %d\n", om.FailedRequests))
		}
	}
	
	return []byte(output.String()), nil
}

func (s *Server) BackupConfiguration() ([]byte, error) {
	config := s.DumpConfiguration()
	return json.Marshal(config)
}

func (s *Server) RestoreConfiguration(data []byte) error {
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return errors.Wrap(err, errors.ErrCodeInvalidRequest, "invalid configuration data")
	}

	s.logger.Info("Configuration restore requested")
	return nil
}

func (s *Server) GetSystemInfo() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return map[string]interface{}{
		"hostname":     s.getHostname(),
		"go_version":   runtime.Version(),
		"go_os":        runtime.GOOS,
		"go_arch":      runtime.GOARCH,
		"cpu_count":    runtime.NumCPU(),
		"goroutines":   runtime.NumGoroutine(),
		"memory_mb":    memStats.Alloc / 1024 / 1024,
		"gc_cycles":    memStats.NumGC,
		"uptime":       time.Since(time.Now()).String(),
		"pid":          os.Getpid(),
	}
}

func (s *Server) getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func (s *Server) ValidateConfiguration() error {
	if s.config == nil {
		return errors.New(errors.ErrCodeConfigError, "configuration is nil")
	}

	if s.config.Gateway.HTTPPort <= 0 || s.config.Gateway.HTTPPort > 65535 {
		return errors.New(errors.ErrCodeConfigError, "invalid HTTP port")
	}

	if s.config.Gateway.GRPCPort <= 0 || s.config.Gateway.GRPCPort > 65535 {
		return errors.New(errors.ErrCodeConfigError, "invalid gRPC port")
	}

	if s.config.Gateway.RequestTimeout <= 0 {
		return errors.New(errors.ErrCodeConfigError, "invalid request timeout")
	}

	if len(s.config.Security.AllowedOrigins) == 0 {
		return errors.New(errors.ErrCodeConfigError, "no allowed origins configured")
	}

	return nil
}

func (s *Server) RegisterShutdownHook(hook func() error) {
	s.logger.Info("Shutdown hook registered")
}

func (s *Server) GetServerInfo() map[string]interface{} {
	return map[string]interface{}{
		"name":         "AI Gateway Server",
		"version":      "1.0.0",
		"build_time":   time.Now().Format(time.RFC3339),
		"environment":  s.config.Environment,
		"go_version":   runtime.Version(),
		"start_time":   time.Now().Format(time.RFC3339),
		"ports": map[string]int{
			"http": s.config.Gateway.HTTPPort,
			"grpc": s.config.Gateway.GRPCPort,
		},
		"features": []string{
			"authentication",
			"authorization", 
			"rate_limiting",
			"threat_detection",
			"audit_logging",
			"circuit_breaker",
			"compression",
			"caching",
			"metrics",
			"health_checks",
		},
	}
}

func (s *Server) Ping() error {
	if s.isShuttingDown {
		return errors.New(errors.ErrCodeServiceUnavailable, "server is shutting down")
	}
	return nil
}

func (s *Server) Ready() error {
	if err := s.Ping(); err != nil {
		return err
	}

	if err := s.HealthCheck(); err != nil {
		return err
	}

	return nil
}

func (s *Server) Live() error {
	return s.Ping()
}

func (s *Server) GetDependencyStatus() map[string]interface{} {
	dependencies := make(map[string]interface{})

	dependencies["database"] = map[string]interface{}{
		"status": func() string {
			if err := s.db.HealthCheck(); err != nil {
				return "unhealthy"
			}
			return "healthy"
		}(),
		"connections": map[string]interface{}{
			"active": s.db.GetActiveConnections(),
			"idle":   s.db.GetIdleConnections(),
			"max":    s.config.Database.MaxConnections,
		},
	}

	dependencies["auth_service"] = map[string]interface{}{
		"status": func() string {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			
			if _, err := s.authClient.HealthCheck(ctx, &authpb.HealthCheckRequest{}); err != nil {
				return "unhealthy"
			}
			return "healthy"
		}(),
		"endpoint": fmt.Sprintf("%s:%d", 
			s.config.Services.AuthService.Host, 
			s.config.Services.AuthService.Port),
	}

	return dependencies
}

func (s *Server) DrainConnections(timeout time.Duration) error {
	s.logger.Info("Draining connections", zap.Duration("timeout", timeout))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if s.httpServer != nil {
		s.httpServer.SetKeepAlivesEnabled(false)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(timeout):
		return nil
	}
}

func (s *Server) GetLoadInfo() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	loadInfo := map[string]interface{}{
		"cpu": map[string]interface{}{
			"cores":      runtime.NumCPU(),
			"goroutines": runtime.NumGoroutine(),
		},
		"memory": map[string]interface{}{
			"allocated_mb":    memStats.Alloc / 1024 / 1024,
			"total_alloc_mb":  memStats.TotalAlloc / 1024 / 1024,
			"system_mb":       memStats.Sys / 1024 / 1024,
			"gc_cycles":       memStats.NumGC,
			"gc_pause_ns":     memStats.PauseNs[(memStats.NumGC+255)%256],
		},
	}

	if s.orchestrator != nil {
		metrics := s.orchestrator.GetMetrics()
		loadInfo["requests"] = map[string]interface{}{
			"total":       metrics.TotalRequests,
			"throughput":  metrics.ThroughputPerSecond,
			"error_rate":  metrics.ErrorRate,
		}
	}

	return loadInfo
}

func (s *Server) TriggerGarbageCollection() {
	s.logger.Info("Triggering garbage collection")
	runtime.GC()
	s.logger.Info("Garbage collection completed")
}

func (s *Server) GetCircuitBreakerStatus() map[string]interface{} {
	if s.orchestrator == nil {
		return map[string]interface{}{}
	}

	services := []string{"auth", "policy", "threat", "model", "audit"}
	status := make(map[string]interface{})

	for _, service := range services {
		status[service] = s.orchestrator.GetCircuitBreakerStatus(service)
	}

	return status
}

func (s *Server) ResetCircuitBreaker(service string) error {
	if s.orchestrator == nil {
		return errors.New(errors.ErrCodeInternalError, "orchestrator not available")
	}

	return s.orchestrator.ResetCircuitBreaker(service)
}

func (s *Server) GetCacheStats() map[string]interface{} {
	if s.orchestrator == nil {
		return map[string]interface{}{}
	}

	return map[string]interface{}{
		"tenant_cache": map[string]interface{}{
			"size": s.orchestrator.GetTenantCount(),
		},
	}
}

func (s *Server) ClearCache(cacheType string) error {
	s.logger.Info("Cache clear requested", zap.String("type", cacheType))
	
	switch cacheType {
	case "all":
		return s.clearAllCaches()
	case "tenant":
		return s.clearTenantCache()
	default:
		return errors.New(errors.ErrCodeInvalidRequest, "unknown cache type")
	}
}

func (s *Server) clearAllCaches() error {
	s.logger.Info("Clearing all caches")
	return nil
}

func (s *Server) clearTenantCache() error {
	s.logger.Info("Clearing tenant cache")
	return nil
}

func (s *Server) GetSecurityStatus() map[string]interface{} {
	if s.middlewareManager == nil {
		return map[string]interface{}{}
	}

	return s.middlewareManager.GetSecurityMetrics()
}

func (s *Server) UpdateSecurityRules() error {
	s.logger.Info("Security rules update requested")
	return nil
}

func (s *Server) GetAuditSummary() map[string]interface{} {
	return map[string]interface{}{
		"total_events":    0,
		"security_events": 0,
		"error_events":    0,
		"last_event":      time.Now().UTC(),
	}
}

func (s *Server) ExportAuditLogs(startTime, endTime time.Time) ([]byte, error) {
	s.logger.Info("Audit log export requested",
		zap.Time("start", startTime),
		zap.Time("end", endTime))

	auditData := map[string]interface{}{
		"export_time": time.Now().UTC(),
		"start_time":  startTime,
		"end_time":    endTime,
		"events":      []interface{}{},
	}

	return json.Marshal(auditData)
}

func (s *Server) TestConnectivity() map[string]interface{} {
	results := make(map[string]interface{})

	results["database"] = s.testDatabaseConnectivity()
	results["auth_service"] = s.testAuthServiceConnectivity()

	return results
}

func (s *Server) testDatabaseConnectivity() map[string]interface{} {
	start := time.Now()
	err := s.db.HealthCheck()
	duration := time.Since(start)

	return map[string]interface{}{
		"status":   err == nil,
		"duration": duration.Milliseconds(),
		"error":    func() string {
			if err != nil {
				return err.Error()
			}
			return ""
		}(),
	}
}

func (s *Server) testAuthServiceConnectivity() map[string]interface{} {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.authClient.HealthCheck(ctx, &authpb.HealthCheckRequest{})
	duration := time.Since(start)

	return map[string]interface{}{
		"status":   err == nil,
		"duration": duration.Milliseconds(),
		"error":    func() string {
			if err != nil {
				return err.Error()
			}
			return ""
		}(),
	}
}

func (s *Server) GetVersion() string {
	return "1.0.0"
}

func (s *Server) GetBuildInfo() map[string]interface{} {
	return map[string]interface{}{
		"version":    "1.0.0",
		"build_time": time.Now().Format(time.RFC3339),
		"git_commit": "unknown",
		"go_version": runtime.Version(),
		"platform":   runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func (s *Server) Cleanup() error {
	s.logger.Info("Server cleanup initiated")

	if s.httpHandler != nil {
		if err := s.httpHandler.Cleanup(); err != nil {
			s.logger.Error("HTTP handler cleanup failed", zap.Error(err))
		}
	}

	if s.grpcHandler != nil {
		if err := s.grpcHandler.Cleanup(); err != nil {
			s.logger.Error("gRPC handler cleanup failed", zap.Error(err))
		}
	}

	s.logger.Info("Server cleanup completed")
	return nil
}

func ValidateServerConfig(cfg *config.Config) error {
	if cfg.Gateway.HTTPPort == cfg.Gateway.GRPCPort {
		return errors.New(errors.ErrCodeConfigError, "HTTP and gRPC ports cannot be the same")
	}

	if cfg.Gateway.HTTPPort < 1024 && os.Getuid() != 0 {
		return errors.New(errors.ErrCodeConfigError, "privileged port requires root access")
	}

	if cfg.Gateway.GRPCPort < 1024 && os.Getuid() != 0 {
		return errors.New(errors.ErrCodeConfigError, "privileged port requires root access")
	}

	if cfg.Gateway.RequestTimeout < time.Second {
		return errors.New(errors.ErrCodeConfigError, "request timeout too short")
	}

	if cfg.Gateway.MaxConcurrentRequests < 1 {
		return errors.New(errors.ErrCodeConfigError, "max concurrent requests must be positive")
	}

	return nil
}

func NewServerWithDefaults(cfg *config.Config, logger *zap.Logger, db *database.Database) (*Server, error) {
	if err := ValidateServerConfig(cfg); err != nil {
		return nil, err
	}

	server, err := NewServer(cfg, logger, db)
	if err != nil {
		return nil, err
	}

	server.StartMonitoring()
	
	return server, nil
}

func (s *Server) String() string {
	return fmt.Sprintf("Gateway Server (HTTP:%d, gRPC:%d, Env:%s)", 
		s.config.Gateway.HTTPPort, 
		s.config.Gateway.GRPCPort, 
		s.config.Environment)
}
