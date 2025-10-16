package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/durationpb"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	"flamo/backend/internal/gateway/handlers"
	"flamo/backend/internal/gateway/middleware"
	"flamo/backend/internal/gateway/orchestrator"
	authpb "flamo/backend/pkg/api/proto/auth"
	commonpb "flamo/backend/pkg/api/proto/common"
	gatewaypb "flamo/backend/pkg/api/proto/gateway"
	"flamo/backend/pkg/api/proto/models/request"
	"flamo/backend/pkg/api/proto/models/response"
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
	startTime        time.Time
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
		return nil, &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "configuration is required",
			Severity:  commonpb.Severity_SEVERITY_CRITICAL,
			Timestamp: timestamppb.Now(),
		}
	}
	if logger == nil {
		return nil, &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "logger is required",
			Severity:  commonpb.Severity_SEVERITY_CRITICAL,
			Timestamp: timestamppb.Now(),
		}
	}
	if db == nil {
		return nil, &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "database connection is required",
			Severity:  commonpb.Severity_SEVERITY_CRITICAL,
			Timestamp: timestamppb.Now(),
		}
	}

	server := &Server{
		config:       cfg,
		logger:       logger,
		db:           db,
		shutdownChan: make(chan os.Signal, 1),
		startTime:    time.Now().UTC(),
	}

	if err := server.initialize(); err != nil {
		return nil, &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "failed to initialize server",
			Details:   err.Error(),
			Severity:  commonpb.Severity_SEVERITY_CRITICAL,
			Timestamp: timestamppb.Now(),
		}
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "failed to connect to auth service",
			Details:   err.Error(),
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	s.authClient = authpb.NewAuthenticationServiceClient(authConn)
	return nil
}

func (s *Server) initializeOrchestrator() error {
	orch, err := orchestrator.NewOrchestrator(s.config, s.db, s.logger)
	if err != nil {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "failed to create orchestrator",
			Details:   err.Error(),
			Severity:  commonpb.Severity_SEVERITY_CRITICAL,
			Timestamp: timestamppb.Now(),
		}
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "invalid middleware configuration",
			Details:   err.Error(),
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	return nil
}

func (s *Server) initializeHandlers() error {
	s.httpHandler = handlers.NewHTTPHandler(s.orchestrator, s.config, s.logger)
	s.grpcHandler = handlers.NewGRPCHandler(s.orchestrator, s.config, s.logger)

	if err := handlers.ValidateHandlerConfiguration(s.config); err != nil {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "invalid handler configuration",
			Details:   err.Error(),
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
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
			return &commonpb.ErrorDetails{
				Code:      commonpb.ErrorCode_ERROR_CODE_CERTIFICATE_INVALID,
				Message:   "failed to load TLS credentials",
				Details:   err.Error(),
				Severity:  commonpb.Severity_SEVERITY_HIGH,
				Timestamp: timestamppb.Now(),
			}
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "server is shutting down",
			Severity:  commonpb.Severity_SEVERITY_MEDIUM,
			Timestamp: timestamppb.Now(),
		}
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "server is already shutting down",
			Severity:  commonpb.Severity_SEVERITY_LOW,
			Timestamp: timestamppb.Now(),
		}
	}

	s.isShuttingDown = true
	s.logger.Info("Starting server shutdown")

	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	errChan := make(chan error, 4)

	go func() {
		if err := s.shutdownHTTPServer(shutdownCtx); err != nil {
			errChan <- &commonpb.ErrorDetails{
				Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
				Message:   "HTTP server shutdown failed",
				Details:   err.Error(),
				Severity:  commonpb.Severity_SEVERITY_HIGH,
				Timestamp: timestamppb.Now(),
			}
		} else {
			errChan <- nil
		}
	}()

	go func() {
		if err := s.shutdownGRPCServer(shutdownCtx); err != nil {
			errChan <- &commonpb.ErrorDetails{
				Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
				Message:   "gRPC server shutdown failed",
				Details:   err.Error(),
				Severity:  commonpb.Severity_SEVERITY_HIGH,
				Timestamp: timestamppb.Now(),
			}
		} else {
			errChan <- nil
		}
	}()

	go func() {
		if err := s.shutdownOrchestrator(shutdownCtx); err != nil {
			errChan <- &commonpb.ErrorDetails{
				Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
				Message:   "orchestrator shutdown failed",
				Details:   err.Error(),
				Severity:  commonpb.Severity_SEVERITY_HIGH,
				Timestamp: timestamppb.Now(),
			}
		} else {
			errChan <- nil
		}
	}()

	go func() {
		if err := s.shutdownMiddleware(shutdownCtx); err != nil {
			errChan <- &commonpb.ErrorDetails{
				Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
				Message:   "middleware shutdown failed",
				Details:   err.Error(),
				Severity:  commonpb.Severity_SEVERITY_HIGH,
				Timestamp: timestamppb.Now(),
			}
		} else {
			errChan <- nil
		}
	}()

	var shutdownErrors []*commonpb.ErrorDetails
	for i := 0; i < 4; i++ {
		if err := <-errChan; err != nil {
			if errorDetail, ok := err.(*commonpb.ErrorDetails); ok {
				shutdownErrors = append(shutdownErrors, errorDetail)
			}
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_TIMEOUT,
			Message:   "server shutdown timed out",
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
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

func (s *Server) HealthCheck() *commonpb.HealthStatus {
	components := []*commonpb.ComponentHealth{}

	if s.isShuttingDown {
		return &commonpb.HealthStatus{
			OverallStatus: commonpb.Status_STATUS_ERROR,
			Components:    components,
			LastCheck:     timestamppb.Now(),
			Version:       "1.0.0",
			Uptime:        durationpb.New(time.Since(s.startTime)),
		}
	}

	if s.orchestrator == nil {
		components = append(components, &commonpb.ComponentHealth{
			Name:      "orchestrator",
			Status:    commonpb.Status_STATUS_ERROR,
			Message:   "orchestrator not initialized",
			LastCheck: timestamppb.Now(),
		})
	} else if !s.orchestrator.IsHealthy() {
		components = append(components, &commonpb.ComponentHealth{
			Name:      "orchestrator",
			Status:    commonpb.Status_STATUS_ERROR,
			Message:   "orchestrator is unhealthy",
			LastCheck: timestamppb.Now(),
		})
	} else {
		components = append(components, &commonpb.ComponentHealth{
			Name:      "orchestrator",
			Status:    commonpb.Status_STATUS_SUCCESS,
			Message:   "healthy",
			LastCheck: timestamppb.Now(),
		})
	}

	if s.middlewareManager == nil {
		components = append(components, &commonpb.ComponentHealth{
			Name:      "middleware",
			Status:    commonpb.Status_STATUS_ERROR,
			Message:   "middleware manager not initialized",
			LastCheck: timestamppb.Now(),
		})
	} else if err := s.middlewareManager.HealthCheck(); err != nil {
		components = append(components, &commonpb.ComponentHealth{
			Name:      "middleware",
			Status:    commonpb.Status_STATUS_ERROR,
			Message:   "middleware health check failed: " + err.Error(),
			LastCheck: timestamppb.Now(),
		})
	} else {
		components = append(components, &commonpb.ComponentHealth{
			Name:      "middleware",
			Status:    commonpb.Status_STATUS_SUCCESS,
			Message:   "healthy",
			LastCheck: timestamppb.Now(),
		})
	}

	if err := s.db.HealthCheck(); err != nil {
		components = append(components, &commonpb.ComponentHealth{
			Name:      "database",
			Status:    commonpb.Status_STATUS_ERROR,
			Message:   "database health check failed: " + err.Error(),
			LastCheck: timestamppb.Now(),
		})
	} else {
		components = append(components, &commonpb.ComponentHealth{
			Name:      "database",
			Status:    commonpb.Status_STATUS_SUCCESS,
			Message:   "healthy",
			LastCheck: timestamppb.Now(),
		})
	}

	overallStatus := commonpb.Status_STATUS_SUCCESS
	for _, component := range components {
		if component.Status == commonpb.Status_STATUS_ERROR {
			overallStatus = commonpb.Status_STATUS_ERROR
			break
		}
	}

	return &commonpb.HealthStatus{
		OverallStatus: overallStatus,
		Components:    components,
		LastCheck:     timestamppb.Now(),
		Version:       "1.0.0",
		Uptime:        durationpb.New(time.Since(s.startTime)),
	}
}

func (s *Server) GetMetrics() *commonpb.UsageMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	metrics := &commonpb.UsageMetrics{
		RequestCount:   1,
		CacheHits:      0,
		CacheMisses:    0,
		BandwidthBytes: 0,
		ComputeUnits:   0.0,
		MeasuredAt:     timestamppb.Now(),
	}

	if s.orchestrator != nil {
		orchestratorMetrics := s.orchestrator.GetMetrics()
		metrics.RequestCount = int32(orchestratorMetrics.TotalRequests)
		metrics.CacheHits = int32(orchestratorMetrics.CacheHits)
		metrics.CacheMisses = int32(orchestratorMetrics.CacheMisses)
	}

	return metrics
}

func (s *Server) GetPerformanceMetrics() *commonpb.PerformanceMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	performance := &commonpb.PerformanceMetrics{
		TotalLatencyMs:     0,
		ModelLatencyMs:     0,
		SecurityLatencyMs:  0,
		ComplianceLatencyMs: 0,
		NetworkLatencyMs:   0,
		QueueTimeMs:        0,
		TimeToFirstTokenMs: 0,
		TokensPerSecond:    0.0,
		Throughput:         0.0,
		ConcurrentRequests: 0,
		RetryCount:         0,
		CacheHitRatio:      0.0,
		MeasuredAt:         timestamppb.Now(),
	}

	if s.orchestrator != nil {
		orchestratorMetrics := s.orchestrator.GetMetrics()
		performance.TotalLatencyMs = orchestratorMetrics.AverageResponseTime.Milliseconds()
		performance.Throughput = orchestratorMetrics.ThroughputPerSecond
		performance.ConcurrentRequests = int32(orchestratorMetrics.ConcurrentRequests)
	}

	return performance
}

func (s *Server) GetStatus() *commonpb.SystemInfo {
	return &commonpb.SystemInfo{
		ServiceName:  "gateway",
		Version:      "1.0.0",
		BuildCommit:  "unknown",
		BuildTime:    timestamppb.Now(),
		Environment:  string(s.config.Environment),
		StartTime:    timestamppb.New(s.startTime),
	}
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	errorDetails := &commonpb.ErrorDetails{
		Code:      commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
		Message:   "endpoint not found",
		Details:   fmt.Sprintf("path: %s, method: %s", r.URL.Path, r.Method),
		Severity:  commonpb.Severity_SEVERITY_LOW,
		Timestamp: timestamppb.Now(),
		RequestId: request.ExtractClientInfo(r).IPAddress,
		TraceId:   r.Header.Get("X-Trace-ID"),
	}

	s.writeErrorResponse(w, errorDetails)
}

func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "GET, POST, PUT, DELETE, OPTIONS")
	
	errorDetails := &commonpb.ErrorDetails{
		Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
		Message:   "method not allowed",
		Details:   fmt.Sprintf("method: %s, path: %s", r.Method, r.URL.Path),
		Severity:  commonpb.Severity_SEVERITY_LOW,
		Timestamp: timestamppb.Now(),
		RequestId: request.ExtractClientInfo(r).IPAddress,
		TraceId:   r.Header.Get("X-Trace-ID"),
	}

	s.writeErrorResponse(w, errorDetails)
}

func (s *Server) writeErrorResponse(w http.ResponseWriter, errorDetails *commonpb.ErrorDetails) {
	aiResponse := response.NewErrorResponse(
		"", 
		errorDetails.TraceId,
		response.ErrorCode(errorDetails.Code.String()),
		errorDetails.Message,
		response.ErrorSeverity(errorDetails.Severity.String()),
	)

	statusCode := s.getHTTPStatusFromErrorCode(errorDetails.Code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := utils.WriteJSONResponse(w, statusCode, aiResponse); err != nil {
		s.logger.Error("Failed to write error response", zap.Error(err))
	}
}

func (s *Server) getHTTPStatusFromErrorCode(code commonpb.ErrorCode) int {
	switch code {
	case commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST:
		return http.StatusBadRequest
	case commonpb.ErrorCode_ERROR_CODE_UNAUTHORIZED:
		return http.StatusUnauthorized
	case commonpb.ErrorCode_ERROR_CODE_FORBIDDEN:
		return http.StatusForbidden
	case commonpb.ErrorCode_ERROR_CODE_NOT_FOUND:
		return http.StatusNotFound
	case commonpb.ErrorCode_ERROR_CODE_RATE_LIMIT_EXCEEDED:
		return http.StatusTooManyRequests
	case commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR:
		return http.StatusInternalServerError
	case commonpb.ErrorCode_ERROR_CODE_TIMEOUT:
		return http.StatusRequestTimeout
	default:
		return http.StatusInternalServerError
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "cannot reload config during shutdown",
			Severity:  commonpb.Severity_SEVERITY_MEDIUM,
			Timestamp: timestamppb.Now(),
		}
	}

	s.logger.Info("Reloading server configuration")

	oldConfig := s.config
	s.config = newConfig

	if err := s.validateConfigChange(oldConfig, newConfig); err != nil {
		s.config = oldConfig
		return err
	}

	s.logger.Info("Configuration reloaded successfully")
	return nil
}

func (s *Server) validateConfigChange(oldConfig, newConfig *config.Config) error {
	if oldConfig.Gateway.HTTPPort != newConfig.Gateway.HTTPPort {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "HTTP port cannot be changed without restart",
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	if oldConfig.Gateway.GRPCPort != newConfig.Gateway.GRPCPort {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "gRPC port cannot be changed without restart",
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	if oldConfig.Security.TLSEnabled != newConfig.Security.TLSEnabled {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "TLS settings cannot be changed without restart",
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
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

func (s *Server) GetConnectionCount() *commonpb.UsageMetrics {
	return &commonpb.UsageMetrics{
		RequestCount:   0,
		CacheHits:      0,
		CacheMisses:    0,
		BandwidthBytes: 0,
		ComputeUnits:   0.0,
		MeasuredAt:     timestamppb.Now(),
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "cannot restart component during shutdown",
			Severity:  commonpb.Severity_SEVERITY_MEDIUM,
			Timestamp: timestamppb.Now(),
		}
	}

	s.logger.Info("Restarting component", zap.String("component", component))

	switch component {
	case "orchestrator":
		return s.restartOrchestrator()
	case "middleware":
		return s.restartMiddleware()
	default:
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "unknown component",
			Details:   "component: " + component,
			Severity:  commonpb.Severity_SEVERITY_LOW,
			Timestamp: timestamppb.Now(),
		}
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "failed to restart orchestrator",
			Details:   err.Error(),
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
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
	healthStatus := s.HealthCheck()
	
	if healthStatus.OverallStatus != commonpb.Status_STATUS_SUCCESS {
		s.logger.Error("Health check failed", 
			zap.String("status", healthStatus.OverallStatus.String()))
		
		if s.shouldTriggerAlert(healthStatus) {
			s.triggerHealthAlert(healthStatus)
		}
	} else {
		s.logger.Debug("Health check passed")
	}
}

func (s *Server) collectMetrics() {
	metrics := s.GetMetrics()
	
	s.logger.Info("Server metrics collected",
		zap.Int32("request_count", metrics.RequestCount),
		zap.Int32("cache_hits", metrics.CacheHits),
		zap.Int32("cache_misses", metrics.CacheMisses),
		zap.Time("timestamp", metrics.MeasuredAt.AsTime()))
}

func (s *Server) monitorPerformance() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	performanceMetrics := &commonpb.PerformanceMetrics{
		TotalLatencyMs:     0,
		ModelLatencyMs:     0,
		SecurityLatencyMs:  0,
		ComplianceLatencyMs: 0,
		NetworkLatencyMs:   0,
		QueueTimeMs:        0,
		TimeToFirstTokenMs: 0,
		TokensPerSecond:    0.0,
		Throughput:         0.0,
		ConcurrentRequests: int32(runtime.NumGoroutine()),
		RetryCount:         0,
		CacheHitRatio:      0.0,
		MeasuredAt:         timestamppb.Now(),
	}

	s.logger.Info("Performance metrics",
		zap.Uint64("memory_alloc", memStats.Alloc),
		zap.Uint64("memory_total_alloc", memStats.TotalAlloc),
		zap.Uint64("memory_sys", memStats.Sys),
		zap.Uint32("gc_cycles", memStats.NumGC),
		zap.Int("goroutines", runtime.NumGoroutine()),
		zap.Int("cpu_count", runtime.NumCPU()))

	if s.shouldOptimizePerformance(performanceMetrics, memStats) {
		s.optimizePerformance()
	}
}

func (s *Server) shouldTriggerAlert(healthStatus *commonpb.HealthStatus) bool {
	for _, component := range healthStatus.Components {
		if component.Status == commonpb.Status_STATUS_ERROR {
			return true
		}
	}
	return false
}

func (s *Server) triggerHealthAlert(healthStatus *commonpb.HealthStatus) {
	auditEvent := &commonpb.AuditEvent{
		EventId:      fmt.Sprintf("health-alert-%d", time.Now().Unix()),
		EventType:    "health_check_failed",
		ActorId:      "system",
		ActorType:    "server",
		ResourceId:   "gateway",
		ResourceType: "service",
		Action:       "health_check",
		Status:       commonpb.Status_STATUS_ERROR,
		SourceIp:     "127.0.0.1",
		UserAgent:    "gateway-server",
		Timestamp:    timestamppb.Now(),
		TraceId:      fmt.Sprintf("health-%d", time.Now().UnixNano()),
		TenantId:     "system",
		Severity:     commonpb.Severity_SEVERITY_HIGH,
	}

	s.logger.Error("Health alert triggered", 
		zap.String("event_id", auditEvent.EventId),
		zap.String("status", healthStatus.OverallStatus.String()))
}

func (s *Server) shouldOptimizePerformance(metrics *commonpb.PerformanceMetrics, memStats runtime.MemStats) bool {
	if memStats.HeapAlloc > 500*1024*1024 {
		return true
	}

	if metrics.ConcurrentRequests > 10000 {
		return true
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

func (s *Server) GetDetailedStatus() *commonpb.SystemInfo {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &commonpb.SystemInfo{
		ServiceName:  "gateway",
		Version:      "1.0.0",
		BuildCommit:  "unknown",
		BuildTime:    timestamppb.Now(),
		Environment:  string(s.config.Environment),
		StartTime:    timestamppb.New(s.startTime),
	}
}

func (s *Server) DumpConfiguration() []*commonpb.ConfigurationValue {
	configs := []*commonpb.ConfigurationValue{
		{
			Key:         "environment",
			Description: "Server environment",
			IsSensitive: false,
			UpdatedAt:   timestamppb.Now(),
			UpdatedBy:   "system",
		},
		{
			Key:         "gateway.http_port",
			Description: "HTTP server port",
			IsSensitive: false,
			UpdatedAt:   timestamppb.Now(),
			UpdatedBy:   "system",
		},
		{
			Key:         "gateway.grpc_port",
			Description: "gRPC server port",
			IsSensitive: false,
			UpdatedAt:   timestamppb.Now(),
			UpdatedBy:   "system",
		},
		{
			Key:         "security.tls_enabled",
			Description: "TLS encryption enabled",
			IsSensitive: false,
			UpdatedAt:   timestamppb.Now(),
			UpdatedBy:   "system",
		},
	}

	return configs
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

func (s *Server) GetActiveConnections() *commonpb.UsageMetrics {
	return &commonpb.UsageMetrics{
		RequestCount:   0,
		CacheHits:      int32(s.db.GetActiveConnections()),
		CacheMisses:    int32(s.db.GetIdleConnections()),
		BandwidthBytes: 0,
		ComputeUnits:   0.0,
		MeasuredAt:     timestamppb.Now(),
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "invalid log level",
			Details:   "level: " + level,
			Severity:  commonpb.Severity_SEVERITY_LOW,
			Timestamp: timestamppb.Now(),
		}
	}

	s.logger.Info("Log level changed", zap.String("new_level", level))
	return nil
}

func (s *Server) GetRequestStats() *commonpb.UsageMetrics {
	if s.orchestrator == nil {
		return &commonpb.UsageMetrics{
			RequestCount:   0,
			CacheHits:      0,
			CacheMisses:    0,
			BandwidthBytes: 0,
			ComputeUnits:   0.0,
			MeasuredAt:     timestamppb.Now(),
		}
	}

	metrics := s.orchestrator.GetMetrics()
	
	return &commonpb.UsageMetrics{
		RequestCount:   int32(metrics.TotalRequests),
		CacheHits:      int32(metrics.SuccessfulRequests),
		CacheMisses:    int32(metrics.FailedRequests),
		BandwidthBytes: 0,
		ComputeUnits:   metrics.ThroughputPerSecond,
		MeasuredAt:     timestamppb.New(metrics.LastUpdated),
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
		return nil, &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "unsupported export format",
			Details:   "format: " + format,
			Severity:  commonpb.Severity_SEVERITY_LOW,
			Timestamp: timestamppb.Now(),
		}
	}
}

func (s *Server) exportPrometheusMetrics(metrics *commonpb.UsageMetrics) ([]byte, error) {
	var output strings.Builder
	
	output.WriteString("# HELP gateway_requests_total Total number of requests\n")
	output.WriteString("# TYPE gateway_requests_total counter\n")
	output.WriteString(fmt.Sprintf("gateway_requests_total %d\n", metrics.RequestCount))
	output.WriteString(fmt.Sprintf("gateway_cache_hits %d\n", metrics.CacheHits))
	output.WriteString(fmt.Sprintf("gateway_cache_misses %d\n", metrics.CacheMisses))
	
	return []byte(output.String()), nil
}

func (s *Server) BackupConfiguration() ([]byte, error) {
	configs := s.DumpConfiguration()
	return json.Marshal(configs)
}

func (s *Server) RestoreConfiguration(data []byte) error {
	var configs []*commonpb.ConfigurationValue
	if err := json.Unmarshal(data, &configs); err != nil {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "invalid configuration data",
			Details:   err.Error(),
			Severity:  commonpb.Severity_SEVERITY_MEDIUM,
			Timestamp: timestamppb.Now(),
		}
	}

	s.logger.Info("Configuration restore requested")
	return nil
}

func (s *Server) GetSystemInfo() *commonpb.SystemInfo {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &commonpb.SystemInfo{
		ServiceName:  "gateway",
		Version:      "1.0.0",
		BuildCommit:  "unknown",
		BuildTime:    timestamppb.Now(),
		Environment:  string(s.config.Environment),
		StartTime:    timestamppb.New(s.startTime),
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "configuration is nil",
			Severity:  commonpb.Severity_SEVERITY_CRITICAL,
			Timestamp: timestamppb.Now(),
		}
	}

	if s.config.Gateway.HTTPPort <= 0 || s.config.Gateway.HTTPPort > 65535 {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "invalid HTTP port",
			Details:   fmt.Sprintf("port: %d", s.config.Gateway.HTTPPort),
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	if s.config.Gateway.GRPCPort <= 0 || s.config.Gateway.GRPCPort > 65535 {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "invalid gRPC port",
			Details:   fmt.Sprintf("port: %d", s.config.Gateway.GRPCPort),
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	if s.config.Gateway.RequestTimeout <= 0 {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "invalid request timeout",
			Details:   s.config.Gateway.RequestTimeout.String(),
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	if len(s.config.Security.AllowedOrigins) == 0 {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "no allowed origins configured",
			Severity:  commonpb.Severity_SEVERITY_MEDIUM,
			Timestamp: timestamppb.Now(),
		}
	}

	return nil
}

func (s *Server) RegisterShutdownHook(hook func() error) {
	s.logger.Info("Shutdown hook registered")
}

func (s *Server) GetServerInfo() *commonpb.SystemInfo {
	return &commonpb.SystemInfo{
		ServiceName:  "AI Gateway Server",
		Version:      "1.0.0",
		BuildCommit:  "unknown",
		BuildTime:    timestamppb.Now(),
		Environment:  string(s.config.Environment),
		StartTime:    timestamppb.New(s.startTime),
	}
}

func (s *Server) Ping() error {
	if s.isShuttingDown {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "server is shutting down",
			Severity:  commonpb.Severity_SEVERITY_MEDIUM,
			Timestamp: timestamppb.Now(),
		}
	}
	return nil
}

func (s *Server) Ready() error {
	if err := s.Ping(); err != nil {
		return err
	}

	healthStatus := s.HealthCheck()
	if healthStatus.OverallStatus != commonpb.Status_STATUS_SUCCESS {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "server is not ready",
			Details:   "health check failed",
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	return nil
}

func (s *Server) Live() error {
	return s.Ping()
}

func (s *Server) GetDependencyStatus() []*commonpb.ComponentHealth {
	dependencies := []*commonpb.ComponentHealth{}

	dbStatus := commonpb.Status_STATUS_SUCCESS
	dbMessage := "healthy"
	if err := s.db.HealthCheck(); err != nil {
		dbStatus = commonpb.Status_STATUS_ERROR
		dbMessage = "unhealthy: " + err.Error()
	}

	dependencies = append(dependencies, &commonpb.ComponentHealth{
		Name:      "database",
		Status:    dbStatus,
		Message:   dbMessage,
		LastCheck: timestamppb.Now(),
	})

	authStatus := commonpb.Status_STATUS_SUCCESS
	authMessage := "healthy"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	
	if _, err := s.authClient.HealthCheck(ctx, &authpb.HealthCheckRequest{}); err != nil {
		authStatus = commonpb.Status_STATUS_ERROR
		authMessage = "unhealthy: " + err.Error()
	}

	dependencies = append(dependencies, &commonpb.ComponentHealth{
		Name:      "auth_service",
		Status:    authStatus,
		Message:   authMessage,
		LastCheck: timestamppb.Now(),
	})

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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_TIMEOUT,
			Message:   "connection draining timed out",
			Severity:  commonpb.Severity_SEVERITY_MEDIUM,
			Timestamp: timestamppb.Now(),
		}
	case <-time.After(timeout):
		return nil
	}
}

func (s *Server) GetLoadInfo() *commonpb.PerformanceMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	loadInfo := &commonpb.PerformanceMetrics{
		TotalLatencyMs:     0,
		ModelLatencyMs:     0,
		SecurityLatencyMs:  0,
		ComplianceLatencyMs: 0,
		NetworkLatencyMs:   0,
		QueueTimeMs:        0,
		TimeToFirstTokenMs: 0,
		TokensPerSecond:    0.0,
		Throughput:         0.0,
		ConcurrentRequests: int32(runtime.NumGoroutine()),
		RetryCount:         0,
		CacheHitRatio:      0.0,
		MeasuredAt:         timestamppb.Now(),
	}

	if s.orchestrator != nil {
		metrics := s.orchestrator.GetMetrics()
		loadInfo.Throughput = metrics.ThroughputPerSecond
		loadInfo.TotalLatencyMs = metrics.AverageResponseTime.Milliseconds()
	}

	return loadInfo
}

func (s *Server) TriggerGarbageCollection() {
	s.logger.Info("Triggering garbage collection")
	runtime.GC()
	s.logger.Info("Garbage collection completed")
}

func (s *Server) GetCircuitBreakerStatus() []*commonpb.ComponentHealth {
	if s.orchestrator == nil {
		return []*commonpb.ComponentHealth{}
	}

	services := []string{"auth", "policy", "threat", "model", "audit"}
	status := []*commonpb.ComponentHealth{}

	for _, service := range services {
		cbStatus := s.orchestrator.GetCircuitBreakerStatus(service)
		status = append(status, &commonpb.ComponentHealth{
			Name:      service + "_circuit_breaker",
			Status:    cbStatus.Status,
			Message:   cbStatus.Message,
			LastCheck: timestamppb.Now(),
		})
	}

	return status
}

func (s *Server) ResetCircuitBreaker(service string) error {
	if s.orchestrator == nil {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
			Message:   "orchestrator not available",
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	return s.orchestrator.ResetCircuitBreaker(service)
}

func (s *Server) GetCacheStats() *commonpb.UsageMetrics {
	if s.orchestrator == nil {
		return &commonpb.UsageMetrics{
			RequestCount:   0,
			CacheHits:      0,
			CacheMisses:    0,
			BandwidthBytes: 0,
			ComputeUnits:   0.0,
			MeasuredAt:     timestamppb.Now(),
		}
	}

	return &commonpb.UsageMetrics{
		RequestCount:   0,
		CacheHits:      int32(s.orchestrator.GetTenantCount()),
		CacheMisses:    0,
		BandwidthBytes: 0,
		ComputeUnits:   0.0,
		MeasuredAt:     timestamppb.Now(),
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "unknown cache type",
			Details:   "type: " + cacheType,
			Severity:  commonpb.Severity_SEVERITY_LOW,
			Timestamp: timestamppb.Now(),
		}
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

func (s *Server) GetSecurityStatus() *commonpb.SecurityAnalysis {
	if s.middlewareManager == nil {
		return &commonpb.SecurityAnalysis{
			ThreatLevel:      commonpb.ThreatLevel_THREAT_LEVEL_NONE,
			ThreatsDetected:  []*commonpb.ThreatDetection{},
			RiskScore:        0.0,
			Confidence:       1.0,
			DetectionMethods: []string{},
			Recommendations:  []string{},
			ProcessingTimeMs: 0,
			EngineVersion:    "1.0.0",
			Signatures:       []*commonpb.SignatureMatch{},
			Anomalies:        []*commonpb.AnomalyDetection{},
			AnalyzedAt:       timestamppb.Now(),
		}
	}

	securityMetrics := s.middlewareManager.GetSecurityMetrics()
	return &commonpb.SecurityAnalysis{
		ThreatLevel:      commonpb.ThreatLevel_THREAT_LEVEL_LOW,
		ThreatsDetected:  []*commonpb.ThreatDetection{},
		RiskScore:        securityMetrics.RiskScore,
		Confidence:       1.0,
		DetectionMethods: []string{"middleware"},
		Recommendations:  []string{},
		ProcessingTimeMs: 0,
		EngineVersion:    "1.0.0",
		Signatures:       []*commonpb.SignatureMatch{},
		Anomalies:        []*commonpb.AnomalyDetection{},
		AnalyzedAt:       timestamppb.Now(),
	}
}

func (s *Server) UpdateSecurityRules() error {
	s.logger.Info("Security rules update requested")
	return nil
}

func (s *Server) GetAuditSummary() []*commonpb.AuditEvent {
	return []*commonpb.AuditEvent{}
}

func (s *Server) ExportAuditLogs(startTime, endTime time.Time) ([]byte, error) {
	s.logger.Info("Audit log export requested",
		zap.Time("start", startTime),
		zap.Time("end", endTime))

	auditData := []*commonpb.AuditEvent{}
	return json.Marshal(auditData)
}

func (s *Server) TestConnectivity() []*commonpb.ComponentHealth {
	results := []*commonpb.ComponentHealth{}

	results = append(results, s.testDatabaseConnectivity())
	results = append(results, s.testAuthServiceConnectivity())

	return results
}

func (s *Server) testDatabaseConnectivity() *commonpb.ComponentHealth {
	start := time.Now()
	err := s.db.HealthCheck()
	duration := time.Since(start)

	status := commonpb.Status_STATUS_SUCCESS
	message := "healthy"
	if err != nil {
		status = commonpb.Status_STATUS_ERROR
		message = err.Error()
	}

	return &commonpb.ComponentHealth{
		Name:         "database",
		Status:       status,
		Message:      message,
		LastCheck:    timestamppb.Now(),
		ResponseTime: durationpb.New(duration),
	}
}

func (s *Server) testAuthServiceConnectivity() *commonpb.ComponentHealth {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.authClient.HealthCheck(ctx, &authpb.HealthCheckRequest{})
	duration := time.Since(start)

	status := commonpb.Status_STATUS_SUCCESS
	message := "healthy"
	if err != nil {
		status = commonpb.Status_STATUS_ERROR
		message = err.Error()
	}

	return &commonpb.ComponentHealth{
		Name:         "auth_service",
		Status:       status,
		Message:      message,
		LastCheck:    timestamppb.Now(),
		ResponseTime: durationpb.New(duration),
	}
}

func (s *Server) GetVersion() string {
	return "1.0.0"
}

func (s *Server) GetBuildInfo() *commonpb.SystemInfo {
	return &commonpb.SystemInfo{
		ServiceName:  "gateway",
		Version:      "1.0.0",
		BuildCommit:  "unknown",
		BuildTime:    timestamppb.Now(),
		Environment:  string(s.config.Environment),
		StartTime:    timestamppb.New(s.startTime),
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
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "HTTP and gRPC ports cannot be the same",
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	if cfg.Gateway.HTTPPort < 1024 && os.Getuid() != 0 {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INSUFFICIENT_PERMISSIONS,
			Message:   "privileged port requires root access",
			Details:   fmt.Sprintf("HTTP port: %d", cfg.Gateway.HTTPPort),
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	if cfg.Gateway.GRPCPort < 1024 && os.Getuid() != 0 {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INSUFFICIENT_PERMISSIONS,
			Message:   "privileged port requires root access",
			Details:   fmt.Sprintf("gRPC port: %d", cfg.Gateway.GRPCPort),
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.Now(),
		}
	}

	if cfg.Gateway.RequestTimeout < time.Second {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "request timeout too short",
			Details:   cfg.Gateway.RequestTimeout.String(),
			Severity:  commonpb.Severity_SEVERITY_MEDIUM,
			Timestamp: timestamppb.Now(),
		}
	}

	if cfg.Gateway.MaxConcurrentRequests < 1 {
		return &commonpb.ErrorDetails{
			Code:      commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			Message:   "max concurrent requests must be positive",
			Details:   fmt.Sprintf("value: %d", cfg.Gateway.MaxConcurrentRequests),
			Severity:  commonpb.Severity_SEVERITY_MEDIUM,
			Timestamp: timestamppb.Now(),
		}
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
