package handlers

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"exoper/backend/internal/auth/service"
	"exoper/backend/internal/common/config"
	"exoper/backend/internal/common/database"
	"exoper/backend/internal/common/errors"
	"exoper/backend/internal/common/metrics"
	authpb "exoper/backend/pkg/api/proto/auth"
)

type Server struct {
	config         *config.Config
	logger         *zap.Logger
	grpcServer     *grpc.Server
	authHandler    *AuthHandler
	apiKeyHandler  *APIKeyHandler
	sessionHandler *SessionHandler
	healthHandler  *HealthHandler
	authService    *service.AuthService
}

func NewServer(cfg *config.Config, db *database.Database, metrics *metrics.Metrics, logger *zap.Logger) (*Server, error) {
	authService, err := service.NewAuthService(cfg, db, logger)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to create auth service")
	}

	authHandler := NewAuthHandler(authService, cfg, logger)
	apiKeyHandler := NewAPIKeyHandler(authService, cfg, logger)
	sessionHandler := NewSessionHandler(authService, cfg, logger)
	healthHandler := NewHealthHandler(authService, db, cfg, logger)

	server := &Server{
		config:         cfg,
		logger:         logger,
		authHandler:    authHandler,
		apiKeyHandler:  apiKeyHandler,
		sessionHandler: sessionHandler,
		healthHandler:  healthHandler,
		authService:    authService,
	}

	if err := server.setupGRPCServer(metrics); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to setup gRPC server")
	}

	return server, nil
}

func (s *Server) setupGRPCServer(metrics *metrics.Metrics) error {
	interceptors := []grpc.UnaryServerInterceptor{
		NewLoggingInterceptor(s.logger).UnaryInterceptor(),
		NewMetricsInterceptor(metrics).UnaryInterceptor(),
		NewRateLimitInterceptor(s.config, s.logger).UnaryInterceptor(),
		NewValidationInterceptor(s.logger).UnaryInterceptor(),
		NewAuthMiddleware(s.authService, s.config, s.logger).UnaryInterceptor(),
	}

	streamInterceptors := []grpc.StreamServerInterceptor{
		NewAuthMiddleware(s.authService, s.config, s.logger).StreamInterceptor(),
	}

	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(interceptors...),
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

	s.grpcServer = grpc.NewServer(opts...)

	s.registerServices()

	if s.config.Environment == "development" {
		reflection.Register(s.grpcServer)
		s.logger.Info("gRPC reflection enabled for development")
	}

	return nil
}

func (s *Server) registerServices() {
	authpb.RegisterAuthenticationServiceServer(s.grpcServer, s.authHandler)
	authpb.RegisterAPIKeyServiceServer(s.grpcServer, s.apiKeyHandler)
	authpb.RegisterSessionServiceServer(s.grpcServer, s.sessionHandler)

	s.logger.Info("gRPC services registered",
		zap.Strings("services", []string{
			"AuthenticationService",
			"APIKeyService", 
			"SessionService",
		}))
}

func (s *Server) Start() error {
	address := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)
	if address == ":0" {
		address = ":8080"
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeConfigError, "failed to create listener")
	}

	s.logger.Info("Starting gRPC server",
		zap.String("address", address),
		zap.String("environment", string(s.config.Environment)))

	if err := s.grpcServer.Serve(listener); err != nil {
		return errors.Wrap(err, errors.ErrCodeServiceUnavailable, "gRPC server failed")
	}

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping gRPC server")

	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("gRPC server stopped gracefully")
	case <-ctx.Done():
		s.logger.Warn("Forcing gRPC server shutdown")
		s.grpcServer.Stop()
	}

	if err := s.authService.Shutdown(ctx); err != nil {
		s.logger.Warn("Auth service shutdown error", zap.Error(err))
	}

	return nil
}

func (s *Server) GetAuthService() *service.AuthService {
	return s.authService
}

func (s *Server) GetHealthHandler() *HealthHandler {
	return s.healthHandler
}
