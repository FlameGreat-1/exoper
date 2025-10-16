package handlers

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"flamo/backend/internal/auth/service"
	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	healthpb "flamo/backend/pkg/api/proto/health"
)

type HealthHandler struct {
	healthpb.UnimplementedHealthServiceServer
	service *service.AuthService
	db      *database.Database
	config  *config.Config
	logger  *zap.Logger
}

func NewHealthHandler(authService *service.AuthService, db *database.Database, cfg *config.Config, logger *zap.Logger) *HealthHandler {
	return &HealthHandler{
		service: authService,
		db:      db,
		config:  cfg,
		logger:  logger,
	}
}

func (h *HealthHandler) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	service := req.Service
	if service == "" {
		service = "auth"
	}

	status := h.checkServiceHealth(ctx, service)
	
	return &healthpb.HealthCheckResponse{
		Status: status,
	}, nil
}

func (h *HealthHandler) Watch(req *healthpb.HealthCheckRequest, stream healthpb.HealthService_WatchServer) error {
	service := req.Service
	if service == "" {
		service = "auth"
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			status := h.checkServiceHealth(stream.Context(), service)
			
			if err := stream.Send(&healthpb.HealthCheckResponse{
				Status: status,
			}); err != nil {
				h.logger.Error("Failed to send health check response", zap.Error(err))
				return err
			}
		}
	}
}

func (h *HealthHandler) checkServiceHealth(ctx context.Context, service string) healthpb.HealthCheckResponse_ServingStatus {
	switch service {
	case "auth":
		return h.checkAuthServiceHealth(ctx)
	case "database":
		return h.checkDatabaseHealth(ctx)
	case "overall":
		return h.checkOverallHealth(ctx)
	default:
		return healthpb.HealthCheckResponse_SERVICE_UNKNOWN
	}
}

func (h *HealthHandler) checkAuthServiceHealth(ctx context.Context) healthpb.HealthCheckResponse_ServingStatus {
	supportedMethods := h.service.GetSupportedMethods()
	if len(supportedMethods) == 0 {
		h.logger.Warn("No authentication methods available")
		return healthpb.HealthCheckResponse_NOT_SERVING
	}

	return healthpb.HealthCheckResponse_SERVING
}

func (h *HealthHandler) checkDatabaseHealth(ctx context.Context) healthpb.HealthCheckResponse_ServingStatus {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := h.db.Ping(ctx); err != nil {
		h.logger.Error("Database health check failed", zap.Error(err))
		return healthpb.HealthCheckResponse_NOT_SERVING
	}

	return healthpb.HealthCheckResponse_SERVING
}

func (h *HealthHandler) checkOverallHealth(ctx context.Context) healthpb.HealthCheckResponse_ServingStatus {
	authStatus := h.checkAuthServiceHealth(ctx)
	dbStatus := h.checkDatabaseHealth(ctx)

	if authStatus == healthpb.HealthCheckResponse_SERVING && 
	   dbStatus == healthpb.HealthCheckResponse_SERVING {
		return healthpb.HealthCheckResponse_SERVING
	}

	return healthpb.HealthCheckResponse_NOT_SERVING
}

func (h *HealthHandler) GetReadiness(ctx context.Context, req *healthpb.ReadinessRequest) (*healthpb.ReadinessResponse, error) {
	checks := make(map[string]bool)
	
	checks["auth_service"] = h.checkAuthServiceHealth(ctx) == healthpb.HealthCheckResponse_SERVING
	checks["database"] = h.checkDatabaseHealth(ctx) == healthpb.HealthCheckResponse_SERVING
	
	ready := true
	for _, check := range checks {
		if !check {
			ready = false
			break
		}
	}

	return &healthpb.ReadinessResponse{
		Ready:  ready,
		Checks: checks,
	}, nil
}

func (h *HealthHandler) GetLiveness(ctx context.Context, req *healthpb.LivenessRequest) (*healthpb.LivenessResponse, error) {
	return &healthpb.LivenessResponse{
		Alive: true,
	}, nil
}
