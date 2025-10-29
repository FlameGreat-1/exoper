package handlers

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	"exoper/backend/internal/auth/service"
	"exoper/backend/internal/common/config"
	"exoper/backend/internal/common/database"
	commonpb "exoper/backend/pkg/api/proto/common"
)

type HealthHandler struct {
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

func (h *HealthHandler) Check(ctx context.Context, service string) (*commonpb.ComponentHealth, error) {
	if service == "" {
		service = "auth"
	}

	result := h.checkServiceHealth(ctx, service)
	
	return result, nil
}

func (h *HealthHandler) checkServiceHealth(ctx context.Context, service string) *commonpb.ComponentHealth {
	switch service {
	case "auth":
		return h.checkAuthServiceHealth(ctx)
	case "database":
		return h.checkDatabaseHealth(ctx)
	case "overall":
		return h.checkOverallHealth(ctx)
	default:
		return &commonpb.ComponentHealth{
			Name:      service,
			Status:    commonpb.Status_STATUS_ERROR,
			Message:   "unknown service",
			LastCheck: timestamppb.Now(),
		}
	}
}

func (h *HealthHandler) checkAuthServiceHealth(ctx context.Context) *commonpb.ComponentHealth {
	supportedMethods := h.service.GetSupportedMethods()
	if len(supportedMethods) == 0 {
		h.logger.Warn("No authentication methods available")
		return &commonpb.ComponentHealth{
			Name:      "auth_service",
			Status:    commonpb.Status_STATUS_ERROR,
			Message:   "no authentication methods available",
			LastCheck: timestamppb.Now(),
		}
	}

	return &commonpb.ComponentHealth{
		Name:      "auth_service",
		Status:    commonpb.Status_STATUS_SUCCESS,
		Message:   "healthy",
		LastCheck: timestamppb.Now(),
	}
}

func (h *HealthHandler) checkDatabaseHealth(ctx context.Context) *commonpb.ComponentHealth {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := h.db.Ping(ctx); err != nil {
		h.logger.Error("Database health check failed", zap.Error(err))
		return &commonpb.ComponentHealth{
			Name:      "database",
			Status:    commonpb.Status_STATUS_ERROR,
			Message:   "database ping failed: " + err.Error(),
			LastCheck: timestamppb.Now(),
		}
	}

	return &commonpb.ComponentHealth{
		Name:      "database",
		Status:    commonpb.Status_STATUS_SUCCESS,
		Message:   "healthy",
		LastCheck: timestamppb.Now(),
	}
}

func (h *HealthHandler) checkOverallHealth(ctx context.Context) *commonpb.ComponentHealth {
	authStatus := h.checkAuthServiceHealth(ctx)
	dbStatus := h.checkDatabaseHealth(ctx)

	if authStatus.Status == commonpb.Status_STATUS_SUCCESS && 
	   dbStatus.Status == commonpb.Status_STATUS_SUCCESS {
		return &commonpb.ComponentHealth{
			Name:      "overall",
			Status:    commonpb.Status_STATUS_SUCCESS,
			Message:   "all services healthy",
			LastCheck: timestamppb.Now(),
		}
	}

	return &commonpb.ComponentHealth{
		Name:      "overall",
		Status:    commonpb.Status_STATUS_ERROR,
		Message:   "one or more services unhealthy",
		LastCheck: timestamppb.Now(),
	}
}

func (h *HealthHandler) GetReadiness(ctx context.Context) (*commonpb.SystemInfo, error) {
	return &commonpb.SystemInfo{
		ServiceName: "auth-service",
		Version:     "1.0.0",
		Environment: string(h.config.Environment),
		StartTime:   timestamppb.Now(),
	}, nil
}

func (h *HealthHandler) GetLiveness(ctx context.Context) (*commonpb.SystemInfo, error) {
	return &commonpb.SystemInfo{
		ServiceName: "auth-service",
		Version:     "1.0.0",
		Environment: string(h.config.Environment),
		StartTime:   timestamppb.Now(),
	}, nil
}
