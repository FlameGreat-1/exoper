package handlers

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"flamo/backend/internal/auth/service"
	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/errors"
	authpb "flamo/backend/pkg/api/proto/auth"
	commonpb "flamo/backend/pkg/api/proto/common"
)

type APIKeyHandler struct {
	authpb.UnimplementedAPIKeyServiceServer
	service *service.AuthService
	config  *config.Config
	logger  *zap.Logger
}

func NewAPIKeyHandler(authService *service.AuthService, cfg *config.Config, logger *zap.Logger) *APIKeyHandler {
	return &APIKeyHandler{
		service: authService,
		config:  cfg,
		logger:  logger,
	}
}

func (h *APIKeyHandler) CreateAPIKey(ctx context.Context, req *authpb.CreateAPIKeyRequest) (*authpb.CreateAPIKeyResponse, error) {
	startTime := time.Now()

	if err := h.validateCreateAPIKeyRequest(req); err != nil {
		return h.buildCreateAPIKeyErrorResponse(err), nil
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime()
		expiresAt = &t
	}

	result, err := h.service.CreateAPIKey(ctx, req.TenantId, req.Name, req.Description, req.Permissions, req.Scopes, expiresAt, req.CreatedBy)
	if err != nil {
		h.logger.Error("API key creation failed",
			zap.String("tenant_id", req.TenantId),
			zap.String("name", req.Name),
			zap.Error(err))
		return h.buildCreateAPIKeyErrorResponse(err), nil
	}

	response := &authpb.CreateAPIKeyResponse{
		Status: &commonpb.Status{
			Code:    commonpb.StatusCode_STATUS_CODE_OK,
			Message: "API key created successfully",
		},
		Result:         h.convertAPIKeyResult(result),
		ProcessingTime: durationpb.New(time.Since(startTime)),
	}

	h.logger.Info("API key created successfully",
		zap.String("key_id", result.KeyID),
		zap.String("tenant_id", req.TenantId),
		zap.String("name", req.Name))

	return response, nil
}

func (h *APIKeyHandler) RevokeAPIKey(ctx context.Context, req *authpb.RevokeAPIKeyRequest) (*authpb.RevokeAPIKeyResponse, error) {
	startTime := time.Now()

	if err := h.validateRevokeAPIKeyRequest(req); err != nil {
		return h.buildRevokeAPIKeyErrorResponse(err), nil
	}

	err := h.service.RevokeAPIKey(ctx, req.KeyId, req.Reason, req.RevokedBy)
	if err != nil {
		h.logger.Error("API key revocation failed",
			zap.String("key_id", req.KeyId),
			zap.String("reason", req.Reason),
			zap.Error(err))
		return h.buildRevokeAPIKeyErrorResponse(err), nil
	}

	response := &authpb.RevokeAPIKeyResponse{
		Status: &commonpb.Status{
			Code:    commonpb.StatusCode_STATUS_CODE_OK,
			Message: "API key revoked successfully",
		},
		ProcessingTime: durationpb.New(time.Since(startTime)),
	}

	h.logger.Info("API key revoked successfully",
		zap.String("key_id", req.KeyId),
		zap.String("reason", req.Reason))

	return response, nil
}

func (h *APIKeyHandler) validateCreateAPIKeyRequest(req *authpb.CreateAPIKeyRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.TenantId == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "tenant ID is required")
	}

	if req.Name == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "API key name is required")
	}

	if len(req.Name) > 100 {
		return errors.New(errors.ErrCodeInvalidRequest, "API key name too long")
	}

	if len(req.Permissions) == 0 {
		return errors.New(errors.ErrCodeInvalidRequest, "at least one permission is required")
	}

	if req.CreatedBy == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "created_by is required")
	}

	if req.ExpiresAt != nil {
		expiryTime := req.ExpiresAt.AsTime()
		if expiryTime.Before(time.Now()) {
			return errors.New(errors.ErrCodeInvalidRequest, "expiry time cannot be in the past")
		}

		if expiryTime.After(time.Now().Add(365 * 24 * time.Hour)) {
			return errors.New(errors.ErrCodeInvalidRequest, "expiry time cannot be more than 1 year in the future")
		}
	}

	return nil
}

func (h *APIKeyHandler) validateRevokeAPIKeyRequest(req *authpb.RevokeAPIKeyRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.KeyId == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "key ID is required")
	}

	if req.RevokedBy == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "revoked_by is required")
	}

	return nil
}

func (h *APIKeyHandler) convertAPIKeyResult(result *service.APIKeyResult) *authpb.APIKeyResult {
	return &authpb.APIKeyResult{
		KeyId:     result.KeyID,
		Key:       result.Key,
		Prefix:    result.Prefix,
		KeyInfo:   h.convertAPIKeyInfo(result.KeyInfo),
		CreatedAt: timestamppb.New(result.CreatedAt),
	}
}

func (h *APIKeyHandler) convertAPIKeyInfo(keyInfo *service.APIKeyInfo) *authpb.APIKeyInfo {
	if keyInfo == nil {
		return nil
	}

	return &authpb.APIKeyInfo{
		KeyId:       keyInfo.KeyID,
		TenantId:    keyInfo.TenantID,
		Name:        keyInfo.Name,
		Description: keyInfo.Description,
		Prefix:      keyInfo.Prefix,
		Permissions: keyInfo.Permissions,
		Scopes:      keyInfo.Scopes,
		ExpiresAt:   h.convertTimeToTimestamp(keyInfo.ExpiresAt),
		LastUsedAt:  h.convertTimeToTimestamp(keyInfo.LastUsedAt),
		IsActive:    keyInfo.IsActive,
		CreatedAt:   timestamppb.New(keyInfo.CreatedAt),
		CreatedBy:   keyInfo.CreatedBy,
		RevokedAt:   h.convertTimeToTimestamp(keyInfo.RevokedAt),
		Metadata:    h.convertMapToStruct(keyInfo.Metadata),
	}
}

func (h *APIKeyHandler) buildCreateAPIKeyErrorResponse(err error) *authpb.CreateAPIKeyResponse {
	return &authpb.CreateAPIKeyResponse{
		Status: h.convertErrorToStatus(err),
	}
}

func (h *APIKeyHandler) buildRevokeAPIKeyErrorResponse(err error) *authpb.RevokeAPIKeyResponse {
	return &authpb.RevokeAPIKeyResponse{
		Status: h.convertErrorToStatus(err),
	}
}

func (h *APIKeyHandler) convertErrorToStatus(err error) *commonpb.Status {
	if customErr, ok := err.(*errors.CustomError); ok {
		return &commonpb.Status{
			Code:    h.convertErrorCodeToStatusCode(customErr.Code),
			Message: customErr.Message,
			Details: customErr.Details,
		}
	}

	return &commonpb.Status{
		Code:    commonpb.StatusCode_STATUS_CODE_INTERNAL_ERROR,
		Message: err.Error(),
	}
}

func (h *APIKeyHandler) convertErrorCodeToStatusCode(code errors.ErrorCode) commonpb.StatusCode {
	switch code {
	case errors.ErrCodeInvalidRequest:
		return commonpb.StatusCode_STATUS_CODE_INVALID_ARGUMENT
	case errors.ErrCodeUnauthorized:
		return commonpb.StatusCode_STATUS_CODE_UNAUTHENTICATED
	case errors.ErrCodeForbidden:
		return commonpb.StatusCode_STATUS_CODE_PERMISSION_DENIED
	case errors.ErrCodeNotFound:
		return commonpb.StatusCode_STATUS_CODE_NOT_FOUND
	case errors.ErrCodeConflict:
		return commonpb.StatusCode_STATUS_CODE_ALREADY_EXISTS
	case errors.ErrCodeDatabaseError:
		return commonpb.StatusCode_STATUS_CODE_INTERNAL_ERROR
	case errors.ErrCodeConfigError:
		return commonpb.StatusCode_STATUS_CODE_INTERNAL_ERROR
	case errors.ErrCodeServiceUnavailable:
		return commonpb.StatusCode_STATUS_CODE_UNAVAILABLE
	default:
		return commonpb.StatusCode_STATUS_CODE_INTERNAL_ERROR
	}
}
