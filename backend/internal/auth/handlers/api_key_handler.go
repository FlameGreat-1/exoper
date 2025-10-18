package handlers

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
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

	createdBy := h.extractCreatedByFromContext(ctx)

	result, err := h.service.CreateAPIKey(ctx, req.TenantId, req.Name, req.Description, req.Permissions, req.Scopes, expiresAt, createdBy)
	if err != nil {
		h.logger.Error("API key creation failed",
			zap.String("tenant_id", req.TenantId),
			zap.String("name", req.Name),
			zap.Error(err))
		return h.buildCreateAPIKeyErrorResponse(err), nil
	}

	response := &authpb.CreateAPIKeyResponse{
		Status:         commonpb.Status_STATUS_SUCCESS,
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
	if err := h.validateRevokeAPIKeyRequest(req); err != nil {
		return h.buildRevokeAPIKeyErrorResponse(err), nil
	}

	revokedBy := h.extractRevokedByFromContext(ctx)

	err := h.service.RevokeAPIKey(ctx, req.KeyId, req.Reason, revokedBy)
	if err != nil {
		h.logger.Error("API key revocation failed",
			zap.String("key_id", req.KeyId),
			zap.String("reason", req.Reason),
			zap.Error(err))
		return h.buildRevokeAPIKeyErrorResponse(err), nil
	}

	response := &authpb.RevokeAPIKeyResponse{
		Status:    commonpb.Status_STATUS_SUCCESS,
		RevokedAt: timestamppb.New(time.Now().UTC()),
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

	return nil
}

func (h *APIKeyHandler) extractCreatedByFromContext(ctx context.Context) string {
	if principal := ctx.Value("principal"); principal != nil {
		if p, ok := principal.(*service.Principal); ok {
			return p.ID
		}
	}
	return "system"
}

func (h *APIKeyHandler) extractRevokedByFromContext(ctx context.Context) string {
	if principal := ctx.Value("principal"); principal != nil {
		if p, ok := principal.(*service.Principal); ok {
			return p.ID
		}
	}
	return "system"
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

func (h *APIKeyHandler) convertTimeToTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *APIKeyHandler) convertMapToStruct(m map[string]interface{}) *structpb.Struct {
	if m == nil {
		return nil
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		h.logger.Warn("Failed to convert map to struct", zap.Error(err))
		return nil
	}
	return s
}

func (h *APIKeyHandler) buildCreateAPIKeyErrorResponse(err error) *authpb.CreateAPIKeyResponse {
	return &authpb.CreateAPIKeyResponse{
		Status: h.convertErrorToStatus(err),
		Error:  h.convertErrorToErrorDetails(err),
	}
}

func (h *APIKeyHandler) buildRevokeAPIKeyErrorResponse(err error) *authpb.RevokeAPIKeyResponse {
	return &authpb.RevokeAPIKeyResponse{
		Status: h.convertErrorToStatus(err),
		Error:  h.convertErrorToErrorDetails(err),
	}
}

func (h *APIKeyHandler) convertErrorToStatus(err error) commonpb.Status {
	if appErr, ok := err.(*errors.AppError); ok {
		switch appErr.Code {
		case errors.ErrCodeInvalidRequest:
			return commonpb.Status_STATUS_ERROR
		case errors.ErrCodeUnauthorized:
			return commonpb.Status_STATUS_ERROR
		case errors.ErrCodeForbidden:
			return commonpb.Status_STATUS_BLOCKED
		case errors.ErrCodeNotFound:
			return commonpb.Status_STATUS_ERROR
		case errors.ErrCodeConflict:
			return commonpb.Status_STATUS_ERROR
		default:
			return commonpb.Status_STATUS_ERROR
		}
	}
	return commonpb.Status_STATUS_ERROR
}

func (h *APIKeyHandler) convertErrorToErrorDetails(err error) *commonpb.ErrorDetails {
	if appErr, ok := err.(*errors.AppError); ok {
		return &commonpb.ErrorDetails{
			Code:      h.convertErrorCodeToCommonErrorCode(appErr.Code),
			Message:   appErr.Message,
			Details:   appErr.Details,
			Severity:  commonpb.Severity_SEVERITY_HIGH,
			Timestamp: timestamppb.New(time.Now().UTC()),
		}
	}

	return &commonpb.ErrorDetails{
		Code:      commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR,
		Message:   err.Error(),
		Severity:  commonpb.Severity_SEVERITY_HIGH,
		Timestamp: timestamppb.New(time.Now().UTC()),
	}
}

func (h *APIKeyHandler) convertErrorCodeToCommonErrorCode(code errors.ErrorCode) commonpb.ErrorCode {
	switch code {
	case errors.ErrCodeInvalidRequest:
		return commonpb.ErrorCode_ERROR_CODE_INVALID_REQUEST
	case errors.ErrCodeUnauthorized:
		return commonpb.ErrorCode_ERROR_CODE_UNAUTHORIZED
	case errors.ErrCodeForbidden:
		return commonpb.ErrorCode_ERROR_CODE_FORBIDDEN
	case errors.ErrCodeNotFound:
		return commonpb.ErrorCode_ERROR_CODE_NOT_FOUND
	case errors.ErrCodeConflict:
		return commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR
	case errors.ErrCodeDatabaseError:
		return commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR
	case errors.ErrCodeConfigError:
		return commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR
	case errors.ErrCodeServiceUnavailable:
		return commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR
	default:
		return commonpb.ErrorCode_ERROR_CODE_INTERNAL_ERROR
	}
}
