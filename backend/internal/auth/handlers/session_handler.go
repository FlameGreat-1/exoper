package handlers

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"exoper/backend/internal/auth/service"
	"exoper/backend/internal/common/config"
	"exoper/backend/internal/common/errors"
	authpb "exoper/backend/pkg/api/proto/auth"
	commonpb "exoper/backend/pkg/api/proto/common"
)

type SessionHandler struct {
	authpb.UnimplementedSessionServiceServer
	service *service.AuthService
	config  *config.Config
	logger  *zap.Logger
}

func NewSessionHandler(authService *service.AuthService, cfg *config.Config, logger *zap.Logger) *SessionHandler {
	return &SessionHandler{
		service: authService,
		config:  cfg,
		logger:  logger,
	}
}

func (h *SessionHandler) CreateSession(ctx context.Context, req *authpb.CreateSessionRequest) (*authpb.CreateSessionResponse, error) {
	if err := h.validateCreateSessionRequest(req); err != nil {
		return h.buildCreateSessionErrorResponse(err), nil
	}

	duration := 24 * time.Hour
	if req.Duration != nil {
		duration = req.Duration.AsDuration()
	}

	attributes := h.convertStructToMap(req.SessionAttributes)

	result, err := h.service.CreateSession(ctx, req.UserId, req.TenantId, duration, attributes, req.RequireMfa)
	if err != nil {
		h.logger.Error("Session creation failed",
			zap.String("user_id", req.UserId),
			zap.String("tenant_id", req.TenantId),
			zap.Error(err))
		return h.buildCreateSessionErrorResponse(err), nil
	}

	response := &authpb.CreateSessionResponse{
		Status: commonpb.Status_STATUS_SUCCESS,
		Result: h.convertSessionResult(result),
	}

	h.logger.Info("Session created successfully",
		zap.String("session_id", result.SessionID),
		zap.String("user_id", req.UserId),
		zap.String("tenant_id", req.TenantId))

	return response, nil
}

func (h *SessionHandler) ValidateSession(ctx context.Context, req *authpb.ValidateSessionRequest) (*authpb.ValidateSessionResponse, error) {
	if err := h.validateSessionRequest(req); err != nil {
		return h.buildValidateSessionErrorResponse(err), nil
	}

	extensionDuration := time.Duration(0)
	if req.ExtendSession && req.ExtensionDuration != nil {
		extensionDuration = req.ExtensionDuration.AsDuration()
	}

	result, err := h.service.ValidateSession(ctx, req.SessionId, req.SessionToken, req.ExtendSession, extensionDuration)
	if err != nil {
		h.logger.Error("Session validation failed",
			zap.String("session_id", req.SessionId),
			zap.Error(err))
		return h.buildValidateSessionErrorResponse(err), nil
	}

	response := &authpb.ValidateSessionResponse{
		Status: commonpb.Status_STATUS_SUCCESS,
		Result: h.convertSessionValidationResult(result),
	}

	return response, nil
}

func (h *SessionHandler) RevokeSession(ctx context.Context, req *authpb.RevokeSessionRequest) (*authpb.RevokeSessionResponse, error) {
	if err := h.validateRevokeSessionRequest(req); err != nil {
		return h.buildRevokeSessionErrorResponse(err), nil
	}

	revokedBy := h.extractRevokedByFromContext(ctx)

	err := h.service.RevokeSession(ctx, req.SessionId, req.Reason, revokedBy)
	if err != nil {
		h.logger.Error("Session revocation failed",
			zap.String("session_id", req.SessionId),
			zap.String("reason", req.Reason),
			zap.Error(err))
		return h.buildRevokeSessionErrorResponse(err), nil
	}

	response := &authpb.RevokeSessionResponse{
		Status:    commonpb.Status_STATUS_SUCCESS,
		RevokedAt: timestamppb.New(time.Now().UTC()),
	}

	h.logger.Info("Session revoked successfully",
		zap.String("session_id", req.SessionId),
		zap.String("reason", req.Reason))

	return response, nil
}

func (h *SessionHandler) validateCreateSessionRequest(req *authpb.CreateSessionRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.UserId == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "user ID is required")
	}

	if req.TenantId == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "tenant ID is required")
	}

	if req.Duration != nil {
		duration := req.Duration.AsDuration()
		if duration <= 0 {
			return errors.New(errors.ErrCodeInvalidRequest, "session duration must be positive")
		}

		if duration > 7*24*time.Hour {
			return errors.New(errors.ErrCodeInvalidRequest, "session duration cannot exceed 7 days")
		}
	}

	return nil
}

func (h *SessionHandler) validateSessionRequest(req *authpb.ValidateSessionRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.SessionId == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "session ID is required")
	}

	if req.SessionToken == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "session token is required")
	}

	if req.ExtendSession && req.ExtensionDuration != nil {
		duration := req.ExtensionDuration.AsDuration()
		if duration <= 0 {
			return errors.New(errors.ErrCodeInvalidRequest, "extension duration must be positive")
		}

		if duration > 24*time.Hour {
			return errors.New(errors.ErrCodeInvalidRequest, "extension duration cannot exceed 24 hours")
		}
	}

	return nil
}

func (h *SessionHandler) validateRevokeSessionRequest(req *authpb.RevokeSessionRequest) error {
	if req == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request is required")
	}

	if req.Metadata == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "request metadata is required")
	}

	if req.SessionId == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "session ID is required")
	}

	return nil
}

func (h *SessionHandler) extractRevokedByFromContext(ctx context.Context) string {
	if principal := ctx.Value("principal"); principal != nil {
		if p, ok := principal.(*service.Principal); ok {
			return p.ID
		}
	}
	return "system"
}

func (h *SessionHandler) convertSessionResult(result *service.SessionResult) *authpb.SessionResult {
	return &authpb.SessionResult{
		SessionId:    result.SessionID,
		SessionToken: result.SessionToken,
		SessionInfo:  h.convertSessionInfo(result.SessionInfo),
		CreatedAt:    timestamppb.New(result.CreatedAt),
	}
}

func (h *SessionHandler) convertSessionValidationResult(result *service.SessionValidationResult) *authpb.SessionValidationResult {
	return &authpb.SessionValidationResult{
		Valid:         result.Valid,
		SessionInfo:   h.convertSessionInfo(result.SessionInfo),
		Principal:     h.convertPrincipal(result.Principal),
		ValidatedAt:   timestamppb.New(result.ValidatedAt),
		ExtendedUntil: h.convertTimeToTimestamp(result.ExtendedUntil),
	}
}

func (h *SessionHandler) convertSessionInfo(sessionInfo *service.SessionInfo) *authpb.SessionInfo {
	if sessionInfo == nil {
		return nil
	}

	return &authpb.SessionInfo{
		SessionId:    sessionInfo.SessionID,
		UserId:       sessionInfo.UserID,
		TenantId:     sessionInfo.TenantID,
		CreatedAt:    timestamppb.New(sessionInfo.CreatedAt),
		LastActivity: timestamppb.New(sessionInfo.LastActivity),
		ExpiresAt:    timestamppb.New(sessionInfo.ExpiresAt),
		IpAddress:    sessionInfo.IPAddress,
		UserAgent:    sessionInfo.UserAgent,
		IsActive:     sessionInfo.IsActive,
		Metadata:     h.convertMapToStruct(sessionInfo.Metadata),
	}
}

func (h *SessionHandler) convertPrincipal(principal *service.Principal) *authpb.Principal {
	if principal == nil {
		return nil
	}

	return &authpb.Principal{
		Id:             principal.ID,
		Type:           principal.Type,
		Name:           principal.Name,
		Email:          principal.Email,
		TenantId:       principal.TenantID,
		OrganizationId: principal.OrganizationID,
		Roles:          principal.Roles,
		Groups:         principal.Groups,
		Attributes:     h.convertMapToStruct(principal.Attributes),
		CreatedAt:      timestamppb.New(principal.CreatedAt),
		LastLogin:      h.convertTimeToTimestamp(principal.LastLogin),
		IsActive:       principal.IsActive,
		MfaEnabled:     principal.MFAEnabled,
	}
}

func (h *SessionHandler) convertTimeToTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *SessionHandler) convertMapToStruct(m map[string]interface{}) *structpb.Struct {
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

func (h *SessionHandler) convertStructToMap(s *structpb.Struct) map[string]interface{} {
	if s == nil {
		return make(map[string]interface{})
	}
	return s.AsMap()
}

func (h *SessionHandler) buildCreateSessionErrorResponse(err error) *authpb.CreateSessionResponse {
	return &authpb.CreateSessionResponse{
		Status: h.convertErrorToStatus(err),
		Error:  h.convertErrorToErrorDetails(err),
	}
}

func (h *SessionHandler) buildValidateSessionErrorResponse(err error) *authpb.ValidateSessionResponse {
	return &authpb.ValidateSessionResponse{
		Status: h.convertErrorToStatus(err),
		Result: &authpb.SessionValidationResult{
			Valid: false,
		},
		Error: h.convertErrorToErrorDetails(err),
	}
}

func (h *SessionHandler) buildRevokeSessionErrorResponse(err error) *authpb.RevokeSessionResponse {
	return &authpb.RevokeSessionResponse{
		Status: h.convertErrorToStatus(err),
		Error:  h.convertErrorToErrorDetails(err),
	}
}

func (h *SessionHandler) convertErrorToStatus(err error) commonpb.Status {
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

func (h *SessionHandler) convertErrorToErrorDetails(err error) *commonpb.ErrorDetails {
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

func (h *SessionHandler) convertErrorCodeToCommonErrorCode(code errors.ErrorCode) commonpb.ErrorCode {
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
