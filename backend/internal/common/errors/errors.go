package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type ErrorCode string
type ErrorCategory string
type ErrorSeverity string

const (
	ErrCodeInvalidRequest     ErrorCode = "INVALID_REQUEST"
	ErrCodeUnauthorized       ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden          ErrorCode = "FORBIDDEN"
	ErrCodeNotFound           ErrorCode = "NOT_FOUND"
	ErrCodeConflict           ErrorCode = "CONFLICT"
	ErrCodeRateLimit          ErrorCode = "RATE_LIMIT_EXCEEDED"
	ErrCodeQuotaExceeded      ErrorCode = "QUOTA_EXCEEDED"
	ErrCodeModelUnavailable   ErrorCode = "MODEL_UNAVAILABLE"
	ErrCodeThreatDetected     ErrorCode = "THREAT_DETECTED"
	ErrCodeComplianceViolation ErrorCode = "COMPLIANCE_VIOLATION"
	ErrCodeInternalError      ErrorCode = "INTERNAL_ERROR"
	ErrCodeTimeout            ErrorCode = "TIMEOUT"
	ErrCodeInvalidModel       ErrorCode = "INVALID_MODEL"
	ErrCodeContentFiltered    ErrorCode = "CONTENT_FILTERED"
	ErrCodeDatabaseError      ErrorCode = "DATABASE_ERROR"
	ErrCodeCacheError         ErrorCode = "CACHE_ERROR"
	ErrCodeNetworkError       ErrorCode = "NETWORK_ERROR"
	ErrCodeConfigError        ErrorCode = "CONFIG_ERROR"
	ErrCodeValidationError    ErrorCode = "VALIDATION_ERROR"
	ErrCodeAuthenticationError ErrorCode = "AUTHENTICATION_ERROR"
	ErrCodeAuthorizationError ErrorCode = "AUTHORIZATION_ERROR"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeBadGateway         ErrorCode = "BAD_GATEWAY"
	ErrCodeGatewayTimeout     ErrorCode = "GATEWAY_TIMEOUT"
	ErrCodeTooManyRequests    ErrorCode = "TOO_MANY_REQUESTS"
	ErrCodePayloadTooLarge    ErrorCode = "PAYLOAD_TOO_LARGE"
	ErrCodeUnsupportedMedia   ErrorCode = "UNSUPPORTED_MEDIA_TYPE"
	ErrCodeMethodNotAllowed   ErrorCode = "METHOD_NOT_ALLOWED"
	ErrCodeNotAcceptable      ErrorCode = "NOT_ACCEPTABLE"
	ErrCodePreconditionFailed ErrorCode = "PRECONDITION_FAILED"
	ErrCodeExpectationFailed  ErrorCode = "EXPECTATION_FAILED"
	ErrCodeTeapot             ErrorCode = "IM_A_TEAPOT"
	ErrCodeUnprocessableEntity ErrorCode = "UNPROCESSABLE_ENTITY"
	ErrCodeLocked             ErrorCode = "LOCKED"
	ErrCodeFailedDependency   ErrorCode = "FAILED_DEPENDENCY"
	ErrCodeUpgradeRequired    ErrorCode = "UPGRADE_REQUIRED"
	ErrCodePreconditionRequired ErrorCode = "PRECONDITION_REQUIRED"
	ErrCodeRequestHeaderFieldsTooLarge ErrorCode = "REQUEST_HEADER_FIELDS_TOO_LARGE"
	ErrCodeUnavailableForLegalReasons ErrorCode = "UNAVAILABLE_FOR_LEGAL_REASONS"
)

const (
	CategoryValidation    ErrorCategory = "validation"
	CategoryAuthentication ErrorCategory = "authentication"
	CategoryAuthorization ErrorCategory = "authorization"
	CategoryBusiness      ErrorCategory = "business"
	CategorySystem        ErrorCategory = "system"
	CategoryNetwork       ErrorCategory = "network"
	CategoryDatabase      ErrorCategory = "database"
	CategoryCache         ErrorCategory = "cache"
	CategorySecurity      ErrorCategory = "security"
	CategoryCompliance    ErrorCategory = "compliance"
	CategoryConfiguration ErrorCategory = "configuration"
	CategoryExternal      ErrorCategory = "external"
)

const (
	SeverityLow      ErrorSeverity = "low"
	SeverityMedium   ErrorSeverity = "medium"
	SeverityHigh     ErrorSeverity = "high"
	SeverityCritical ErrorSeverity = "critical"
)

type AppError struct {
	ID          string                 `json:"id"`
	Code        ErrorCode              `json:"code"`
	Message     string                 `json:"message"`
	Details     string                 `json:"details,omitempty"`
	Category    ErrorCategory          `json:"category"`
	Severity    ErrorSeverity          `json:"severity"`
	HTTPStatus  int                    `json:"http_status"`
	Retryable   bool                   `json:"retryable"`
	RetryAfter  *time.Duration         `json:"retry_after,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Cause       error                  `json:"-"`
	StackTrace  []StackFrame           `json:"stack_trace,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	TenantID    string                 `json:"tenant_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	TraceID     string                 `json:"trace_id,omitempty"`
	SpanID      string                 `json:"span_id,omitempty"`
	ServiceName string                 `json:"service_name,omitempty"`
	Version     string                 `json:"version,omitempty"`
	Environment string                 `json:"environment,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type StackFrame struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

type ErrorResponse struct {
	Error      *AppError              `json:"error"`
	RequestID  string                 `json:"request_id"`
	Timestamp  time.Time              `json:"timestamp"`
	Path       string                 `json:"path,omitempty"`
	Method     string                 `json:"method,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	ClientIP   string                 `json:"client_ip,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type ValidationError struct {
	Field   string      `json:"field"`
	Value   interface{} `json:"value"`
	Tag     string      `json:"tag"`
	Message string      `json:"message"`
}

type ErrorHandler struct {
	logger      *zap.Logger
	environment string
	serviceName string
	version     string
}

var (
	globalErrorHandler *ErrorHandler
	errorCodeToHTTPStatus = map[ErrorCode]int{
		ErrCodeInvalidRequest:     http.StatusBadRequest,
		ErrCodeUnauthorized:       http.StatusUnauthorized,
		ErrCodeForbidden:          http.StatusForbidden,
		ErrCodeNotFound:           http.StatusNotFound,
		ErrCodeConflict:           http.StatusConflict,
		ErrCodeRateLimit:          http.StatusTooManyRequests,
		ErrCodeQuotaExceeded:      http.StatusTooManyRequests,
		ErrCodeModelUnavailable:   http.StatusServiceUnavailable,
		ErrCodeThreatDetected:     http.StatusForbidden,
		ErrCodeComplianceViolation: http.StatusForbidden,
		ErrCodeInternalError:      http.StatusInternalServerError,
		ErrCodeTimeout:            http.StatusGatewayTimeout,
		ErrCodeInvalidModel:       http.StatusBadRequest,
		ErrCodeContentFiltered:    http.StatusForbidden,
		ErrCodeDatabaseError:      http.StatusInternalServerError,
		ErrCodeCacheError:         http.StatusInternalServerError,
		ErrCodeNetworkError:       http.StatusBadGateway,
		ErrCodeConfigError:        http.StatusInternalServerError,
		ErrCodeValidationError:    http.StatusBadRequest,
		ErrCodeAuthenticationError: http.StatusUnauthorized,
		ErrCodeAuthorizationError: http.StatusForbidden,
		ErrCodeServiceUnavailable: http.StatusServiceUnavailable,
		ErrCodeBadGateway:         http.StatusBadGateway,
		ErrCodeGatewayTimeout:     http.StatusGatewayTimeout,
		ErrCodeTooManyRequests:    http.StatusTooManyRequests,
		ErrCodePayloadTooLarge:    http.StatusRequestEntityTooLarge,
		ErrCodeUnsupportedMedia:   http.StatusUnsupportedMediaType,
		ErrCodeMethodNotAllowed:   http.StatusMethodNotAllowed,
		ErrCodeNotAcceptable:      http.StatusNotAcceptable,
		ErrCodePreconditionFailed: http.StatusPreconditionFailed,
		ErrCodeExpectationFailed:  http.StatusExpectationFailed,
		ErrCodeTeapot:             http.StatusTeapot,
		ErrCodeUnprocessableEntity: http.StatusUnprocessableEntity,
		ErrCodeLocked:             http.StatusLocked,
		ErrCodeFailedDependency:   http.StatusFailedDependency,
		ErrCodeUpgradeRequired:    http.StatusUpgradeRequired,
		ErrCodePreconditionRequired: http.StatusPreconditionRequired,
		ErrCodeRequestHeaderFieldsTooLarge: http.StatusRequestHeaderFieldsTooLarge,
		ErrCodeUnavailableForLegalReasons: http.StatusUnavailableForLegalReasons,
	}

	errorCodeToCategory = map[ErrorCode]ErrorCategory{
		ErrCodeInvalidRequest:     CategoryValidation,
		ErrCodeUnauthorized:       CategoryAuthentication,
		ErrCodeForbidden:          CategoryAuthorization,
		ErrCodeNotFound:           CategoryBusiness,
		ErrCodeConflict:           CategoryBusiness,
		ErrCodeRateLimit:          CategorySystem,
		ErrCodeQuotaExceeded:      CategorySystem,
		ErrCodeModelUnavailable:   CategoryExternal,
		ErrCodeThreatDetected:     CategorySecurity,
		ErrCodeComplianceViolation: CategoryCompliance,
		ErrCodeInternalError:      CategorySystem,
		ErrCodeTimeout:            CategoryNetwork,
		ErrCodeInvalidModel:       CategoryValidation,
		ErrCodeContentFiltered:    CategorySecurity,
		ErrCodeDatabaseError:      CategoryDatabase,
		ErrCodeCacheError:         CategoryCache,
		ErrCodeNetworkError:       CategoryNetwork,
		ErrCodeConfigError:        CategoryConfiguration,
		ErrCodeValidationError:    CategoryValidation,
		ErrCodeAuthenticationError: CategoryAuthentication,
		ErrCodeAuthorizationError: CategoryAuthorization,
		ErrCodeServiceUnavailable: CategorySystem,
		ErrCodeBadGateway:         CategoryNetwork,
		ErrCodeGatewayTimeout:     CategoryNetwork,
		ErrCodeTooManyRequests:    CategorySystem,
		ErrCodePayloadTooLarge:    CategoryValidation,
		ErrCodeUnsupportedMedia:   CategoryValidation,
		ErrCodeMethodNotAllowed:   CategoryValidation,
		ErrCodeNotAcceptable:      CategoryValidation,
		ErrCodePreconditionFailed: CategoryValidation,
		ErrCodeExpectationFailed:  CategoryValidation,
		ErrCodeTeapot:             CategorySystem,
		ErrCodeUnprocessableEntity: CategoryValidation,
		ErrCodeLocked:             CategoryBusiness,
		ErrCodeFailedDependency:   CategorySystem,
		ErrCodeUpgradeRequired:    CategorySystem,
		ErrCodePreconditionRequired: CategoryValidation,
		ErrCodeRequestHeaderFieldsTooLarge: CategoryValidation,
		ErrCodeUnavailableForLegalReasons: CategoryCompliance,
	}

	errorCodeToSeverity = map[ErrorCode]ErrorSeverity{
		ErrCodeInvalidRequest:     SeverityLow,
		ErrCodeUnauthorized:       SeverityMedium,
		ErrCodeForbidden:          SeverityMedium,
		ErrCodeNotFound:           SeverityLow,
		ErrCodeConflict:           SeverityLow,
		ErrCodeRateLimit:          SeverityMedium,
		ErrCodeQuotaExceeded:      SeverityMedium,
		ErrCodeModelUnavailable:   SeverityHigh,
		ErrCodeThreatDetected:     SeverityHigh,
		ErrCodeComplianceViolation: SeverityHigh,
		ErrCodeInternalError:      SeverityCritical,
		ErrCodeTimeout:            SeverityMedium,
		ErrCodeInvalidModel:       SeverityLow,
		ErrCodeContentFiltered:    SeverityMedium,
		ErrCodeDatabaseError:      SeverityCritical,
		ErrCodeCacheError:         SeverityMedium,
		ErrCodeNetworkError:       SeverityMedium,
		ErrCodeConfigError:        SeverityCritical,
		ErrCodeValidationError:    SeverityLow,
		ErrCodeAuthenticationError: SeverityMedium,
		ErrCodeAuthorizationError: SeverityMedium,
		ErrCodeServiceUnavailable: SeverityHigh,
		ErrCodeBadGateway:         SeverityHigh,
		ErrCodeGatewayTimeout:     SeverityMedium,
		ErrCodeTooManyRequests:    SeverityMedium,
		ErrCodePayloadTooLarge:    SeverityLow,
		ErrCodeUnsupportedMedia:   SeverityLow,
		ErrCodeMethodNotAllowed:   SeverityLow,
		ErrCodeNotAcceptable:      SeverityLow,
		ErrCodePreconditionFailed: SeverityLow,
		ErrCodeExpectationFailed:  SeverityLow,
		ErrCodeTeapot:             SeverityLow,
		ErrCodeUnprocessableEntity: SeverityLow,
		ErrCodeLocked:             SeverityMedium,
		ErrCodeFailedDependency:   SeverityMedium,
		ErrCodeUpgradeRequired:    SeverityMedium,
		ErrCodePreconditionRequired: SeverityLow,
		ErrCodeRequestHeaderFieldsTooLarge: SeverityLow,
		ErrCodeUnavailableForLegalReasons: SeverityHigh,
	}

	retryableErrors = map[ErrorCode]bool{
		ErrCodeRateLimit:          true,
		ErrCodeQuotaExceeded:      true,
		ErrCodeModelUnavailable:   true,
		ErrCodeInternalError:      true,
		ErrCodeTimeout:            true,
		ErrCodeNetworkError:       true,
		ErrCodeServiceUnavailable: true,
		ErrCodeBadGateway:         true,
		ErrCodeGatewayTimeout:     true,
		ErrCodeTooManyRequests:    true,
		ErrCodeFailedDependency:   true,
	}
)

func NewErrorHandler(logger *zap.Logger, environment, serviceName, version string) *ErrorHandler {
	return &ErrorHandler{
		logger:      logger,
		environment: environment,
		serviceName: serviceName,
		version:     version,
	}
}

func InitializeErrorHandler(logger *zap.Logger, environment, serviceName, version string) {
	globalErrorHandler = NewErrorHandler(logger, environment, serviceName, version)
}

func New(code ErrorCode, message string) *AppError {
	return &AppError{
		ID:          uuid.New().String(),
		Code:        code,
		Message:     message,
		Category:    getErrorCategory(code),
		Severity:    getErrorSeverity(code),
		HTTPStatus:  getHTTPStatus(code),
		Retryable:   isRetryable(code),
		Context:     make(map[string]interface{}),
		StackTrace:  captureStackTrace(),
		Timestamp:   time.Now().UTC(),
		Metadata:    make(map[string]interface{}),
	}
}

func Newf(code ErrorCode, format string, args ...interface{}) *AppError {
	return New(code, fmt.Sprintf(format, args...))
}

func Wrap(err error, code ErrorCode, message string) *AppError {
	if err == nil {
		return nil
	}

	appErr := New(code, message)
	appErr.Cause = err
	appErr.Details = err.Error()

	if existingAppErr, ok := err.(*AppError); ok {
		appErr.TenantID = existingAppErr.TenantID
		appErr.UserID = existingAppErr.UserID
		appErr.RequestID = existingAppErr.RequestID
		appErr.TraceID = existingAppErr.TraceID
		appErr.SpanID = existingAppErr.SpanID
	}

	return appErr
}

func Wrapf(err error, code ErrorCode, format string, args ...interface{}) *AppError {
	return Wrap(err, code, fmt.Sprintf(format, args...))
}

func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Details)
	}
	return e.Message
}

func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

func (e *AppError) WithTenantID(tenantID string) *AppError {
	e.TenantID = tenantID
	return e
}

func (e *AppError) WithUserID(userID string) *AppError {
	e.UserID = userID
	return e
}

func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

func (e *AppError) WithTraceID(traceID string) *AppError {
	e.TraceID = traceID
	return e
}

func (e *AppError) WithSpanID(spanID string) *AppError {
	e.SpanID = spanID
	return e
}

func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

func (e *AppError) WithCause(cause error) *AppError {
	e.Cause = cause
	if e.Details == "" && cause != nil {
		e.Details = cause.Error()
	}
	return e
}

func (e *AppError) WithMetadata(key string, value interface{}) *AppError {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

func (e *AppError) WithRetryAfter(duration time.Duration) *AppError {
	e.RetryAfter = &duration
	return e
}

func (e *AppError) IsRetryable() bool {
	return e.Retryable
}

func (e *AppError) IsCritical() bool {
	return e.Severity == SeverityCritical
}

func (e *AppError) IsSecurityRelated() bool {
	return e.Category == CategorySecurity || e.Category == CategoryCompliance
}

func (e *AppError) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

func (e *AppError) ToHTTPResponse() *ErrorResponse {
	return &ErrorResponse{
		Error:     e,
		RequestID: e.RequestID,
		Timestamp: time.Now().UTC(),
	}
}

func (e *AppError) Log(logger *zap.Logger) {
	fields := []zap.Field{
		zap.String("error_id", e.ID),
		zap.String("error_code", string(e.Code)),
		zap.String("category", string(e.Category)),
		zap.String("severity", string(e.Severity)),
		zap.Int("http_status", e.HTTPStatus),
		zap.Bool("retryable", e.Retryable),
		zap.Time("timestamp", e.Timestamp),
	}

	if e.TenantID != "" {
		fields = append(fields, zap.String("tenant_id", e.TenantID))
	}
	if e.UserID != "" {
		fields = append(fields, zap.String("user_id", e.UserID))
	}
	if e.RequestID != "" {
		fields = append(fields, zap.String("request_id", e.RequestID))
	}
	if e.TraceID != "" {
		fields = append(fields, zap.String("trace_id", e.TraceID))
	}
	if e.SpanID != "" {
		fields = append(fields, zap.String("span_id", e.SpanID))
	}
	if e.Details != "" {
		fields = append(fields, zap.String("details", e.Details))
	}
	if len(e.Context) > 0 {
		fields = append(fields, zap.Any("context", e.Context))
	}
	if len(e.Metadata) > 0 {
		fields = append(fields, zap.Any("metadata", e.Metadata))
	}
	if e.Cause != nil {
		fields = append(fields, zap.Error(e.Cause))
	}

	switch e.Severity {
	case SeverityCritical:
		logger.Error(e.Message, fields...)
	case SeverityHigh:
		logger.Error(e.Message, fields...)
	case SeverityMedium:
		logger.Warn(e.Message, fields...)
	case SeverityLow:
		logger.Info(e.Message, fields...)
	default:
		logger.Info(e.Message, fields...)
	}
}

func Handle(err error) *AppError {
	if err == nil {
		return nil
	}

	if appErr, ok := err.(*AppError); ok {
		if globalErrorHandler != nil {
			appErr.ServiceName = globalErrorHandler.serviceName
			appErr.Version = globalErrorHandler.version
			appErr.Environment = globalErrorHandler.environment
			appErr.Log(globalErrorHandler.logger)
		}
		return appErr
	}

	appErr := Wrap(err, ErrCodeInternalError, "Internal server error")
	if globalErrorHandler != nil {
		appErr.ServiceName = globalErrorHandler.serviceName
		appErr.Version = globalErrorHandler.version
		appErr.Environment = globalErrorHandler.environment
		appErr.Log(globalErrorHandler.logger)
	}

	return appErr
}

func HandleWithCode(err error, code ErrorCode) *AppError {
	if err == nil {
		return nil
	}

	if appErr, ok := err.(*AppError); ok {
		appErr.Code = code
		appErr.Category = getErrorCategory(code)
		appErr.Severity = getErrorSeverity(code)
		appErr.HTTPStatus = getHTTPStatus(code)
		appErr.Retryable = isRetryable(code)
		
		if globalErrorHandler != nil {
			appErr.ServiceName = globalErrorHandler.serviceName
			appErr.Version = globalErrorHandler.version
			appErr.Environment = globalErrorHandler.environment
			appErr.Log(globalErrorHandler.logger)
		}
		return appErr
	}

	appErr := Wrap(err, code, err.Error())
	if globalErrorHandler != nil {
		appErr.ServiceName = globalErrorHandler.serviceName
		appErr.Version = globalErrorHandler.version
		appErr.Environment = globalErrorHandler.environment
		appErr.Log(globalErrorHandler.logger)
	}

	return appErr
}

func NewValidationError(field, message string, value interface{}) *AppError {
	validationErr := ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	}

	appErr := New(ErrCodeValidationError, fmt.Sprintf("Validation failed for field '%s': %s", field, message))
	appErr.WithContext("validation_error", validationErr)
	
	return appErr
}

func NewValidationErrors(errors []ValidationError) *AppError {
	messages := make([]string, len(errors))
	for i, err := range errors {
		messages[i] = fmt.Sprintf("%s: %s", err.Field, err.Message)
	}

	appErr := New(ErrCodeValidationError, fmt.Sprintf("Validation failed: %s", strings.Join(messages, "; ")))
	appErr.WithContext("validation_errors", errors)
	
	return appErr
}

func NewUnauthorizedError(message string) *AppError {
	if message == "" {
		message = "Authentication required"
	}
	return New(ErrCodeUnauthorized, message)
}

func NewForbiddenError(message string) *AppError {
	if message == "" {
		message = "Access denied"
	}
	return New(ErrCodeForbidden, message)
}

func NewNotFoundError(resource string) *AppError {
	message := "Resource not found"
	if resource != "" {
		message = fmt.Sprintf("%s not found", resource)
	}
	return New(ErrCodeNotFound, message).WithContext("resource", resource)
}

func NewConflictError(message string) *AppError {
	if message == "" {
		message = "Resource conflict"
	}
	return New(ErrCodeConflict, message)
}

func NewRateLimitError(retryAfter time.Duration) *AppError {
	appErr := New(ErrCodeRateLimit, "Rate limit exceeded")
	if retryAfter > 0 {
		appErr.WithRetryAfter(retryAfter)
	}
	return appErr
}

func NewTimeoutError(operation string) *AppError {
	message := "Operation timed out"
	if operation != "" {
		message = fmt.Sprintf("%s timed out", operation)
	}
	return New(ErrCodeTimeout, message).WithContext("operation", operation)
}

func NewDatabaseError(operation string, cause error) *AppError {
	message := "Database operation failed"
	if operation != "" {
		message = fmt.Sprintf("Database %s failed", operation)
	}
	return Wrap(cause, ErrCodeDatabaseError, message).WithContext("operation", operation)
}

func NewNetworkError(endpoint string, cause error) *AppError {
	message := "Network operation failed"
	if endpoint != "" {
		message = fmt.Sprintf("Network request to %s failed", endpoint)
	}
	return Wrap(cause, ErrCodeNetworkError, message).WithContext("endpoint", endpoint)
}

func NewSecurityError(threatType, description string) *AppError {
	message := "Security threat detected"
	if threatType != "" {
		message = fmt.Sprintf("Security threat detected: %s", threatType)
	}
	
	appErr := New(ErrCodeThreatDetected, message)
	appErr.WithContext("threat_type", threatType)
	if description != "" {
		appErr.WithContext("description", description)
	}
	
	return appErr
}

func NewComplianceError(framework, violation string) *AppError {
	message := "Compliance violation detected"
	if framework != "" && violation != "" {
		message = fmt.Sprintf("Compliance violation in %s: %s", framework, violation)
	}
	
	appErr := New(ErrCodeComplianceViolation, message)
	appErr.WithContext("framework", framework)
	appErr.WithContext("violation", violation)
	
	return appErr
}

func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

func GetErrorCode(err error) ErrorCode {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code
	}
	return ErrCodeInternalError
}

func GetHTTPStatus(err error) int {
	if appErr, ok := err.(*AppError); ok {
		return appErr.HTTPStatus
	}
	return http.StatusInternalServerError
}

func IsRetryableError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Retryable
	}
	return false
}

func GetRetryAfter(err error) *time.Duration {
	if appErr, ok := err.(*AppError); ok {
		return appErr.RetryAfter
	}
	return nil
}

func captureStackTrace() []StackFrame {
	const maxFrames = 32
	frames := make([]StackFrame, 0, maxFrames)
	
	pc := make([]uintptr, maxFrames)
	n := runtime.Callers(3, pc)
	
	for i := 0; i < n; i++ {
		fn := runtime.FuncForPC(pc[i])
		if fn == nil {
			continue
		}
		
		file, line := fn.FileLine(pc[i])
		frames = append(frames, StackFrame{
			Function: fn.Name(),
			File:     file,
			Line:     line,
		})
	}
	
	return frames
}

func getErrorCategory(code ErrorCode) ErrorCategory {
	if category, exists := errorCodeToCategory[code]; exists {
		return category
	}
	return CategorySystem
}

func getErrorSeverity(code ErrorCode) ErrorSeverity {
	if severity, exists := errorCodeToSeverity[code]; exists {
		return severity
	}
	return SeverityMedium
}

func getHTTPStatus(code ErrorCode) int {
	if status, exists := errorCodeToHTTPStatus[code]; exists {
		return status
	}
	return http.StatusInternalServerError
}

func isRetryable(code ErrorCode) bool {
	return retryableErrors[code]
}

func getRetryAfterDuration(code ErrorCode) time.Duration {
	switch code {
	case ErrCodeRateLimit:
		return time.Minute
	case ErrCodeQuotaExceeded:
		return time.Hour
	case ErrCodeModelUnavailable:
		return 30 * time.Second
	case ErrCodeServiceUnavailable:
		return 30 * time.Second
	case ErrCodeBadGateway:
		return 10 * time.Second
	case ErrCodeGatewayTimeout:
		return 5 * time.Second
	case ErrCodeTooManyRequests:
		return time.Minute
	case ErrCodeFailedDependency:
		return 30 * time.Second
	default:
		return 30 * time.Second
	}
}

func RecoverFromPanic() *AppError {
	if r := recover(); r != nil {
		var err error
		switch x := r.(type) {
		case string:
			err = fmt.Errorf("panic: %s", x)
		case error:
			err = x
		default:
			err = fmt.Errorf("panic: %v", x)
		}
		
		appErr := Wrap(err, ErrCodeInternalError, "Internal server error due to panic")
		appErr.WithContext("panic_value", r)
		
		if globalErrorHandler != nil {
			appErr.Log(globalErrorHandler.logger)
		}
		
		return appErr
	}
	return nil
}

func SafeExecute(fn func() error) (appErr *AppError) {
	defer func() {
		if panicErr := RecoverFromPanic(); panicErr != nil {
			appErr = panicErr
		}
	}()
	
	if err := fn(); err != nil {
		appErr = Handle(err)
	}
	
	return appErr
}

func SafeExecuteWithResult[T any](fn func() (T, error)) (result T, appErr *AppError) {
	defer func() {
		if panicErr := RecoverFromPanic(); panicErr != nil {
			appErr = panicErr
		}
	}()
	
	var err error
	result, err = fn()
	if err != nil {
		appErr = Handle(err)
	}
	
	return result, appErr
}

func FormatErrorForUser(err error) string {
	if appErr, ok := err.(*AppError); ok {
		switch appErr.Category {
		case CategoryValidation:
			return appErr.Message
		case CategoryAuthentication:
			return "Authentication failed. Please check your credentials."
		case CategoryAuthorization:
			return "You don't have permission to perform this action."
		case CategoryBusiness:
			return appErr.Message
		case CategorySecurity:
			return "Request blocked for security reasons."
		case CategoryCompliance:
			return "Request violates compliance policies."
		default:
			return "An error occurred while processing your request."
		}
	}
	return "An unexpected error occurred."
}

func GetErrorHelpURL(code ErrorCode) string {
	baseURL := "https://docs.exoper.ai/errors/"
	return fmt.Sprintf("%s%s", baseURL, strings.ToLower(string(code)))
}

func CreateErrorResponse(err error, requestID, path, method, userAgent, clientIP string) *ErrorResponse {
	appErr := Handle(err)
	
	response := &ErrorResponse{
		Error:     appErr,
		RequestID: requestID,
		Timestamp: time.Now().UTC(),
		Path:      path,
		Method:    method,
		UserAgent: userAgent,
		ClientIP:  clientIP,
		Metadata:  make(map[string]interface{}),
	}
	
	if appErr.RequestID == "" {
		appErr.RequestID = requestID
	}
	
	return response
}

func LogError(err error, logger *zap.Logger) {
	if appErr, ok := err.(*AppError); ok {
		appErr.Log(logger)
	} else {
		logger.Error("Unhandled error", zap.Error(err))
	}
}

func ShouldRetry(err error, attempt int, maxAttempts int) bool {
	if attempt >= maxAttempts {
		return false
	}
	
	if appErr, ok := err.(*AppError); ok {
		return appErr.Retryable
	}
	
	return false
}

func CalculateBackoffDelay(attempt int, baseDelay time.Duration, maxDelay time.Duration) time.Duration {
	delay := baseDelay * time.Duration(1<<uint(attempt))
	if delay > maxDelay {
		delay = maxDelay
	}
	return delay
}

func NewServiceUnavailableError(message string) error {
	return fmt.Errorf("service unavailable: %s", message)
}
