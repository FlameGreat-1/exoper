package handlers

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/metrics"
)

type LoggingInterceptor struct {
	logger *zap.Logger
}

func NewLoggingInterceptor(logger *zap.Logger) *LoggingInterceptor {
	return &LoggingInterceptor{
		logger: logger,
	}
}

func (i *LoggingInterceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()
		
		requestID := extractRequestID(ctx)
		clientIP := extractClientIP(ctx)
		userAgent := extractUserAgent(ctx)

		i.logger.Info("Request started",
			zap.String("method", info.FullMethod),
			zap.String("request_id", requestID),
			zap.String("client_ip", clientIP),
			zap.String("user_agent", userAgent))

		resp, err := handler(ctx, req)

		duration := time.Since(startTime)
		
		if err != nil {
			i.logger.Error("Request failed",
				zap.String("method", info.FullMethod),
				zap.String("request_id", requestID),
				zap.Error(err),
				zap.Duration("duration", duration))
		} else {
			i.logger.Info("Request completed",
				zap.String("method", info.FullMethod),
				zap.String("request_id", requestID),
				zap.Duration("duration", duration))
		}

		return resp, err
	}
}

type MetricsInterceptor struct {
	metrics *metrics.Metrics
}

func NewMetricsInterceptor(metrics *metrics.Metrics) *MetricsInterceptor {
	return &MetricsInterceptor{
		metrics: metrics,
	}
}

func (i *MetricsInterceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()
		
		i.metrics.IncrementCounter("grpc_requests_total", map[string]string{
			"method": info.FullMethod,
		})

		resp, err := handler(ctx, req)

		duration := time.Since(startTime)
		
		status := "success"
		if err != nil {
			status = "error"
			i.metrics.IncrementCounter("grpc_errors_total", map[string]string{
				"method": info.FullMethod,
				"code":   getGRPCCode(err),
			})
		}

		i.metrics.RecordHistogram("grpc_request_duration_seconds", duration.Seconds(), map[string]string{
			"method": info.FullMethod,
			"status": status,
		})

		return resp, err
	}
}

type RateLimitInterceptor struct {
	config *config.Config
	logger *zap.Logger
}

func NewRateLimitInterceptor(cfg *config.Config, logger *zap.Logger) *RateLimitInterceptor {
	return &RateLimitInterceptor{
		config: cfg,
		logger: logger,
	}
}

func (i *RateLimitInterceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		clientIP := extractClientIP(ctx)
		
		if i.isRateLimited(clientIP, info.FullMethod) {
			i.logger.Warn("Rate limit exceeded",
				zap.String("client_ip", clientIP),
				zap.String("method", info.FullMethod))
			
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

func (i *RateLimitInterceptor) isRateLimited(clientIP, method string) bool {
	return false
}

type ValidationInterceptor struct {
	logger *zap.Logger
}

func NewValidationInterceptor(logger *zap.Logger) *ValidationInterceptor {
	return &ValidationInterceptor{
		logger: logger,
	}
}

func (i *ValidationInterceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if err := i.validateRequest(req, info.FullMethod); err != nil {
			i.logger.Warn("Request validation failed",
				zap.String("method", info.FullMethod),
				zap.Error(err))
			
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		return handler(ctx, req)
	}
}

func (i *ValidationInterceptor) validateRequest(req interface{}, method string) error {
	switch method {
	case "/auth.AuthenticationService/Authenticate":
		return i.validateAuthenticateRequest(req)
	case "/auth.AuthenticationService/ValidateToken":
		return i.validateTokenRequest(req)
	case "/auth.APIKeyService/CreateAPIKey":
		return i.validateCreateAPIKeyRequest(req)
	case "/auth.SessionService/CreateSession":
		return i.validateCreateSessionRequest(req)
	}
	
	return nil
}

func (i *ValidationInterceptor) validateAuthenticateRequest(req interface{}) error {
	return nil
}

func (i *ValidationInterceptor) validateTokenRequest(req interface{}) error {
	return nil
}

func (i *ValidationInterceptor) validateCreateAPIKeyRequest(req interface{}) error {
	return nil
}

func (i *ValidationInterceptor) validateCreateSessionRequest(req interface{}) error {
	return nil
}

func extractRequestID(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ids := md.Get("x-request-id"); len(ids) > 0 {
			return ids[0]
		}
	}
	return generateRequestID()
}

func extractClientIP(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
			return ips[0]
		}
		if ips := md.Get("x-real-ip"); len(ips) > 0 {
			return ips[0]
		}
	}
	return "unknown"
}

func extractUserAgent(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if agents := md.Get("user-agent"); len(agents) > 0 {
			return agents[0]
		}
	}
	return "unknown"
}

func getGRPCCode(err error) string {
	if s, ok := status.FromError(err); ok {
		return s.Code().String()
	}
	return codes.Unknown.String()
}


