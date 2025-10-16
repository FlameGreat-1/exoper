package metrics

import (
	"context"
	"strconv"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type GRPCMetricsMiddleware struct {
	metrics *Metrics
	logger  *zap.Logger
}

func NewGRPCMetricsMiddleware(metrics *Metrics, logger *zap.Logger) *GRPCMetricsMiddleware {
	return &GRPCMetricsMiddleware{
		metrics: metrics,
		logger:  logger,
	}
}

func (m *GRPCMetricsMiddleware) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !m.metrics.IsEnabled() {
			return handler(ctx, req)
		}

		startTime := time.Now()
		
		// Increment request counter
		m.metrics.IncrementCounter("grpc_requests_total", map[string]string{
			"method": info.FullMethod,
			"type":   "unary",
		})

		// Execute handler
		resp, err := handler(ctx, req)

		// Record metrics
		duration := time.Since(startTime)
		statusCode := "OK"
		if err != nil {
			if s, ok := status.FromError(err); ok {
				statusCode = s.Code().String()
			} else {
				statusCode = "Unknown"
			}
		}

		labels := map[string]string{
			"method": info.FullMethod,
			"status": statusCode,
			"type":   "unary",
		}

		m.metrics.RecordHistogram("grpc_request_duration_seconds", duration.Seconds(), labels)
		
		if err != nil {
			m.metrics.IncrementCounter("grpc_request_errors_total", labels)
		}

		return resp, err
	}
}

func (m *GRPCMetricsMiddleware) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !m.metrics.IsEnabled() {
			return handler(srv, stream)
		}

		startTime := time.Now()
		
		// Increment request counter
		m.metrics.IncrementCounter("grpc_requests_total", map[string]string{
			"method": info.FullMethod,
			"type":   "stream",
		})

		// Execute handler
		err := handler(srv, stream)

		// Record metrics
		duration := time.Since(startTime)
		statusCode := "OK"
		if err != nil {
			if s, ok := status.FromError(err); ok {
				statusCode = s.Code().String()
			} else {
				statusCode = "Unknown"
			}
		}

		labels := map[string]string{
			"method": info.FullMethod,
			"status": statusCode,
			"type":   "stream",
		}

		m.metrics.RecordHistogram("grpc_request_duration_seconds", duration.Seconds(), labels)
		
		if err != nil {
			m.metrics.IncrementCounter("grpc_request_errors_total", labels)
		}

		return err
	}
}
