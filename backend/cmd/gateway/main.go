package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"exoper/backend/internal/common/config"
	"exoper/backend/internal/common/database"
	"exoper/backend/internal/gateway/server"
	"exoper/backend/internal/gateway/orchestrator"
	"exoper/backend/internal/gateway/handlers"
	"exoper/backend/internal/gateway/middleware"
	"exoper/backend/internal/gateway/routing"
	authpb "exoper/backend/pkg/api/proto/auth"
	gatewaypb "exoper/backend/pkg/api/proto/gateway"
)

const (
	serviceName    = "gateway"
	serviceVersion = "1.0.0"
	defaultPort    = 8080
	defaultGRPCPort = 9090
)

var (
	configPath = flag.String("config", "", "Path to configuration file")
	logLevel   = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	port       = flag.Int("port", defaultPort, "HTTP server port")
	grpcPort   = flag.Int("grpc-port", defaultGRPCPort, "gRPC server port")
	env        = flag.String("env", "development", "Environment (development, staging, production)")
	version    = flag.Bool("version", false, "Show version information")
	validate   = flag.Bool("validate", false, "Validate configuration and exit")
)

func main() {
	flag.Parse()

	if *version {
		printVersion()
		os.Exit(0)
	}

	logger := initializeLogger(*logLevel)
	defer func() {
		if err := logger.Sync(); err != nil {
			fmt.Printf("Failed to sync logger: %v\n", err)
		}
	}()

	logger.Info("Starting AI Gateway Service",
		zap.String("service", serviceName),
		zap.String("version", serviceVersion),
		zap.String("environment", *env),
		zap.String("go_version", runtime.Version()),
		zap.Int("http_port", *port),
		zap.Int("grpc_port", *grpcPort))

	cfg, err := loadConfiguration(*configPath, *env)
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	if *port != defaultPort {
		cfg.Server.Port = *port
	}
	if *grpcPort != defaultGRPCPort {
		cfg.Server.GRPCPort = *grpcPort
	}

	if *validate {
		if err := validateConfiguration(cfg, logger); err != nil {
			logger.Fatal("Configuration validation failed", zap.Error(err))
			os.Exit(1)
		}
		logger.Info("Configuration validation passed")
		os.Exit(0)
	}

	if err := validateConfiguration(cfg, logger); err != nil {
		logger.Fatal("Configuration validation failed", zap.Error(err))
	}

	db, err := initializeDatabase(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("Failed to close database connection", zap.Error(err))
		}
	}()

	authClient, err := initializeAuthClient(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize auth client", zap.Error(err))
	}

	router, err := routing.NewRouterWithDefaults(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize router", zap.Error(err))
	}

	middlewareManager := middleware.NewMiddlewareManager(cfg, logger, authClient)
	if err := middlewareManager.HealthCheck(); err != nil {
		logger.Fatal("Middleware manager health check failed", zap.Error(err))
	}

	orch, err := orchestrator.NewOrchestrator(cfg, db, logger)
	if err != nil {
		logger.Fatal("Failed to initialize orchestrator", zap.Error(err))
	}

	if err := handlers.ValidateHandlerConfiguration(cfg); err != nil {
		logger.Fatal("Handler configuration validation failed", zap.Error(err))
	}

	gatewayServer, err := server.NewServer(cfg, logger, db)
	if err != nil {
		logger.Fatal("Failed to create gateway server", zap.Error(err))
	}

	logger.Info("All components initialized successfully",
		zap.String("router_status", router.String()),
		zap.Bool("orchestrator_healthy", orch.IsHealthy()),
		zap.Int("tenant_count", orch.GetTenantCount()))

	if err := gatewayServer.Start(); err != nil {
		logger.Fatal("Failed to start gateway server", zap.Error(err))
	}

	logger.Info("Gateway server started successfully",
		zap.String("http_address", fmt.Sprintf(":%d", cfg.Server.Port)),
		zap.String("grpc_address", fmt.Sprintf(":%d", cfg.Server.GRPCPort)),
		zap.Bool("tls_enabled", cfg.Server.TLSConfig.Enabled))

	startHealthMonitoring(gatewayServer, orch, router, middlewareManager, logger)

	setupGracefulShutdown(gatewayServer, orch, router, middlewareManager, logger)

	if err := gatewayServer.Wait(); err != nil {
		logger.Error("Gateway server shutdown with error", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("Gateway service shutdown completed")
}

func initializeAuthClient(cfg *config.Config, logger *zap.Logger) (authpb.AuthenticationServiceClient, error) {
	logger.Info("Initializing auth service client",
		zap.String("host", cfg.Services.AuthService.Host),
		zap.Int("port", cfg.Services.AuthService.Port))

	conn, err := grpc.Dial(
		fmt.Sprintf("%s:%d", cfg.Services.AuthService.Host, cfg.Services.AuthService.Port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithTimeout(10*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to auth service: %w", err)
	}

	client := authpb.NewAuthenticationServiceClient(conn)

	if err := conn.Close(); err != nil {
		logger.Warn("Failed to close auth service connection test", zap.Error(err))
	} else {
		logger.Info("Auth service connection established successfully")
	}

	return client, nil
}

func startHealthMonitoring(gatewayServer *server.Server, orch *orchestrator.Orchestrator, router *routing.Router, middlewareManager *middleware.MiddlewareManager, logger *zap.Logger) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				performHealthChecks(gatewayServer, orch, router, middlewareManager, logger)
			}
		}
	}()
}

func performHealthChecks(gatewayServer *server.Server, orch *orchestrator.Orchestrator, router *routing.Router, middlewareManager *middleware.MiddlewareManager, logger *zap.Logger) {
	healthData := map[string]interface{}{
		"timestamp": time.Now().UTC(),
		"server":    gatewayServer.HealthCheck() == nil,
		"orchestrator": map[string]interface{}{
			"healthy":      orch.IsHealthy(),
			"tenant_count": orch.GetTenantCount(),
			"metrics": func() interface{} {
				if metrics, err := orch.GetMetrics(context.Background(), &gatewaypb.GetMetricsRequest{}); err == nil {
					return metrics
				}
				return nil
			}(),
		},
		"router": router.GetHealthStatus(),
		"middleware": map[string]interface{}{
			"healthy":          middlewareManager.HealthCheck() == nil,
			"security_metrics": middlewareManager.GetSecurityMetrics(),
			"rate_limit_status": middlewareManager.GetRateLimitStatus(),
		},
	}

	logger.Debug("Health check completed", zap.Any("health", healthData))

	if !orch.IsHealthy() {
		logger.Warn("Orchestrator is unhealthy")
	}

	routerHealth := router.GetHealthStatus()
	if status, ok := routerHealth["status"].(string); ok && status != "healthy" {
		logger.Warn("Router is unhealthy", zap.Any("router_status", routerHealth))
	}
}

func setupGracefulShutdown(gatewayServer *server.Server, orch *orchestrator.Orchestrator, router *routing.Router, middlewareManager *middleware.MiddlewareManager, logger *zap.Logger) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		sig := <-sigChan
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger.Info("Initiating graceful shutdown of all components")

		if err := gatewayServer.DrainConnections(5 * time.Second); err != nil {
			logger.Warn("Failed to drain connections", zap.Error(err))
		}

		shutdownErrors := make([]error, 0)

		if err := router.Shutdown(shutdownCtx); err != nil {
			logger.Error("Router shutdown failed", zap.Error(err))
			shutdownErrors = append(shutdownErrors, err)
		}

		if err := middlewareManager.Shutdown(shutdownCtx); err != nil {
			logger.Error("Middleware manager shutdown failed", zap.Error(err))
			shutdownErrors = append(shutdownErrors, err)
		}

		if err := orch.Shutdown(shutdownCtx); err != nil {
			logger.Error("Orchestrator shutdown failed", zap.Error(err))
			shutdownErrors = append(shutdownErrors, err)
		}

		if err := gatewayServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("Gateway server shutdown failed", zap.Error(err))
			shutdownErrors = append(shutdownErrors, err)
		}

		if len(shutdownErrors) > 0 {
			logger.Error("Graceful shutdown completed with errors", zap.Int("error_count", len(shutdownErrors)))
			gatewayServer.ForceShutdown()
		} else {
			logger.Info("Graceful shutdown completed successfully")
		}
	}()
}

func printVersion() {
	fmt.Printf("%s version %s\n", serviceName, serviceVersion)
	fmt.Printf("Go version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Build time: %s\n", time.Now().Format(time.RFC3339))
}

func initializeLogger(level string) *zap.Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	config := zap.Config{
		Level:       zap.NewAtomicLevelAt(zapLevel),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding: "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		InitialFields: map[string]interface{}{
			"service": serviceName,
			"version": serviceVersion,
			"pid":     os.Getpid(),
		},
	}

	logger, err := config.Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}

	return logger
}

func loadConfiguration(configPath, environment string) (*config.Config, error) {
	if configPath == "" {
		envMap := map[string]string{
			"development": "local",
			"staging":     "staging",
			"production":  "production",
		}
		
		if mappedEnv, exists := envMap[environment]; exists {
			configPath = fmt.Sprintf("configs/%s/gateway.yaml", mappedEnv)
		} else {
			configPath = fmt.Sprintf("configs/%s/gateway.yaml", environment)
		}
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", configPath)
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration from %s: %w", configPath, err)
	}

	if cfg.Environment == "" {
		cfg.Environment = config.Environment(environment)
	}

	return cfg, nil
}

func validateConfiguration(cfg *config.Config, logger *zap.Logger) error {
	logger.Info("Validating configuration")

	if err := server.ValidateServerConfig(cfg); err != nil {
		return fmt.Errorf("server configuration validation failed: %w", err)
	}

	if err := routing.ValidateRoutingConfig(cfg); err != nil {
		return fmt.Errorf("routing configuration validation failed: %w", err)
	}

	if err := middleware.ValidateMiddlewareConfig(cfg); err != nil {
		return fmt.Errorf("middleware configuration validation failed: %w", err)
	}

	logger.Info("Configuration validation completed successfully")
	return nil
}

func initializeDatabase(cfg *config.Config, logger *zap.Logger) (*database.Database, error) {
	logger.Info("Initializing database connection",
		zap.String("host", cfg.Database.Host),
		zap.Int("port", cfg.Database.Port),
		zap.String("database", cfg.Database.Database))

	db, err := database.NewDatabase(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create database connection: %w", err)
	}

	if err := db.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.HealthCheck(context.Background()); err != nil {
		return nil, fmt.Errorf("database health check failed: %w", err)
	}

	logger.Info("Database connection established successfully")
	return db, nil
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	if os.Getenv("GOGC") == "" {
		os.Setenv("GOGC", "100")
	}

	if os.Getenv("GOMEMLIMIT") == "" {
		os.Setenv("GOMEMLIMIT", "1GiB")
	}
}
