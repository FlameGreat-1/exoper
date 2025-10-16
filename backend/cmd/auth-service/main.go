package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"flamo/backend/internal/auth/handlers"
	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/metrics"
	"flamo/backend/internal/common/utils"
)

const (
	serviceName    = "auth-service"
	serviceVersion = "1.0.0"
	shutdownTimeout = 30 * time.Second
)

func main() {
	// Initialize logger first for early error reporting
	logger := initializeLogger()
	defer logger.Sync()

	logger.Info("Starting auth service",
		zap.String("service", serviceName),
		zap.String("version", serviceVersion),
		zap.String("go_version", utils.GetGoVersion()),
		zap.String("build_time", utils.GetBuildTime()))

	// Load configuration
	cfg, err := loadConfiguration(logger)
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Reconfigure logger with loaded config
	logger = reconfigureLogger(cfg)
	logger.Info("Configuration loaded successfully",
		zap.String("environment", cfg.Environment),
		zap.String("log_level", cfg.Logging.Level))

	// Validate configuration
	if err := validateConfiguration(cfg, logger); err != nil {
		logger.Fatal("Configuration validation failed", zap.Error(err))
	}

	// Initialize metrics
	metricsCollector, err := initializeMetrics(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize metrics", zap.Error(err))
	}

	// Initialize database
	db, err := initializeDatabase(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("Failed to close database connection", zap.Error(err))
		}
	}()

	// Run database migrations
	if err := runMigrations(db, cfg, logger); err != nil {
		logger.Fatal("Failed to run database migrations", zap.Error(err))
	}

	// Initialize auth server
	server, err := initializeServer(cfg, db, metricsCollector, logger)
	if err != nil {
		logger.Fatal("Failed to initialize auth server", zap.Error(err))
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in goroutine
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("Auth service ready to serve requests")
		serverErrors <- server.Start()
	}()

	// Wait for shutdown signal or server error
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		logger.Error("Server startup failed", zap.Error(err))
		os.Exit(1)

	case sig := <-shutdown:
		logger.Info("Shutdown signal received",
			zap.String("signal", sig.String()))

		// Graceful shutdown with timeout
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, shutdownTimeout)
		defer shutdownCancel()

		if err := gracefulShutdown(shutdownCtx, server, db, metricsCollector, logger); err != nil {
			logger.Error("Graceful shutdown failed", zap.Error(err))
			os.Exit(1)
		}

		logger.Info("Auth service shutdown completed successfully")
	}
}

func initializeLogger() *zap.Logger {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.MessageKey = "message"
	config.EncoderConfig.LevelKey = "level"
	config.EncoderConfig.CallerKey = "caller"
	config.EncoderConfig.StacktraceKey = "stacktrace"

	logger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
		zap.Fields(
			zap.String("service", serviceName),
			zap.String("version", serviceVersion),
		),
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}

	return logger
}

func loadConfiguration(logger *zap.Logger) (*config.Config, error) {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "configs/auth-service.yaml"
	}

	logger.Info("Loading configuration", zap.String("path", configPath))

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to load configuration file")
	}

	// Override with environment variables
	if err := config.LoadFromEnv(cfg); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to load environment variables")
	}

	return cfg, nil
}

func reconfigureLogger(cfg *config.Config) *zap.Logger {
	var level zapcore.Level
	switch cfg.Logging.Level {
	case "debug":
		level = zap.DebugLevel
	case "info":
		level = zap.InfoLevel
	case "warn":
		level = zap.WarnLevel
	case "error":
		level = zap.ErrorLevel
	default:
		level = zap.InfoLevel
	}

	config := zap.NewProductionConfig()
	if cfg.Environment == "development" {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	config.Level = zap.NewAtomicLevelAt(level)
	config.OutputPaths = []string{cfg.Logging.Output}
	config.ErrorOutputPaths = []string{cfg.Logging.ErrorOutput}

	logger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
		zap.Fields(
			zap.String("service", serviceName),
			zap.String("version", serviceVersion),
			zap.String("environment", cfg.Environment),
		),
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to reconfigure logger: %v", err))
	}

	return logger
}

func validateConfiguration(cfg *config.Config, logger *zap.Logger) error {
	logger.Info("Validating configuration")

	if cfg.Environment == "" {
		return errors.New(errors.ErrCodeConfigError, "environment is required")
	}

	if cfg.Server.Address == "" {
		logger.Warn("Server address not specified, using default :8080")
		cfg.Server.Address = ":8080"
	}

	if cfg.Database.Host == "" {
		return errors.New(errors.ErrCodeConfigError, "database host is required")
	}

	if cfg.Database.Name == "" {
		return errors.New(errors.ErrCodeConfigError, "database name is required")
	}

	if cfg.Security.JWTSecret == "" && cfg.Security.JWTPrivateKey == "" {
		return errors.New(errors.ErrCodeConfigError, "JWT secret or private key is required")
	}

	// Validate security settings for production
	if cfg.Environment == "production" {
		if !cfg.Security.TLSEnabled {
			logger.Warn("TLS is disabled in production environment")
		}

		if cfg.Security.JWTSecret != "" && len(cfg.Security.JWTSecret) < 32 {
			return errors.New(errors.ErrCodeConfigError, "JWT secret must be at least 32 characters in production")
		}

		if cfg.Database.SSLMode != "require" {
			logger.Warn("Database SSL is not required in production")
		}
	}

	logger.Info("Configuration validation completed successfully")
	return nil
}

func initializeMetrics(cfg *config.Config, logger *zap.Logger) (*metrics.Metrics, error) {
	logger.Info("Initializing metrics collector")

	metricsConfig := &metrics.Config{
		Enabled:   cfg.Metrics.Enabled,
		Address:   cfg.Metrics.Address,
		Path:      cfg.Metrics.Path,
		Namespace: "flamo_auth",
		Subsystem: "service",
	}

	metricsCollector, err := metrics.NewMetrics(metricsConfig, logger)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to create metrics collector")
	}

	// Register custom metrics
	if err := registerCustomMetrics(metricsCollector); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to register custom metrics")
	}

	logger.Info("Metrics collector initialized successfully")
	return metricsCollector, nil
}

func registerCustomMetrics(m *metrics.Metrics) error {
	// Authentication metrics
	if err := m.RegisterCounter("authentication_requests_total", "Total number of authentication requests", []string{"method", "status", "tenant_id"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("authentication_failures_total", "Total number of authentication failures", []string{"method", "reason", "tenant_id"}); err != nil {
		return err
	}

	if err := m.RegisterHistogram("authentication_duration_seconds", "Authentication request duration", []string{"method", "status"}); err != nil {
		return err
	}

	// Authorization metrics
	if err := m.RegisterCounter("authorization_requests_total", "Total number of authorization requests", []string{"resource", "action", "status"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("authorization_denials_total", "Total number of authorization denials", []string{"resource", "action", "reason"}); err != nil {
		return err
	}

	// Token metrics
	if err := m.RegisterCounter("tokens_issued_total", "Total number of tokens issued", []string{"type", "tenant_id"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("tokens_validated_total", "Total number of token validations", []string{"type", "status"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("tokens_revoked_total", "Total number of tokens revoked", []string{"type", "reason"}); err != nil {
		return err
	}

	// Session metrics
	if err := m.RegisterCounter("sessions_created_total", "Total number of sessions created", []string{"tenant_id"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("sessions_expired_total", "Total number of sessions expired", []string{"tenant_id"}); err != nil {
		return err
	}

	// Certificate metrics
	if err := m.RegisterCounter("certificates_validated_total", "Total number of certificate validations", []string{"status"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("certificate_validation_failures_total", "Total number of certificate validation failures", []string{"reason"}); err != nil {
		return err
	}

	// API Key metrics
	if err := m.RegisterCounter("api_keys_created_total", "Total number of API keys created", []string{"tenant_id"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("api_keys_revoked_total", "Total number of API keys revoked", []string{"reason"}); err != nil {
		return err
	}

	return nil
}

func initializeDatabase(cfg *config.Config, logger *zap.Logger) (*database.Database, error) {
	logger.Info("Initializing database connection",
		zap.String("host", cfg.Database.Host),
		zap.Int("port", cfg.Database.Port),
		zap.String("database", cfg.Database.Name))

	db, err := database.NewDatabase(cfg, logger)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to create database connection")
	}

	// Test database connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.Ping(ctx); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "database connectivity test failed")
	}

	logger.Info("Database connection established successfully")
	return db, nil
}

func runMigrations(db *database.Database, cfg *config.Config, logger *zap.Logger) error {
	if !cfg.Database.RunMigrations {
		logger.Info("Database migrations disabled, skipping")
		return nil
	}

	logger.Info("Running database migrations")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := db.RunMigrations(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "database migration failed")
	}

	logger.Info("Database migrations completed successfully")
	return nil
}

func initializeServer(cfg *config.Config, db *database.Database, metrics *metrics.Metrics, logger *zap.Logger) (*handlers.Server, error) {
	logger.Info("Initializing auth server")

	server, err := handlers.NewServer(cfg, db, metrics, logger)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to create auth server")
	}

	logger.Info("Auth server initialized successfully")
	return server, nil
}

func gracefulShutdown(ctx context.Context, server *handlers.Server, db *database.Database, metrics *metrics.Metrics, logger *zap.Logger) error {
	logger.Info("Starting graceful shutdown")

	// Stop accepting new requests
	if err := server.Stop(ctx); err != nil {
		logger.Error("Server shutdown error", zap.Error(err))
	}

	// Close database connections
	if err := db.Close(); err != nil {
		logger.Error("Database close error", zap.Error(err))
	}

	// Stop metrics collection
	if err := metrics.Shutdown(ctx); err != nil {
		logger.Error("Metrics shutdown error", zap.Error(err))
	}

	logger.Info("Graceful shutdown completed")
	return nil
}
