package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/metrics"
	"flamo/backend/internal/policy/handlers"
	"flamo/backend/internal/policy/opa"
	"flamo/backend/internal/policy/repository"
	"flamo/backend/internal/policy/service"
	"flamo/backend/internal/policy/storage"
	v1 "flamo/backend/pkg/api/policy/v1"
)

const (
	serviceName     = "policy-service"
	serviceVersion  = "1.0.0"
	shutdownTimeout = 30 * time.Second
)

func main() {
	logger := initializeLogger()
	defer logger.Sync()

	logger.Info("Starting policy service",
		zap.String("service", serviceName),
		zap.String("version", serviceVersion),
		zap.String("go_version", runtime.Version()),
		zap.String("build_time", time.Now().Format(time.RFC3339)))

	cfg, err := loadConfiguration(logger)
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	logger = reconfigureLogger(cfg)
	logger.Info("Configuration loaded successfully",
		zap.String("environment", string(cfg.Environment)),
		zap.String("log_level", string(cfg.Monitoring.LogLevel)))

	if err := validateConfiguration(cfg, logger); err != nil {
		logger.Fatal("Configuration validation failed", zap.Error(err))
	}

	metricsCollector, err := initializeMetrics(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize metrics", zap.Error(err))
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

	if err := runMigrations(db, cfg, logger); err != nil {
		logger.Fatal("Failed to run database migrations", zap.Error(err))
	}

	policyStore, err := initializePolicyStore(db, cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize policy store", zap.Error(err))
	}

	decisionRepository, err := initializeDecisionRepository(db, logger)
	if err != nil {
		logger.Fatal("Failed to initialize decision repository", zap.Error(err))
	}

	bundleManager, err := initializeBundleManager(db, policyStore, cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize bundle manager", zap.Error(err))
	}

	cache, err := initializeCache(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize cache", zap.Error(err))
	}

	opaClient, err := initializeOPAClient(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize OPA client", zap.Error(err))
	}

	opaEngine, err := initializeOPAEngine(opaClient, cache, policyStore, db, cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize OPA engine", zap.Error(err))
	}

	policyLoader, err := initializePolicyLoader(opaClient, policyStore, bundleManager, db, cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize policy loader", zap.Error(err))
	}

	policyService := initializePolicyService(
		policyStore,
		bundleManager,
		opaEngine,
		opaClient,
		policyLoader,
		cache,
		db,
		cfg,
		logger,
	)

	decisionService := initializeDecisionService(
		opaEngine,
		opaClient,
		cache,
		policyStore,
		bundleManager,
		db,
		decisionRepository,
		cfg,
		logger,
	)

	server, err := initializeServer(
		policyService,
		decisionService,
		opaEngine,
		opaClient,
		policyLoader,
		cache,
		policyStore,
		bundleManager,
		db,
		cfg,
		metricsCollector,
		logger,
	)
	if err != nil {
		logger.Fatal("Failed to initialize policy server", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("Policy service ready to serve requests")
		serverErrors <- server.Start()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		logger.Error("Server startup failed", zap.Error(err))
		os.Exit(1)

	case sig := <-shutdown:
		logger.Info("Shutdown signal received",
			zap.String("signal", sig.String()))

		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, shutdownTimeout)
		defer shutdownCancel()

		if err := gracefulShutdown(shutdownCtx, server, db, metricsCollector, logger); err != nil {
			logger.Error("Graceful shutdown failed", zap.Error(err))
			os.Exit(1)
		}

		logger.Info("Policy service shutdown completed successfully")
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
		env := os.Getenv("ENVIRONMENT")
		if env == "" {
			env = "local"
		}
		configPath = fmt.Sprintf("configs/%s/policy.yaml", env)
	}

	logger.Info("Loading configuration", zap.String("path", configPath))

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to load configuration file")
	}

	return cfg, nil
}

func reconfigureLogger(cfg *config.Config) *zap.Logger {
	var level zapcore.Level
	switch cfg.Monitoring.LogLevel {
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
	if cfg.Environment == "local" {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	config.Level = zap.NewAtomicLevelAt(level)
	config.OutputPaths = []string{cfg.Monitoring.LogOutput}
	config.ErrorOutputPaths = []string{"stderr"}

	logger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
		zap.Fields(
			zap.String("service", serviceName),
			zap.String("version", serviceVersion),
			zap.String("environment", string(cfg.Environment)),
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

	if cfg.Server.Host == "" {
		logger.Warn("Server host not specified, using default 0.0.0.0")
		cfg.Server.Host = "0.0.0.0"
	}

	if cfg.Server.Port == 0 {
		logger.Warn("Server port not specified, using default 8080")
		cfg.Server.Port = 8080
	}

	if cfg.Database.Host == "" {
		return errors.New(errors.ErrCodeConfigError, "database host is required")
	}

	if cfg.Database.Database == "" {
		return errors.New(errors.ErrCodeConfigError, "database name is required")
	}

	if cfg.Services.OPAService.Host == "" {
		logger.Warn("OPA host not specified, using default localhost")
		cfg.Services.OPAService.Host = "localhost"
	}

	if cfg.Services.OPAService.Port == 0 {
		logger.Warn("OPA port not specified, using default 8181")
		cfg.Services.OPAService.Port = 8181
	}

	if cfg.Services.OPAService.Protocol == "" {
		logger.Warn("OPA protocol not specified, using default http")
		cfg.Services.OPAService.Protocol = "http"
	}

	if cfg.Environment == "production" {
		if !cfg.Server.TLSConfig.Enabled {
			logger.Warn("TLS is disabled in production environment")
		}

		if cfg.Database.SSLMode != "require" {
			logger.Warn("Database SSL is not required in production")
		}

		if cfg.Services.OPAService.Host == "localhost" {
			logger.Warn("Using localhost OPA host in production")
		}
	}

	logger.Info("Configuration validation completed successfully")
	return nil
}

func initializeMetrics(cfg *config.Config, logger *zap.Logger) (*metrics.Metrics, error) {
	logger.Info("Initializing metrics collector")

	metricsConfig := &metrics.Config{
		Enabled:   cfg.Monitoring.EnableMetrics,
		Address:   fmt.Sprintf(":%d", cfg.Monitoring.MetricsPort),
		Path:      "/metrics",
		Namespace: "flamo_policy",
		Subsystem: "service",
	}

	metricsCollector, err := metrics.NewMetrics(metricsConfig, logger)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to create metrics collector")
	}

	if err := registerPolicyMetrics(metricsCollector); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to register policy metrics")
	}

	logger.Info("Metrics collector initialized successfully")
	return metricsCollector, nil
}

func registerPolicyMetrics(m *metrics.Metrics) error {
	if err := m.RegisterCounter("policy_evaluations_total", "Total number of policy evaluations", []string{"tenant_id", "resource", "action", "decision"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("policy_operations_total", "Total number of policy operations", []string{"operation", "status", "tenant_id"}); err != nil {
		return err
	}

	if err := m.RegisterHistogram("policy_evaluation_duration_seconds", "Policy evaluation duration", []string{"tenant_id", "cached"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("policy_cache_operations_total", "Total number of cache operations", []string{"operation", "result"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("opa_requests_total", "Total number of OPA requests", []string{"endpoint", "status"}); err != nil {
		return err
	}

	if err := m.RegisterHistogram("opa_request_duration_seconds", "OPA request duration", []string{"endpoint"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("policy_bundles_deployed_total", "Total number of policy bundles deployed", []string{"tenant_id", "target"}); err != nil {
		return err
	}

	if err := m.RegisterCounter("policy_sync_operations_total", "Total number of policy sync operations", []string{"tenant_id", "status"}); err != nil {
		return err
	}

	return nil
}

func initializeDatabase(cfg *config.Config, logger *zap.Logger) (*database.Database, error) {
	logger.Info("Initializing database connection",
		zap.String("host", cfg.Database.Host),
		zap.Int("port", cfg.Database.Port),
		zap.String("database", cfg.Database.Database))

	db, err := database.NewDatabase(cfg, logger)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to create database connection")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.Ping(ctx); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "database connectivity test failed")
	}

	logger.Info("Database connection established successfully")
	return db, nil
}

func runMigrations(db *database.Database, cfg *config.Config, logger *zap.Logger) error {
	logger.Info("Running database migrations")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := db.RunMigrations(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "database migration failed")
	}

	logger.Info("Database migrations completed successfully")
	return nil
}

func initializePolicyStore(db *database.Database, cfg *config.Config, logger *zap.Logger) (*storage.PolicyStore, error) {
	logger.Info("Initializing policy store")

	store := storage.NewPolicyStore(db, cfg, logger)

	logger.Info("Policy store initialized successfully")
	return store, nil
}

func initializeDecisionRepository(db *database.Database, logger *zap.Logger) (repository.DecisionRepository, error) {
	logger.Info("Initializing decision repository")

	repo := repository.NewDecisionRepository(db, logger)

	logger.Info("Decision repository initialized successfully")
	return repo, nil
}

func initializeBundleManager(db *database.Database, policyStore *storage.PolicyStore, cfg *config.Config, logger *zap.Logger) (*storage.BundleManager, error) {
	logger.Info("Initializing bundle manager")

	manager := storage.NewBundleManager(db, policyStore, cfg, logger)

	logger.Info("Bundle manager initialized successfully")
	return manager, nil
}

func initializeCache(cfg *config.Config, logger *zap.Logger) (*opa.Cache, error) {
	logger.Info("Initializing cache")

	cache := opa.NewCache(cfg, logger)

	logger.Info("Cache initialized successfully")
	return cache, nil
}

func initializeOPAClient(cfg *config.Config, logger *zap.Logger) (*opa.Client, error) {
	logger.Info("Initializing OPA client")

	client := opa.NewClient(cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := client.HealthCheck(ctx); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeServiceUnavailable, "OPA health check failed")
	}

	logger.Info("OPA client initialized successfully")
	return client, nil
}

func initializeOPAEngine(client *opa.Client, cache *opa.Cache, policyStore *storage.PolicyStore, db *database.Database, cfg *config.Config, logger *zap.Logger) (*opa.Engine, error) {
	logger.Info("Initializing OPA engine")

	engine := opa.NewEngine(client, policyStore, cache, db, cfg, logger)

	logger.Info("OPA engine initialized successfully")
	return engine, nil
}

func initializePolicyLoader(client *opa.Client, policyStore *storage.PolicyStore, bundleManager *storage.BundleManager, db *database.Database, cfg *config.Config, logger *zap.Logger) (*opa.PolicyLoader, error) {
	logger.Info("Initializing policy loader")

	loader := opa.NewPolicyLoader(client, policyStore, bundleManager, db, cfg, logger)

	logger.Info("Policy loader initialized successfully")
	return loader, nil
}

func initializePolicyService(
	policyStore *storage.PolicyStore,
	bundleManager *storage.BundleManager,
	opaEngine *opa.Engine,
	opaClient *opa.Client,
	policyLoader *opa.PolicyLoader,
	cache *opa.Cache,
	db *database.Database,
	cfg *config.Config,
	logger *zap.Logger,
) v1.PolicyService {
	logger.Info("Initializing policy service")

	policyService := service.NewPolicyService(
		policyStore,
		bundleManager,
		opaEngine,
		opaClient,
		policyLoader,
		cache,
		db,
		cfg,
		logger,
	)

	logger.Info("Policy service initialized successfully")
	return policyService
}

func initializeDecisionService(
	opaEngine *opa.Engine,
	opaClient *opa.Client,
	cache *opa.Cache,
	policyStore *storage.PolicyStore,
	bundleManager *storage.BundleManager,
	db *database.Database,
	decisionRepository repository.DecisionRepository,
	cfg *config.Config,
	logger *zap.Logger,
) v1.DecisionService {
	logger.Info("Initializing decision service")

	decisionService := service.NewDecisionService(
		opaEngine,
		opaClient,
		cache,
		policyStore,
		bundleManager,
		db,
		decisionRepository,
		cfg,
		logger,
	)

	logger.Info("Decision service initialized successfully")
	return decisionService
}

func initializeServer(
	policyService v1.PolicyService,
	decisionService v1.DecisionService,
	opaEngine *opa.Engine,
	opaClient *opa.Client,
	policyLoader *opa.PolicyLoader,
	cache *opa.Cache,
	policyStore *storage.PolicyStore,
	bundleManager *storage.BundleManager,
	db *database.Database,
	cfg *config.Config,
	metrics *metrics.Metrics,
	logger *zap.Logger,
) (*handlers.Server, error) {
	logger.Info("Initializing policy server")

	server := handlers.NewServer(
		policyService,
		decisionService,
		opaEngine,
		opaClient,
		policyLoader,
		cache,
		policyStore,
		bundleManager,
		db,
		cfg,
		logger,
	)

	logger.Info("Policy server initialized successfully")
	return server, nil
}

func gracefulShutdown(ctx context.Context, server *handlers.Server, db *database.Database, metrics *metrics.Metrics, logger *zap.Logger) error {
	logger.Info("Starting graceful shutdown")

	if err := server.Stop(ctx); err != nil {
		logger.Error("Server shutdown error", zap.Error(err))
	}

	if err := db.Close(); err != nil {
		logger.Error("Database close error", zap.Error(err))
	}

	if err := metrics.Shutdown(ctx); err != nil {
		logger.Error("Metrics shutdown error", zap.Error(err))
	}

	logger.Info("Graceful shutdown completed")
	return nil
}
