package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type Environment string
type LogLevel string
type DatabaseType string
type CacheType string

const (
	EnvDevelopment Environment = "development"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"

	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"

	DatabasePostgreSQL DatabaseType = "postgresql"
	DatabaseMySQL      DatabaseType = "mysql"
	DatabaseSQLite     DatabaseType = "sqlite"

	CacheRedis     CacheType = "redis"
	CacheMemcached CacheType = "memcached"
	CacheInMemory  CacheType = "inmemory"
)

type Config struct {
	Environment Environment    `yaml:"environment" mapstructure:"environment"`
	Server      ServerConfig   `yaml:"server" mapstructure:"server"`
	Database    DatabaseConfig `yaml:"database" mapstructure:"database"`
	Cache       CacheConfig    `yaml:"cache" mapstructure:"cache"`
	Security    SecurityConfig `yaml:"security" mapstructure:"security"`
	Compliance  ComplianceConfig `yaml:"compliance" mapstructure:"compliance"`
	Monitoring  MonitoringConfig `yaml:"monitoring" mapstructure:"monitoring"`
	Gateway     GatewayConfig  `yaml:"gateway" mapstructure:"gateway"`
	Services    ServicesConfig `yaml:"services" mapstructure:"services"`
	Features    FeatureFlags   `yaml:"features" mapstructure:"features"`
	Secrets     SecretsConfig  `yaml:"secrets" mapstructure:"secrets"`
	
	// Runtime configuration
	mu           sync.RWMutex
	watchers     []ConfigWatcher
	lastModified time.Time
	configPath   string
	logger       *zap.Logger
}

type ServerConfig struct {
	Host                string        `yaml:"host" mapstructure:"host"`
	Port                int           `yaml:"port" mapstructure:"port"`
	GRPCPort            int           `yaml:"grpc_port" mapstructure:"grpc_port"`
	ReadTimeout         time.Duration `yaml:"read_timeout" mapstructure:"read_timeout"`
	WriteTimeout        time.Duration `yaml:"write_timeout" mapstructure:"write_timeout"`
	IdleTimeout         time.Duration `yaml:"idle_timeout" mapstructure:"idle_timeout"`
	MaxHeaderBytes      int           `yaml:"max_header_bytes" mapstructure:"max_header_bytes"`
	GracefulTimeout     time.Duration `yaml:"graceful_timeout" mapstructure:"graceful_timeout"`
	EnableProfiling     bool          `yaml:"enable_profiling" mapstructure:"enable_profiling"`
	EnableMetrics       bool          `yaml:"enable_metrics" mapstructure:"enable_metrics"`
	EnableHealthCheck   bool          `yaml:"enable_health_check" mapstructure:"enable_health_check"`
	TLSConfig           TLSConfig     `yaml:"tls" mapstructure:"tls"`
	CORSConfig          CORSConfig    `yaml:"cors" mapstructure:"cors"`
	RateLimitConfig     RateLimitConfig `yaml:"rate_limit" mapstructure:"rate_limit"`
}

type DatabaseConfig struct {
	Type                DatabaseType  `yaml:"type" mapstructure:"type"`
	Host                string        `yaml:"host" mapstructure:"host"`
	Port                int           `yaml:"port" mapstructure:"port"`
	Database            string        `yaml:"database" mapstructure:"database"`
	Username            string        `yaml:"username" mapstructure:"username"`
	Password            string        `yaml:"password" mapstructure:"password"`
	SSLMode             string        `yaml:"ssl_mode" mapstructure:"ssl_mode"`
	MaxOpenConnections  int           `yaml:"max_open_connections" mapstructure:"max_open_connections"`
	MaxIdleConnections  int           `yaml:"max_idle_connections" mapstructure:"max_idle_connections"`
	ConnectionLifetime  time.Duration `yaml:"connection_lifetime" mapstructure:"connection_lifetime"`
	ConnectionTimeout   time.Duration `yaml:"connection_timeout" mapstructure:"connection_timeout"`
	QueryTimeout        time.Duration `yaml:"query_timeout" mapstructure:"query_timeout"`
	EnableQueryLogging  bool          `yaml:"enable_query_logging" mapstructure:"enable_query_logging"`
	EnableMigrations    bool          `yaml:"enable_migrations" mapstructure:"enable_migrations"`
	MigrationsPath      string        `yaml:"migrations_path" mapstructure:"migrations_path"`
	EncryptionKey       string        `yaml:"encryption_key" mapstructure:"encryption_key"`
}

type CacheConfig struct {
	Type                CacheType     `yaml:"type" mapstructure:"type"`
	Host                string        `yaml:"host" mapstructure:"host"`
	Port                int           `yaml:"port" mapstructure:"port"`
	Password            string        `yaml:"password" mapstructure:"password"`
	Database            int           `yaml:"database" mapstructure:"database"`
	MaxRetries          int           `yaml:"max_retries" mapstructure:"max_retries"`
	DialTimeout         time.Duration `yaml:"dial_timeout" mapstructure:"dial_timeout"`
	ReadTimeout         time.Duration `yaml:"read_timeout" mapstructure:"read_timeout"`
	WriteTimeout        time.Duration `yaml:"write_timeout" mapstructure:"write_timeout"`
	PoolSize            int           `yaml:"pool_size" mapstructure:"pool_size"`
	MinIdleConnections  int           `yaml:"min_idle_connections" mapstructure:"min_idle_connections"`
	MaxConnAge          time.Duration `yaml:"max_conn_age" mapstructure:"max_conn_age"`
	DefaultTTL          time.Duration `yaml:"default_ttl" mapstructure:"default_ttl"`
	EnableCompression   bool          `yaml:"enable_compression" mapstructure:"enable_compression"`
	EnableEncryption    bool          `yaml:"enable_encryption" mapstructure:"enable_encryption"`
}

type SecurityConfig struct {
	EncryptionKey       string        `yaml:"encryption_key" mapstructure:"encryption_key"`
	JWTSecret           string        `yaml:"jwt_secret" mapstructure:"jwt_secret"`
	JWTExpiration       time.Duration `yaml:"jwt_expiration" mapstructure:"jwt_expiration"`
	APIKeyLength        int           `yaml:"api_key_length" mapstructure:"api_key_length"`
	PasswordMinLength   int           `yaml:"password_min_length" mapstructure:"password_min_length"`
	PasswordComplexity  bool          `yaml:"password_complexity" mapstructure:"password_complexity"`
	SessionTimeout      time.Duration `yaml:"session_timeout" mapstructure:"session_timeout"`
	MaxLoginAttempts    int           `yaml:"max_login_attempts" mapstructure:"max_login_attempts"`
	LockoutDuration     time.Duration `yaml:"lockout_duration" mapstructure:"lockout_duration"`
	EnableMFA           bool          `yaml:"enable_mfa" mapstructure:"enable_mfa"`
	EnableAuditLogging  bool          `yaml:"enable_audit_logging" mapstructure:"enable_audit_logging"`
	TrustedProxies      []string      `yaml:"trusted_proxies" mapstructure:"trusted_proxies"`
	AllowedOrigins      []string      `yaml:"allowed_origins" mapstructure:"allowed_origins"`
	CSPPolicy           string        `yaml:"csp_policy" mapstructure:"csp_policy"`
	HSTSMaxAge          int           `yaml:"hsts_max_age" mapstructure:"hsts_max_age"`
}

type ComplianceConfig struct {
	EnableGDPR          bool          `yaml:"enable_gdpr" mapstructure:"enable_gdpr"`
	EnableHIPAA         bool          `yaml:"enable_hipaa" mapstructure:"enable_hipaa"`
	EnableSOC2          bool          `yaml:"enable_soc2" mapstructure:"enable_soc2"`
	EnableISO27001      bool          `yaml:"enable_iso27001" mapstructure:"enable_iso27001"`
	EnableFedRAMP       bool          `yaml:"enable_fedramp" mapstructure:"enable_fedramp"`
	DataRetentionDays   int           `yaml:"data_retention_days" mapstructure:"data_retention_days"`
	LogRetentionDays    int           `yaml:"log_retention_days" mapstructure:"log_retention_days"`
	EnablePIIDetection  bool          `yaml:"enable_pii_detection" mapstructure:"enable_pii_detection"`
	EnableDataMasking   bool          `yaml:"enable_data_masking" mapstructure:"enable_data_masking"`
	EnableRightToDelete bool          `yaml:"enable_right_to_delete" mapstructure:"enable_right_to_delete"`
	ConsentRequired     bool          `yaml:"consent_required" mapstructure:"consent_required"`
	DataResidency       string        `yaml:"data_residency" mapstructure:"data_residency"`
	EncryptionAtRest    bool          `yaml:"encryption_at_rest" mapstructure:"encryption_at_rest"`
	EncryptionInTransit bool          `yaml:"encryption_in_transit" mapstructure:"encryption_in_transit"`
}

type MonitoringConfig struct {
	EnableMetrics       bool          `yaml:"enable_metrics" mapstructure:"enable_metrics"`
	EnableTracing       bool          `yaml:"enable_tracing" mapstructure:"enable_tracing"`
	EnableLogging       bool          `yaml:"enable_logging" mapstructure:"enable_logging"`
	MetricsPort         int           `yaml:"metrics_port" mapstructure:"metrics_port"`
	LogLevel            LogLevel      `yaml:"log_level" mapstructure:"log_level"`
	LogFormat           string        `yaml:"log_format" mapstructure:"log_format"`
	LogOutput           string        `yaml:"log_output" mapstructure:"log_output"`
	TracingEndpoint     string        `yaml:"tracing_endpoint" mapstructure:"tracing_endpoint"`
	TracingSampleRate   float64       `yaml:"tracing_sample_rate" mapstructure:"tracing_sample_rate"`
	MetricsNamespace    string        `yaml:"metrics_namespace" mapstructure:"metrics_namespace"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" mapstructure:"health_check_interval"`
	AlertingEnabled     bool          `yaml:"alerting_enabled" mapstructure:"alerting_enabled"`
	AlertingWebhook     string        `yaml:"alerting_webhook" mapstructure:"alerting_webhook"`
}

type GatewayConfig struct {
	MaxConcurrentRequests int           `yaml:"max_concurrent_requests" mapstructure:"max_concurrent_requests"`
	RequestTimeout        time.Duration `yaml:"request_timeout" mapstructure:"request_timeout"`
	EnableLoadBalancing   bool          `yaml:"enable_load_balancing" mapstructure:"enable_load_balancing"`
	LoadBalancingStrategy string        `yaml:"load_balancing_strategy" mapstructure:"load_balancing_strategy"`
	EnableCircuitBreaker  bool          `yaml:"enable_circuit_breaker" mapstructure:"enable_circuit_breaker"`
	CircuitBreakerConfig  CircuitBreakerConfig `yaml:"circuit_breaker" mapstructure:"circuit_breaker"`
	EnableRetry           bool          `yaml:"enable_retry" mapstructure:"enable_retry"`
	RetryConfig           RetryConfig   `yaml:"retry" mapstructure:"retry"`
	EnableCaching         bool          `yaml:"enable_caching" mapstructure:"enable_caching"`
	CacheTTL              time.Duration `yaml:"cache_ttl" mapstructure:"cache_ttl"`
	EnableCompression     bool          `yaml:"enable_compression" mapstructure:"enable_compression"`
	CompressionLevel      int           `yaml:"compression_level" mapstructure:"compression_level"`
}

type ServicesConfig struct {
	AuthService      ServiceEndpoint `yaml:"auth_service" mapstructure:"auth_service"`
	ModelProxy       ServiceEndpoint `yaml:"model_proxy" mapstructure:"model_proxy"`
	SecurityAnalyzer ServiceEndpoint `yaml:"security_analyzer" mapstructure:"security_analyzer"`
	ComplianceEngine ServiceEndpoint `yaml:"compliance_engine" mapstructure:"compliance_engine"`
	AuditService     ServiceEndpoint `yaml:"audit_service" mapstructure:"audit_service"`
	OPAService       ServiceEndpoint `yaml:"opa_service" mapstructure:"opa_service"`
}

type ServiceEndpoint struct {
	Host            string        `yaml:"host" mapstructure:"host"`
	Port            int           `yaml:"port" mapstructure:"port"`
	Protocol        string        `yaml:"protocol" mapstructure:"protocol"`
	Timeout         time.Duration `yaml:"timeout" mapstructure:"timeout"`
	MaxRetries      int           `yaml:"max_retries" mapstructure:"max_retries"`
	EnableTLS       bool          `yaml:"enable_tls" mapstructure:"enable_tls"`
	TLSConfig       TLSConfig     `yaml:"tls" mapstructure:"tls"`
	HealthCheckPath string        `yaml:"health_check_path" mapstructure:"health_check_path"`
}

type TLSConfig struct {
	Enabled            bool   `yaml:"enabled" mapstructure:"enabled"`
	CertFile           string `yaml:"cert_file" mapstructure:"cert_file"`
	KeyFile            string `yaml:"key_file" mapstructure:"key_file"`
	CAFile             string `yaml:"ca_file" mapstructure:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" mapstructure:"insecure_skip_verify"`
	MinVersion         string `yaml:"min_version" mapstructure:"min_version"`
	MaxVersion         string `yaml:"max_version" mapstructure:"max_version"`
	CipherSuites       []string `yaml:"cipher_suites" mapstructure:"cipher_suites"`
}

type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowed_origins" mapstructure:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods" mapstructure:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers" mapstructure:"allowed_headers"`
	ExposedHeaders   []string `yaml:"exposed_headers" mapstructure:"exposed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials" mapstructure:"allow_credentials"`
	MaxAge           int      `yaml:"max_age" mapstructure:"max_age"`
}

type RateLimitConfig struct {
	Enabled         bool          `yaml:"enabled" mapstructure:"enabled"`
	RequestsPerMin  int           `yaml:"requests_per_min" mapstructure:"requests_per_min"`
	BurstSize       int           `yaml:"burst_size" mapstructure:"burst_size"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" mapstructure:"cleanup_interval"`
	KeyGenerator    string        `yaml:"key_generator" mapstructure:"key_generator"`
}

type CircuitBreakerConfig struct {
	MaxRequests         uint32        `yaml:"max_requests" mapstructure:"max_requests"`
	Interval            time.Duration `yaml:"interval" mapstructure:"interval"`
	Timeout             time.Duration `yaml:"timeout" mapstructure:"timeout"`
	ReadyToTrip         func(counts map[string]uint64) bool `yaml:"-"`
	OnStateChange       func(name string, from, to string) `yaml:"-"`
	FailureThreshold    float64       `yaml:"failure_threshold" mapstructure:"failure_threshold"`
	SuccessThreshold    uint32        `yaml:"success_threshold" mapstructure:"success_threshold"`
}

type RetryConfig struct {
	MaxAttempts     int           `yaml:"max_attempts" mapstructure:"max_attempts"`
	InitialDelay    time.Duration `yaml:"initial_delay" mapstructure:"initial_delay"`
	MaxDelay        time.Duration `yaml:"max_delay" mapstructure:"max_delay"`
	BackoffFactor   float64       `yaml:"backoff_factor" mapstructure:"backoff_factor"`
	RetryableErrors []string      `yaml:"retryable_errors" mapstructure:"retryable_errors"`
}

type FeatureFlags struct {
	EnableNewAuth       bool `yaml:"enable_new_auth" mapstructure:"enable_new_auth"`
	EnableAdvancedAudit bool `yaml:"enable_advanced_audit" mapstructure:"enable_advanced_audit"`
	EnableMLDetection   bool `yaml:"enable_ml_detection" mapstructure:"enable_ml_detection"`
	EnableRealTimeAlerts bool `yaml:"enable_real_time_alerts" mapstructure:"enable_real_time_alerts"`
	EnableBetaFeatures  bool `yaml:"enable_beta_features" mapstructure:"enable_beta_features"`
}

type SecretsConfig struct {
	Provider        string            `yaml:"provider" mapstructure:"provider"`
	VaultAddress    string            `yaml:"vault_address" mapstructure:"vault_address"`
	VaultToken      string            `yaml:"vault_token" mapstructure:"vault_token"`
	VaultPath       string            `yaml:"vault_path" mapstructure:"vault_path"`
	AWSRegion       string            `yaml:"aws_region" mapstructure:"aws_region"`
	AWSSecretPrefix string            `yaml:"aws_secret_prefix" mapstructure:"aws_secret_prefix"`
	EncryptionKey   string            `yaml:"encryption_key" mapstructure:"encryption_key"`
	LocalSecrets    map[string]string `yaml:"local_secrets" mapstructure:"local_secrets"`
}

type ConfigWatcher interface {
	OnConfigChange(config *Config) error
}

var (
	globalConfig *Config
	configMutex  sync.RWMutex
)

func NewConfig() *Config {
	return &Config{
		Environment: EnvDevelopment,
		watchers:    make([]ConfigWatcher, 0),
		logger:      zap.NewNop(),
	}
}

func LoadConfig(configPath string) (*Config, error) {
	config := NewConfig()
	config.configPath = configPath

	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	config.logger = logger

	if err := config.loadFromFile(configPath); err != nil {
		return nil, fmt.Errorf("failed to load config from file: %w", err)
	}

	if err := config.loadFromEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to load config from environment: %w", err)
	}

	if err := config.loadSecrets(); err != nil {
		return nil, fmt.Errorf("failed to load secrets: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	setGlobalConfig(config)

	if err := config.startFileWatcher(); err != nil {
		logger.Warn("Failed to start config file watcher", zap.Error(err))
	}

	logger.Info("Configuration loaded successfully", 
		zap.String("environment", string(config.Environment)),
		zap.String("config_path", configPath))

	return config, nil
}

func (c *Config) loadFromFile(configPath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", configPath)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, c); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	if stat, err := os.Stat(configPath); err == nil {
		c.lastModified = stat.ModTime()
	}

	return nil
}

func (c *Config) loadFromEnvironment() error {
	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetEnvPrefix("EXOPER")

	envOverrides := map[string]interface{}{
		"environment":                    v.GetString("ENVIRONMENT"),
		"server.host":                   v.GetString("SERVER_HOST"),
		"server.port":                   v.GetInt("SERVER_PORT"),
		"server.grpc_port":              v.GetInt("SERVER_GRPC_PORT"),
		"database.host":                 v.GetString("DATABASE_HOST"),
		"database.port":                 v.GetInt("DATABASE_PORT"),
		"database.database":             v.GetString("DATABASE_NAME"),
		"database.username":             v.GetString("DATABASE_USERNAME"),
		"database.password":             v.GetString("DATABASE_PASSWORD"),
		"cache.host":                    v.GetString("CACHE_HOST"),
		"cache.port":                    v.GetInt("CACHE_PORT"),
		"cache.password":                v.GetString("CACHE_PASSWORD"),
		"security.encryption_key":       v.GetString("SECURITY_ENCRYPTION_KEY"),
		"security.jwt_secret":           v.GetString("SECURITY_JWT_SECRET"),
		"monitoring.log_level":          v.GetString("MONITORING_LOG_LEVEL"),
		"monitoring.tracing_endpoint":   v.GetString("MONITORING_TRACING_ENDPOINT"),
		"secrets.vault_address":         v.GetString("SECRETS_VAULT_ADDRESS"),
		"secrets.vault_token":           v.GetString("SECRETS_VAULT_TOKEN"),
	}

	return c.applyOverrides(envOverrides)
}

func (c *Config) loadSecrets() error {
	switch c.Secrets.Provider {
	case "vault":
		return c.loadFromVault()
	case "aws":
		return c.loadFromAWS()
	case "local":
		return c.loadFromLocalSecrets()
	default:
		c.logger.Info("No secrets provider configured, using local secrets")
		return c.loadFromLocalSecrets()
	}
}

func (c *Config) loadFromVault() error {
	c.logger.Info("Vault secrets provider not implemented yet")
	return nil
}

func (c *Config) loadFromAWS() error {
	c.logger.Info("AWS secrets provider not implemented yet")
	return nil
}

func (c *Config) loadFromLocalSecrets() error {
	if c.Secrets.LocalSecrets == nil {
		return nil
	}

	if c.Secrets.EncryptionKey != "" {
		for key, encryptedValue := range c.Secrets.LocalSecrets {
			decryptedValue, err := c.decryptSecret(encryptedValue, c.Secrets.EncryptionKey)
			if err != nil {
				c.logger.Warn("Failed to decrypt secret", zap.String("key", key), zap.Error(err))
				continue
			}
			c.Secrets.LocalSecrets[key] = decryptedValue
		}
	}

	secretMappings := map[string]string{
		"database_password":  "Database.Password",
		"cache_password":     "Cache.Password",
		"jwt_secret":         "Security.JWTSecret",
		"encryption_key":     "Security.EncryptionKey",
	}

	for secretKey, configPath := range secretMappings {
		if secretValue, exists := c.Secrets.LocalSecrets[secretKey]; exists {
			if err := c.setNestedValue(strings.ToLower(configPath), secretValue); err != nil {
				c.logger.Warn("Failed to apply secret to config", 
					zap.String("secret_key", secretKey), 
					zap.String("config_path", configPath),
					zap.Error(err))
			}
		}
	}

	return nil
}

func (c *Config) Validate() error {
	var errors []string

	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		errors = append(errors, "invalid server port")
	}
	if c.Server.GRPCPort <= 0 || c.Server.GRPCPort > 65535 {
		errors = append(errors, "invalid gRPC port")
	}
	if c.Server.Port == c.Server.GRPCPort {
		errors = append(errors, "server port and gRPC port cannot be the same")
	}

	if c.Database.Host == "" {
		errors = append(errors, "database host is required")
	}
	if c.Database.Database == "" {
		errors = append(errors, "database name is required")
	}
	if c.Database.Username == "" {
		errors = append(errors, "database username is required")
	}

	if c.Security.JWTSecret == "" {
		errors = append(errors, "JWT secret is required")
	}
	if len(c.Security.JWTSecret) < 32 {
		errors = append(errors, "JWT secret must be at least 32 characters")
	}
	if c.Security.EncryptionKey == "" {
		errors = append(errors, "encryption key is required")
	}
	if len(c.Security.EncryptionKey) < 32 {
		errors = append(errors, "encryption key must be at least 32 characters")
	}

	if c.Environment == EnvProduction {
		if !c.Compliance.EncryptionAtRest {
			errors = append(errors, "encryption at rest is required in production")
		}
		if !c.Compliance.EncryptionInTransit {
			errors = append(errors, "encryption in transit is required in production")
		}
		if !c.Security.EnableAuditLogging {
			errors = append(errors, "audit logging is required in production")
		}
	}

	services := map[string]ServiceEndpoint{
		"auth_service":        c.Services.AuthService,
		"model_proxy":         c.Services.ModelProxy,
		"security_analyzer":   c.Services.SecurityAnalyzer,
		"compliance_engine":   c.Services.ComplianceEngine,
		"audit_service":       c.Services.AuditService,
		"opa_service":         c.Services.OPAService,
	}

	for serviceName, endpoint := range services {
		if endpoint.Host == "" {
			errors = append(errors, fmt.Sprintf("%s host is required", serviceName))
		}
		if endpoint.Port <= 0 || endpoint.Port > 65535 {
			errors = append(errors, fmt.Sprintf("%s port is invalid", serviceName))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

func (c *Config) applyOverrides(overrides map[string]interface{}) error {
	for key, value := range overrides {
		if value == nil || (reflect.ValueOf(value).Kind() == reflect.String && value.(string) == "") {
			continue
		}

		if err := c.setNestedValue(key, value); err != nil {
			return fmt.Errorf("failed to set config value %s: %w", key, err)
		}
	}
	return nil
}

func (c *Config) setNestedValue(key string, value interface{}) error {
	keys := strings.Split(key, ".")
	configValue := reflect.ValueOf(c).Elem()

	for i, k := range keys {
		if i == len(keys)-1 {
			field := configValue.FieldByName(c.fieldNameFromKey(k))
			if !field.IsValid() || !field.CanSet() {
				return fmt.Errorf("cannot set field %s", k)
			}

			convertedValue, err := c.convertValue(value, field.Type())
			if err != nil {
				return fmt.Errorf("failed to convert value for field %s: %w", k, err)
			}

			field.Set(convertedValue)
		} else {
			field := configValue.FieldByName(c.fieldNameFromKey(k))
			if !field.IsValid() {
				return fmt.Errorf("field %s not found", k)
			}
			configValue = field
		}
	}

	return nil
}

func (c *Config) fieldNameFromKey(key string) string {
	parts := strings.Split(key, "_")
	for i, part := range parts {
		parts[i] = strings.Title(part)
	}
	return strings.Join(parts, "")
}

func (c *Config) convertValue(value interface{}, targetType reflect.Type) (reflect.Value, error) {
	sourceValue := reflect.ValueOf(value)
	
	if sourceValue.Type() == targetType {
		return sourceValue, nil
	}

	switch targetType.Kind() {
	case reflect.String:
		return reflect.ValueOf(fmt.Sprintf("%v", value)), nil
	case reflect.Int, reflect.Int32, reflect.Int64:
		if str, ok := value.(string); ok {
			if i, err := strconv.ParseInt(str, 10, 64); err == nil {
				return reflect.ValueOf(i).Convert(targetType), nil
			}
		}
		return sourceValue.Convert(targetType), nil
	case reflect.Bool:
		if str, ok := value.(string); ok {
			if b, err := strconv.ParseBool(str); err == nil {
				return reflect.ValueOf(b), nil
			}
		}
		return sourceValue.Convert(targetType), nil
	default:
		return sourceValue.Convert(targetType), nil
	}
}

func (c *Config) decryptSecret(encryptedData, key string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	keyBytes := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func (c *Config) startFileWatcher() error {
	if c.configPath == "" {
		return fmt.Errorf("config path not set")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	go func() {
		defer watcher.Close()
		
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				
				if event.Op&fsnotify.Write == fsnotify.Write {
					c.logger.Info("Config file changed, reloading", zap.String("file", event.Name))
					if err := c.reload(); err != nil {
						c.logger.Error("Failed to reload config", zap.Error(err))
					}
				}
				
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				c.logger.Error("File watcher error", zap.Error(err))
			}
		}
	}()

	return watcher.Add(filepath.Dir(c.configPath))
}

func (c *Config) reload() error {
	newConfig := NewConfig()
	newConfig.configPath = c.configPath
	newConfig.logger = c.logger

	if err := newConfig.loadFromFile(c.configPath); err != nil {
		return fmt.Errorf("failed to reload config from file: %w", err)
	}

	if err := newConfig.loadFromEnvironment(); err != nil {
		return fmt.Errorf("failed to reload config from environment: %w", err)
	}

	if err := newConfig.loadSecrets(); err != nil {
		return fmt.Errorf("failed to reload secrets: %w", err)
	}

	if err := newConfig.Validate(); err != nil {
		return fmt.Errorf("reloaded configuration validation failed: %w", err)
	}

	c.mu.Lock()
	*c = *newConfig
	c.mu.Unlock()

	for _, watcher := range c.watchers {
		if err := watcher.OnConfigChange(c); err != nil {
			c.logger.Error("Config watcher error", zap.Error(err))
		}
	}

	setGlobalConfig(c)

	c.logger.Info("Configuration reloaded successfully")
	return nil
}

func (c *Config) AddWatcher(watcher ConfigWatcher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.watchers = append(c.watchers, watcher)
}

func (c *Config) GetSecret(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if c.Secrets.LocalSecrets == nil {
		return "", false
	}
	
	value, exists := c.Secrets.LocalSecrets[key]
	return value, exists
}

func (c *Config) EncryptSecret(plaintext, key string) (string, error) {
	keyBytes := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	plaintextBytes := []byte(plaintext)
	ciphertext := make([]byte, len(plaintextBytes))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, plaintextBytes)

	result := append(iv, ciphertext...)
	
	return base64.StdEncoding.EncodeToString(result), nil
}

func (c *Config) IsDevelopment() bool {
	return c.Environment == EnvDevelopment
}

func (c *Config) IsProduction() bool {
	return c.Environment == EnvProduction
}

func (c *Config) IsStaging() bool {
	return c.Environment == EnvStaging
}

func GetGlobalConfig() *Config {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return globalConfig
}

func setGlobalConfig(config *Config) {
	configMutex.Lock()
	defer configMutex.Unlock()
	globalConfig = config
}

func GetDatabaseDSN(config *Config) string {
	switch config.Database.Type {
	case DatabasePostgreSQL:
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			config.Database.Host,
			config.Database.Port,
			config.Database.Username,
			config.Database.Password,
			config.Database.Database,
			config.Database.SSLMode)
	case DatabaseMySQL:
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC",
			config.Database.Username,
			config.Database.Password,
			config.Database.Host,
			config.Database.Port,
			config.Database.Database)
	default:
		return ""
	}
}

func GetCacheAddress(config *Config) string {
	return fmt.Sprintf("%s:%d", config.Cache.Host, config.Cache.Port)
}

func ValidateEnvironment(env string) error {
	validEnvs := []string{string(EnvDevelopment), string(EnvStaging), string(EnvProduction)}
	for _, validEnv := range validEnvs {
		if env == validEnv {
			return nil
		}
	}
	return fmt.Errorf("invalid environment: %s, must be one of: %s", env, strings.Join(validEnvs, ", "))
}
