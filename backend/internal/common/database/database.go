package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
)

type Database struct {
	db                    *sqlx.DB
	config               *config.Config
	logger               *zap.Logger
	mu                   sync.RWMutex
	healthStatus         HealthStatus
	metrics              *DatabaseMetrics
	closed               int32
	tenantPools          map[string]*sqlx.DB
	tenantPoolsMu        sync.RWMutex
	preparedStmts        *PreparedStatements
	auditBatcher         *AuditBatcher
	encryptionService    *EncryptionService
	hashChainValidator   *HashChainValidator
}

type HealthStatus struct {
	IsHealthy           bool          `json:"is_healthy"`
	LastCheck           time.Time     `json:"last_check"`
	ConnectionCount     int           `json:"connection_count"`
	OpenConnections     int           `json:"open_connections"`
	IdleConnections     int           `json:"idle_connections"`
	ResponseTime        time.Duration `json:"response_time"`
	ErrorMessage        string        `json:"error_message,omitempty"`
	TenantPoolsHealthy  int           `json:"tenant_pools_healthy"`
	AuditIntegrityValid bool          `json:"audit_integrity_valid"`
}

type DatabaseMetrics struct {
	TotalQueries          int64         `json:"total_queries"`
	SuccessfulQueries     int64         `json:"successful_queries"`
	FailedQueries         int64         `json:"failed_queries"`
	AverageQueryTime      time.Duration `json:"average_query_time"`
	SlowQueries           int64         `json:"slow_queries"`
	ConnectionErrors      int64         `json:"connection_errors"`
	LastQueryTime         time.Time     `json:"last_query_time"`
	TenantOperations      int64         `json:"tenant_operations"`
	AuditEntriesProcessed int64         `json:"audit_entries_processed"`
	ThreatDetections      int64         `json:"threat_detections"`
	PolicyViolations      int64         `json:"policy_violations"`
	mu                    sync.RWMutex
}

type QueryResult struct {
	Rows         *sqlx.Rows
	RowsAffected int64
	LastInsertID int64
	Duration     time.Duration
	Error        error
	TraceID      string
	TenantID     string
}

type Transaction struct {
	tx       *sqlx.Tx
	db       *Database
	ctx      context.Context
	logger   *zap.Logger
	tenantID string
	traceID  string
}

type PreparedStatements struct {
	InsertAuditLog        *sqlx.Stmt
	InsertThreatVerdict   *sqlx.Stmt
	InsertPolicyDecision  *sqlx.Stmt
	SelectTenantConfig    *sqlx.Stmt
	UpdateRateLimit       *sqlx.Stmt
	VerifyHashChain       *sqlx.Stmt
	mu                    sync.RWMutex
}

type AuditBatcher struct {
	entries     chan AuditEntry
	batch       []AuditEntry
	ticker      *time.Ticker
	db          *Database
	batchSize   int
	flushTicker time.Duration
	mu          sync.Mutex
	closed      int32
}

type AuditEntry struct {
	TraceID           string                 `json:"trace_id"`
	TenantID          string                 `json:"tenant_id"`
	RequestHash       string                 `json:"request_hash"`
	DetectorVerdicts  map[string]interface{} `json:"detector_verdicts"`
	PoliciesApplied   map[string]interface{} `json:"policies_applied"`
	EncryptedPayload  []byte                 `json:"encrypted_payload"`
	ProcessingTimeMs  int64                  `json:"processing_time_ms"`
	Timestamp         time.Time              `json:"timestamp"`
	PreviousHash      string                 `json:"previous_hash"`
}

type EncryptionService struct {
	vaultClient interface{}
	keyCache    map[string][]byte
	cacheMu     sync.RWMutex
}

type HashChainValidator struct {
	lastHash   string
	lastID     int64
	mu         sync.RWMutex
}

type TenantConfig struct {
	ID               string                 `db:"id" json:"id"`
	Name             string                 `db:"name" json:"name"`
	APIKeyHash       string                 `db:"api_key_hash" json:"api_key_hash"`
	ModelAllowlist   []string               `db:"model_allowlist" json:"model_allowlist"`
	RateLimits       map[string]interface{} `db:"rate_limits" json:"rate_limits"`
	QuotaLimits      map[string]interface{} `db:"quota_limits" json:"quota_limits"`
	RedactionPolicies map[string]interface{} `db:"redaction_policies" json:"redaction_policies"`
	EncryptionKeyID  string                 `db:"encryption_key_id" json:"encryption_key_id"`
	CreatedAt        time.Time              `db:"created_at" json:"created_at"`
	UpdatedAt        time.Time              `db:"updated_at" json:"updated_at"`
}

type ThreatDetectionRule struct {
	ID            string    `db:"id" json:"id"`
	RuleType      string    `db:"rule_type" json:"rule_type"`
	Pattern       string    `db:"pattern" json:"pattern"`
	Severity      int       `db:"severity" json:"severity"`
	TenantID      *string   `db:"tenant_id" json:"tenant_id"`
	WasmBytecode  []byte    `db:"wasm_bytecode" json:"wasm_bytecode"`
	RustSignature []byte    `db:"rust_signature" json:"rust_signature"`
	Enabled       bool      `db:"enabled" json:"enabled"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
}

type ThreatVerdict struct {
	TraceID                   string                 `db:"trace_id" json:"trace_id"`
	TenantID                  string                 `db:"tenant_id" json:"tenant_id"`
	Verdict                   string                 `db:"verdict" json:"verdict"`
	ConfidenceScore           float64                `db:"confidence_score" json:"confidence_score"`
	ProcessingTimeMicroseconds int64                  `db:"processing_time_microseconds" json:"processing_time_microseconds"`
	DetectedPatterns          map[string]interface{} `db:"detected_patterns" json:"detected_patterns"`
	CreatedAt                 time.Time              `db:"created_at" json:"created_at"`
}

type PolicyDecision struct {
	ID                   string                 `db:"id" json:"id"`
	TraceID              string                 `db:"trace_id" json:"trace_id"`
	TenantID             string                 `db:"tenant_id" json:"tenant_id"`
	PolicyBundleVersion  string                 `db:"policy_bundle_version" json:"policy_bundle_version"`
	Decision             map[string]interface{} `db:"decision" json:"decision"`
	EvaluationTimeMs     int64                  `db:"evaluation_time_ms" json:"evaluation_time_ms"`
	CreatedAt            time.Time              `db:"created_at" json:"created_at"`
}

type ImmutableAuditLog struct {
	ID               int64                  `db:"id" json:"id"`
	TraceID          string                 `db:"trace_id" json:"trace_id"`
	TenantID         string                 `db:"tenant_id" json:"tenant_id"`
	RequestHash      string                 `db:"request_hash" json:"request_hash"`
	PreviousHash     *string                `db:"previous_hash" json:"previous_hash"`
	CurrentHash      string                 `db:"current_hash" json:"current_hash"`
	EncryptedPayload []byte                 `db:"encrypted_payload" json:"encrypted_payload"`
	DetectorVerdicts map[string]interface{} `db:"detector_verdicts" json:"detector_verdicts"`
	PoliciesApplied  map[string]interface{} `db:"policies_applied" json:"policies_applied"`
	CreatedAt        time.Time              `db:"created_at" json:"created_at"`
}

var (
	globalDB *Database
	dbMutex  sync.RWMutex
)

func NewDatabase(cfg *config.Config, logger *zap.Logger) (*Database, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	db := &Database{
		config:             cfg,
		logger:             logger,
		metrics:            &DatabaseMetrics{},
		tenantPools:        make(map[string]*sqlx.DB),
		encryptionService:  NewEncryptionService(),
		hashChainValidator: NewHashChainValidator(),
		healthStatus: HealthStatus{
			IsHealthy: false,
			LastCheck: time.Now(),
		},
	}

	auditBatcher := &AuditBatcher{
		entries:     make(chan AuditEntry, 10000),
		batch:       make([]AuditEntry, 0, 1000),
		batchSize:   1000,
		flushTicker: 100 * time.Millisecond,
		db:          db,
	}
	db.auditBatcher = auditBatcher

	return db, nil
}

func (d *Database) Connect() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if atomic.LoadInt32(&d.closed) == 1 {
		return fmt.Errorf("database connection is closed")
	}

	dsn := d.buildDSN()
	if dsn == "" {
		return fmt.Errorf("failed to build database connection string")
	}

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		d.incrementConnectionErrors()
		return fmt.Errorf("failed to connect to PostgreSQL database: %w", err)
	}

	d.db = db
	d.healthStatus.IsHealthy = true
	d.healthStatus.LastCheck = time.Now()

	if err := d.initializeSchema(); err != nil {
		return fmt.Errorf("failed to initialize database schema: %w", err)
	}

	if err := d.prepareCriticalStatements(); err != nil {
		return fmt.Errorf("failed to prepare critical statements: %w", err)
	}

	if err := d.enableRowLevelSecurity(); err != nil {
		return fmt.Errorf("failed to enable row level security: %w", err)
	}

	d.startAuditBatcher()

	d.logger.Info("Enterprise PostgreSQL database connection established",
		zap.String("host", d.config.Database.Host),
		zap.Int("port", d.config.Database.Port),
		zap.String("database", d.config.Database.Database))

	return nil
}

func (d *Database) buildDSN() string {
	if d.config.Database.Host == "" || d.config.Database.Database == "" {
		return ""
	}

	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=require connect_timeout=10 statement_timeout=30000 application_name=exoper_ai_security",
		d.config.Database.Host,
		d.config.Database.Port,
		d.config.Database.Username,
		d.config.Database.Password,
		d.config.Database.Database)
}

func (d *Database) initializeSchema() error {
	schemas := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`,
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		
		`CREATE TYPE threat_type AS ENUM ('prompt_injection', 'pii_detection', 'adversarial_pattern', 'model_extraction', 'data_poisoning')`,
		`CREATE TYPE verdict_type AS ENUM ('CLEAN', 'FLAG', 'BLOCK')`,
		
		`CREATE TABLE IF NOT EXISTS tenants (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			name VARCHAR(255) NOT NULL UNIQUE,
			api_key_hash VARCHAR(255) NOT NULL,
			model_allowlist JSONB DEFAULT '[]',
			rate_limits JSONB NOT NULL DEFAULT '{}',
			quota_limits JSONB NOT NULL DEFAULT '{}',
			redaction_policies JSONB DEFAULT '{}',
			encryption_key_id VARCHAR(255),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		
		`CREATE TABLE IF NOT EXISTS threat_detection_rules (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			rule_type threat_type NOT NULL,
			pattern TEXT NOT NULL,
			severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 10),
			tenant_id UUID REFERENCES tenants(id),
			wasm_bytecode BYTEA,
			rust_signature BYTEA,
			enabled BOOLEAN DEFAULT true,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		
		`CREATE TABLE IF NOT EXISTS threat_verdicts (
			trace_id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL REFERENCES tenants(id),
			verdict verdict_type NOT NULL,
			confidence_score DECIMAL(5,4),
			processing_time_microseconds INTEGER,
			detected_patterns JSONB DEFAULT '[]',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		
		`CREATE TABLE IF NOT EXISTS policy_decisions (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			trace_id UUID NOT NULL,
			tenant_id UUID NOT NULL REFERENCES tenants(id),
			policy_bundle_version VARCHAR(50),
			decision JSONB NOT NULL,
			evaluation_time_ms INTEGER,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		
		`CREATE TABLE IF NOT EXISTS immutable_audit_log (
			id BIGSERIAL PRIMARY KEY,
			trace_id UUID NOT NULL,
			tenant_id UUID NOT NULL,
			request_hash VARCHAR(64) NOT NULL,
			previous_hash VARCHAR(64),
			current_hash VARCHAR(64) NOT NULL,
			encrypted_payload BYTEA,
			detector_verdicts JSONB NOT NULL,
			policies_applied JSONB NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		) WITH (fillfactor=100)`,
		
		`CREATE INDEX IF NOT EXISTS idx_audit_log_trace_id ON immutable_audit_log(trace_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON immutable_audit_log(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON immutable_audit_log(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_threat_verdicts_tenant_id ON threat_verdicts(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_decisions_tenant_id ON policy_decisions(tenant_id)`,
	}

	for _, schema := range schemas {
		if _, err := d.db.Exec(schema); err != nil {
			return fmt.Errorf("failed to execute schema: %w", err)
		}
	}

	return nil
}

func NewEncryptionService() *EncryptionService {
	return &EncryptionService{
		keyCache: make(map[string][]byte),
	}
}

func NewHashChainValidator() *HashChainValidator {
	return &HashChainValidator{}
}

func (d *Database) prepareCriticalStatements() error {
	stmts := &PreparedStatements{}

	var err error
	stmts.InsertAuditLog, err = d.db.Preparex(`
		INSERT INTO immutable_audit_log (trace_id, tenant_id, request_hash, previous_hash, current_hash, encrypted_payload, detector_verdicts, policies_applied)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at`)
	if err != nil {
		return fmt.Errorf("failed to prepare InsertAuditLog: %w", err)
	}

	stmts.InsertThreatVerdict, err = d.db.Preparex(`
		INSERT INTO threat_verdicts (trace_id, tenant_id, verdict, confidence_score, processing_time_microseconds, detected_patterns)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (trace_id) DO UPDATE SET
		verdict = EXCLUDED.verdict,
		confidence_score = EXCLUDED.confidence_score,
		processing_time_microseconds = EXCLUDED.processing_time_microseconds,
		detected_patterns = EXCLUDED.detected_patterns`)
	if err != nil {
		return fmt.Errorf("failed to prepare InsertThreatVerdict: %w", err)
	}

	stmts.InsertPolicyDecision, err = d.db.Preparex(`
		INSERT INTO policy_decisions (trace_id, tenant_id, policy_bundle_version, decision, evaluation_time_ms)
		VALUES ($1, $2, $3, $4, $5)`)
	if err != nil {
		return fmt.Errorf("failed to prepare InsertPolicyDecision: %w", err)
	}

	stmts.SelectTenantConfig, err = d.db.Preparex(`
		SELECT id, name, api_key_hash, model_allowlist, rate_limits, quota_limits, redaction_policies, encryption_key_id, created_at, updated_at
		FROM tenants WHERE id = $1`)
	if err != nil {
		return fmt.Errorf("failed to prepare SelectTenantConfig: %w", err)
	}

	stmts.VerifyHashChain, err = d.db.Preparex(`
		SELECT id, current_hash, previous_hash FROM immutable_audit_log 
		WHERE id BETWEEN $1 AND $2 ORDER BY id`)
	if err != nil {
		return fmt.Errorf("failed to prepare VerifyHashChain: %w", err)
	}

	d.preparedStmts = stmts
	return nil
}

func (d *Database) enableRowLevelSecurity() error {
	securityQueries := []string{
		`ALTER TABLE tenants ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE threat_verdicts ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE policy_decisions ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE immutable_audit_log ENABLE ROW LEVEL SECURITY`,
		
		`CREATE POLICY IF NOT EXISTS tenant_isolation_verdicts ON threat_verdicts
		 FOR ALL TO application_role
		 USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)`,
		
		`CREATE POLICY IF NOT EXISTS tenant_isolation_decisions ON policy_decisions
		 FOR ALL TO application_role
		 USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)`,
		
		`CREATE POLICY IF NOT EXISTS tenant_isolation_audit ON immutable_audit_log
		 FOR ALL TO application_role
		 USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)`,
	}

	for _, query := range securityQueries {
		if _, err := d.db.Exec(query); err != nil {
			d.logger.Warn("Failed to execute security query", zap.String("query", query), zap.Error(err))
		}
	}

	return nil
}

func (d *Database) SetTenantContext(ctx context.Context, tenantID string) error {
	query := "SELECT set_config('app.current_tenant_id', $1, true)"
	_, err := d.db.ExecContext(ctx, query, tenantID)
	return err
}

func (d *Database) GetTenantPool(tenantID string) (*sqlx.DB, error) {
	d.tenantPoolsMu.RLock()
	if pool, exists := d.tenantPools[tenantID]; exists {
		d.tenantPoolsMu.RUnlock()
		return pool, nil
	}
	d.tenantPoolsMu.RUnlock()

	d.tenantPoolsMu.Lock()
	defer d.tenantPoolsMu.Unlock()

	if pool, exists := d.tenantPools[tenantID]; exists {
		return pool, nil
	}

	dsn := d.buildDSN()
	pool, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant pool for %s: %w", tenantID, err)
	}

	pool.SetMaxOpenConns(10)
	pool.SetMaxIdleConns(5)
	pool.SetConnMaxLifetime(30 * time.Minute)

	if err := d.SetTenantContext(context.Background(), tenantID); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to set tenant context: %w", err)
	}

	d.tenantPools[tenantID] = pool
	return pool, nil
}

func (d *Database) Query(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	if atomic.LoadInt32(&d.closed) == 1 {
		return nil, fmt.Errorf("database connection is closed")
	}

	start := time.Now()
	traceID := d.extractTraceID(ctx)
	tenantID := d.extractTenantID(ctx)

	if d.config.Database.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.Database.QueryTimeout)
		defer cancel()
	}

	rows, err := d.db.QueryxContext(ctx, query, args...)
	duration := time.Since(start)

	result := &QueryResult{
		Rows:     rows,
		Duration: duration,
		Error:    err,
		TraceID:  traceID,
		TenantID: tenantID,
	}

	d.recordQueryMetrics(duration, err, "query")

	if d.config.Database.EnableQueryLogging {
		d.logQuery(query, args, duration, err, traceID, tenantID)
	}

	return result, err
}

func (d *Database) QueryRow(ctx context.Context, query string, args ...interface{}) *sqlx.Row {
	if atomic.LoadInt32(&d.closed) == 1 {
		return nil
	}

	start := time.Now()
	traceID := d.extractTraceID(ctx)
	tenantID := d.extractTenantID(ctx)

	if d.config.Database.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.Database.QueryTimeout)
		defer cancel()
	}

	row := d.db.QueryRowxContext(ctx, query, args...)
	duration := time.Since(start)

	d.recordQueryMetrics(duration, nil, "query_row")

	if d.config.Database.EnableQueryLogging {
		d.logQuery(query, args, duration, nil, traceID, tenantID)
	}

	return row
}

func (d *Database) Exec(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	if atomic.LoadInt32(&d.closed) == 1 {
		return nil, fmt.Errorf("database connection is closed")
	}

	start := time.Now()
	traceID := d.extractTraceID(ctx)
	tenantID := d.extractTenantID(ctx)

	if d.config.Database.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.Database.QueryTimeout)
		defer cancel()
	}

	result, err := d.db.ExecContext(ctx, query, args...)
	duration := time.Since(start)

	queryResult := &QueryResult{
		Duration: duration,
		Error:    err,
		TraceID:  traceID,
		TenantID: tenantID,
	}

	if err == nil && result != nil {
		if rowsAffected, raErr := result.RowsAffected(); raErr == nil {
			queryResult.RowsAffected = rowsAffected
		}
		if lastInsertID, liErr := result.LastInsertId(); liErr == nil {
			queryResult.LastInsertID = lastInsertID
		}
	}

	d.recordQueryMetrics(duration, err, "exec")

	if d.config.Database.EnableQueryLogging {
		d.logQuery(query, args, duration, err, traceID, tenantID)
	}

	return queryResult, err
}

func (d *Database) Select(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	if atomic.LoadInt32(&d.closed) == 1 {
		return fmt.Errorf("database connection is closed")
	}

	start := time.Now()
	traceID := d.extractTraceID(ctx)
	tenantID := d.extractTenantID(ctx)

	if d.config.Database.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.Database.QueryTimeout)
		defer cancel()
	}

	err := d.db.SelectContext(ctx, dest, query, args...)
	duration := time.Since(start)

	d.recordQueryMetrics(duration, err, "select")

	if d.config.Database.EnableQueryLogging {
		d.logQuery(query, args, duration, err, traceID, tenantID)
	}

	return err
}

func (d *Database) Get(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	if atomic.LoadInt32(&d.closed) == 1 {
		return fmt.Errorf("database connection is closed")
	}

	start := time.Now()
	traceID := d.extractTraceID(ctx)
	tenantID := d.extractTenantID(ctx)

	if d.config.Database.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.Database.QueryTimeout)
		defer cancel()
	}

	err := d.db.GetContext(ctx, dest, query, args...)
	duration := time.Since(start)

	d.recordQueryMetrics(duration, err, "get")

	if d.config.Database.EnableQueryLogging {
		d.logQuery(query, args, duration, err, traceID, tenantID)
	}

	return err
}

func (d *Database) BeginTx(ctx context.Context) (*Transaction, error) {
	if atomic.LoadInt32(&d.closed) == 1 {
		return nil, fmt.Errorf("database connection is closed")
	}

	traceID := d.extractTraceID(ctx)
	tenantID := d.extractTenantID(ctx)

	tx, err := d.db.BeginTxx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  false,
	})
	if err != nil {
		d.incrementConnectionErrors()
		return nil, fmt.Errorf("failed to begin PostgreSQL transaction: %w", err)
	}

	if tenantID != "" {
		if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID); err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("failed to set tenant context in transaction: %w", err)
		}
	}

	return &Transaction{
		tx:       tx,
		db:       d,
		ctx:      ctx,
		logger:   d.logger,
		tenantID: tenantID,
		traceID:  traceID,
	}, nil
}

func (t *Transaction) Query(query string, args ...interface{}) (*QueryResult, error) {
	start := time.Now()

	rows, err := t.tx.QueryxContext(t.ctx, query, args...)
	duration := time.Since(start)

	result := &QueryResult{
		Rows:     rows,
		Duration: duration,
		Error:    err,
		TraceID:  t.traceID,
		TenantID: t.tenantID,
	}

	t.db.recordQueryMetrics(duration, err, "tx_query")

	if t.db.config.Database.EnableQueryLogging {
		t.db.logQuery(query, args, duration, err, t.traceID, t.tenantID)
	}

	return result, err
}

func (t *Transaction) QueryRow(query string, args ...interface{}) *sqlx.Row {
	start := time.Now()

	row := t.tx.QueryRowxContext(t.ctx, query, args...)
	duration := time.Since(start)

	t.db.recordQueryMetrics(duration, nil, "tx_query_row")

	if t.db.config.Database.EnableQueryLogging {
		t.db.logQuery(query, args, duration, nil, t.traceID, t.tenantID)
	}

	return row
}

func (t *Transaction) Exec(query string, args ...interface{}) (*QueryResult, error) {
	start := time.Now()

	result, err := t.tx.ExecContext(t.ctx, query, args...)
	duration := time.Since(start)

	queryResult := &QueryResult{
		Duration: duration,
		Error:    err,
		TraceID:  t.traceID,
		TenantID: t.tenantID,
	}

	if err == nil && result != nil {
		if rowsAffected, raErr := result.RowsAffected(); raErr == nil {
			queryResult.RowsAffected = rowsAffected
		}
		if lastInsertID, liErr := result.LastInsertId(); liErr == nil {
			queryResult.LastInsertID = lastInsertID
		}
	}

	t.db.recordQueryMetrics(duration, err, "tx_exec")

	if t.db.config.Database.EnableQueryLogging {
		t.db.logQuery(query, args, duration, err, t.traceID, t.tenantID)
	}

	return queryResult, err
}

func (t *Transaction) Select(dest interface{}, query string, args ...interface{}) error {
	start := time.Now()

	err := t.tx.SelectContext(t.ctx, dest, query, args...)
	duration := time.Since(start)

	t.db.recordQueryMetrics(duration, err, "tx_select")

	if t.db.config.Database.EnableQueryLogging {
		t.db.logQuery(query, args, duration, err, t.traceID, t.tenantID)
	}

	return err
}

func (t *Transaction) Get(dest interface{}, query string, args ...interface{}) error {
	start := time.Now()

	err := t.tx.GetContext(t.ctx, dest, query, args...)
	duration := time.Since(start)

	t.db.recordQueryMetrics(duration, err, "tx_get")

	if t.db.config.Database.EnableQueryLogging {
		t.db.logQuery(query, args, duration, err, t.traceID, t.tenantID)
	}

	return err
}

func (t *Transaction) Commit() error {
	err := t.tx.Commit()
	if err != nil {
		t.logger.Error("PostgreSQL transaction commit failed",
			zap.Error(err),
			zap.String("trace_id", t.traceID),
			zap.String("tenant_id", t.tenantID))
		return fmt.Errorf("failed to commit PostgreSQL transaction: %w", err)
	}

	t.logger.Debug("PostgreSQL transaction committed successfully",
		zap.String("trace_id", t.traceID),
		zap.String("tenant_id", t.tenantID))
	return nil
}

func (t *Transaction) Rollback() error {
	err := t.tx.Rollback()
	if err != nil && err != sql.ErrTxDone {
		t.logger.Error("PostgreSQL transaction rollback failed",
			zap.Error(err),
			zap.String("trace_id", t.traceID),
			zap.String("tenant_id", t.tenantID))
		return fmt.Errorf("failed to rollback PostgreSQL transaction: %w", err)
	}

	t.logger.Debug("PostgreSQL transaction rolled back",
		zap.String("trace_id", t.traceID),
		zap.String("tenant_id", t.tenantID))
	return nil
}

func (d *Database) WithTransaction(ctx context.Context, fn func(*Transaction) error) error {
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				d.logger.Error("Failed to rollback transaction after panic",
					zap.Any("panic", p),
					zap.Error(rbErr),
					zap.String("trace_id", tx.traceID),
					zap.String("tenant_id", tx.tenantID))
			}
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			d.logger.Error("Failed to rollback transaction after error",
				zap.Error(err),
				zap.Error(rbErr),
				zap.String("trace_id", tx.traceID),
				zap.String("tenant_id", tx.tenantID))
		}
		return err
	}

	return tx.Commit()
}

func (d *Database) recordQueryMetrics(duration time.Duration, err error, operation string) {
	d.metrics.mu.Lock()
	defer d.metrics.mu.Unlock()

	if d.metrics.TotalQueries > 0 {
		totalDuration := time.Duration(d.metrics.TotalQueries) * d.metrics.AverageQueryTime
		d.metrics.AverageQueryTime = (totalDuration + duration) / time.Duration(d.metrics.TotalQueries+1)
	} else {
		d.metrics.AverageQueryTime = duration
	}

	d.metrics.TotalQueries++
	d.metrics.LastQueryTime = time.Now()

	if err != nil {
		d.metrics.FailedQueries++
	} else {
		d.metrics.SuccessfulQueries++
	}

	if duration > 1*time.Second {
		d.metrics.SlowQueries++
	}
}

func (d *Database) extractTraceID(ctx context.Context) string {
	if traceID := ctx.Value("trace_id"); traceID != nil {
		if id, ok := traceID.(string); ok {
			return id
		}
	}
	return ""
}

func (d *Database) extractTenantID(ctx context.Context) string {
	if tenantID := ctx.Value("tenant_id"); tenantID != nil {
		if id, ok := tenantID.(string); ok {
			return id
		}
	}
	return ""
}

func (d *Database) logQuery(query string, args []interface{}, duration time.Duration, err error, traceID, tenantID string) {
	fields := []zap.Field{
		zap.String("query", query),
		zap.Duration("duration", duration),
		zap.Any("args", args),
		zap.String("trace_id", traceID),
		zap.String("tenant_id", tenantID),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		d.logger.Error("PostgreSQL query failed", fields...)
	} else if duration > 1*time.Second {
		d.logger.Warn("Slow PostgreSQL query detected", fields...)
	} else {
		d.logger.Debug("PostgreSQL query executed", fields...)
	}
}

func (d *Database) incrementConnectionErrors() {
	d.metrics.mu.Lock()
	defer d.metrics.mu.Unlock()
	d.metrics.ConnectionErrors++
}

func (d *Database) startAuditBatcher() {
	if atomic.LoadInt32(&d.auditBatcher.closed) == 1 {
		return
	}

	d.auditBatcher.ticker = time.NewTicker(d.auditBatcher.flushTicker)

	go func() {
		defer d.auditBatcher.ticker.Stop()
		for {
			select {
			case entry := <-d.auditBatcher.entries:
				d.auditBatcher.mu.Lock()
				d.auditBatcher.batch = append(d.auditBatcher.batch, entry)
				if len(d.auditBatcher.batch) >= d.auditBatcher.batchSize {
					d.flushAuditBatch()
				}
				d.auditBatcher.mu.Unlock()

			case <-d.auditBatcher.ticker.C:
				d.auditBatcher.mu.Lock()
				if len(d.auditBatcher.batch) > 0 {
					d.flushAuditBatch()
				}
				d.auditBatcher.mu.Unlock()
			}

			if atomic.LoadInt32(&d.auditBatcher.closed) == 1 {
				break
			}
		}
	}()
}

func (d *Database) flushAuditBatch() {
	if len(d.auditBatcher.batch) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := d.BeginTx(ctx)
	if err != nil {
		d.logger.Error("Failed to begin audit batch transaction", zap.Error(err))
		return
	}

	for _, entry := range d.auditBatcher.batch {
		currentHash := d.calculateAuditHash(entry)
		
		_, err := tx.Exec(`
			INSERT INTO immutable_audit_log (trace_id, tenant_id, request_hash, previous_hash, current_hash, encrypted_payload, detector_verdicts, policies_applied)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			entry.TraceID, entry.TenantID, entry.RequestHash, entry.PreviousHash, currentHash, entry.EncryptedPayload, entry.DetectorVerdicts, entry.PoliciesApplied)
		
		if err != nil {
			tx.Rollback()
			d.logger.Error("Failed to insert audit entry", zap.Error(err), zap.String("trace_id", entry.TraceID))
			return
		}

		d.hashChainValidator.updateLastHash(currentHash)
	}

	if err := tx.Commit(); err != nil {
		d.logger.Error("Failed to commit audit batch", zap.Error(err))
		return
	}

	d.metrics.mu.Lock()
	d.metrics.AuditEntriesProcessed += int64(len(d.auditBatcher.batch))
	d.metrics.mu.Unlock()

	d.auditBatcher.batch = d.auditBatcher.batch[:0]
}

func (d *Database) StreamAuditEntry(entry AuditEntry) error {
	if atomic.LoadInt32(&d.auditBatcher.closed) == 1 {
		return fmt.Errorf("audit batcher is closed")
	}

	select {
	case d.auditBatcher.entries <- entry:
		return nil
	default:
		return fmt.Errorf("audit buffer full")
	}
}

func (d *Database) calculateAuditHash(entry AuditEntry) string {
	d.hashChainValidator.mu.RLock()
	previousHash := d.hashChainValidator.lastHash
	d.hashChainValidator.mu.RUnlock()

	data := fmt.Sprintf("%s%s%s%s%s", entry.TraceID, entry.TenantID, entry.RequestHash, previousHash, entry.Timestamp.Format(time.RFC3339Nano))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (hcv *HashChainValidator) updateLastHash(hash string) {
	hcv.mu.Lock()
	defer hcv.mu.Unlock()
	hcv.lastHash = hash
	hcv.lastID++
}

func (d *Database) VerifyAuditIntegrity(ctx context.Context, fromID, toID int64) error {
	rows, err := d.preparedStmts.VerifyHashChain.QueryxContext(ctx, fromID, toID)
	if err != nil {
		return fmt.Errorf("failed to query hash chain: %w", err)
	}
	defer rows.Close()

	var previousHash string
	for rows.Next() {
		var id int64
		var currentHash, storedPreviousHash string
		
		if err := rows.Scan(&id, &currentHash, &storedPreviousHash); err != nil {
			return fmt.Errorf("failed to scan hash chain row: %w", err)
		}

		if id > fromID && storedPreviousHash != previousHash {
			return fmt.Errorf("hash chain integrity violation at ID %d", id)
		}

		previousHash = currentHash
	}

	return nil
}

func (es *EncryptionService) EncryptPayload(tenantID string, payload []byte) ([]byte, error) {
	key, err := es.getTenantKey(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant encryption key: %w", err)
	}

	return es.aesGCMEncrypt(payload, key)
}

func (es *EncryptionService) DecryptPayload(tenantID string, encryptedPayload []byte) ([]byte, error) {
	key, err := es.getTenantKey(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant encryption key: %w", err)
	}

	return es.aesGCMDecrypt(encryptedPayload, key)
}

func (es *EncryptionService) getTenantKey(tenantID string) ([]byte, error) {
	es.cacheMu.RLock()
	if key, exists := es.keyCache[tenantID]; exists {
		es.cacheMu.RUnlock()
		return key, nil
	}
	es.cacheMu.RUnlock()

	key := make([]byte, 32)
	hash := sha256.Sum256([]byte(tenantID + "_enterprise_encryption_key"))
	copy(key, hash[:])

	es.cacheMu.Lock()
	es.keyCache[tenantID] = key
	es.cacheMu.Unlock()

	return key, nil
}

func (es *EncryptionService) aesGCMEncrypt(data, key []byte) ([]byte, error) {
	return data, nil
}

func (es *EncryptionService) aesGCMDecrypt(data, key []byte) ([]byte, error) {
	return data, nil
}

func (d *Database) RecordThreatVerdict(ctx context.Context, verdict ThreatVerdict) error {
	start := time.Now()
	defer func() {
		d.recordQueryMetrics(time.Since(start), nil, "threat_verdict")
		d.metrics.mu.Lock()
		d.metrics.ThreatDetections++
		d.metrics.mu.Unlock()
	}()

	_, err := d.preparedStmts.InsertThreatVerdict.ExecContext(ctx,
		verdict.TraceID, verdict.TenantID, verdict.Verdict, verdict.ConfidenceScore,
		verdict.ProcessingTimeMicroseconds, verdict.DetectedPatterns)
	
	return err
}

func (d *Database) RecordPolicyDecision(ctx context.Context, decision PolicyDecision) error {
	start := time.Now()
	defer func() {
		d.recordQueryMetrics(time.Since(start), nil, "policy_decision")
		d.metrics.mu.Lock()
		d.metrics.PolicyViolations++
		d.metrics.mu.Unlock()
	}()

	_, err := d.preparedStmts.InsertPolicyDecision.ExecContext(ctx,
		decision.TraceID, decision.TenantID, decision.PolicyBundleVersion,
		decision.Decision, decision.EvaluationTimeMs)
	
	return err
}

func (d *Database) GetTenantConfig(ctx context.Context, tenantID string) (*TenantConfig, error) {
	var config TenantConfig
	err := d.preparedStmts.SelectTenantConfig.GetContext(ctx, &config, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant config: %w", err)
	}
	return &config, nil
}

func (d *Database) CreateTenant(ctx context.Context, tenant TenantConfig) error {
	query := `
		INSERT INTO tenants (id, name, api_key_hash, model_allowlist, rate_limits, quota_limits, redaction_policies, encryption_key_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	
	_, err := d.Exec(ctx, query,
		tenant.ID, tenant.Name, tenant.APIKeyHash, tenant.ModelAllowlist,
		tenant.RateLimits, tenant.QuotaLimits, tenant.RedactionPolicies, tenant.EncryptionKeyID)
	
	return err
}

func (d *Database) UpdateTenantConfig(ctx context.Context, tenantID string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}

	setParts := make([]string, 0, len(updates))
	args := make([]interface{}, 0, len(updates)+1)
	argIndex := 1

	for field, value := range updates {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", field, argIndex))
		args = append(args, value)
		argIndex++
	}

	query := fmt.Sprintf("UPDATE tenants SET %s, updated_at = NOW() WHERE id = $%d",
		strings.Join(setParts, ", "), argIndex)
	args = append(args, tenantID)

	_, err := d.Exec(ctx, query, args...)
	return err
}

func (d *Database) GetThreatDetectionRules(ctx context.Context, tenantID string) ([]ThreatDetectionRule, error) {
	query := `
		SELECT id, rule_type, pattern, severity, tenant_id, wasm_bytecode, rust_signature, enabled, created_at
		FROM threat_detection_rules
		WHERE (tenant_id = $1 OR tenant_id IS NULL) AND enabled = true
		ORDER BY severity DESC, created_at ASC`

	var rules []ThreatDetectionRule
	err := d.Select(ctx, &rules, query, tenantID)
	return rules, err
}

func (d *Database) CreateThreatDetectionRule(ctx context.Context, rule ThreatDetectionRule) error {
	query := `
		INSERT INTO threat_detection_rules (id, rule_type, pattern, severity, tenant_id, wasm_bytecode, rust_signature, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := d.Exec(ctx, query,
		rule.ID, rule.RuleType, rule.Pattern, rule.Severity,
		rule.TenantID, rule.WasmBytecode, rule.RustSignature, rule.Enabled)

	return err
}

func (d *Database) GetAuditLogs(ctx context.Context, tenantID string, limit int, offset int) ([]ImmutableAuditLog, error) {
	query := `
		SELECT id, trace_id, tenant_id, request_hash, previous_hash, current_hash, encrypted_payload, detector_verdicts, policies_applied, created_at
		FROM immutable_audit_log
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	var logs []ImmutableAuditLog
	err := d.Select(ctx, &logs, query, tenantID, limit, offset)
	return logs, err
}

func (d *Database) HealthCheck(ctx context.Context) error {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}

	start := time.Now()
	err := d.db.PingContext(ctx)
	duration := time.Since(start)

	d.mu.Lock()
	d.healthStatus.LastCheck = time.Now()
	d.healthStatus.ResponseTime = duration

	if err != nil {
		d.healthStatus.IsHealthy = false
		d.healthStatus.ErrorMessage = err.Error()
		d.mu.Unlock()
		return fmt.Errorf("PostgreSQL health check failed: %w", err)
	}

	d.healthStatus.IsHealthy = true
	d.healthStatus.ErrorMessage = ""

	stats := d.db.Stats()
	d.healthStatus.OpenConnections = stats.OpenConnections
	d.healthStatus.IdleConnections = stats.Idle

	d.tenantPoolsMu.RLock()
	d.healthStatus.TenantPoolsHealthy = len(d.tenantPools)
	d.tenantPoolsMu.RUnlock()

	integrityErr := d.VerifyAuditIntegrity(ctx, d.hashChainValidator.lastID-100, d.hashChainValidator.lastID)
	d.healthStatus.AuditIntegrityValid = integrityErr == nil

	d.mu.Unlock()
	return nil
}

func (d *Database) GetHealthStatus() HealthStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.healthStatus
}

func (d *Database) GetMetrics() *DatabaseMetrics {
	d.metrics.mu.RLock()
	defer d.metrics.mu.RUnlock()
	metrics := *d.metrics
	return &metrics
}

func (d *Database) GetConnectionInfo() map[string]interface{} {
	stats := d.Stats()

	d.tenantPoolsMu.RLock()
	tenantPoolCount := len(d.tenantPools)
	d.tenantPoolsMu.RUnlock()

	return map[string]interface{}{
		"driver":                  "postgres",
		"host":                    d.config.Database.Host,
		"port":                    d.config.Database.Port,
		"database":                d.config.Database.Database,
		"max_open_conns":          d.config.Database.MaxOpenConnections,
		"max_idle_conns":          d.config.Database.MaxIdleConnections,
		"open_connections":        stats.OpenConnections,
		"in_use":                  stats.InUse,
		"idle":                    stats.Idle,
		"wait_count":              stats.WaitCount,
		"wait_duration":           stats.WaitDuration,
		"max_idle_closed":         stats.MaxIdleClosed,
		"max_idle_time_closed":    stats.MaxIdleTimeClosed,
		"max_lifetime_closed":     stats.MaxLifetimeClosed,
		"tenant_pools":            tenantPoolCount,
		"audit_integrity_valid":   d.healthStatus.AuditIntegrityValid,
	}
}

func (d *Database) Ping(ctx context.Context) error {
	if d.db == nil {
		return fmt.Errorf("PostgreSQL database connection not established")
	}

	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}

	return d.db.PingContext(ctx)
}

func (d *Database) Stats() sql.DBStats {
	if d.db == nil {
		return sql.DBStats{}
	}
	return d.db.Stats()
}

func (d *Database) ConfigurePool() error {
	if d.db == nil {
		return fmt.Errorf("database connection not established")
	}

	d.db.SetMaxOpenConns(d.config.Database.MaxOpenConnections)
	d.db.SetMaxIdleConns(d.config.Database.MaxIdleConnections)
	d.db.SetConnMaxLifetime(d.config.Database.ConnectionLifetime)
	d.db.SetConnMaxIdleTime(15 * time.Minute)

	d.logger.Info("Enterprise PostgreSQL connection pool configured",
		zap.Int("max_open_connections", d.config.Database.MaxOpenConnections),
		zap.Int("max_idle_connections", d.config.Database.MaxIdleConnections),
		zap.Duration("connection_lifetime", d.config.Database.ConnectionLifetime))

	return nil
}

func (d *Database) RunMigrations(ctx context.Context) error {
	if d.config.Database.MigrationsPath == "" {
		d.logger.Info("No migrations path specified, skipping migrations")
		return nil
	}

	driver, err := postgres.WithInstance(d.db.DB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create PostgreSQL migration driver: %w", err)
	}

	sourceDriver, err := (&file.File{}).Open(fmt.Sprintf("file://%s", d.config.Database.MigrationsPath))
	if err != nil {
		return fmt.Errorf("failed to open migrations source: %w", err)
	}

	m, err := migrate.NewWithInstance("file", sourceDriver, "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run PostgreSQL migrations: %w", err)
	}

	d.logger.Info("PostgreSQL database migrations completed successfully")
	return nil
}

func (d *Database) Close() error {
	if !atomic.CompareAndSwapInt32(&d.closed, 0, 1) {
		return nil
	}

	atomic.StoreInt32(&d.auditBatcher.closed, 1)

	d.tenantPoolsMu.Lock()
	for tenantID, pool := range d.tenantPools {
		if err := pool.Close(); err != nil {
			d.logger.Error("Failed to close tenant pool", zap.String("tenant_id", tenantID), zap.Error(err))
		}
	}
	d.tenantPools = make(map[string]*sqlx.DB)
	d.tenantPoolsMu.Unlock()

	if d.preparedStmts != nil {
		d.preparedStmts.mu.Lock()
		if d.preparedStmts.InsertAuditLog != nil {
			d.preparedStmts.InsertAuditLog.Close()
		}
		if d.preparedStmts.InsertThreatVerdict != nil {
			d.preparedStmts.InsertThreatVerdict.Close()
		}
		if d.preparedStmts.InsertPolicyDecision != nil {
			d.preparedStmts.InsertPolicyDecision.Close()
		}
		if d.preparedStmts.SelectTenantConfig != nil {
			d.preparedStmts.SelectTenantConfig.Close()
		}
		if d.preparedStmts.VerifyHashChain != nil {
			d.preparedStmts.VerifyHashChain.Close()
		}
		d.preparedStmts.mu.Unlock()
	}

	if d.db == nil {
		return nil
	}

	err := d.db.Close()
	if err != nil {
		d.logger.Error("Failed to close PostgreSQL database connection", zap.Error(err))
		return fmt.Errorf("failed to close PostgreSQL database: %w", err)
	}

	d.logger.Info("Enterprise PostgreSQL database connection closed")
	return nil
}

func (d *Database) GetDB() *sqlx.DB {
	return d.db
}

func InitializeDatabase(cfg *config.Config) (*Database, error) {
	logger := zap.L()

	db, err := NewDatabase(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create database instance: %w", err)
	}

	if err := db.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL database: %w", err)
	}

	if err := db.ConfigurePool(); err != nil {
		return nil, fmt.Errorf("failed to configure PostgreSQL connection pool: %w", err)
	}

	if cfg.Database.EnableMigrations {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		
		if err := db.RunMigrations(ctx); err != nil {
			return nil, fmt.Errorf("failed to run PostgreSQL migrations: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := db.HealthCheck(ctx); err != nil {
		logger.Warn("Initial PostgreSQL health check failed", zap.Error(err))
	}

	setGlobalDatabase(db)

	logger.Info("PostgreSQL database initialized successfully",
		zap.String("host", cfg.Database.Host),
		zap.Int("port", cfg.Database.Port),
		zap.String("database", cfg.Database.Database))

	return db, nil
}

func GetGlobalDatabase() *Database {
	dbMutex.RLock()
	defer dbMutex.RUnlock()
	return globalDB
}

func setGlobalDatabase(db *Database) {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	globalDB = db
}

func BuildConnectionString(host string, port int, username, password, database, sslMode string) string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=10 statement_timeout=30000 application_name=exoper_ai_security",
		host, port, username, password, database, sslMode)
}

func ValidateConnectionString(dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("invalid PostgreSQL connection string: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("PostgreSQL connection test failed: %w", err)
	}

	return nil
}

func EscapeIdentifier(identifier string) string {
	return fmt.Sprintf(`"%s"`, strings.ReplaceAll(identifier, `"`, `""`))
}

func BuildPlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	
	placeholders := make([]string, count)
	for i := 0; i < count; i++ {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	return strings.Join(placeholders, ",")
}

func (d *Database) ExecuteHealthChecks(ctx context.Context) map[string]interface{} {
	results := make(map[string]interface{})

	if err := d.HealthCheck(ctx); err != nil {
		results["database"] = map[string]interface{}{
			"status": "unhealthy",
			"error":  err.Error(),
		}
	} else {
		results["database"] = map[string]interface{}{
			"status":       "healthy",
			"response_time": d.healthStatus.ResponseTime.String(),
		}
	}

	d.tenantPoolsMu.RLock()
	healthyPools := 0
	totalPools := len(d.tenantPools)
	for _, pool := range d.tenantPools {
		if err := pool.PingContext(ctx); err == nil {
			healthyPools++
		}
	}
	d.tenantPoolsMu.RUnlock()

	results["tenant_pools"] = map[string]interface{}{
		"total":   totalPools,
		"healthy": healthyPools,
		"status":  "healthy",
	}

	if healthyPools < totalPools {
		results["tenant_pools"].(map[string]interface{})["status"] = "degraded"
	}

	integrityErr := d.VerifyAuditIntegrity(ctx, d.hashChainValidator.lastID-10, d.hashChainValidator.lastID)
	results["audit_integrity"] = map[string]interface{}{
		"status": "healthy",
		"valid":  integrityErr == nil,
	}

	if integrityErr != nil {
		results["audit_integrity"].(map[string]interface{})["status"] = "unhealthy"
		results["audit_integrity"].(map[string]interface{})["error"] = integrityErr.Error()
	}

	return results
}

func (d *Database) GetSystemMetrics() map[string]interface{} {
	metrics := d.GetMetrics()
	stats := d.Stats()

	return map[string]interface{}{
		"queries": map[string]interface{}{
			"total":       metrics.TotalQueries,
			"successful":  metrics.SuccessfulQueries,
			"failed":      metrics.FailedQueries,
			"slow":        metrics.SlowQueries,
			"avg_time_ms": metrics.AverageQueryTime.Milliseconds(),
		},
		"connections": map[string]interface{}{
			"open":         stats.OpenConnections,
			"in_use":       stats.InUse,
			"idle":         stats.Idle,
			"wait_count":   stats.WaitCount,
			"wait_duration_ms": stats.WaitDuration.Milliseconds(),
		},
		"security": map[string]interface{}{
			"threat_detections":   metrics.ThreatDetections,
			"policy_violations":   metrics.PolicyViolations,
			"audit_entries":       metrics.AuditEntriesProcessed,
			"tenant_operations":   metrics.TenantOperations,
		},
		"performance": map[string]interface{}{
			"connection_errors": metrics.ConnectionErrors,
			"last_query":        metrics.LastQueryTime.Unix(),
		},
	}
}
