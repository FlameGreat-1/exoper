package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
)

type Database struct {
	db           *sqlx.DB
	config       *config.DatabaseConfig
	logger       *zap.Logger
	mu           sync.RWMutex
	healthStatus HealthStatus
	metrics      *DatabaseMetrics
}

type HealthStatus struct {
	IsHealthy        bool      `json:"is_healthy"`
	LastCheck        time.Time `json:"last_check"`
	ConnectionCount  int       `json:"connection_count"`
	OpenConnections  int       `json:"open_connections"`
	IdleConnections  int       `json:"idle_connections"`
	ResponseTime     time.Duration `json:"response_time"`
	ErrorMessage     string    `json:"error_message,omitempty"`
}

type DatabaseMetrics struct {
	TotalQueries       int64         `json:"total_queries"`
	SuccessfulQueries  int64         `json:"successful_queries"`
	FailedQueries      int64         `json:"failed_queries"`
	AverageQueryTime   time.Duration `json:"average_query_time"`
	SlowQueries        int64         `json:"slow_queries"`
	ConnectionErrors   int64         `json:"connection_errors"`
	LastQueryTime      time.Time     `json:"last_query_time"`
	mu                 sync.RWMutex
}

type QueryResult struct {
	Rows         *sqlx.Rows
	RowsAffected int64
	LastInsertID int64
	Duration     time.Duration
	Error        error
}

type Transaction struct {
	tx     *sqlx.Tx
	db     *Database
	ctx    context.Context
	logger *zap.Logger
}

type ConnectionPool struct {
	MaxOpenConnections int
	MaxIdleConnections int
	ConnectionLifetime time.Duration
	ConnectionTimeout  time.Duration
}

var (
	globalDB *Database
	dbMutex  sync.RWMutex
)

func NewDatabase(cfg *config.DatabaseConfig, logger *zap.Logger) *Database {
	return &Database{
		config:  cfg,
		logger:  logger,
		metrics: &DatabaseMetrics{},
		healthStatus: HealthStatus{
			IsHealthy: false,
			LastCheck: time.Now(),
		},
	}
}

func InitializeDatabase(cfg *config.Config) (*Database, error) {
	logger := zap.L()
	
	db := NewDatabase(&cfg.Database, logger)
	
	if err := db.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.ConfigurePool(); err != nil {
		return nil, fmt.Errorf("failed to configure connection pool: %w", err)
	}

	if cfg.Database.EnableMigrations {
		if err := db.RunMigrations(); err != nil {
			return nil, fmt.Errorf("failed to run migrations: %w", err)
		}
	}

	if err := db.HealthCheck(); err != nil {
		logger.Warn("Initial health check failed", zap.Error(err))
	}

	setGlobalDatabase(db)

	logger.Info("Database initialized successfully",
		zap.String("type", string(cfg.Database.Type)),
		zap.String("host", cfg.Database.Host),
		zap.Int("port", cfg.Database.Port))

	return db, nil
}

func (d *Database) Connect() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	dsn := d.buildDSN()
	
	db, err := sqlx.Connect(string(d.config.Type), dsn)
	if err != nil {
		d.metrics.incrementConnectionErrors()
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	d.db = db
	d.healthStatus.IsHealthy = true
	d.healthStatus.LastCheck = time.Now()

	d.logger.Info("Database connection established",
		zap.String("driver", string(d.config.Type)),
		zap.String("host", d.config.Host))

	return nil
}

func (d *Database) buildDSN() string {
	switch d.config.Type {
	case config.DatabasePostgreSQL:
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			d.config.Host,
			d.config.Port,
			d.config.Username,
			d.config.Password,
			d.config.Database,
			d.config.SSLMode)
	case config.DatabaseMySQL:
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC&timeout=%s",
			d.config.Username,
			d.config.Password,
			d.config.Host,
			d.config.Port,
			d.config.Database,
			d.config.ConnectionTimeout)
	case config.DatabaseSQLite:
		return d.config.Database
	default:
		return ""
	}
}

func (d *Database) ConfigurePool() error {
	if d.db == nil {
		return fmt.Errorf("database connection not established")
	}

	d.db.SetMaxOpenConns(d.config.MaxOpenConnections)
	d.db.SetMaxIdleConns(d.config.MaxIdleConnections)
	d.db.SetConnMaxLifetime(d.config.ConnectionLifetime)

	d.logger.Info("Database connection pool configured",
		zap.Int("max_open_connections", d.config.MaxOpenConnections),
		zap.Int("max_idle_connections", d.config.MaxIdleConnections),
		zap.Duration("connection_lifetime", d.config.ConnectionLifetime))

	return nil
}

func (d *Database) RunMigrations() error {
	if d.config.MigrationsPath == "" {
		d.logger.Info("No migrations path specified, skipping migrations")
		return nil
	}

	driver, err := d.getMigrationDriver()
	if err != nil {
		return fmt.Errorf("failed to get migration driver: %w", err)
	}

	sourceDriver, err := (&file.File{}).Open(fmt.Sprintf("file://%s", d.config.MigrationsPath))
	if err != nil {
		return fmt.Errorf("failed to open migrations source: %w", err)
	}

	m, err := migrate.NewWithInstance("file", sourceDriver, string(d.config.Type), driver)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	d.logger.Info("Database migrations completed successfully")
	return nil
}

func (d *Database) getMigrationDriver() (migrate.DatabaseDriver, error) {
	switch d.config.Type {
	case config.DatabasePostgreSQL:
		return postgres.WithInstance(d.db.DB, &postgres.Config{})
	case config.DatabaseMySQL:
		return mysql.WithInstance(d.db.DB, &mysql.Config{})
	default:
		return nil, fmt.Errorf("unsupported database type for migrations: %s", d.config.Type)
	}
}

func (d *Database) HealthCheck() error {
	start := time.Now()
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := d.db.PingContext(ctx)
	duration := time.Since(start)

	d.mu.Lock()
	d.healthStatus.LastCheck = time.Now()
	d.healthStatus.ResponseTime = duration
	
	if err != nil {
		d.healthStatus.IsHealthy = false
		d.healthStatus.ErrorMessage = err.Error()
		d.mu.Unlock()
		return fmt.Errorf("database health check failed: %w", err)
	}

	d.healthStatus.IsHealthy = true
	d.healthStatus.ErrorMessage = ""
	
	stats := d.db.Stats()
	d.healthStatus.OpenConnections = stats.OpenConnections
	d.healthStatus.IdleConnections = stats.Idle
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

func (d *Database) Query(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	start := time.Now()
	
	if d.config.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.QueryTimeout)
		defer cancel()
	}

	rows, err := d.db.QueryxContext(ctx, query, args...)
	duration := time.Since(start)

	result := &QueryResult{
		Rows:     rows,
		Duration: duration,
		Error:    err,
	}

	d.recordQueryMetrics(duration, err)

	if d.config.EnableQueryLogging {
		d.logQuery(query, args, duration, err)
	}

	return result, err
}

func (d *Database) QueryRow(ctx context.Context, query string, args ...interface{}) *sqlx.Row {
	start := time.Now()
	
	if d.config.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.QueryTimeout)
		defer cancel()
	}

	row := d.db.QueryRowxContext(ctx, query, args...)
	duration := time.Since(start)

	d.recordQueryMetrics(duration, nil)

	if d.config.EnableQueryLogging {
		d.logQuery(query, args, duration, nil)
	}

	return row
}

func (d *Database) Exec(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	start := time.Now()
	
	if d.config.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.QueryTimeout)
		defer cancel()
	}

	result, err := d.db.ExecContext(ctx, query, args...)
	duration := time.Since(start)

	queryResult := &QueryResult{
		Duration: duration,
		Error:    err,
	}

	if err == nil && result != nil {
		if rowsAffected, raErr := result.RowsAffected(); raErr == nil {
			queryResult.RowsAffected = rowsAffected
		}
		if lastInsertID, liErr := result.LastInsertId(); liErr == nil {
			queryResult.LastInsertID = lastInsertID
		}
	}

	d.recordQueryMetrics(duration, err)

	if d.config.EnableQueryLogging {
		d.logQuery(query, args, duration, err)
	}

	return queryResult, err
}

func (d *Database) Select(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	start := time.Now()
	
	if d.config.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.QueryTimeout)
		defer cancel()
	}

	err := d.db.SelectContext(ctx, dest, query, args...)
	duration := time.Since(start)

	d.recordQueryMetrics(duration, err)

	if d.config.EnableQueryLogging {
		d.logQuery(query, args, duration, err)
	}

	return err
}

func (d *Database) Get(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	start := time.Now()
	
	if d.config.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.QueryTimeout)
		defer cancel()
	}

	err := d.db.GetContext(ctx, dest, query, args...)
	duration := time.Since(start)

	d.recordQueryMetrics(duration, err)

	if d.config.EnableQueryLogging {
		d.logQuery(query, args, duration, err)
	}

	return err
}


func (d *Database) BeginTx(ctx context.Context) (*Transaction, error) {
	tx, err := d.db.BeginTxx(ctx, nil)
	if err != nil {
		d.metrics.incrementConnectionErrors()
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &Transaction{
		tx:     tx,
		db:     d,
		ctx:    ctx,
		logger: d.logger,
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
	}

	t.db.recordQueryMetrics(duration, err)

	if t.db.config.EnableQueryLogging {
		t.db.logQuery(query, args, duration, err)
	}

	return result, err
}

func (t *Transaction) QueryRow(query string, args ...interface{}) *sqlx.Row {
	start := time.Now()
	
	row := t.tx.QueryRowxContext(t.ctx, query, args...)
	duration := time.Since(start)

	t.db.recordQueryMetrics(duration, nil)

	if t.db.config.EnableQueryLogging {
		t.db.logQuery(query, args, duration, nil)
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
	}

	if err == nil && result != nil {
		if rowsAffected, raErr := result.RowsAffected(); raErr == nil {
			queryResult.RowsAffected = rowsAffected
		}
		if lastInsertID, liErr := result.LastInsertId(); liErr == nil {
			queryResult.LastInsertID = lastInsertID
		}
	}

	t.db.recordQueryMetrics(duration, err)

	if t.db.config.EnableQueryLogging {
		t.db.logQuery(query, args, duration, err)
	}

	return queryResult, err
}

func (t *Transaction) Select(dest interface{}, query string, args ...interface{}) error {
	start := time.Now()
	
	err := t.tx.SelectContext(t.ctx, dest, query, args...)
	duration := time.Since(start)

	t.db.recordQueryMetrics(duration, err)

	if t.db.config.EnableQueryLogging {
		t.db.logQuery(query, args, duration, err)
	}

	return err
}

func (t *Transaction) Get(dest interface{}, query string, args ...interface{}) error {
	start := time.Now()
	
	err := t.tx.GetContext(t.ctx, dest, query, args...)
	duration := time.Since(start)

	t.db.recordQueryMetrics(duration, err)

	if t.db.config.EnableQueryLogging {
		t.db.logQuery(query, args, duration, err)
	}

	return err
}

func (t *Transaction) Commit() error {
	err := t.tx.Commit()
	if err != nil {
		t.logger.Error("Transaction commit failed", zap.Error(err))
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	t.logger.Debug("Transaction committed successfully")
	return nil
}

func (t *Transaction) Rollback() error {
	err := t.tx.Rollback()
	if err != nil && err != sql.ErrTxDone {
		t.logger.Error("Transaction rollback failed", zap.Error(err))
		return fmt.Errorf("failed to rollback transaction: %w", err)
	}

	t.logger.Debug("Transaction rolled back")
	return nil
}

func (d *Database) recordQueryMetrics(duration time.Duration, err error) {
	d.metrics.mu.Lock()
	defer d.metrics.mu.Unlock()

	d.metrics.TotalQueries++
	d.metrics.LastQueryTime = time.Now()

	if err != nil {
		d.metrics.FailedQueries++
	} else {
		d.metrics.SuccessfulQueries++
	}

	if d.metrics.TotalQueries > 0 {
		totalDuration := time.Duration(d.metrics.TotalQueries) * d.metrics.AverageQueryTime
		d.metrics.AverageQueryTime = (totalDuration + duration) / time.Duration(d.metrics.TotalQueries)
	} else {
		d.metrics.AverageQueryTime = duration
	}

	if duration > 1*time.Second {
		d.metrics.SlowQueries++
	}
}

func (d *Database) incrementConnectionErrors() {
	d.metrics.mu.Lock()
	defer d.metrics.mu.Unlock()
	d.metrics.ConnectionErrors++
}

func (d *Database) logQuery(query string, args []interface{}, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("query", query),
		zap.Duration("duration", duration),
		zap.Any("args", args),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		d.logger.Error("Database query failed", fields...)
	} else if duration > 1*time.Second {
		d.logger.Warn("Slow database query", fields...)
	} else {
		d.logger.Debug("Database query executed", fields...)
	}
}

func (d *Database) Close() error {
	if d.db == nil {
		return nil
	}

	err := d.db.Close()
	if err != nil {
		d.logger.Error("Failed to close database connection", zap.Error(err))
		return fmt.Errorf("failed to close database: %w", err)
	}

	d.logger.Info("Database connection closed")
	return nil
}

func (d *Database) GetDB() *sqlx.DB {
	return d.db
}

func (d *Database) Ping() error {
	if d.db == nil {
		return fmt.Errorf("database connection not established")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return d.db.PingContext(ctx)
}

func (d *Database) Stats() sql.DBStats {
	if d.db == nil {
		return sql.DBStats{}
	}
	return d.db.Stats()
}

func (d *Database) WithTransaction(ctx context.Context, fn func(*Transaction) error) error {
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			d.logger.Error("Failed to rollback transaction after error", 
				zap.Error(err), 
				zap.Error(rbErr))
		}
		return err
	}

	return tx.Commit()
}

func (d *Database) BulkInsert(ctx context.Context, table string, columns []string, values [][]interface{}) error {
	if len(values) == 0 {
		return nil
	}

	placeholders := make([]string, len(columns))
	for i := range placeholders {
		placeholders[i] = "?"
	}

	valueStrings := make([]string, len(values))
	args := make([]interface{}, 0, len(values)*len(columns))

	for i, row := range values {
		valueStrings[i] = "(" + fmt.Sprintf(strings.Join(placeholders, ",")) + ")"
		args = append(args, row...)
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES %s",
		table,
		strings.Join(columns, ","),
		strings.Join(valueStrings, ","))

	_, err := d.Exec(ctx, query, args...)
	return err
}

func (d *Database) TableExists(ctx context.Context, tableName string) (bool, error) {
	var query string
	var args []interface{}

	switch d.config.Type {
	case config.DatabasePostgreSQL:
		query = "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)"
		args = []interface{}{tableName}
	case config.DatabaseMySQL:
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?"
		args = []interface{}{tableName}
	case config.DatabaseSQLite:
		query = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?"
		args = []interface{}{tableName}
	default:
		return false, fmt.Errorf("unsupported database type: %s", d.config.Type)
	}

	var exists bool
	err := d.Get(ctx, &exists, query, args...)
	return exists, err
}

func (d *Database) GetTableSchema(ctx context.Context, tableName string) ([]ColumnInfo, error) {
	var query string
	var args []interface{}

	switch d.config.Type {
	case config.DatabasePostgreSQL:
		query = `SELECT column_name, data_type, is_nullable, column_default 
				FROM information_schema.columns 
				WHERE table_schema = 'public' AND table_name = $1 
				ORDER BY ordinal_position`
		args = []interface{}{tableName}
	case config.DatabaseMySQL:
		query = `SELECT column_name, data_type, is_nullable, column_default 
				FROM information_schema.columns 
				WHERE table_schema = DATABASE() AND table_name = ? 
				ORDER BY ordinal_position`
		args = []interface{}{tableName}
	default:
		return nil, fmt.Errorf("unsupported database type for schema inspection: %s", d.config.Type)
	}

	var columns []ColumnInfo
	err := d.Select(ctx, &columns, query, args...)
	return columns, err
}

type ColumnInfo struct {
	ColumnName    string         `db:"column_name"`
	DataType      string         `db:"data_type"`
	IsNullable    string         `db:"is_nullable"`
	ColumnDefault sql.NullString `db:"column_default"`
}

func (d *Database) ExecuteInBatches(ctx context.Context, query string, batchSize int, args [][]interface{}) error {
	for i := 0; i < len(args); i += batchSize {
		end := i + batchSize
		if end > len(args) {
			end = len(args)
		}

		batch := args[i:end]
		for _, argSet := range batch {
			if _, err := d.Exec(ctx, query, argSet...); err != nil {
				return fmt.Errorf("batch execution failed at index %d: %w", i, err)
			}
		}
	}

	return nil
}

func (d *Database) GetConnectionInfo() map[string]interface{} {
	stats := d.Stats()
	
	return map[string]interface{}{
		"driver":              string(d.config.Type),
		"host":                d.config.Host,
		"port":                d.config.Port,
		"database":            d.config.Database,
		"max_open_conns":      d.config.MaxOpenConnections,
		"max_idle_conns":      d.config.MaxIdleConnections,
		"open_connections":    stats.OpenConnections,
		"in_use":              stats.InUse,
		"idle":                stats.Idle,
		"wait_count":          stats.WaitCount,
		"wait_duration":       stats.WaitDuration,
		"max_idle_closed":     stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed": stats.MaxLifetimeClosed,
	}
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

func BuildConnectionString(dbType config.DatabaseType, host string, port int, username, password, database, sslMode string) string {
	switch dbType {
	case config.DatabasePostgreSQL:
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			host, port, username, password, database, sslMode)
	case config.DatabaseMySQL:
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC",
			username, password, host, port, database)
	case config.DatabaseSQLite:
		return database
	default:
		return ""
	}
}

func ValidateConnectionString(dbType config.DatabaseType, dsn string) error {
	db, err := sql.Open(string(dbType), dsn)
	if err != nil {
		return fmt.Errorf("invalid connection string: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}

	return nil
}

func EscapeIdentifier(dbType config.DatabaseType, identifier string) string {
	switch dbType {
	case config.DatabasePostgreSQL:
		return fmt.Sprintf(`"%s"`, strings.ReplaceAll(identifier, `"`, `""`))
	case config.DatabaseMySQL:
		return fmt.Sprintf("`%s`", strings.ReplaceAll(identifier, "`", "``"))
	case config.DatabaseSQLite:
		return fmt.Sprintf(`"%s"`, strings.ReplaceAll(identifier, `"`, `""`))
	default:
		return identifier
	}
}

func BuildPlaceholders(dbType config.DatabaseType, count int) string {
	switch dbType {
	case config.DatabasePostgreSQL:
		placeholders := make([]string, count)
		for i := 0; i < count; i++ {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
		}
		return strings.Join(placeholders, ",")
	case config.DatabaseMySQL, config.DatabaseSQLite:
		return strings.Repeat("?,", count-1) + "?"
	default:
		return strings.Repeat("?,", count-1) + "?"
	}
}
