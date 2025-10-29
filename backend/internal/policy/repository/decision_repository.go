package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"exoper/backend/internal/common/database"
	"exoper/backend/internal/common/errors"
)

type DecisionRepository interface {
	GetDecisionHistory(ctx context.Context, query *GetDecisionHistoryQuery) (*DecisionHistoryResult, error)
	SaveDecision(ctx context.Context, decision *PolicyDecision) error
	GetDecisionByTraceID(ctx context.Context, tenantID, traceID string) (*PolicyDecision, error)
	DeleteDecisionHistory(ctx context.Context, tenantID string, olderThan time.Time) (int64, error)
}

type GetDecisionHistoryQuery struct {
	TenantID  string
	SubjectID string
	StartTime time.Time
	EndTime   time.Time
	Limit     int
	Offset    int
}

type DecisionHistoryResult struct {
	Decisions []PolicyDecision
	Total     int
	HasMore   bool
}

type PolicyDecision struct {
	ID                   string                 `json:"id"`
	TraceID              string                 `json:"trace_id"`
	TenantID             string                 `json:"tenant_id"`
	PolicyBundleVersion  string                 `json:"policy_bundle_version"`
	Decision             map[string]interface{} `json:"decision"`
	EvaluationTimeMs     int64                  `json:"evaluation_time_ms"`
	CreatedAt            time.Time              `json:"created_at"`
}

type decisionRepository struct {
	db     *database.Database
	logger *zap.Logger
}

func NewDecisionRepository(db *database.Database, logger *zap.Logger) DecisionRepository {
	return &decisionRepository{
		db:     db,
		logger: logger,
	}
}

func (r *decisionRepository) GetDecisionHistory(ctx context.Context, query *GetDecisionHistoryQuery) (*DecisionHistoryResult, error) {
	conditions := []string{"tenant_id = $1"}
	args := []interface{}{query.TenantID}
	paramCount := 1

	if query.SubjectID != "" {
		paramCount++
		conditions = append(conditions, fmt.Sprintf("trace_id = $%d", paramCount))
		args = append(args, query.SubjectID)
	}

	if !query.StartTime.IsZero() {
		paramCount++
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", paramCount))
		args = append(args, query.StartTime)
	}

	if !query.EndTime.IsZero() {
		paramCount++
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", paramCount))
		args = append(args, query.EndTime)
	}

	whereClause := strings.Join(conditions, " AND ")

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM policy_decisions WHERE %s", whereClause)
	
	var total int
	row := r.db.QueryRow(ctx, countQuery, args...)
	err := row.Scan(&total)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to count decision history")
	}

	limit := query.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	paramCount++
	limitParam := paramCount
	paramCount++
	offsetParam := paramCount

	selectQuery := fmt.Sprintf(`
		SELECT id, trace_id, tenant_id, policy_bundle_version, decision, 
		       evaluation_time_ms, created_at
		FROM policy_decisions 
		WHERE %s 
		ORDER BY created_at DESC 
		LIMIT $%d OFFSET $%d`, 
		whereClause, limitParam, offsetParam)

	args = append(args, limit, offset)

	result, err := r.db.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to query decision history")
	}
	if result.Error != nil {
		return nil, errors.Wrap(result.Error, errors.ErrCodeInternalError, "Failed to query decision history")
	}
	defer result.Rows.Close()

	var decisions []PolicyDecision
	for result.Rows.Next() {
		var decision PolicyDecision
		var decisionJSON []byte
		var evaluationTimeMs int64

		err := result.Rows.Scan(
			&decision.ID,
			&decision.TraceID,
			&decision.TenantID,
			&decision.PolicyBundleVersion,
			&decisionJSON,
			&evaluationTimeMs,
			&decision.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to scan decision record")
		}

		if len(decisionJSON) > 0 {
			json.Unmarshal(decisionJSON, &decision.Decision)
		}

		decision.EvaluationTimeMs = evaluationTimeMs
		decisions = append(decisions, decision)
	}

	if err := result.Rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Error iterating decision records")
	}

	return &DecisionHistoryResult{
		Decisions: decisions,
		Total:     total,
		HasMore:   offset+len(decisions) < total,
	}, nil
}

func (r *decisionRepository) SaveDecision(ctx context.Context, decision *PolicyDecision) error {
	decisionJSON, err := json.Marshal(decision.Decision)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to marshal decision")
	}

	query := `
		INSERT INTO policy_decisions (id, trace_id, tenant_id, policy_bundle_version, decision, evaluation_time_ms, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	result, err := r.db.Exec(ctx, query,
		decision.ID,
		decision.TraceID,
		decision.TenantID,
		decision.PolicyBundleVersion,
		decisionJSON,
		decision.EvaluationTimeMs,
		decision.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "Failed to save decision")
	}
	if result.Error != nil {
		return errors.Wrap(result.Error, errors.ErrCodeInternalError, "Failed to save decision")
	}

	return nil
}

func (r *decisionRepository) GetDecisionByTraceID(ctx context.Context, tenantID, traceID string) (*PolicyDecision, error) {
	query := `
		SELECT id, trace_id, tenant_id, policy_bundle_version, decision, evaluation_time_ms, created_at
		FROM policy_decisions 
		WHERE tenant_id = $1 AND trace_id = $2`

	result, err := r.db.Query(ctx, query, tenantID, traceID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to get decision by trace ID")
	}
	if result.Error != nil {
		return nil, errors.Wrap(result.Error, errors.ErrCodeInternalError, "Failed to get decision by trace ID")
	}
	defer result.Rows.Close()

	if !result.Rows.Next() {
		return nil, errors.New(errors.ErrCodeNotFound, "Decision not found")
	}

	var decision PolicyDecision
	var decisionJSON []byte
	var evaluationTimeMs int64

	err = result.Rows.Scan(
		&decision.ID,
		&decision.TraceID,
		&decision.TenantID,
		&decision.PolicyBundleVersion,
		&decisionJSON,
		&evaluationTimeMs,
		&decision.CreatedAt,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to scan decision record")
	}

	if len(decisionJSON) > 0 {
		json.Unmarshal(decisionJSON, &decision.Decision)
	}

	decision.EvaluationTimeMs = evaluationTimeMs

	return &decision, nil
}

func (r *decisionRepository) DeleteDecisionHistory(ctx context.Context, tenantID string, olderThan time.Time) (int64, error) {
	query := `DELETE FROM policy_decisions WHERE tenant_id = $1 AND created_at < $2`

	result, err := r.db.Exec(ctx, query, tenantID, olderThan)
	if err != nil {
		return 0, errors.Wrap(err, errors.ErrCodeInternalError, "Failed to delete decision history")
	}
	if result.Error != nil {
		return 0, errors.Wrap(result.Error, errors.ErrCodeInternalError, "Failed to delete decision history")
	}

	return result.RowsAffected, nil
}
