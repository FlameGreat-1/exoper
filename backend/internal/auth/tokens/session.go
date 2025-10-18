package tokens

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
)

type SessionManager struct {
	config *config.Config
	db     *database.Database
	logger *zap.Logger
}

type Session struct {
	ID           string                 `db:"id"`
	Token        string                 `db:"token"`
	UserID       uuid.UUID              `db:"user_id"`
	TenantID     uuid.UUID              `db:"tenant_id"`
	CreatedAt    time.Time              `db:"created_at"`
	LastActivity time.Time              `db:"last_activity"`
	ExpiresAt    time.Time              `db:"expires_at"`
	IPAddress    string                 `db:"ip_address"`
	UserAgent    string                 `db:"user_agent"`
	IsActive     bool                   `db:"is_active"`
	RevokedAt    *time.Time             `db:"revoked_at"`
	RevokedBy    *uuid.UUID             `db:"revoked_by"`
	Metadata     map[string]interface{} `db:"metadata"`
}

type SessionRequest struct {
	UserID     uuid.UUID
	TenantID   uuid.UUID
	Duration   time.Duration
	IPAddress  string
	UserAgent  string
	RequireMFA bool
	Attributes map[string]interface{}
}

func NewSessionManager(cfg *config.Config, db *database.Database, logger *zap.Logger) *SessionManager {
	return &SessionManager{
		config: cfg,
		db:     db,
		logger: logger,
	}
}

func (sm *SessionManager) CreateSession(ctx context.Context, req *SessionRequest) (*Session, error) {
	if err := sm.validateSessionRequest(req); err != nil {
		return nil, err
	}

	sessionID := sm.generateSessionID()
	sessionToken := sm.generateSessionToken()
	now := time.Now().UTC()
	expiresAt := now.Add(req.Duration)

	session := &Session{
		ID:           sessionID,
		Token:        sessionToken,
		UserID:       req.UserID,
		TenantID:     req.TenantID,
		CreatedAt:    now,
		LastActivity: now,
		ExpiresAt:    expiresAt,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		IsActive:     true,
		Metadata:     req.Attributes,
	}

	if err := sm.storeSession(ctx, session); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to create session")
	}

	sm.logger.Info("Session created",
		zap.String("session_id", sessionID),
		zap.String("user_id", req.UserID.String()),
		zap.String("tenant_id", req.TenantID.String()))

	return session, nil
}

func (sm *SessionManager) ValidateSession(ctx context.Context, sessionID, sessionToken string) (*Session, error) {
	session, err := sm.getSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if !session.IsActive {
		return nil, errors.New(errors.ErrCodeUnauthorized, "session is inactive")
	}

	if session.RevokedAt != nil {
		return nil, errors.New(errors.ErrCodeUnauthorized, "session has been revoked")
	}

	if session.ExpiresAt.Before(time.Now().UTC()) {
		return nil, errors.New(errors.ErrCodeUnauthorized, "session has expired")
	}

	if session.Token != sessionToken {
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid session token")
	}

	sm.updateLastActivity(ctx, sessionID)

	return session, nil
}

func (sm *SessionManager) validateSessionRequest(req *SessionRequest) error {
	if req.UserID == uuid.Nil {
		return errors.New(errors.ErrCodeInvalidRequest, "user ID is required")
	}

	if req.TenantID == uuid.Nil {
		return errors.New(errors.ErrCodeInvalidRequest, "tenant ID is required")
	}

	if req.Duration <= 0 {
		return errors.New(errors.ErrCodeInvalidRequest, "session duration must be positive")
	}

	if req.Duration > 24*time.Hour {
		return errors.New(errors.ErrCodeInvalidRequest, "session duration cannot exceed 24 hours")
	}

	return nil
}

func (sm *SessionManager) generateSessionID() string {
	return uuid.New().String()
}

func (sm *SessionManager) generateSessionToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (sm *SessionManager) storeSession(ctx context.Context, session *Session) error {
	query := `
		INSERT INTO sessions (
			id, token, user_id, tenant_id, created_at, last_activity,
			expires_at, ip_address, user_agent, is_active, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := sm.db.Exec(ctx, query,
		session.ID,
		session.Token,
		session.UserID,
		session.TenantID,
		session.CreatedAt,
		session.LastActivity,
		session.ExpiresAt,
		session.IPAddress,
		session.UserAgent,
		session.IsActive,
		session.Metadata,
	)

	return err
}

func (sm *SessionManager) getSession(ctx context.Context, sessionID string) (*Session, error) {
	query := `
		SELECT id, token, user_id, tenant_id, created_at, last_activity,
		       expires_at, ip_address, user_agent, is_active, revoked_at,
		       revoked_by, metadata
		FROM sessions 
		WHERE id = $1`

	var session Session
	err := sm.db.Get(ctx, &session, query, sessionID)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, errors.New(errors.ErrCodeNotFound, "session not found")
		}
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to retrieve session")
	}

	return &session, nil
}

func (sm *SessionManager) updateLastActivity(ctx context.Context, sessionID string) {
	query := `UPDATE sessions SET last_activity = $1 WHERE id = $2`
	_, err := sm.db.Exec(ctx, query, time.Now().UTC(), sessionID)
	if err != nil {
		sm.logger.Warn("Failed to update session last activity", zap.Error(err))
	}
}

func (sm *SessionManager) ExtendSession(ctx context.Context, sessionID string, duration time.Duration) error {
	if duration <= 0 {
		return errors.New(errors.ErrCodeInvalidRequest, "extension duration must be positive")
	}

	if duration > 24*time.Hour {
		return errors.New(errors.ErrCodeInvalidRequest, "extension duration cannot exceed 24 hours")
	}

	newExpiresAt := time.Now().UTC().Add(duration)
	query := `UPDATE sessions SET expires_at = $1, last_activity = $2 WHERE id = $3 AND is_active = true`

	result, err := sm.db.Exec(ctx, query, newExpiresAt, time.Now().UTC(), sessionID)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to extend session")
	}

	if result.RowsAffected == 0 {
		return errors.New(errors.ErrCodeNotFound, "session not found or inactive")
	}

	sm.logger.Info("Session extended",
		zap.String("session_id", sessionID),
		zap.Duration("duration", duration))

	return nil
}

func (sm *SessionManager) RevokeSession(ctx context.Context, sessionID, revokedBy, reason string) error {
	now := time.Now().UTC()
	revokedByUUID, err := uuid.Parse(revokedBy)
	if err != nil {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid revoked_by user ID")
	}

	query := `
		UPDATE sessions 
		SET is_active = false, revoked_at = $1, revoked_by = $2 
		WHERE id = $3 AND is_active = true`

	result, err := sm.db.Exec(ctx, query, now, revokedByUUID, sessionID)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to revoke session")
	}

	if result.RowsAffected == 0 {
		return errors.New(errors.ErrCodeNotFound, "session not found or already revoked")
	}

	sm.logger.Info("Session revoked",
		zap.String("session_id", sessionID),
		zap.String("reason", reason),
		zap.String("revoked_by", revokedBy))

	return nil
}

func (sm *SessionManager) RevokeAllUserSessions(ctx context.Context, userID, revokedBy, reason string) error {
	now := time.Now().UTC()
	revokedByUUID, err := uuid.Parse(revokedBy)
	if err != nil {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid revoked_by user ID")
	}

	query := `
		UPDATE sessions 
		SET is_active = false, revoked_at = $1, revoked_by = $2 
		WHERE user_id = $3 AND is_active = true`

	result, err := sm.db.Exec(ctx, query, now, revokedByUUID, userID)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to revoke user sessions")
	}

	sm.logger.Info("All user sessions revoked",
		zap.String("user_id", userID),
		zap.String("reason", reason),
		zap.Int64("sessions_revoked", result.RowsAffected))

	return nil
}

func (sm *SessionManager) ListUserSessions(ctx context.Context, userID string, includeExpired bool) ([]*Session, error) {
	query := `
		SELECT id, token, user_id, tenant_id, created_at, last_activity,
		       expires_at, ip_address, user_agent, is_active, revoked_at,
		       revoked_by, metadata
		FROM sessions 
		WHERE user_id = $1`

	if !includeExpired {
		query += ` AND expires_at > $2`
	}

	query += ` ORDER BY created_at DESC`

	var sessions []*Session
	var err error

	if !includeExpired {
		err = sm.db.Select(ctx, &sessions, query, userID, time.Now().UTC())
	} else {
		err = sm.db.Select(ctx, &sessions, query, userID)
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to list user sessions")
	}

	return sessions, nil
}

func (sm *SessionManager) CleanupExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < $1`
	result, err := sm.db.Exec(ctx, query, time.Now().UTC())
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to cleanup expired sessions")
	}

	sm.logger.Info("Expired sessions cleaned up", zap.Int64("count", result.RowsAffected))
	return nil
}
