package providers

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/database"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
	authpb "flamo/backend/pkg/api/proto/auth"
)

type BasicProvider struct {
	config *config.Config
	db     *database.Database
	logger *zap.Logger
}

type UserData struct {
	ID             uuid.UUID  `db:"id"`
	TenantID       uuid.UUID  `db:"tenant_id"`
	Username       string     `db:"username"`
	Email          string     `db:"email"`
	PasswordHash   string     `db:"password_hash"`
	IsActive       bool       `db:"is_active"`
	MFAEnabled     bool       `db:"mfa_enabled"`
	LastLogin      *time.Time `db:"last_login"`
	FailedAttempts int        `db:"failed_attempts"`
	LockedUntil    *time.Time `db:"locked_until"`
	CreatedAt      time.Time  `db:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"`
}

func NewBasicProvider(cfg *config.Config, db *database.Database, logger *zap.Logger) *BasicProvider {
	return &BasicProvider{
		config: cfg,
		db:     db,
		logger: logger,
	}
}

func (p *BasicProvider) Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResult, error) {
	credentials, ok := req.Credentials.(*authpb.BasicCredentials)
	if !ok {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "invalid basic credentials")
	}

	if credentials.Username == "" || credentials.Password == "" {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "username and password are required")
	}

	userData, err := p.getUserByUsername(ctx, credentials.Username, req.TenantID)
	if err != nil {
		return nil, err
	}

	if err := p.validateUserStatus(userData); err != nil {
		return nil, err
	}

	if !p.verifyPassword(credentials.Password, userData.PasswordHash) {
		p.recordFailedAttempt(ctx, userData.ID)
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid username or password")
	}

	if req.RequireMFA && userData.MFAEnabled {
		return nil, errors.New(errors.ErrCodeAuthenticationError, "MFA verification required")
	}

	p.resetFailedAttempts(ctx, userData.ID)
	p.updateLastLogin(ctx, userData.ID)

	principal := p.buildUserPrincipal(userData)
	permissions, err := p.getUserPermissions(ctx, userData.ID)
	if err != nil {
		p.logger.Warn("Failed to get user permissions", zap.Error(err))
		permissions = []string{}
	}

	riskScore := p.calculateUserRiskScore(req, userData)

	return &AuthenticationResult{
		Authenticated: true,
		Principal:     principal,
		Level:         p.getAuthLevel(userData),
		Permissions:   permissions,
		Scopes:        []string{"user"},
		RiskScore:     riskScore,
		RiskFactors:   p.assessUserRiskFactors(req, userData),
		Metadata: map[string]interface{}{
			"user_id":        userData.ID.String(),
			"failed_attempts": userData.FailedAttempts,
			"last_login":     userData.LastLogin,
		},
	}, nil
}

func (p *BasicProvider) ValidateCredentials(ctx context.Context, credentials interface{}) (*ValidationResult, error) {
	basicCreds, ok := credentials.(*authpb.BasicCredentials)
	if !ok {
		return &ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Code:     "invalid_credentials_type",
				Message:  "credentials must be basic credentials",
				Severity: errors.SeverityHigh,
			}},
		}, nil
	}

	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []string{},
		Metadata: make(map[string]interface{}),
	}

	if basicCreds.Username == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "missing_username",
			Message:  "username is required",
			Field:    "username",
			Severity: errors.SeverityHigh,
		})
	}

	if basicCreds.Password == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "missing_password",
			Message:  "password is required",
			Field:    "password",
			Severity: errors.SeverityHigh,
		})
	}

	if basicCreds.Password != "" {
		passwordValidation := utils.ValidatePassword(basicCreds.Password, 8, true)
		if !passwordValidation.Valid {
			for _, err := range passwordValidation.Errors {
				result.Errors = append(result.Errors, ValidationError{
					Code:     "weak_password",
					Message:  err,
					Field:    "password",
					Severity: errors.SeverityMedium,
				})
			}
		}
	}

	return result, nil
}

func (p *BasicProvider) GetSupportedMethods() []AuthenticationMethod {
	return []AuthenticationMethod{MethodBasic}
}

func (p *BasicProvider) GetAuthenticationLevel() AuthenticationLevel {
	return LevelBasic
}

func (p *BasicProvider) IsEnabled() bool {
	return true
}

func (p *BasicProvider) getUserByUsername(ctx context.Context, username string, tenantID uuid.UUID) (*UserData, error) {
	query := `
		SELECT id, tenant_id, username, email, password_hash, is_active, 
		       mfa_enabled, last_login, failed_attempts, locked_until, 
		       created_at, updated_at
		FROM users 
		WHERE (username = $1 OR email = $1) AND tenant_id = $2`

	var userData UserData
	err := p.db.Get(ctx, &userData, query, username, tenantID)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, errors.New(errors.ErrCodeUnauthorized, "invalid username or password")
		}
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to retrieve user")
	}

	return &userData, nil
}

func (p *BasicProvider) validateUserStatus(userData *UserData) error {
	if !userData.IsActive {
		return errors.New(errors.ErrCodeUnauthorized, "user account is inactive")
	}

	if userData.LockedUntil != nil && userData.LockedUntil.After(time.Now().UTC()) {
		return errors.New(errors.ErrCodeUnauthorized, "user account is locked")
	}

	return nil
}

func (p *BasicProvider) verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (p *BasicProvider) buildUserPrincipal(userData *UserData) *Principal {
	return &Principal{
		ID:         userData.ID.String(),
		Type:       "user",
		Name:       userData.Username,
		Email:      userData.Email,
		TenantID:   userData.TenantID.String(),
		Roles:      []string{"user"},
		Groups:     []string{},
		Attributes: map[string]interface{}{
			"username": userData.Username,
		},
		CreatedAt:  userData.CreatedAt,
		LastLogin:  userData.LastLogin,
		IsActive:   userData.IsActive,
		MFAEnabled: userData.MFAEnabled,
	}
}

func (p *BasicProvider) getUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	query := `
		SELECT DISTINCT p.name 
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1`

	var permissions []string
	err := p.db.Select(ctx, &permissions, query, userID)
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (p *BasicProvider) calculateUserRiskScore(req *AuthenticationRequest, userData *UserData) float64 {
	score := 0.0

	if userData.FailedAttempts > 0 {
		score += float64(userData.FailedAttempts) * 0.1
	}

	if userData.LastLogin == nil {
		score += 0.2
	} else {
		daysSinceLastLogin := time.Since(*userData.LastLogin).Hours() / 24
		if daysSinceLastLogin > 30 {
			score += 0.3
		}
	}

	if !userData.MFAEnabled {
		score += 0.2
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (p *BasicProvider) assessUserRiskFactors(req *AuthenticationRequest, userData *UserData) []string {
	factors := []string{}

	if userData.FailedAttempts > 0 {
		factors = append(factors, "previous_failed_attempts")
	}

	if userData.LastLogin == nil {
		factors = append(factors, "first_time_login")
	}

	if !userData.MFAEnabled {
		factors = append(factors, "mfa_not_enabled")
	}

	return factors
}

func (p *BasicProvider) getAuthLevel(userData *UserData) AuthenticationLevel {
	if userData.MFAEnabled {
		return LevelMultiFactor
	}
	return LevelBasic
}

func (p *BasicProvider) recordFailedAttempt(ctx context.Context, userID uuid.UUID) {
	query := `UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = $1`
	p.db.Exec(ctx, query, userID)
}

func (p *BasicProvider) resetFailedAttempts(ctx context.Context, userID uuid.UUID) {
	query := `UPDATE users SET failed_attempts = 0 WHERE id = $1`
	p.db.Exec(ctx, query, userID)
}

func (p *BasicProvider) updateLastLogin(ctx context.Context, userID uuid.UUID) {
	query := `UPDATE users SET last_login = $1 WHERE id = $2`
	p.db.Exec(ctx, query, time.Now().UTC(), userID)
}
