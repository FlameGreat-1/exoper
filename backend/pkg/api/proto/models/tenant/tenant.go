package tenant

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TenantStatus string
type TenantTier string
type ComplianceFramework string
type DataResidency string
type EncryptionLevel string

const (
	StatusActive    TenantStatus = "active"
	StatusSuspended TenantStatus = "suspended"
	StatusPending   TenantStatus = "pending"
	StatusTerminated TenantStatus = "terminated"

	TierEnterprise TenantTier = "enterprise"
	TierBusiness   TenantTier = "business"
	TierStarter    TenantTier = "starter"

	ComplianceGDPR     ComplianceFramework = "gdpr"
	ComplianceHIPAA    ComplianceFramework = "hipaa"
	ComplianceSOC2     ComplianceFramework = "soc2"
	ComplianceISO27001 ComplianceFramework = "iso27001"
	ComplianceFedRAMP  ComplianceFramework = "fedramp"

	ResidencyUS     DataResidency = "us"
	ResidencyEU     DataResidency = "eu"
	ResidencyAPAC   DataResidency = "apac"
	ResidencyCanada DataResidency = "canada"

	EncryptionAES256    EncryptionLevel = "aes256"
	EncryptionAES256GCM EncryptionLevel = "aes256gcm"
	EncryptionChaCha20  EncryptionLevel = "chacha20"
)

type Tenant struct {
	ID                uuid.UUID                `json:"id" db:"id"`
	Name              string                   `json:"name" db:"name"`
	Slug              string                   `json:"slug" db:"slug"`
	Status            TenantStatus             `json:"status" db:"status"`
	Tier              TenantTier               `json:"tier" db:"tier"`
	OrganizationID    string                   `json:"organization_id" db:"organization_id"`
	ParentTenantID    *uuid.UUID               `json:"parent_tenant_id,omitempty" db:"parent_tenant_id"`
	ComplianceConfig  ComplianceConfiguration  `json:"compliance_config" db:"compliance_config"`
	SecurityConfig    SecurityConfiguration    `json:"security_config" db:"security_config"`
	ResourceLimits    ResourceLimits           `json:"resource_limits" db:"resource_limits"`
	BillingConfig     BillingConfiguration     `json:"billing_config" db:"billing_config"`
	NetworkConfig     NetworkConfiguration     `json:"network_config" db:"network_config"`
	AuditConfig       AuditConfiguration       `json:"audit_config" db:"audit_config"`
	APIKeys           []APIKey                 `json:"api_keys,omitempty" db:"-"`
	Metadata          map[string]interface{}   `json:"metadata" db:"metadata"`
	CreatedAt         time.Time                `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time                `json:"updated_at" db:"updated_at"`
	CreatedBy         uuid.UUID                `json:"created_by" db:"created_by"`
	UpdatedBy         uuid.UUID                `json:"updated_by" db:"updated_by"`
	Version           int64                    `json:"version" db:"version"`
}

type ComplianceConfiguration struct {
	Frameworks          []ComplianceFramework `json:"frameworks"`
	DataResidency       DataResidency         `json:"data_residency"`
	DataRetentionDays   int                   `json:"data_retention_days"`
	PIIRedactionEnabled bool                  `json:"pii_redaction_enabled"`
	AuditLogRetention   int                   `json:"audit_log_retention"`
	ComplianceContact   ContactInfo           `json:"compliance_contact"`
	CertificationLevel  string                `json:"certification_level"`
	RegulatoryReporting bool                  `json:"regulatory_reporting"`
}

type SecurityConfiguration struct {
	EncryptionLevel        EncryptionLevel `json:"encryption_level"`
	MTLSRequired          bool            `json:"mtls_required"`
	IPWhitelist           []string        `json:"ip_whitelist"`
	AllowedDomains        []string        `json:"allowed_domains"`
	SessionTimeout        time.Duration   `json:"session_timeout"`
	MFARequired           bool            `json:"mfa_required"`
	PasswordPolicy        PasswordPolicy  `json:"password_policy"`
	ThreatDetectionLevel  string          `json:"threat_detection_level"`
	SecurityContact       ContactInfo     `json:"security_contact"`
	IncidentResponsePlan  string          `json:"incident_response_plan"`
}

type ResourceLimits struct {
	MaxUsers              int     `json:"max_users"`
	MaxAPICallsPerMinute  int     `json:"max_api_calls_per_minute"`
	MaxAPICallsPerDay     int     `json:"max_api_calls_per_day"`
	MaxStorageGB          int     `json:"max_storage_gb"`
	MaxModelsPerTenant    int     `json:"max_models_per_tenant"`
	MaxConcurrentRequests int     `json:"max_concurrent_requests"`
	BandwidthLimitMbps    float64 `json:"bandwidth_limit_mbps"`
	ComputeUnitsLimit     int     `json:"compute_units_limit"`
}

type BillingConfiguration struct {
	BillingModel       string    `json:"billing_model"`
	Currency           string    `json:"currency"`
	BillingCycle       string    `json:"billing_cycle"`
	PaymentMethodID    string    `json:"payment_method_id"`
	BillingContact     ContactInfo `json:"billing_contact"`
	TaxID              string    `json:"tax_id"`
	InvoiceDelivery    string    `json:"invoice_delivery"`
	AutoPayEnabled     bool      `json:"auto_pay_enabled"`
	CreditLimit        float64   `json:"credit_limit"`
	UsageAlertsEnabled bool      `json:"usage_alerts_enabled"`
}

type NetworkConfiguration struct {
	AllowedCIDRs        []string `json:"allowed_cidrs"`
	VPCEndpointEnabled  bool     `json:"vpc_endpoint_enabled"`
	PrivateLinkEnabled  bool     `json:"private_link_enabled"`
	CDNEnabled          bool     `json:"cdn_enabled"`
	LoadBalancerConfig  string   `json:"load_balancer_config"`
	DNSConfiguration    string   `json:"dns_configuration"`
	FirewallRules       []string `json:"firewall_rules"`
}

type AuditConfiguration struct {
	LogLevel              string        `json:"log_level"`
	RetentionPeriodDays   int           `json:"retention_period_days"`
	ExternalSIEMEnabled   bool          `json:"external_siem_enabled"`
	SIEMEndpoint          string        `json:"siem_endpoint"`
	RealTimeAlertsEnabled bool          `json:"real_time_alerts_enabled"`
	ComplianceReporting   bool          `json:"compliance_reporting"`
	LogEncryptionEnabled  bool          `json:"log_encryption_enabled"`
	ImmutableLogsEnabled  bool          `json:"immutable_logs_enabled"`
}

type ContactInfo struct {
	Name         string `json:"name"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Department   string `json:"department"`
	Organization string `json:"organization"`
}

type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSymbols   bool `json:"require_symbols"`
	MaxAge           int  `json:"max_age"`
	HistoryCount     int  `json:"history_count"`
}

type APIKey struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	KeyHash     string    `json:"-" db:"key_hash"`
	Prefix      string    `json:"prefix" db:"prefix"`
	Permissions []string  `json:"permissions" db:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	CreatedBy   uuid.UUID `json:"created_by" db:"created_by"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedBy   *uuid.UUID `json:"revoked_by,omitempty" db:"revoked_by"`
}

var (
	slugRegex = regexp.MustCompile(`^[a-z0-9-]+$`)
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

func NewTenant(name, organizationID string, tier TenantTier, createdBy uuid.UUID) (*Tenant, error) {
	if err := validateTenantName(name); err != nil {
		return nil, fmt.Errorf("invalid tenant name: %w", err)
	}

	if organizationID == "" {
		return nil, fmt.Errorf("organization ID is required")
	}

	slug := generateSlug(name)
	if err := validateSlug(slug); err != nil {
		return nil, fmt.Errorf("invalid tenant slug: %w", err)
	}

	tenant := &Tenant{
		ID:             uuid.New(),
		Name:           strings.TrimSpace(name),
		Slug:           slug,
		Status:         StatusPending,
		Tier:           tier,
		OrganizationID: organizationID,
		ComplianceConfig: ComplianceConfiguration{
			Frameworks:          []ComplianceFramework{ComplianceSOC2},
			DataResidency:       ResidencyUS,
			DataRetentionDays:   2555,
			PIIRedactionEnabled: true,
			AuditLogRetention:   2555,
			RegulatoryReporting: false,
		},
		SecurityConfig: SecurityConfiguration{
			EncryptionLevel:      EncryptionAES256GCM,
			MTLSRequired:         true,
			SessionTimeout:       time.Hour * 8,
			MFARequired:          true,
			ThreatDetectionLevel: "high",
			PasswordPolicy: PasswordPolicy{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSymbols:   true,
				MaxAge:           90,
				HistoryCount:     12,
			},
		},
		ResourceLimits:    getDefaultResourceLimits(tier),
		BillingConfig:     getDefaultBillingConfig(),
		NetworkConfig:     getDefaultNetworkConfig(),
		AuditConfig:       getDefaultAuditConfig(),
		Metadata:          make(map[string]interface{}),
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
		CreatedBy:         createdBy,
		UpdatedBy:         createdBy,
		Version:           1,
	}

	return tenant, nil
}

func (t *Tenant) Validate() error {
	if t.ID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}

	if err := validateTenantName(t.Name); err != nil {
		return fmt.Errorf("invalid tenant name: %w", err)
	}

	if err := validateSlug(t.Slug); err != nil {
		return fmt.Errorf("invalid tenant slug: %w", err)
	}

	if !isValidStatus(t.Status) {
		return fmt.Errorf("invalid tenant status: %s", t.Status)
	}

	if !isValidTier(t.Tier) {
		return fmt.Errorf("invalid tenant tier: %s", t.Tier)
	}

	if t.OrganizationID == "" {
		return fmt.Errorf("organization ID is required")
	}

	if err := t.ComplianceConfig.Validate(); err != nil {
		return fmt.Errorf("invalid compliance configuration: %w", err)
	}

	if err := t.SecurityConfig.Validate(); err != nil {
		return fmt.Errorf("invalid security configuration: %w", err)
	}

	if err := t.ResourceLimits.Validate(); err != nil {
		return fmt.Errorf("invalid resource limits: %w", err)
	}

	if err := t.BillingConfig.Validate(); err != nil {
		return fmt.Errorf("invalid billing configuration: %w", err)
	}

	return nil
}

func (t *Tenant) IsActive() bool {
	return t.Status == StatusActive
}

func (t *Tenant) CanAccess() bool {
	return t.Status == StatusActive || t.Status == StatusPending
}

func (t *Tenant) Activate() error {
	if t.Status == StatusTerminated {
		return fmt.Errorf("cannot activate terminated tenant")
	}
	t.Status = StatusActive
	t.UpdatedAt = time.Now().UTC()
	t.Version++
	return nil
}

func (t *Tenant) Suspend() error {
	if t.Status == StatusTerminated {
		return fmt.Errorf("cannot suspend terminated tenant")
	}
	t.Status = StatusSuspended
	t.UpdatedAt = time.Now().UTC()
	t.Version++
	return nil
}

func (t *Tenant) Terminate() error {
	t.Status = StatusTerminated
	t.UpdatedAt = time.Now().UTC()
	t.Version++
	return nil
}

func (t *Tenant) UpdateSecurityConfig(config SecurityConfiguration, updatedBy uuid.UUID) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid security configuration: %w", err)
	}
	t.SecurityConfig = config
	t.UpdatedAt = time.Now().UTC()
	t.UpdatedBy = updatedBy
	t.Version++
	return nil
}

func (t *Tenant) AddComplianceFramework(framework ComplianceFramework) {
	for _, existing := range t.ComplianceConfig.Frameworks {
		if existing == framework {
			return
		}
	}
	t.ComplianceConfig.Frameworks = append(t.ComplianceConfig.Frameworks, framework)
	t.UpdatedAt = time.Now().UTC()
	t.Version++
}

func (t *Tenant) GenerateAPIKey(name string, permissions []string, expiresAt *time.Time, createdBy uuid.UUID) (*APIKey, string, error) {
	if name == "" {
		return nil, "", fmt.Errorf("API key name is required")
	}

	if len(permissions) == 0 {
		return nil, "", fmt.Errorf("API key permissions are required")
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate API key: %w", err)
	}

	keyString := hex.EncodeToString(keyBytes)
	prefix := fmt.Sprintf("exo_%s_%s", t.Slug, keyString[:8])
	fullKey := fmt.Sprintf("%s_%s", prefix, keyString[8:])

	keyHash, err := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash API key: %w", err)
	}

	apiKey := &APIKey{
		ID:          uuid.New(),
		TenantID:    t.ID,
		Name:        name,
		KeyHash:     string(keyHash),
		Prefix:      prefix,
		Permissions: permissions,
		ExpiresAt:   expiresAt,
		IsActive:    true,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   createdBy,
	}

	return apiKey, fullKey, nil
}

func (cc *ComplianceConfiguration) Validate() error {
	if len(cc.Frameworks) == 0 {
		return fmt.Errorf("at least one compliance framework is required")
	}

	for _, framework := range cc.Frameworks {
		if !isValidComplianceFramework(framework) {
			return fmt.Errorf("invalid compliance framework: %s", framework)
		}
	}

	if !isValidDataResidency(cc.DataResidency) {
		return fmt.Errorf("invalid data residency: %s", cc.DataResidency)
	}

	if cc.DataRetentionDays < 1 || cc.DataRetentionDays > 3650 {
		return fmt.Errorf("data retention days must be between 1 and 3650")
	}

	if cc.ComplianceContact.Email != "" && !emailRegex.MatchString(cc.ComplianceContact.Email) {
		return fmt.Errorf("invalid compliance contact email")
	}

	return nil
}

func (sc *SecurityConfiguration) Validate() error {
	if !isValidEncryptionLevel(sc.EncryptionLevel) {
		return fmt.Errorf("invalid encryption level: %s", sc.EncryptionLevel)
	}

	for _, ip := range sc.IPWhitelist {
		if _, _, err := net.ParseCIDR(ip); err != nil {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid IP address or CIDR: %s", ip)
			}
		}
	}

	if sc.SessionTimeout < time.Minute*5 || sc.SessionTimeout > time.Hour*24 {
		return fmt.Errorf("session timeout must be between 5 minutes and 24 hours")
	}

	if err := sc.PasswordPolicy.Validate(); err != nil {
		return fmt.Errorf("invalid password policy: %w", err)
	}

	if sc.SecurityContact.Email != "" && !emailRegex.MatchString(sc.SecurityContact.Email) {
		return fmt.Errorf("invalid security contact email")
	}

	return nil
}

func (rl *ResourceLimits) Validate() error {
	if rl.MaxUsers < 1 || rl.MaxUsers > 1000000 {
		return fmt.Errorf("max users must be between 1 and 1,000,000")
	}

	if rl.MaxAPICallsPerMinute < 1 || rl.MaxAPICallsPerMinute > 100000 {
		return fmt.Errorf("max API calls per minute must be between 1 and 100,000")
	}

	if rl.MaxStorageGB < 1 || rl.MaxStorageGB > 100000 {
		return fmt.Errorf("max storage must be between 1GB and 100TB")
	}

	return nil
}

func (bc *BillingConfiguration) Validate() error {
	if bc.Currency == "" {
		return fmt.Errorf("currency is required")
	}

	if bc.BillingContact.Email != "" && !emailRegex.MatchString(bc.BillingContact.Email) {
		return fmt.Errorf("invalid billing contact email")
	}

	return nil
}

func (pp *PasswordPolicy) Validate() error {
	if pp.MinLength < 8 || pp.MinLength > 128 {
		return fmt.Errorf("password minimum length must be between 8 and 128")
	}

	if pp.MaxAge < 30 || pp.MaxAge > 365 {
		return fmt.Errorf("password max age must be between 30 and 365 days")
	}

	return nil
}

func validateTenantName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("tenant name is required")
	}
	if len(name) < 2 || len(name) > 100 {
		return fmt.Errorf("tenant name must be between 2 and 100 characters")
	}
	return nil
}

func validateSlug(slug string) error {
	if slug == "" {
		return fmt.Errorf("slug is required")
	}
	if len(slug) < 2 || len(slug) > 50 {
		return fmt.Errorf("slug must be between 2 and 50 characters")
	}
	if !slugRegex.MatchString(slug) {
		return fmt.Errorf("slug must contain only lowercase letters, numbers, and hyphens")
	}
	return nil
}

func generateSlug(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = regexp.MustCompile(`[^a-z0-9\s-]`).ReplaceAllString(slug, "")
	slug = regexp.MustCompile(`\s+`).ReplaceAllString(slug, "-")
	slug = regexp.MustCompile(`-+`).ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	
	if len(slug) > 50 {
		slug = slug[:50]
	}
	
	return slug
}

func isValidStatus(status TenantStatus) bool {
	return status == StatusActive || status == StatusSuspended || status == StatusPending || status == StatusTerminated
}

func isValidTier(tier TenantTier) bool {
	return tier == TierEnterprise || tier == TierBusiness || tier == TierStarter
}

func isValidComplianceFramework(framework ComplianceFramework) bool {
	return framework == ComplianceGDPR || framework == ComplianceHIPAA || framework == ComplianceSOC2 || framework == ComplianceISO27001 || framework == ComplianceFedRAMP
}

func isValidDataResidency(residency DataResidency) bool {
	return residency == ResidencyUS || residency == ResidencyEU || residency == ResidencyAPAC || residency == ResidencyCanada
}

func isValidEncryptionLevel(level EncryptionLevel) bool {
	return level == EncryptionAES256 || level == EncryptionAES256GCM || level == EncryptionChaCha20
}

func getDefaultResourceLimits(tier TenantTier) ResourceLimits {
	switch tier {
	case TierEnterprise:
		return ResourceLimits{
			MaxUsers:              10000,
			MaxAPICallsPerMinute:  10000,
			MaxAPICallsPerDay:     1000000,
			MaxStorageGB:          10000,
			MaxModelsPerTenant:    100,
			MaxConcurrentRequests: 1000,
			BandwidthLimitMbps:    1000.0,
			ComputeUnitsLimit:     100000,
		}
	case TierBusiness:
		return ResourceLimits{
			MaxUsers:              1000,
			MaxAPICallsPerMinute:  1000,
			MaxAPICallsPerDay:     100000,
			MaxStorageGB:          1000,
			MaxModelsPerTenant:    20,
			MaxConcurrentRequests: 100,
			BandwidthLimitMbps:    100.0,
			ComputeUnitsLimit:     10000,
		}
	default:
		return ResourceLimits{
			MaxUsers:              100,
			MaxAPICallsPerMinute:  100,
			MaxAPICallsPerDay:     10000,
			MaxStorageGB:          100,
			MaxModelsPerTenant:    5,
			MaxConcurrentRequests: 10,
			BandwidthLimitMbps:    10.0,
			ComputeUnitsLimit:     1000,
		}
	}
}

func getDefaultBillingConfig() BillingConfiguration {
	return BillingConfiguration{
		BillingModel:       "usage",
		Currency:           "USD",
		BillingCycle:       "monthly",
		InvoiceDelivery:    "email",
		AutoPayEnabled:     false,
		UsageAlertsEnabled: true,
	}
}

func getDefaultNetworkConfig() NetworkConfiguration {
	return NetworkConfiguration{
		AllowedCIDRs:       []string{"0.0.0.0/0"},
		VPCEndpointEnabled: false,
		PrivateLinkEnabled: false,
		CDNEnabled:         true,
	}
}

func getDefaultAuditConfig() AuditConfiguration {
	return AuditConfiguration{
		LogLevel:              "info",
		RetentionPeriodDays:   2555,
		ExternalSIEMEnabled:   false,
		RealTimeAlertsEnabled: true,
		ComplianceReporting:   true,
		LogEncryptionEnabled:  true,
		ImmutableLogsEnabled:  true,
	}
}
