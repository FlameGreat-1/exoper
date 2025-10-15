package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	phoneRegex    = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	uuidRegex     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	alphaNumRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	slugRegex     = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	
	piiPatterns = map[string]*regexp.Regexp{
		"ssn":         regexp.MustCompile(`\b\d{3}-?\d{2}-?\d{4}\b`),
		"credit_card": regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),
		"email":       emailRegex,
		"phone":       regexp.MustCompile(`\b\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`),
		"ip_address":  regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
	}
)

type ValidationResult struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type PIIDetectionResult struct {
	HasPII   bool              `json:"has_pii"`
	Findings map[string][]int  `json:"findings"`
	Masked   string            `json:"masked,omitempty"`
}

type EncryptionConfig struct {
	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"key_size"`
	IVSize    int    `json:"iv_size"`
}

func IsValidEmail(email string) bool {
	if len(email) > 254 {
		return false
	}
	
	if !emailRegex.MatchString(email) {
		return false
	}
	
	_, err := mail.ParseAddress(email)
	return err == nil
}

func IsValidPhone(phone string) bool {
	cleaned := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(phone, " ", ""), "-", ""), "(", "")
	cleaned = strings.ReplaceAll(strings.ReplaceAll(cleaned, ")", ""), ".", "")
	
	return phoneRegex.MatchString(cleaned)
}

func IsValidUUID(str string) bool {
	return uuidRegex.MatchString(strings.ToLower(str))
}

func IsValidURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsValidIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

func IsValidIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

func IsValidPort(port int) bool {
	return port > 0 && port <= 65535
}

func IsValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return false
			}
		}
	}
	
	return true
}

func IsAlphaNumeric(str string) bool {
	return alphaNumRegex.MatchString(str)
}

func IsValidSlug(slug string) bool {
	return slugRegex.MatchString(slug)
}

func ValidatePassword(password string, minLength int, requireSpecial bool) ValidationResult {
	result := ValidationResult{Valid: true, Errors: []string{}, Warnings: []string{}}
	
	if len(password) < minLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Password must be at least %d characters long", minLength))
	}
	
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	
	if !hasUpper {
		result.Valid = false
		result.Errors = append(result.Errors, "Password must contain at least one uppercase letter")
	}
	
	if !hasLower {
		result.Valid = false
		result.Errors = append(result.Errors, "Password must contain at least one lowercase letter")
	}
	
	if !hasDigit {
		result.Valid = false
		result.Errors = append(result.Errors, "Password must contain at least one digit")
	}
	
	if requireSpecial && !hasSpecial {
		result.Valid = false
		result.Errors = append(result.Errors, "Password must contain at least one special character")
	}
	
	if len(password) < 12 {
		result.Warnings = append(result.Warnings, "Consider using a longer password for better security")
	}
	
	return result
}

func GenerateSecurePassword(length int, includeSpecial bool) string {
	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		special   = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	)
	
	charset := lowercase + uppercase + digits
	if includeSpecial {
		charset += special
	}
	
	password := make([]byte, length)
	for i := range password {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		password[i] = charset[randomIndex.Int64()]
	}
	
	return string(password)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateAPIKey(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	
	key := make([]byte, length)
	for i := range key {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		key[i] = charset[randomIndex.Int64()]
	}
	
	return string(key)
}

func GenerateSecretKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func GenerateHMAC(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func VerifyHMAC(message, signature, secret string) bool {
	expectedSignature := GenerateHMAC(message, secret)
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

func HashSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func HashSHA512(data string) string {
	hash := sha512.Sum512([]byte(data))
	return hex.EncodeToString(hash[:])
}

func HashMD5(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func DeriveKey(password, salt string, iterations, keyLength int) []byte {
	return pbkdf2.Key([]byte(password), []byte(salt), iterations, keyLength, sha256.New)
}

func EncryptAES(plaintext, key string) (string, error) {
	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		keyHash := sha256.Sum256(keyBytes)
		keyBytes = keyHash[:]
	}
	
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	
	plaintextBytes := []byte(plaintext)
	
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	
	stream := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintextBytes))
	stream.XORKeyStream(ciphertext, plaintextBytes)
	
	result := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(result), nil
}

func DecryptAES(ciphertext, key string) (string, error) {
	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		keyHash := sha256.Sum256(keyBytes)
		keyBytes = keyHash[:]
	}
	
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	
	if len(data) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	
	iv := data[:aes.BlockSize]
	cipherData := data[aes.BlockSize:]
	
	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(cipherData))
	stream.XORKeyStream(plaintext, cipherData)
	
	return string(plaintext), nil
}

func DetectPII(text string) PIIDetectionResult {
	result := PIIDetectionResult{
		HasPII:   false,
		Findings: make(map[string][]int),
		Masked:   text,
	}
	
	for piiType, pattern := range piiPatterns {
		matches := pattern.FindAllStringIndex(text, -1)
		if len(matches) > 0 {
			result.HasPII = true
			positions := make([]int, len(matches))
			for i, match := range matches {
				positions[i] = match[0]
			}
			result.Findings[piiType] = positions
		}
	}
	
	return result
}

func MaskPII(text string) string {
	masked := text
	
	for _, pattern := range piiPatterns {
		masked = pattern.ReplaceAllStringFunc(masked, func(match string) string {
			if len(match) <= 4 {
				return strings.Repeat("*", len(match))
			}
			return match[:2] + strings.Repeat("*", len(match)-4) + match[len(match)-2:]
		})
	}
	
	return masked
}

func SanitizeString(input string) string {
	input = strings.TrimSpace(input)
	input = strings.ReplaceAll(input, "\x00", "")
	input = regexp.MustCompile(`[<>\"'&]`).ReplaceAllStringFunc(input, func(s string) string {
		switch s {
		case "<":
			return "<"
		case ">":
			return ">"
		case "\"":
			return "&quot;"
		case "'":
			return "&#39;"
		case "&":
			return "&amp;"
		default:
			return s
		}
	})
	
	return input
}

func TruncateString(str string, maxLength int) string {
	if len(str) <= maxLength {
		return str
	}
	
	if maxLength <= 3 {
		return str[:maxLength]
	}
	
	return str[:maxLength-3] + "..."
}

func GenerateSlug(text string) string {
	text = strings.ToLower(text)
	text = regexp.MustCompile(`[^a-z0-9\s-]`).ReplaceAllString(text, "")
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, "-")
	text = regexp.MustCompile(`-+`).ReplaceAllString(text, "-")
	text = strings.Trim(text, "-")
	
	return text
}

func ToSnakeCase(str string) string {
	var result strings.Builder
	for i, r := range str {
		if unicode.IsUpper(r) && i > 0 {
			result.WriteRune('_')
		}
		result.WriteRune(unicode.ToLower(r))
	}
	return result.String()
}

func ToCamelCase(str string) string {
	words := strings.FieldsFunc(str, func(r rune) bool {
		return r == '_' || r == '-' || unicode.IsSpace(r)
	})
	
	if len(words) == 0 {
		return ""
	}
	
	result := strings.ToLower(words[0])
	for i := 1; i < len(words); i++ {
		result += strings.Title(strings.ToLower(words[i]))
	}
	
	return result
}

func ToPascalCase(str string) string {
	camel := ToCamelCase(str)
	if len(camel) == 0 {
		return ""
	}
	return strings.ToUpper(camel[:1]) + camel[1:]
}

import (
	"context"
	"crypto/big"
	"encoding/xml"
	"math"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type RetryConfig struct {
	MaxAttempts   int           `json:"max_attempts"`
	BaseDelay     time.Duration `json:"base_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
	Jitter        bool          `json:"jitter"`
}

type CircuitBreakerConfig struct {
	MaxRequests         uint32        `json:"max_requests"`
	Interval            time.Duration `json:"interval"`
	Timeout             time.Duration `json:"timeout"`
	FailureThreshold    float64       `json:"failure_threshold"`
	SuccessThreshold    uint32        `json:"success_threshold"`
}

type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateHalfOpen
	StateOpen
)

type CircuitBreaker struct {
	config       CircuitBreakerConfig
	state        CircuitBreakerState
	failures     uint32
	successes    uint32
	requests     uint32
	lastFailTime time.Time
	mu           sync.RWMutex
}

type RateLimiter struct {
	rate     float64
	capacity int64
	tokens   int64
	lastTime time.Time
	mu       sync.Mutex
}

type HTTPClient struct {
	client        *http.Client
	retryConfig   RetryConfig
	circuitBreaker *CircuitBreaker
	rateLimiter   *RateLimiter
}

func ParseTime(timeStr string, layouts ...string) (time.Time, error) {
	defaultLayouts := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"15:04:05",
		"2006/01/02",
		"01/02/2006",
		"02-01-2006",
	}
	
	allLayouts := append(layouts, defaultLayouts...)
	
	for _, layout := range allLayouts {
		if t, err := time.Parse(layout, timeStr); err == nil {
			return t, nil
		}
	}
	
	return time.Time{}, fmt.Errorf("unable to parse time: %s", timeStr)
}

func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

func GetTimeRange(period string) (TimeRange, error) {
	now := time.Now().UTC()
	
	switch strings.ToLower(period) {
	case "hour", "1h":
		return TimeRange{Start: now.Add(-time.Hour), End: now}, nil
	case "day", "24h", "1d":
		return TimeRange{Start: now.Add(-24 * time.Hour), End: now}, nil
	case "week", "7d", "1w":
		return TimeRange{Start: now.Add(-7 * 24 * time.Hour), End: now}, nil
	case "month", "30d", "1m":
		return TimeRange{Start: now.Add(-30 * 24 * time.Hour), End: now}, nil
	case "year", "365d", "1y":
		return TimeRange{Start: now.Add(-365 * 24 * time.Hour), End: now}, nil
	default:
		if duration, err := time.ParseDuration(period); err == nil {
			return TimeRange{Start: now.Add(-duration), End: now}, nil
		}
		return TimeRange{}, fmt.Errorf("invalid time period: %s", period)
	}
}

func IsBusinessHours(t time.Time, timezone string) bool {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}
	
	localTime := t.In(loc)
	weekday := localTime.Weekday()
	hour := localTime.Hour()
	
	return weekday >= time.Monday && weekday <= time.Friday && hour >= 9 && hour < 17
}

func GetNextBusinessDay(t time.Time, timezone string) time.Time {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}
	
	localTime := t.In(loc)
	
	for {
		localTime = localTime.Add(24 * time.Hour)
		if localTime.Weekday() >= time.Monday && localTime.Weekday() <= time.Friday {
			return localTime
		}
	}
}

func ToJSON(v interface{}) (string, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func ToJSONIndent(v interface{}) (string, error) {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func FromJSON(jsonStr string, v interface{}) error {
	return json.Unmarshal([]byte(jsonStr), v)
}

func ToXML(v interface{}) (string, error) {
	bytes, err := xml.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func FromXML(xmlStr string, v interface{}) error {
	return xml.Unmarshal([]byte(xmlStr), v)
}

func IsValidJSON(jsonStr string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(jsonStr), &js) == nil
}

func IsValidXML(xmlStr string) bool {
	var x interface{}
	return xml.Unmarshal([]byte(xmlStr), &x) == nil
}

func ExtractJSONField(jsonStr, fieldPath string) (interface{}, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil, err
	}
	
	fields := strings.Split(fieldPath, ".")
	current := data
	
	for i, field := range fields {
		if i == len(fields)-1 {
			return current[field], nil
		}
		
		if next, ok := current[field].(map[string]interface{}); ok {
			current = next
		} else {
			return nil, fmt.Errorf("field not found: %s", fieldPath)
		}
	}
	
	return nil, fmt.Errorf("field not found: %s", fieldPath)
}

func GetClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	
	return ip
}

func GetUserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

func SetSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

func SetCORSHeaders(w http.ResponseWriter, allowedOrigins []string, allowedMethods []string, allowedHeaders []string) {
	if len(allowedOrigins) > 0 {
		w.Header().Set("Access-Control-Allow-Origin", strings.Join(allowedOrigins, ","))
	}
	if len(allowedMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ","))
	}
	if len(allowedHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ","))
	}
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "86400")
}

func WriteJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(data)
}

func WriteErrorResponse(w http.ResponseWriter, statusCode int, message string) error {
	errorResponse := map[string]interface{}{
		"error":     true,
		"message":   message,
		"timestamp": time.Now().UTC(),
	}
	return WriteJSONResponse(w, statusCode, errorResponse)
}

func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config: config,
		state:  StateClosed,
	}
}

func (cb *CircuitBreaker) Execute(fn func() error) error {
	if !cb.allowRequest() {
		return fmt.Errorf("circuit breaker is open")
	}
	
	err := fn()
	cb.recordResult(err == nil)
	return err
}

func (cb *CircuitBreaker) allowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	now := time.Now()
	
	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if now.Sub(cb.lastFailTime) > cb.config.Timeout {
			cb.state = StateHalfOpen
			cb.requests = 0
			cb.successes = 0
			return true
		}
		return false
	case StateHalfOpen:
		return cb.requests < cb.config.MaxRequests
	}
	
	return false
}

func (cb *CircuitBreaker) recordResult(success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.requests++
	
	if success {
		cb.successes++
		if cb.state == StateHalfOpen && cb.successes >= cb.config.SuccessThreshold {
			cb.state = StateClosed
			cb.failures = 0
		}
	} else {
		cb.failures++
		cb.lastFailTime = time.Now()
		
		if cb.state == StateClosed {
			failureRate := float64(cb.failures) / float64(cb.requests)
			if failureRate >= cb.config.FailureThreshold {
				cb.state = StateOpen
			}
		} else if cb.state == StateHalfOpen {
			cb.state = StateOpen
		}
	}
}

func NewRateLimiter(rate float64, capacity int64) *RateLimiter {
	return &RateLimiter{
		rate:     rate,
		capacity: capacity,
		tokens:   capacity,
		lastTime: time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.lastTime = now
	
	rl.tokens += int64(elapsed * rl.rate)
	if rl.tokens > rl.capacity {
		rl.tokens = rl.capacity
	}
	
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	
	return false
}

func RetryWithBackoff(ctx context.Context, config RetryConfig, fn func() error) error {
	var lastErr error
	
	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		if attempt > 0 {
			delay := calculateBackoff(attempt, config)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		
		if err := fn(); err != nil {
			lastErr = err
			continue
		}
		
		return nil
	}
	
	return fmt.Errorf("max retry attempts exceeded: %w", lastErr)
}

func calculateBackoff(attempt int, config RetryConfig) time.Duration {
	delay := time.Duration(float64(config.BaseDelay) * math.Pow(config.BackoffFactor, float64(attempt-1)))
	
	if delay > config.MaxDelay {
		delay = config.MaxDelay
	}
	
	if config.Jitter {
		jitter := time.Duration(rand.Int63n(int64(delay / 2)))
		delay = delay/2 + jitter
	}
	
	return delay
}

func NewHTTPClient(timeout time.Duration, retryConfig RetryConfig, circuitConfig CircuitBreakerConfig) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
		retryConfig:    retryConfig,
		circuitBreaker: NewCircuitBreaker(circuitConfig),
		rateLimiter:    NewRateLimiter(10, 100),
	}
}

func (hc *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	if !hc.rateLimiter.Allow() {
		return nil, fmt.Errorf("rate limit exceeded")
	}
	
	var resp *http.Response
	err := hc.circuitBreaker.Execute(func() error {
		var err error
		resp, err = hc.client.Do(req)
		return err
	})
	
	return resp, err
}

func Contains[T comparable](slice []T, item T) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func Filter[T any](slice []T, predicate func(T) bool) []T {
	result := make([]T, 0)
	for _, item := range slice {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

func Map[T, U any](slice []T, mapper func(T) U) []U {
	result := make([]U, len(slice))
	for i, item := range slice {
		result[i] = mapper(item)
	}
	return result
}

func Reduce[T, U any](slice []T, initial U, reducer func(U, T) U) U {
	result := initial
	for _, item := range slice {
		result = reducer(result, item)
	}
	return result
}

func Unique[T comparable](slice []T) []T {
	seen := make(map[T]bool)
	result := make([]T, 0)
	
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

func Chunk[T any](slice []T, size int) [][]T {
	if size <= 0 {
		return nil
	}
	
	chunks := make([][]T, 0, (len(slice)+size-1)/size)
	
	for i := 0; i < len(slice); i += size {
		end := i + size
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	
	return chunks
}

func Reverse[T any](slice []T) []T {
	result := make([]T, len(slice))
	for i, item := range slice {
		result[len(slice)-1-i] = item
	}
	return result
}

func SortBy[T any](slice []T, less func(T, T) bool) {
	sort.Slice(slice, func(i, j int) bool {
		return less(slice[i], slice[j])
	})
}

func MinMax[T comparable](slice []T, less func(T, T) bool) (T, T) {
	if len(slice) == 0 {
		var zero T
		return zero, zero
	}
	
	min, max := slice[0], slice[0]
	for _, item := range slice[1:] {
		if less(item, min) {
			min = item
		}
		if less(max, item) {
			max = item
		}
	}
	
	return min, max
}

func GenerateNonce(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	nonce := make([]byte, length)
	for i := range nonce {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		nonce[i] = charset[randomIndex.Int64()]
	}
	return string(nonce)
}

func GenerateRequestID() string {
	return uuid.New().String()
}

func GenerateTraceID() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

func SafeStringToInt(s string, defaultValue int) int {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return defaultValue
}

func SafeStringToFloat(s string, defaultValue float64) float64 {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return defaultValue
}

func SafeStringToBool(s string, defaultValue bool) bool {
	if b, err := strconv.ParseBool(s); err == nil {
		return b
	}
	return defaultValue
}

func CoalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func DefaultString(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func Ptr[T any](v T) *T {
	return &v
}

func DerefOr[T any](ptr *T, defaultValue T) T {
	if ptr == nil {
		return defaultValue
	}
	return *ptr
}
