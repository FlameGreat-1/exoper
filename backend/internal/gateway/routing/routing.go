
package routing

import (
	"context"
	"fmt"
	"encoding/json"
	"io"
	"net/http"
	"hash/fnv"
	"math/rand"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"flamo/backend/internal/common/config"
	"flamo/backend/internal/common/errors"
	"flamo/backend/internal/common/utils"
)

type Router struct {
	config          *config.Config
	logger          *zap.Logger
	routes          map[string]*Route
	loadBalancers   map[string]LoadBalancer
	healthCheckers  map[string]*HealthChecker
	serviceRegistry *ServiceRegistry
	mu              sync.RWMutex
}

type Route struct {
	ID              string
	Path            string
	Method          string
	ServiceName     string
	Endpoints       []*Endpoint
	LoadBalanceType LoadBalanceType
	HealthCheck     *HealthCheckConfig
	Timeout         time.Duration
	RetryPolicy     *RetryPolicy
	CircuitBreaker  *CircuitBreakerConfig
	Middleware      []string
	Metadata        map[string]interface{}
	IsActive        bool
	Priority        int
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Endpoint struct {
	ID          string
	URL         string
	Weight      int
	IsHealthy   bool
	LastCheck   time.Time
	ResponseTime time.Duration
	ErrorCount  int64
	RequestCount int64
	Metadata    map[string]interface{}
}

type LoadBalanceType string

const (
	LoadBalanceRoundRobin    LoadBalanceType = "round_robin"
	LoadBalanceWeighted      LoadBalanceType = "weighted"
	LoadBalanceLeastConn     LoadBalanceType = "least_conn"
	LoadBalanceIPHash        LoadBalanceType = "ip_hash"
	LoadBalanceRandom        LoadBalanceType = "random"
	LoadBalanceHealthiest    LoadBalanceType = "healthiest"
)

type HealthCheckConfig struct {
	Enabled         bool
	Interval        time.Duration
	Timeout         time.Duration
	HealthyThreshold int
	UnhealthyThreshold int
	Path            string
	Method          string
	ExpectedStatus  []int
	ExpectedBody    string
}

type RetryPolicy struct {
	MaxAttempts   int
	BackoffType   BackoffType
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	RetryOn       []string
}

type BackoffType string

const (
	BackoffFixed       BackoffType = "fixed"
	BackoffExponential BackoffType = "exponential"
	BackoffLinear      BackoffType = "linear"
)

type CircuitBreakerConfig struct {
	Enabled          bool
	FailureThreshold float64
	RecoveryTimeout  time.Duration
	MinRequests      int64
}

type LoadBalancer interface {
	SelectEndpoint(endpoints []*Endpoint, request *RoutingRequest) (*Endpoint, error)
	UpdateEndpoint(endpoint *Endpoint)
	GetStats() map[string]interface{}
}

type RoutingRequest struct {
	Path        string
	Method      string
	Headers     map[string]string
	ClientIP    string
	TenantID    string
	UserID      string
	RequestID   string
	Metadata    map[string]interface{}
}

type RoutingResult struct {
	Route       *Route
	Endpoint    *Endpoint
	BackendURL  string
	Headers     map[string]string
	Timeout     time.Duration
	RetryPolicy *RetryPolicy
	Metadata    map[string]interface{}
}

type ServiceRegistry struct {
	services map[string]*ServiceInfo
	mu       sync.RWMutex
}

type ServiceInfo struct {
	Name        string
	Endpoints   []*Endpoint
	HealthCheck *HealthCheckConfig
	LastUpdated time.Time
	Metadata    map[string]interface{}
}

type HealthChecker struct {
	config   *HealthCheckConfig
	endpoint *Endpoint
	logger   *zap.Logger
	stopChan chan struct{}
	wg       sync.WaitGroup
}

func NewRouter(cfg *config.Config, logger *zap.Logger) *Router {
	return &Router{
		config:          cfg,
		logger:          logger,
		routes:          make(map[string]*Route),
		loadBalancers:   make(map[string]LoadBalancer),
		healthCheckers:  make(map[string]*HealthChecker),
		serviceRegistry: NewServiceRegistry(),
	}
}

func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		services: make(map[string]*ServiceInfo),
	}
}

func (r *Router) Initialize() error {
	if err := r.loadDefaultRoutes(); err != nil {
		return errors.Wrap(err, errors.ErrCodeConfigError, "failed to load default routes")
	}

	if err := r.initializeLoadBalancers(); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "failed to initialize load balancers")
	}

	if err := r.startHealthCheckers(); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "failed to start health checkers")
	}

	r.logger.Info("Router initialized successfully")
	return nil
}

func (r *Router) loadDefaultRoutes() error {
	defaultRoutes := []*Route{
		{
			ID:              "ai-chat",
			Path:            "/api/v1/ai/chat",
			Method:          "POST",
			ServiceName:     "model-proxy",
			LoadBalanceType: LoadBalanceWeighted,
			Timeout:         60 * time.Second,
			RetryPolicy: &RetryPolicy{
				MaxAttempts:  3,
				BackoffType:  BackoffExponential,
				InitialDelay: time.Second,
				MaxDelay:     10 * time.Second,
				RetryOn:      []string{"5xx", "timeout"},
			},
			HealthCheck: &HealthCheckConfig{
				Enabled:            true,
				Interval:           30 * time.Second,
				Timeout:            5 * time.Second,
				HealthyThreshold:   2,
				UnhealthyThreshold: 3,
				Path:               "/health",
				Method:             "GET",
				ExpectedStatus:     []int{200},
			},
			IsActive:  true,
			Priority:  1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:              "ai-completion",
			Path:            "/api/v1/ai/completion",
			Method:          "POST",
			ServiceName:     "model-proxy",
			LoadBalanceType: LoadBalanceRoundRobin,
			Timeout:         60 * time.Second,
			RetryPolicy: &RetryPolicy{
				MaxAttempts:  3,
				BackoffType:  BackoffExponential,
				InitialDelay: time.Second,
				MaxDelay:     10 * time.Second,
				RetryOn:      []string{"5xx", "timeout"},
			},
			IsActive:  true,
			Priority:  1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:              "auth-validate",
			Path:            "/api/v1/auth/validate",
			Method:          "POST",
			ServiceName:     "auth-service",
			LoadBalanceType: LoadBalanceLeastConn,
			Timeout:         10 * time.Second,
			RetryPolicy: &RetryPolicy{
				MaxAttempts:  2,
				BackoffType:  BackoffFixed,
				InitialDelay: 500 * time.Millisecond,
				MaxDelay:     2 * time.Second,
				RetryOn:      []string{"5xx"},
			},
			IsActive:  true,
			Priority:  2,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:              "tenant-info",
			Path:            "/api/v1/tenant",
			Method:          "GET",
			ServiceName:     "tenant-service",
			LoadBalanceType: LoadBalanceRoundRobin,
			Timeout:         15 * time.Second,
			IsActive:        true,
			Priority:        3,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		},
	}

	for _, route := range defaultRoutes {
		if err := r.AddRoute(route); err != nil {
			return err
		}
	}

	return nil
}

func (r *Router) initializeLoadBalancers() error {
	r.loadBalancers[string(LoadBalanceRoundRobin)] = NewRoundRobinBalancer()
	r.loadBalancers[string(LoadBalanceWeighted)] = NewWeightedBalancer()
	r.loadBalancers[string(LoadBalanceLeastConn)] = NewLeastConnBalancer()
	r.loadBalancers[string(LoadBalanceIPHash)] = NewIPHashBalancer()
	r.loadBalancers[string(LoadBalanceRandom)] = NewRandomBalancer()
	r.loadBalancers[string(LoadBalanceHealthiest)] = NewHealthiestBalancer()

	return nil
}

func (r *Router) startHealthCheckers() error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, route := range r.routes {
		if route.HealthCheck != nil && route.HealthCheck.Enabled {
			for _, endpoint := range route.Endpoints {
				checker := NewHealthChecker(route.HealthCheck, endpoint, r.logger)
				r.healthCheckers[endpoint.ID] = checker
				go checker.Start()
			}
		}
	}

	return nil
}

func (r *Router) RouteRequest(request *RoutingRequest) (*RoutingResult, *errors.AppError) {
	route, err := r.findMatchingRoute(request)
	if err != nil {
		return nil, err
	}

	if !route.IsActive {
		return nil, errors.NewNotFoundError("route").WithContext("path", request.Path)
	}

	endpoints := r.getHealthyEndpoints(route)
	if len(endpoints) == 0 {
		return nil, errors.New(errors.ErrCodeServiceUnavailable, "no healthy endpoints available")
	}

	loadBalancer := r.loadBalancers[string(route.LoadBalanceType)]
	if loadBalancer == nil {
		loadBalancer = r.loadBalancers[string(LoadBalanceRoundRobin)]
	}

	endpoint, err := r.selectEndpoint(loadBalancer, endpoints, request)
	if err != nil {
		return nil, err
	}

	backendURL, urlErr := r.buildBackendURL(endpoint, request)
	if urlErr != nil {
		return nil, errors.Wrap(urlErr, errors.ErrCodeInternalError, "failed to build backend URL")
	}

	headers := r.buildHeaders(route, endpoint, request)

	return &RoutingResult{
		Route:       route,
		Endpoint:    endpoint,
		BackendURL:  backendURL,
		Headers:     headers,
		Timeout:     route.Timeout,
		RetryPolicy: route.RetryPolicy,
		Metadata: map[string]interface{}{
			"route_id":    route.ID,
			"endpoint_id": endpoint.ID,
			"service":     route.ServiceName,
		},
	}, nil
}

func (r *Router) findMatchingRoute(request *RoutingRequest) (*Route, *errors.AppError) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matchingRoutes []*Route

	for _, route := range r.routes {
		if r.matchesRoute(route, request) {
			matchingRoutes = append(matchingRoutes, route)
		}
	}

	if len(matchingRoutes) == 0 {
		return nil, errors.NewNotFoundError("route").WithContext("path", request.Path)
	}

	sort.Slice(matchingRoutes, func(i, j int) bool {
		return matchingRoutes[i].Priority < matchingRoutes[j].Priority
	})

	return matchingRoutes[0], nil
}

func (r *Router) matchesRoute(route *Route, request *RoutingRequest) bool {
	if route.Method != "" && route.Method != request.Method {
		return false
	}

	return r.matchesPath(route.Path, request.Path)
}

func (r *Router) matchesPath(routePath, requestPath string) bool {
	if routePath == requestPath {
		return true
	}

	if strings.Contains(routePath, "*") {
		pattern := strings.ReplaceAll(routePath, "*", ".*")
		matched := utils.MatchPattern(pattern, requestPath)
		return matched
	}

	if strings.HasSuffix(routePath, "/") && strings.HasPrefix(requestPath, routePath) {
		return true
	}

	return false
}

func (r *Router) getHealthyEndpoints(route *Route) []*Endpoint {
	var healthyEndpoints []*Endpoint
	
	for _, endpoint := range route.Endpoints {
		if endpoint.IsHealthy {
			healthyEndpoints = append(healthyEndpoints, endpoint)
		}
	}
	
	return healthyEndpoints
}

func (r *Router) selectEndpoint(loadBalancer LoadBalancer, endpoints []*Endpoint, request *RoutingRequest) (*Endpoint, *errors.AppError) {
	endpoint, err := loadBalancer.SelectEndpoint(endpoints, request)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "load balancer selection failed")
	}
	
	if endpoint == nil {
		return nil, errors.New(errors.ErrCodeServiceUnavailable, "no endpoint selected")
	}
	
	endpoint.RequestCount++
	loadBalancer.UpdateEndpoint(endpoint)
	
	return endpoint, nil
}

func (r *Router) buildBackendURL(endpoint *Endpoint, request *RoutingRequest) (string, error) {
	baseURL, err := url.Parse(endpoint.URL)
	if err != nil {
		return "", err
	}
	
	requestURL, err := url.Parse(request.Path)
	if err != nil {
		return "", err
	}
	
	backendURL := baseURL.ResolveReference(requestURL)
	return backendURL.String(), nil
}

func (r *Router) buildHeaders(route *Route, endpoint *Endpoint, request *RoutingRequest) map[string]string {
	headers := make(map[string]string)
	
	for key, value := range request.Headers {
		headers[key] = value
	}
	
	headers["X-Route-ID"] = route.ID
	headers["X-Endpoint-ID"] = endpoint.ID
	headers["X-Service-Name"] = route.ServiceName
	headers["X-Request-ID"] = request.RequestID
	
	if request.TenantID != "" {
		headers["X-Tenant-ID"] = request.TenantID
	}
	
	if request.UserID != "" {
		headers["X-User-ID"] = request.UserID
	}
	
	return headers
}

func (r *Router) AddRoute(route *Route) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if route.ID == "" {
		return errors.New(errors.ErrCodeValidationError, "route ID is required")
	}
	
	if route.Path == "" {
		return errors.New(errors.ErrCodeValidationError, "route path is required")
	}
	
	if route.ServiceName == "" {
		return errors.New(errors.ErrCodeValidationError, "service name is required")
	}
	
	route.UpdatedAt = time.Now()
	r.routes[route.ID] = route
	
	r.logger.Info("Route added", 
		zap.String("route_id", route.ID),
		zap.String("path", route.Path),
		zap.String("service", route.ServiceName))
	
	return nil
}

func (r *Router) RemoveRoute(routeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if _, exists := r.routes[routeID]; !exists {
		return errors.NewNotFoundError("route")
	}
	
	delete(r.routes, routeID)
	
	r.logger.Info("Route removed", zap.String("route_id", routeID))
	return nil
}

func (r *Router) UpdateRoute(route *Route) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if _, exists := r.routes[route.ID]; !exists {
		return errors.NewNotFoundError("route")
	}
	
	route.UpdatedAt = time.Now()
	r.routes[route.ID] = route
	
	r.logger.Info("Route updated", zap.String("route_id", route.ID))
	return nil
}

func (r *Router) GetRoute(routeID string) (*Route, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	route, exists := r.routes[routeID]
	if !exists {
		return nil, errors.NewNotFoundError("route")
	}
	
	return route, nil
}

func (r *Router) ListRoutes() []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	routes := make([]*Route, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route)
	}
	
	return routes
}

func (r *Router) AddEndpoint(routeID string, endpoint *Endpoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	route, exists := r.routes[routeID]
	if !exists {
		return errors.NewNotFoundError("route")
	}
	
	if endpoint.ID == "" {
		endpoint.ID = utils.GenerateRequestID()
	}
	
	endpoint.IsHealthy = true
	endpoint.LastCheck = time.Now()
	
	route.Endpoints = append(route.Endpoints, endpoint)
	route.UpdatedAt = time.Now()
	
	r.logger.Info("Endpoint added",
		zap.String("route_id", routeID),
		zap.String("endpoint_id", endpoint.ID),
		zap.String("url", endpoint.URL))
	
	return nil
}

func (r *Router) RemoveEndpoint(routeID, endpointID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	route, exists := r.routes[routeID]
	if !exists {
		return errors.NewNotFoundError("route")
	}
	
	for i, endpoint := range route.Endpoints {
		if endpoint.ID == endpointID {
			route.Endpoints = append(route.Endpoints[:i], route.Endpoints[i+1:]...)
			route.UpdatedAt = time.Now()
			
			if checker, exists := r.healthCheckers[endpointID]; exists {
				checker.Stop()
				delete(r.healthCheckers, endpointID)
			}
			
			r.logger.Info("Endpoint removed",
				zap.String("route_id", routeID),
				zap.String("endpoint_id", endpointID))
			
			return nil
		}
	}
	
	return errors.NewNotFoundError("endpoint")
}

type RoundRobinBalancer struct {
	counter map[string]int64
	mu      sync.Mutex
}

func NewRoundRobinBalancer() *RoundRobinBalancer {
	return &RoundRobinBalancer{
		counter: make(map[string]int64),
	}
}

func (rb *RoundRobinBalancer) SelectEndpoint(endpoints []*Endpoint, request *RoutingRequest) (*Endpoint, error) {
	if len(endpoints) == 0 {
		return nil, errors.New(errors.ErrCodeServiceUnavailable, "no endpoints available")
	}
	
	rb.mu.Lock()
	defer rb.mu.Unlock()
	
	key := request.Path
	index := rb.counter[key] % int64(len(endpoints))
	rb.counter[key]++
	
	return endpoints[index], nil
}

func (rb *RoundRobinBalancer) UpdateEndpoint(endpoint *Endpoint) {
}

func (rb *RoundRobinBalancer) GetStats() map[string]interface{} {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	
	return map[string]interface{}{
		"type":     "round_robin",
		"counters": rb.counter,
	}
}

type WeightedBalancer struct {
	mu sync.Mutex
}

func NewWeightedBalancer() *WeightedBalancer {
	return &WeightedBalancer{}
}

func (wb *WeightedBalancer) SelectEndpoint(endpoints []*Endpoint, request *RoutingRequest) (*Endpoint, error) {
	if len(endpoints) == 0 {
		return nil, errors.New(errors.ErrCodeServiceUnavailable, "no endpoints available")
	}
	
	totalWeight := 0
	for _, endpoint := range endpoints {
		if endpoint.Weight <= 0 {
			endpoint.Weight = 1
		}
		totalWeight += endpoint.Weight
	}
	
	if totalWeight == 0 {
		return endpoints[0], nil
	}
	
	random := rand.Intn(totalWeight)
	currentWeight := 0
	
	for _, endpoint := range endpoints {
		currentWeight += endpoint.Weight
		if random < currentWeight {
			return endpoint, nil
		}
	}
	
	return endpoints[len(endpoints)-1], nil
}

func (wb *WeightedBalancer) UpdateEndpoint(endpoint *Endpoint) {
}

func (wb *WeightedBalancer) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"type": "weighted",
	}
}

type LeastConnBalancer struct {
	connections map[string]int64
	mu          sync.Mutex
}

func NewLeastConnBalancer() *LeastConnBalancer {
	return &LeastConnBalancer{
		connections: make(map[string]int64),
	}
}

func (lb *LeastConnBalancer) SelectEndpoint(endpoints []*Endpoint, request *RoutingRequest) (*Endpoint, error) {
	if len(endpoints) == 0 {
		return nil, errors.New(errors.ErrCodeServiceUnavailable, "no endpoints available")
	}
	
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	var selectedEndpoint *Endpoint
	minConnections := int64(-1)
	
	for _, endpoint := range endpoints {
		connections := lb.connections[endpoint.ID]
		if minConnections == -1 || connections < minConnections {
			minConnections = connections
			selectedEndpoint = endpoint
		}
	}
	
	if selectedEndpoint != nil {
		lb.connections[selectedEndpoint.ID]++
	}
	
	return selectedEndpoint, nil
}

func (lb *LeastConnBalancer) UpdateEndpoint(endpoint *Endpoint) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	if lb.connections[endpoint.ID] > 0 {
		lb.connections[endpoint.ID]--
	}
}

func (lb *LeastConnBalancer) GetStats() map[string]interface{} {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	return map[string]interface{}{
		"type":        "least_conn",
		"connections": lb.connections,
	}
}

type IPHashBalancer struct{}

func NewIPHashBalancer() *IPHashBalancer {
	return &IPHashBalancer{}
}

func (ih *IPHashBalancer) SelectEndpoint(endpoints []*Endpoint, request *RoutingRequest) (*Endpoint, error) {
	if len(endpoints) == 0 {
		return nil, errors.New(errors.ErrCodeServiceUnavailable, "no endpoints available")
	}
	
	hash := fnv.New32a()
	hash.Write([]byte(request.ClientIP))
	index := hash.Sum32() % uint32(len(endpoints))
	
	return endpoints[index], nil
}

func (ih *IPHashBalancer) UpdateEndpoint(endpoint *Endpoint) {
}

func (ih *IPHashBalancer) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"type": "ip_hash",
	}
}

type RandomBalancer struct{}

func NewRandomBalancer() *RandomBalancer {
	return &RandomBalancer{}
}

func (rb *RandomBalancer) SelectEndpoint(endpoints []*Endpoint, request *RoutingRequest) (*Endpoint, error) {
	if len(endpoints) == 0 {
		return nil, errors.New(errors.ErrCodeServiceUnavailable, "no endpoints available")
	}
	
	index := rand.Intn(len(endpoints))
	return endpoints[index], nil
}

func (rb *RandomBalancer) UpdateEndpoint(endpoint *Endpoint) {
}

func (rb *RandomBalancer) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"type": "random",
	}
}

type HealthiestBalancer struct{}

func NewHealthiestBalancer() *HealthiestBalancer {
	return &HealthiestBalancer{}
}

func (hb *HealthiestBalancer) SelectEndpoint(endpoints []*Endpoint, request *RoutingRequest) (*Endpoint, error) {
	if len(endpoints) == 0 {
		return nil, errors.New(errors.ErrCodeServiceUnavailable, "no endpoints available")
	}
	
	var selectedEndpoint *Endpoint
	bestResponseTime := time.Duration(-1)
	
	for _, endpoint := range endpoints {
		if bestResponseTime == -1 || endpoint.ResponseTime < bestResponseTime {
			bestResponseTime = endpoint.ResponseTime
			selectedEndpoint = endpoint
		}
	}
	
	if selectedEndpoint == nil {
		return endpoints[0], nil
	}
	
	return selectedEndpoint, nil
}

func (hb *HealthiestBalancer) UpdateEndpoint(endpoint *Endpoint) {
}

func (hb *HealthiestBalancer) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"type": "healthiest",
	}
}

func NewHealthChecker(config *HealthCheckConfig, endpoint *Endpoint, logger *zap.Logger) *HealthChecker {
	return &HealthChecker{
		config:   config,
		endpoint: endpoint,
		logger:   logger,
		stopChan: make(chan struct{}),
	}
}

func (hc *HealthChecker) Start() {
	hc.wg.Add(1)
	defer hc.wg.Done()

	ticker := time.NewTicker(hc.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.performHealthCheck()
		case <-hc.stopChan:
			return
		}
	}
}

func (hc *HealthChecker) Stop() {
	close(hc.stopChan)
	hc.wg.Wait()
}

func (hc *HealthChecker) performHealthCheck() {
	startTime := time.Now()
	
	ctx, cancel := context.WithTimeout(context.Background(), hc.config.Timeout)
	defer cancel()

	isHealthy := hc.checkEndpointHealth(ctx)
	responseTime := time.Since(startTime)

	hc.endpoint.LastCheck = time.Now()
	hc.endpoint.ResponseTime = responseTime

	if isHealthy {
		if !hc.endpoint.IsHealthy {
			hc.logger.Info("Endpoint became healthy",
				zap.String("endpoint_id", hc.endpoint.ID),
				zap.String("url", hc.endpoint.URL))
		}
		hc.endpoint.IsHealthy = true
		hc.endpoint.ErrorCount = 0
	} else {
		hc.endpoint.ErrorCount++
		if hc.endpoint.ErrorCount >= int64(hc.config.UnhealthyThreshold) {
			if hc.endpoint.IsHealthy {
				hc.logger.Warn("Endpoint became unhealthy",
					zap.String("endpoint_id", hc.endpoint.ID),
					zap.String("url", hc.endpoint.URL),
					zap.Int64("error_count", hc.endpoint.ErrorCount))
			}
			hc.endpoint.IsHealthy = false
		}
	}
}

func (hc *HealthChecker) checkEndpointHealth(ctx context.Context) bool {
	healthURL := hc.buildHealthCheckURL()
	
	req, err := http.NewRequestWithContext(ctx, hc.config.Method, healthURL, nil)
	if err != nil {
		hc.logger.Error("Failed to create health check request", zap.Error(err))
		return false
	}

	client := &http.Client{
		Timeout: hc.config.Timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		hc.logger.Debug("Health check request failed",
			zap.String("url", healthURL),
			zap.Error(err))
		return false
	}
	defer resp.Body.Close()

	if !hc.isValidStatusCode(resp.StatusCode) {
		hc.logger.Debug("Health check returned invalid status",
			zap.String("url", healthURL),
			zap.Int("status", resp.StatusCode))
		return false
	}

	if hc.config.ExpectedBody != "" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			hc.logger.Debug("Failed to read health check response body", zap.Error(err))
			return false
		}

		if !strings.Contains(string(body), hc.config.ExpectedBody) {
			hc.logger.Debug("Health check body does not contain expected content",
				zap.String("expected", hc.config.ExpectedBody),
				zap.String("actual", string(body)))
			return false
		}
	}

	return true
}

func (hc *HealthChecker) buildHealthCheckURL() string {
	baseURL := strings.TrimSuffix(hc.endpoint.URL, "/")
	healthPath := strings.TrimPrefix(hc.config.Path, "/")
	return fmt.Sprintf("%s/%s", baseURL, healthPath)
}

func (hc *HealthChecker) isValidStatusCode(statusCode int) bool {
	if len(hc.config.ExpectedStatus) == 0 {
		return statusCode >= 200 && statusCode < 300
	}

	for _, expected := range hc.config.ExpectedStatus {
		if statusCode == expected {
			return true
		}
	}

	return false
}

func (sr *ServiceRegistry) RegisterService(service *ServiceInfo) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if service.Name == "" {
		return errors.New(errors.ErrCodeValidationError, "service name is required")
	}

	service.LastUpdated = time.Now()
	sr.services[service.Name] = service

	return nil
}

func (sr *ServiceRegistry) UnregisterService(serviceName string) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if _, exists := sr.services[serviceName]; !exists {
		return errors.NewNotFoundError("service")
	}

	delete(sr.services, serviceName)
	return nil
}

func (sr *ServiceRegistry) GetService(serviceName string) (*ServiceInfo, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	service, exists := sr.services[serviceName]
	if !exists {
		return nil, errors.NewNotFoundError("service")
	}

	return service, nil
}

func (sr *ServiceRegistry) ListServices() []*ServiceInfo {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	services := make([]*ServiceInfo, 0, len(sr.services))
	for _, service := range sr.services {
		services = append(services, service)
	}

	return services
}

func (sr *ServiceRegistry) UpdateServiceEndpoints(serviceName string, endpoints []*Endpoint) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	service, exists := sr.services[serviceName]
	if !exists {
		return errors.NewNotFoundError("service")
	}

	service.Endpoints = endpoints
	service.LastUpdated = time.Now()

	return nil
}

func (r *Router) ExecuteWithRetry(ctx context.Context, request *RoutingRequest, executeFunc func(*RoutingResult) error) error {
	result, err := r.RouteRequest(request)
	if err != nil {
		return err
	}

	if result.RetryPolicy == nil {
		return executeFunc(result)
	}

	return r.retryWithPolicy(ctx, result, executeFunc)
}

func (r *Router) retryWithPolicy(ctx context.Context, result *RoutingResult, executeFunc func(*RoutingResult) error) error {
	policy := result.RetryPolicy
	var lastErr error

	for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
		if attempt > 0 {
			delay := r.calculateBackoffDelay(policy, attempt)
			
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}

			newResult, routeErr := r.RouteRequest(&RoutingRequest{
				Path:      result.Route.Path,
				Method:    result.Route.Method,
				RequestID: result.Metadata["request_id"].(string),
			})
			if routeErr != nil {
				lastErr = routeErr
				continue
			}
			result = newResult
		}

		err := executeFunc(result)
		if err == nil {
			return nil
		}

		lastErr = err

		if !r.shouldRetry(policy, err) {
			break
		}

		r.logger.Debug("Retrying request",
			zap.Int("attempt", attempt+1),
			zap.Int("max_attempts", policy.MaxAttempts),
			zap.Error(err))
	}

	return lastErr
}

func (r *Router) calculateBackoffDelay(policy *RetryPolicy, attempt int) time.Duration {
	switch policy.BackoffType {
	case BackoffFixed:
		return policy.InitialDelay
	case BackoffLinear:
		delay := time.Duration(attempt) * policy.InitialDelay
		if delay > policy.MaxDelay {
			return policy.MaxDelay
		}
		return delay
	case BackoffExponential:
		delay := policy.InitialDelay * time.Duration(1<<uint(attempt-1))
		if delay > policy.MaxDelay {
			return policy.MaxDelay
		}
		return delay
	default:
		return policy.InitialDelay
	}
}

func (r *Router) shouldRetry(policy *RetryPolicy, err error) bool {
	if len(policy.RetryOn) == 0 {
		return true
	}

	errorType := r.classifyError(err)
	return utils.Contains(policy.RetryOn, errorType)
}

func (r *Router) classifyError(err error) string {
	if err == nil {
		return "none"
	}

	errorStr := err.Error()
	
	if strings.Contains(errorStr, "timeout") || strings.Contains(errorStr, "deadline") {
		return "timeout"
	}
	
	if strings.Contains(errorStr, "connection") || strings.Contains(errorStr, "network") {
		return "connection"
	}
	
	if appErr, ok := err.(*errors.AppError); ok {
		switch appErr.Code {
		case errors.ErrCodeServiceUnavailable:
			return "5xx"
		case errors.ErrCodeInternalError:
			return "5xx"
		case errors.ErrCodeTimeout:
			return "timeout"
		case errors.ErrCodeNetworkError:
			return "connection"
		default:
			return "4xx"
		}
	}
	
	return "unknown"
}

func (r *Router) GetRouteMetrics(routeID string) (map[string]interface{}, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	route, exists := r.routes[routeID]
	if !exists {
		return nil, errors.NewNotFoundError("route")
	}

	metrics := map[string]interface{}{
		"route_id":     route.ID,
		"service_name": route.ServiceName,
		"is_active":    route.IsActive,
		"endpoints":    make([]map[string]interface{}, len(route.Endpoints)),
	}

	for i, endpoint := range route.Endpoints {
		metrics["endpoints"].([]map[string]interface{})[i] = map[string]interface{}{
			"id":            endpoint.ID,
			"url":           endpoint.URL,
			"is_healthy":    endpoint.IsHealthy,
			"request_count": endpoint.RequestCount,
			"error_count":   endpoint.ErrorCount,
			"response_time": endpoint.ResponseTime.Milliseconds(),
			"last_check":    endpoint.LastCheck,
		}
	}

	return metrics, nil
}

func (r *Router) GetLoadBalancerStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	for lbType, lb := range r.loadBalancers {
		stats[lbType] = lb.GetStats()
	}
	
	return stats
}

func (r *Router) GetHealthStatus() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	totalEndpoints := 0
	healthyEndpoints := 0
	
	for _, route := range r.routes {
		for _, endpoint := range route.Endpoints {
			totalEndpoints++
			if endpoint.IsHealthy {
				healthyEndpoints++
			}
		}
	}

	healthRatio := float64(0)
	if totalEndpoints > 0 {
		healthRatio = float64(healthyEndpoints) / float64(totalEndpoints)
	}

	status := "healthy"
	if healthRatio < 0.5 {
		status = "unhealthy"
	} else if healthRatio < 0.8 {
		status = "degraded"
	}

	return map[string]interface{}{
		"status":            status,
		"total_endpoints":   totalEndpoints,
		"healthy_endpoints": healthyEndpoints,
		"health_ratio":      healthRatio,
		"total_routes":      len(r.routes),
		"active_routes":     r.countActiveRoutes(),
	}
}

func (r *Router) countActiveRoutes() int {
	count := 0
	for _, route := range r.routes {
		if route.IsActive {
			count++
		}
	}
	return count
}

func (r *Router) RefreshRoutes() error {
	r.logger.Info("Refreshing routes from configuration")
	
	return r.loadDefaultRoutes()
}

func (r *Router) ValidateRoute(route *Route) error {
	if route.ID == "" {
		return errors.New(errors.ErrCodeValidationError, "route ID is required")
	}

	if route.Path == "" {
		return errors.New(errors.ErrCodeValidationError, "route path is required")
	}

	if route.ServiceName == "" {
		return errors.New(errors.ErrCodeValidationError, "service name is required")
	}

	if route.Timeout <= 0 {
		return errors.New(errors.ErrCodeValidationError, "timeout must be positive")
	}

	if route.RetryPolicy != nil {
		if route.RetryPolicy.MaxAttempts < 1 {
			return errors.New(errors.ErrCodeValidationError, "max attempts must be at least 1")
		}
		if route.RetryPolicy.InitialDelay <= 0 {
			return errors.New(errors.ErrCodeValidationError, "initial delay must be positive")
		}
	}

	return nil
}

func (r *Router) EnableRoute(routeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[routeID]
	if !exists {
		return errors.NewNotFoundError("route")
	}

	route.IsActive = true
	route.UpdatedAt = time.Now()

	r.logger.Info("Route enabled", zap.String("route_id", routeID))
	return nil
}

func (r *Router) DisableRoute(routeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[routeID]
	if !exists {
		return errors.NewNotFoundError("route")
	}

	route.IsActive = false
	route.UpdatedAt = time.Now()

	r.logger.Info("Route disabled", zap.String("route_id", routeID))
	return nil
}

func (r *Router) Shutdown(ctx context.Context) error {
	r.logger.Info("Shutting down router")

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, checker := range r.healthCheckers {
		checker.Stop()
	}

	done := make(chan struct{})
	go func() {
		for _, checker := range r.healthCheckers {
			checker.wg.Wait()
		}
		close(done)
	}()

	select {
	case <-done:
		r.logger.Info("Router shutdown completed")
		return nil
	case <-ctx.Done():
		r.logger.Warn("Router shutdown timed out")
		return ctx.Err()
	}
}

func (r *Router) GetRoutingTable() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	table := make(map[string]interface{})
	
	for routeID, route := range r.routes {
		endpoints := make([]map[string]interface{}, len(route.Endpoints))
		for i, endpoint := range route.Endpoints {
			endpoints[i] = map[string]interface{}{
				"id":            endpoint.ID,
				"url":           endpoint.URL,
				"weight":        endpoint.Weight,
				"is_healthy":    endpoint.IsHealthy,
				"request_count": endpoint.RequestCount,
				"error_count":   endpoint.ErrorCount,
				"response_time": endpoint.ResponseTime.Milliseconds(),
			}
		}

		table[routeID] = map[string]interface{}{
			"id":                route.ID,
			"path":              route.Path,
			"method":            route.Method,
			"service_name":      route.ServiceName,
			"load_balance_type": route.LoadBalanceType,
			"is_active":         route.IsActive,
			"priority":          route.Priority,
			"timeout":           route.Timeout.String(),
			"endpoints":         endpoints,
			"created_at":        route.CreatedAt,
			"updated_at":        route.UpdatedAt,
		}
	}

	return table
}

func (r *Router) ExportConfiguration() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	config := map[string]interface{}{
		"version":   "1.0",
		"timestamp": time.Now().UTC(),
		"routes":    r.routes,
		"services":  r.serviceRegistry.services,
	}

	return json.Marshal(config)
}

func (r *Router) ImportConfiguration(data []byte) error {
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return errors.Wrap(err, errors.ErrCodeInvalidRequest, "invalid configuration format")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.logger.Info("Importing router configuration")

	for _, checker := range r.healthCheckers {
		checker.Stop()
	}
	r.healthCheckers = make(map[string]*HealthChecker)

	if routes, ok := config["routes"].(map[string]interface{}); ok {
		r.routes = make(map[string]*Route)
		for routeID, routeData := range routes {
			route := &Route{}
			if err := r.unmarshalRoute(routeData, route); err != nil {
				return errors.Wrap(err, errors.ErrCodeInvalidRequest, "invalid route data")
			}
			r.routes[routeID] = route
		}
	}

	if err := r.startHealthCheckers(); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalError, "failed to restart health checkers")
	}

	r.logger.Info("Router configuration imported successfully")
	return nil
}

func (r *Router) unmarshalRoute(data interface{}, route *Route) error {
	routeBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(routeBytes, route)
}

func (r *Router) GetEndpointStats(routeID, endpointID string) (map[string]interface{}, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	route, exists := r.routes[routeID]
	if !exists {
		return nil, errors.NewNotFoundError("route")
	}

	for _, endpoint := range route.Endpoints {
		if endpoint.ID == endpointID {
			return map[string]interface{}{
				"id":            endpoint.ID,
				"url":           endpoint.URL,
				"weight":        endpoint.Weight,
				"is_healthy":    endpoint.IsHealthy,
				"request_count": endpoint.RequestCount,
				"error_count":   endpoint.ErrorCount,
				"response_time": endpoint.ResponseTime.Milliseconds(),
				"last_check":    endpoint.LastCheck,
				"success_rate":  r.calculateSuccessRate(endpoint),
				"metadata":      endpoint.Metadata,
			}, nil
		}
	}

	return nil, errors.NewNotFoundError("endpoint")
}

func (r *Router) calculateSuccessRate(endpoint *Endpoint) float64 {
	if endpoint.RequestCount == 0 {
		return 0.0
	}
	
	successCount := endpoint.RequestCount - endpoint.ErrorCount
	return float64(successCount) / float64(endpoint.RequestCount) * 100
}

func (r *Router) UpdateEndpointWeight(routeID, endpointID string, weight int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[routeID]
	if !exists {
		return errors.NewNotFoundError("route")
	}

	for _, endpoint := range route.Endpoints {
		if endpoint.ID == endpointID {
			endpoint.Weight = weight
			route.UpdatedAt = time.Now()
			
			r.logger.Info("Endpoint weight updated",
				zap.String("route_id", routeID),
				zap.String("endpoint_id", endpointID),
				zap.Int("weight", weight))
			
			return nil
		}
	}

	return errors.NewNotFoundError("endpoint")
}

func (r *Router) SetEndpointHealth(routeID, endpointID string, isHealthy bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[routeID]
	if !exists {
		return errors.NewNotFoundError("route")
	}

	for _, endpoint := range route.Endpoints {
		if endpoint.ID == endpointID {
			endpoint.IsHealthy = isHealthy
			endpoint.LastCheck = time.Now()
			
			r.logger.Info("Endpoint health status updated",
				zap.String("route_id", routeID),
				zap.String("endpoint_id", endpointID),
				zap.Bool("is_healthy", isHealthy))
			
			return nil
		}
	}

	return errors.NewNotFoundError("endpoint")
}

func (r *Router) GetRoutesByService(serviceName string) []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var routes []*Route
	for _, route := range r.routes {
		if route.ServiceName == serviceName {
			routes = append(routes, route)
		}
	}

	return routes
}

func (r *Router) GetActiveRoutes() []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var activeRoutes []*Route
	for _, route := range r.routes {
		if route.IsActive {
			activeRoutes = append(activeRoutes, route)
		}
	}

	return activeRoutes
}

func (r *Router) TestRoute(routeID string, request *RoutingRequest) (*RoutingResult, error) {
	r.mu.RLock()
	route, exists := r.routes[routeID]
	r.mu.RUnlock()

	if !exists {
		return nil, errors.NewNotFoundError("route")
	}

	if !r.matchesRoute(route, request) {
		return nil, errors.New(errors.ErrCodeValidationError, "request does not match route")
	}

	endpoints := r.getHealthyEndpoints(route)
	if len(endpoints) == 0 {
		return nil, errors.NewServiceUnavailableError("no healthy endpoints available")
	}

	loadBalancer := r.loadBalancers[string(route.LoadBalanceType)]
	if loadBalancer == nil {
		loadBalancer = r.loadBalancers[string(LoadBalanceRoundRobin)]
	}

	endpoint, err := loadBalancer.SelectEndpoint(endpoints, request)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalError, "endpoint selection failed")
	}

	backendURL, urlErr := r.buildBackendURL(endpoint, request)
	if urlErr != nil {
		return nil, errors.Wrap(urlErr, errors.ErrCodeInternalError, "failed to build backend URL")
	}

	return &RoutingResult{
		Route:      route,
		Endpoint:   endpoint,
		BackendURL: backendURL,
		Headers:    r.buildHeaders(route, endpoint, request),
		Timeout:    route.Timeout,
		Metadata: map[string]interface{}{
			"test_mode": true,
			"route_id":  route.ID,
		},
	}, nil
}

func (r *Router) ResetEndpointStats(routeID, endpointID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[routeID]
	if !exists {
		return errors.NewNotFoundError("route")
	}

	for _, endpoint := range route.Endpoints {
		if endpoint.ID == endpointID {
			endpoint.RequestCount = 0
			endpoint.ErrorCount = 0
			endpoint.ResponseTime = 0
			
			r.logger.Info("Endpoint stats reset",
				zap.String("route_id", routeID),
				zap.String("endpoint_id", endpointID))
			
			return nil
		}
	}

	return errors.NewNotFoundError("endpoint")
}

func (r *Router) GetSummaryStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	totalRoutes := len(r.routes)
	activeRoutes := 0
	totalEndpoints := 0
	healthyEndpoints := 0
	totalRequests := int64(0)
	totalErrors := int64(0)

	for _, route := range r.routes {
		if route.IsActive {
			activeRoutes++
		}
		
		for _, endpoint := range route.Endpoints {
			totalEndpoints++
			if endpoint.IsHealthy {
				healthyEndpoints++
			}
			totalRequests += endpoint.RequestCount
			totalErrors += endpoint.ErrorCount
		}
	}

	errorRate := float64(0)
	if totalRequests > 0 {
		errorRate = float64(totalErrors) / float64(totalRequests) * 100
	}

	return map[string]interface{}{
		"total_routes":      totalRoutes,
		"active_routes":     activeRoutes,
		"total_endpoints":   totalEndpoints,
		"healthy_endpoints": healthyEndpoints,
		"total_requests":    totalRequests,
		"total_errors":      totalErrors,
		"error_rate":        errorRate,
		"health_ratio":      func() float64 {
			if totalEndpoints > 0 {
				return float64(healthyEndpoints) / float64(totalEndpoints) * 100
			}
			return 0
		}(),
	}
}

func (r *Router) CleanupInactiveRoutes(olderThan time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	cleaned := 0

	for routeID, route := range r.routes {
		if !route.IsActive && route.UpdatedAt.Before(cutoff) {
			delete(r.routes, routeID)
			cleaned++
			
			r.logger.Info("Cleaned up inactive route",
				zap.String("route_id", routeID),
				zap.Time("last_updated", route.UpdatedAt))
		}
	}

	return cleaned
}

func ValidateRoutingConfig(config *config.Config) error {
	if config.Gateway.RequestTimeout <= 0 {
		return errors.New(errors.ErrCodeConfigError, "request timeout must be positive")
	}

	if config.Gateway.MaxConcurrentRequests <= 0 {
		return errors.New(errors.ErrCodeConfigError, "max concurrent requests must be positive")
	}

	return nil
}

func NewRouterWithDefaults(cfg *config.Config, logger *zap.Logger) (*Router, error) {
	if err := ValidateRoutingConfig(cfg); err != nil {
		return nil, err
	}

	router := NewRouter(cfg, logger)
	
	if err := router.Initialize(); err != nil {
		return nil, err
	}

	return router, nil
}

func (r *Router) String() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	return fmt.Sprintf("Router(routes=%d, active=%d)", 
		len(r.routes), r.countActiveRoutes())
}
