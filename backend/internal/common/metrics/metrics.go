package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"exoper/backend/internal/common/errors"
)

type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeSummary   MetricType = "summary"
)

type Config struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Address   string `yaml:"address" json:"address"`
	Path      string `yaml:"path" json:"path"`
	Namespace string `yaml:"namespace" json:"namespace"`
	Subsystem string `yaml:"subsystem" json:"subsystem"`
}

type Metrics struct {
	config    *Config
	logger    *zap.Logger
	registry  *prometheus.Registry
	server    *http.Server
	counters  map[string]*prometheus.CounterVec
	histograms map[string]*prometheus.HistogramVec
	gauges    map[string]*prometheus.GaugeVec
	summaries map[string]*prometheus.SummaryVec
	mutex     sync.RWMutex
}

type MetricDefinition struct {
	Name        string
	Help        string
	Labels      []string
	Type        MetricType
	Buckets     []float64 // For histograms
	Objectives  map[float64]float64 // For summaries
}

func NewMetrics(cfg *Config, logger *zap.Logger) (*Metrics, error) {
	if cfg == nil {
		return nil, errors.New(errors.ErrCodeConfigError, "metrics config is required")
	}

	if !cfg.Enabled {
		logger.Info("Metrics collection disabled")
		return &Metrics{
			config:     cfg,
			logger:     logger,
			counters:   make(map[string]*prometheus.CounterVec),
			histograms: make(map[string]*prometheus.HistogramVec),
			gauges:     make(map[string]*prometheus.GaugeVec),
			summaries:  make(map[string]*prometheus.SummaryVec),
		}, nil
	}

	registry := prometheus.NewRegistry()
	
	// Add default collectors
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	m := &Metrics{
		config:     cfg,
		logger:     logger,
		registry:   registry,
		counters:   make(map[string]*prometheus.CounterVec),
		histograms: make(map[string]*prometheus.HistogramVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		summaries:  make(map[string]*prometheus.SummaryVec),
	}

	if err := m.startMetricsServer(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfigError, "failed to start metrics server")
	}

	logger.Info("Metrics collection initialized",
		zap.String("address", cfg.Address),
		zap.String("path", cfg.Path),
		zap.String("namespace", cfg.Namespace))

	return m, nil
}

func (m *Metrics) startMetricsServer() error {
	if !m.config.Enabled {
		return nil
	}

	address := m.config.Address
	if address == "" {
		address = ":9090"
	}

	path := m.config.Path
	if path == "" {
		path = "/metrics"
	}

	mux := http.NewServeMux()
	mux.Handle(path, promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
		Registry:         m.registry,
	}))

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	m.server = &http.Server{
		Addr:         address,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		m.logger.Info("Starting metrics server", zap.String("address", address))
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			m.logger.Error("Metrics server failed", zap.Error(err))
		}
	}()

	return nil
}

func (m *Metrics) RegisterCounter(name, help string, labels []string) error {
	if !m.config.Enabled {
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.counters[name]; exists {
		return errors.New(errors.ErrCodeConflict, fmt.Sprintf("counter %s already registered", name))
	}

	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      name,
			Help:      help,
		},
		labels,
	)

	if err := m.registry.Register(counter); err != nil {
		return errors.Wrap(err, errors.ErrCodeConfigError, "failed to register counter")
	}

	m.counters[name] = counter
	m.logger.Debug("Counter registered", zap.String("name", name))

	return nil
}

func (m *Metrics) RegisterHistogram(name, help string, labels []string, buckets ...[]float64) error {
	if !m.config.Enabled {
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.histograms[name]; exists {
		return errors.New(errors.ErrCodeConflict, fmt.Sprintf("histogram %s already registered", name))
	}

	opts := prometheus.HistogramOpts{
		Namespace: m.config.Namespace,
		Subsystem: m.config.Subsystem,
		Name:      name,
		Help:      help,
	}

	if len(buckets) > 0 && len(buckets[0]) > 0 {
		opts.Buckets = buckets[0]
	} else {
		opts.Buckets = prometheus.DefBuckets
	}

	histogram := prometheus.NewHistogramVec(opts, labels)

	if err := m.registry.Register(histogram); err != nil {
		return errors.Wrap(err, errors.ErrCodeConfigError, "failed to register histogram")
	}

	m.histograms[name] = histogram
	m.logger.Debug("Histogram registered", zap.String("name", name))

	return nil
}

func (m *Metrics) RegisterGauge(name, help string, labels []string) error {
	if !m.config.Enabled {
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.gauges[name]; exists {
		return errors.New(errors.ErrCodeConflict, fmt.Sprintf("gauge %s already registered", name))
	}

	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      name,
			Help:      help,
		},
		labels,
	)

	if err := m.registry.Register(gauge); err != nil {
		return errors.Wrap(err, errors.ErrCodeConfigError, "failed to register gauge")
	}

	m.gauges[name] = gauge
	m.logger.Debug("Gauge registered", zap.String("name", name))

	return nil
}

func (m *Metrics) RegisterSummary(name, help string, labels []string, objectives map[float64]float64) error {
	if !m.config.Enabled {
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.summaries[name]; exists {
		return errors.New(errors.ErrCodeConflict, fmt.Sprintf("summary %s already registered", name))
	}

	opts := prometheus.SummaryOpts{
		Namespace: m.config.Namespace,
		Subsystem: m.config.Subsystem,
		Name:      name,
		Help:      help,
	}

	if objectives != nil {
		opts.Objectives = objectives
	} else {
		opts.Objectives = map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001}
	}

	summary := prometheus.NewSummaryVec(opts, labels)

	if err := m.registry.Register(summary); err != nil {
		return errors.Wrap(err, errors.ErrCodeConfigError, "failed to register summary")
	}

	m.summaries[name] = summary
	m.logger.Debug("Summary registered", zap.String("name", name))

	return nil
}

func (m *Metrics) IncrementCounter(name string, labels map[string]string) {
	if !m.config.Enabled {
		return
	}

	m.mutex.RLock()
	counter, exists := m.counters[name]
	m.mutex.RUnlock()

	if !exists {
		m.logger.Warn("Counter not found", zap.String("name", name))
		return
	}

	counter.With(labels).Inc()
}

func (m *Metrics) AddToCounter(name string, value float64, labels map[string]string) {
	if !m.config.Enabled {
		return
	}

	m.mutex.RLock()
	counter, exists := m.counters[name]
	m.mutex.RUnlock()

	if !exists {
		m.logger.Warn("Counter not found", zap.String("name", name))
		return
	}

	counter.With(labels).Add(value)
}

func (m *Metrics) RecordHistogram(name string, value float64, labels map[string]string) {
	if !m.config.Enabled {
		return
	}

	m.mutex.RLock()
	histogram, exists := m.histograms[name]
	m.mutex.RUnlock()

	if !exists {
		m.logger.Warn("Histogram not found", zap.String("name", name))
		return
	}

	histogram.With(labels).Observe(value)
}

func (m *Metrics) SetGauge(name string, value float64, labels map[string]string) {
	if !m.config.Enabled {
		return
	}

	m.mutex.RLock()
	gauge, exists := m.gauges[name]
	m.mutex.RUnlock()

	if !exists {
		m.logger.Warn("Gauge not found", zap.String("name", name))
		return
	}

	gauge.With(labels).Set(value)
}

func (m *Metrics) IncGauge(name string, labels map[string]string) {
	if !m.config.Enabled {
		return
	}

	m.mutex.RLock()
	gauge, exists := m.gauges[name]
	m.mutex.RUnlock()

	if !exists {
		m.logger.Warn("Gauge not found", zap.String("name", name))
		return
	}

	gauge.With(labels).Inc()
}

func (m *Metrics) DecGauge(name string, labels map[string]string) {
	if !m.config.Enabled {
		return
	}

	m.mutex.RLock()
	gauge, exists := m.gauges[name]
	m.mutex.RUnlock()

	if !exists {
		m.logger.Warn("Gauge not found", zap.String("name", name))
		return
	}

	gauge.With(labels).Dec()
}

func (m *Metrics) AddToGauge(name string, value float64, labels map[string]string) {
	if !m.config.Enabled {
		return
	}

	m.mutex.RLock()
	gauge, exists := m.gauges[name]
	m.mutex.RUnlock()

	if !exists {
		m.logger.Warn("Gauge not found", zap.String("name", name))
		return
	}

	gauge.With(labels).Add(value)
}

func (m *Metrics) RecordSummary(name string, value float64, labels map[string]string) {
	if !m.config.Enabled {
		return
	}

	m.mutex.RLock()
	summary, exists := m.summaries[name]
	m.mutex.RUnlock()

	if !exists {
		m.logger.Warn("Summary not found", zap.String("name", name))
		return
	}

	summary.With(labels).Observe(value)
}

func (m *Metrics) TimerStart(name string) *Timer {
	if !m.config.Enabled {
		return &Timer{enabled: false}
	}

	return &Timer{
		name:      name,
		startTime: time.Now(),
		enabled:   true,
		metrics:   m,
	}
}

func (m *Metrics) RecordDuration(name string, duration time.Duration, labels map[string]string) {
	m.RecordHistogram(name, duration.Seconds(), labels)
}

func (m *Metrics) GetRegistry() *prometheus.Registry {
	return m.registry
}

func (m *Metrics) IsEnabled() bool {
	return m.config.Enabled
}

func (m *Metrics) Shutdown(ctx context.Context) error {
	if !m.config.Enabled || m.server == nil {
		return nil
	}

	m.logger.Info("Shutting down metrics server")

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := m.server.Shutdown(shutdownCtx); err != nil {
		m.logger.Error("Failed to shutdown metrics server gracefully", zap.Error(err))
		return err
	}

	m.logger.Info("Metrics server shutdown completed")
	return nil
}

func (m *Metrics) RegisterBulkMetrics(definitions []MetricDefinition) error {
	if !m.config.Enabled {
		return nil
	}

	for _, def := range definitions {
		switch def.Type {
		case MetricTypeCounter:
			if err := m.RegisterCounter(def.Name, def.Help, def.Labels); err != nil {
				return err
			}
		case MetricTypeHistogram:
			if err := m.RegisterHistogram(def.Name, def.Help, def.Labels, def.Buckets); err != nil {
				return err
			}
		case MetricTypeGauge:
			if err := m.RegisterGauge(def.Name, def.Help, def.Labels); err != nil {
				return err
			}
		case MetricTypeSummary:
			if err := m.RegisterSummary(def.Name, def.Help, def.Labels, def.Objectives); err != nil {
				return err
			}
		default:
			return errors.New(errors.ErrCodeInvalidRequest, fmt.Sprintf("unsupported metric type: %s", def.Type))
		}
	}

	return nil
}

type Timer struct {
	name      string
	startTime time.Time
	enabled   bool
	metrics   *Metrics
}

func (t *Timer) Stop(labels map[string]string) time.Duration {
	duration := time.Since(t.startTime)
	
	if t.enabled && t.metrics != nil {
		t.metrics.RecordDuration(t.name, duration, labels)
	}
	
	return duration
}

func (t *Timer) StopWithStatus(status string, labels map[string]string) time.Duration {
	if labels == nil {
		labels = make(map[string]string)
	}
	labels["status"] = status
	
	return t.Stop(labels)
}

