package opa

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"exoper/backend/internal/common/config"
	"exoper/backend/internal/common/errors"
	"exoper/backend/pkg/api/models/policy"
)

type Cache struct {
	store       map[string]*CacheEntry
	config      *config.Config
	logger      *zap.Logger
	mu          sync.RWMutex
	stats       *CacheStats
	janitor     *CacheJanitor
	maxSize     int
	defaultTTL  time.Duration
	compression bool
	encryption  bool
}

type CacheEntry struct {
	Key        string                `json:"key"`
	Value      *policy.PolicyDecision `json:"value"`
	TTL        time.Duration         `json:"ttl"`
	CreatedAt  time.Time             `json:"created_at"`
	ExpiresAt  time.Time             `json:"expires_at"`
	AccessedAt time.Time             `json:"accessed_at"`
	AccessCount int64                `json:"access_count"`
	Size       int64                 `json:"size"`
	Compressed bool                  `json:"compressed"`
	Encrypted  bool                  `json:"encrypted"`
}

type CacheStats struct {
	Hits              int64         `json:"hits"`
	Misses            int64         `json:"misses"`
	Sets              int64         `json:"sets"`
	Deletes           int64         `json:"deletes"`
	Evictions         int64         `json:"evictions"`
	Expirations       int64         `json:"expirations"`
	TotalEntries      int64         `json:"total_entries"`
	TotalSize         int64         `json:"total_size"`
	HitRate           float64       `json:"hit_rate"`
	AverageAccessTime time.Duration `json:"average_access_time"`
	LastCleanup       time.Time     `json:"last_cleanup"`
	mu                sync.RWMutex
}

type CacheJanitor struct {
	interval time.Duration
	stop     chan bool
	cache    *Cache
}

type CacheConfig struct {
	MaxSize        int           `json:"max_size"`
	DefaultTTL     time.Duration `json:"default_ttl"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
	Compression    bool          `json:"compression"`
	Encryption     bool          `json:"encryption"`
}

func NewCache(cfg *config.Config, logger *zap.Logger) *Cache {
	cacheConfig := &CacheConfig{
		MaxSize:        10000,
		DefaultTTL:     5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
		Compression:    cfg.Cache.EnableCompression,
		Encryption:     cfg.Cache.EnableEncryption,
	}

	if cfg.Cache.DefaultTTL > 0 {
		cacheConfig.DefaultTTL = cfg.Cache.DefaultTTL
	}

	cache := &Cache{
		store:       make(map[string]*CacheEntry),
		config:      cfg,
		logger:      logger,
		stats:       &CacheStats{},
		maxSize:     cacheConfig.MaxSize,
		defaultTTL:  cacheConfig.DefaultTTL,
		compression: cacheConfig.Compression,
		encryption:  cacheConfig.Encryption,
	}

	cache.janitor = &CacheJanitor{
		interval: cacheConfig.CleanupInterval,
		stop:     make(chan bool),
		cache:    cache,
	}

	go cache.janitor.start()

	logger.Info("Policy cache initialized",
		zap.Int("max_size", cache.maxSize),
		zap.Duration("default_ttl", cache.defaultTTL),
		zap.Bool("compression", cache.compression),
		zap.Bool("encryption", cache.encryption))

	return cache
}

func (c *Cache) Get(key string) *policy.PolicyDecision {
	if key == "" {
		return nil
	}

	start := time.Now()
	c.mu.RLock()
	entry, exists := c.store[key]
	c.mu.RUnlock()

	if !exists {
		c.recordMiss()
		return nil
	}

	if c.isExpired(entry) {
		c.mu.Lock()
		delete(c.store, key)
		c.mu.Unlock()
		c.recordExpiration()
		c.recordMiss()
		return nil
	}

	c.mu.Lock()
	entry.AccessedAt = time.Now()
	entry.AccessCount++
	c.mu.Unlock()

	c.recordHit(time.Since(start))

	c.logger.Debug("Cache hit",
		zap.String("key", key),
		zap.Int64("access_count", entry.AccessCount),
		zap.Duration("age", time.Since(entry.CreatedAt)))

	return entry.Value
}

func (c *Cache) Set(key string, decision *policy.PolicyDecision, ttl time.Duration) error {
	if key == "" {
		return errors.NewValidationError("key", "Cache key cannot be empty", key)
	}

	if decision == nil {
		return errors.NewValidationError("decision", "Policy decision cannot be nil", decision)
	}

	if ttl <= 0 {
		ttl = c.defaultTTL
	}

	now := time.Now()
	entry := &CacheEntry{
		Key:         key,
		Value:       decision,
		TTL:         ttl,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		AccessedAt:  now,
		AccessCount: 0,
		Compressed:  c.compression,
		Encrypted:   c.encryption,
	}

	if c.compression || c.encryption {
		size, err := c.calculateEntrySize(entry)
		if err != nil {
			c.logger.Warn("Failed to calculate entry size", zap.Error(err))
		} else {
			entry.Size = size
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.store) >= c.maxSize {
		c.evictLRU()
	}

	c.store[key] = entry
	c.recordSet()

	c.logger.Debug("Cache set",
		zap.String("key", key),
		zap.Duration("ttl", ttl),
		zap.Int64("size", entry.Size))

	return nil
}

func (c *Cache) Delete(key string) bool {
	if key == "" {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.store[key]; exists {
		delete(c.store, key)
		c.recordDelete()
		c.logger.Debug("Cache delete", zap.String("key", key))
		return true
	}

	return false
}

func (c *Cache) ClearPattern(pattern string) int {
	if pattern == "" {
		return 0
	}

	regex, err := regexp.Compile(strings.ReplaceAll(pattern, "*", ".*"))
	if err != nil {
		c.logger.Error("Invalid cache pattern", zap.String("pattern", pattern), zap.Error(err))
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	cleared := 0
	for key := range c.store {
		if regex.MatchString(key) {
			delete(c.store, key)
			cleared++
		}
	}

	c.stats.mu.Lock()
	c.stats.Deletes += int64(cleared)
	c.stats.TotalEntries -= int64(cleared)
	c.stats.mu.Unlock()

	c.logger.Info("Cache pattern cleared",
		zap.String("pattern", pattern),
		zap.Int("cleared_entries", cleared))

	return cleared
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := len(c.store)
	c.store = make(map[string]*CacheEntry)

	c.stats.mu.Lock()
	c.stats.Deletes += int64(count)
	c.stats.TotalEntries = 0
	c.stats.TotalSize = 0
	c.stats.mu.Unlock()

	c.logger.Info("Cache cleared", zap.Int("cleared_entries", count))
}

func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.store)
}

func (c *Cache) GetStats() *CacheStats {
	c.stats.mu.RLock()
	defer c.stats.mu.RUnlock()

	stats := *c.stats
	
	if stats.Hits+stats.Misses > 0 {
		stats.HitRate = float64(stats.Hits) / float64(stats.Hits+stats.Misses)
	}

	c.mu.RLock()
	stats.TotalEntries = int64(len(c.store))
	
	var totalSize int64
	for _, entry := range c.store {
		totalSize += entry.Size
	}
	stats.TotalSize = totalSize
	c.mu.RUnlock()

	return &stats
}

func (c *Cache) isExpired(entry *CacheEntry) bool {
	return time.Now().After(entry.ExpiresAt)
}

func (c *Cache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.store {
		if oldestKey == "" || entry.AccessedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.AccessedAt
		}
	}

	if oldestKey != "" {
		delete(c.store, oldestKey)
		c.recordEviction()
		c.logger.Debug("Cache LRU eviction", zap.String("key", oldestKey))
	}
}

func (c *Cache) calculateEntrySize(entry *CacheEntry) (int64, error) {
	data, err := json.Marshal(entry.Value)
	if err != nil {
		return 0, err
	}

	size := int64(len(data))
	
	if c.compression {
		size = size / 2
	}

	if c.encryption {
		size += 32
	}

	return size, nil
}

func (c *Cache) recordHit(accessTime time.Duration) {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()

	c.stats.Hits++
	
	if c.stats.Hits > 0 {
		totalTime := time.Duration(c.stats.Hits-1) * c.stats.AverageAccessTime
		c.stats.AverageAccessTime = (totalTime + accessTime) / time.Duration(c.stats.Hits)
	} else {
		c.stats.AverageAccessTime = accessTime
	}
}

func (c *Cache) recordMiss() {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	c.stats.Misses++
}

func (c *Cache) recordSet() {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	c.stats.Sets++
	c.stats.TotalEntries++
}

func (c *Cache) recordDelete() {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	c.stats.Deletes++
	c.stats.TotalEntries--
}

func (c *Cache) recordEviction() {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	c.stats.Evictions++
	c.stats.TotalEntries--
}

func (c *Cache) recordExpiration() {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	c.stats.Expirations++
	c.stats.TotalEntries--
}

func (cj *CacheJanitor) start() {
	ticker := time.NewTicker(cj.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cj.cleanup()
		case <-cj.stop:
			return
		}
	}
}

func (cj *CacheJanitor) cleanup() {
	start := time.Now()
	expired := 0
	
	cj.cache.mu.Lock()
	defer cj.cache.mu.Unlock()

	for key, entry := range cj.cache.store {
		if cj.cache.isExpired(entry) {
			delete(cj.cache.store, key)
			expired++
		}
	}

	if expired > 0 {
		cj.cache.stats.mu.Lock()
		cj.cache.stats.Expirations += int64(expired)
		cj.cache.stats.TotalEntries -= int64(expired)
		cj.cache.stats.LastCleanup = time.Now()
		cj.cache.stats.mu.Unlock()

		cj.cache.logger.Debug("Cache cleanup completed",
			zap.Int("expired_entries", expired),
			zap.Duration("duration", time.Since(start)))
	}
}

func (cj *CacheJanitor) Stop() {
	close(cj.stop)
}

func (c *Cache) GetEntry(key string) *CacheEntry {
	if key == "" {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.store[key]
	if !exists || c.isExpired(entry) {
		return nil
	}

	entryCopy := *entry
	return &entryCopy
}

func (c *Cache) GetKeys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.store))
	for key, entry := range c.store {
		if !c.isExpired(entry) {
			keys = append(keys, key)
		}
	}

	return keys
}

func (c *Cache) GetKeysByPattern(pattern string) []string {
	if pattern == "" {
		return []string{}
	}

	regex, err := regexp.Compile(strings.ReplaceAll(pattern, "*", ".*"))
	if err != nil {
		c.logger.Error("Invalid cache pattern", zap.String("pattern", pattern), zap.Error(err))
		return []string{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var keys []string
	for key, entry := range c.store {
		if !c.isExpired(entry) && regex.MatchString(key) {
			keys = append(keys, key)
		}
	}

	return keys
}

func (c *Cache) Exists(key string) bool {
	if key == "" {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.store[key]
	return exists && !c.isExpired(entry)
}

func (c *Cache) TTL(key string) time.Duration {
	if key == "" {
		return -1
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.store[key]
	if !exists {
		return -1
	}

	if c.isExpired(entry) {
		return 0
	}

	return time.Until(entry.ExpiresAt)
}

func (c *Cache) Extend(key string, duration time.Duration) bool {
	if key == "" || duration <= 0 {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.store[key]
	if !exists || c.isExpired(entry) {
		return false
	}

	entry.ExpiresAt = entry.ExpiresAt.Add(duration)
	entry.TTL += duration

	c.logger.Debug("Cache entry TTL extended",
		zap.String("key", key),
		zap.Duration("extension", duration),
		zap.Time("new_expiry", entry.ExpiresAt))

	return true
}

func (c *Cache) Touch(key string) bool {
	if key == "" {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.store[key]
	if !exists || c.isExpired(entry) {
		return false
	}

	entry.AccessedAt = time.Now()
	entry.AccessCount++

	return true
}

func (c *Cache) GetMultiple(keys []string) map[string]*policy.PolicyDecision {
	if len(keys) == 0 {
		return make(map[string]*policy.PolicyDecision)
	}

	result := make(map[string]*policy.PolicyDecision)
	
	for _, key := range keys {
		if decision := c.Get(key); decision != nil {
			result[key] = decision
		}
	}

	return result
}

func (c *Cache) SetMultiple(entries map[string]*policy.PolicyDecision, ttl time.Duration) error {
	if len(entries) == 0 {
		return nil
	}

	var errors []string
	
	for key, decision := range entries {
		if err := c.Set(key, decision, ttl); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %s", key, err.Error()))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to set cache entries: %s", strings.Join(errors, "; "))
	}

	return nil
}

func (c *Cache) DeleteMultiple(keys []string) int {
	if len(keys) == 0 {
		return 0
	}

	deleted := 0
	for _, key := range keys {
		if c.Delete(key) {
			deleted++
		}
	}

	return deleted
}

func (c *Cache) GetExpiredKeys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var expiredKeys []string
	for key, entry := range c.store {
		if c.isExpired(entry) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	return expiredKeys
}

func (c *Cache) CleanupExpired() int {
	expiredKeys := c.GetExpiredKeys()
	
	if len(expiredKeys) == 0 {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	cleaned := 0
	for _, key := range expiredKeys {
		if _, exists := c.store[key]; exists {
			delete(c.store, key)
			cleaned++
		}
	}

	if cleaned > 0 {
		c.stats.mu.Lock()
		c.stats.Expirations += int64(cleaned)
		c.stats.TotalEntries -= int64(cleaned)
		c.stats.mu.Unlock()

		c.logger.Debug("Manual cache cleanup",
			zap.Int("cleaned_entries", cleaned))
	}

	return cleaned
}

func (c *Cache) GetMemoryUsage() map[string]interface{} {
	stats := c.GetStats()
	
	return map[string]interface{}{
		"total_entries": stats.TotalEntries,
		"total_size_bytes": stats.TotalSize,
		"max_size": c.maxSize,
		"utilization_percent": float64(stats.TotalEntries) / float64(c.maxSize) * 100,
		"average_entry_size": func() int64 {
			if stats.TotalEntries > 0 {
				return stats.TotalSize / stats.TotalEntries
			}
			return 0
		}(),
	}
}

func (c *Cache) GetPerformanceMetrics() map[string]interface{} {
	stats := c.GetStats()
	
	return map[string]interface{}{
		"hit_rate": stats.HitRate,
		"miss_rate": 1.0 - stats.HitRate,
		"hits": stats.Hits,
		"misses": stats.Misses,
		"sets": stats.Sets,
		"deletes": stats.Deletes,
		"evictions": stats.Evictions,
		"expirations": stats.Expirations,
		"average_access_time_ms": stats.AverageAccessTime.Milliseconds(),
		"last_cleanup": stats.LastCleanup,
	}
}

func (c *Cache) HealthCheck() error {
	stats := c.GetStats()
	
	if stats.TotalEntries < 0 {
		return errors.New(errors.ErrCodeCacheError, "Invalid cache state: negative entry count")
	}

	if c.maxSize > 0 && stats.TotalEntries > int64(c.maxSize) {
		return errors.New(errors.ErrCodeInternalError, "Cache size exceeded maximum limit")
	}

	memUsage := c.GetMemoryUsage()
	if utilization, ok := memUsage["utilization_percent"].(float64); ok && utilization > 95.0 {
		c.logger.Warn("Cache utilization high", zap.Float64("utilization_percent", utilization))
	}

	return nil
}

func (c *Cache) Optimize() {
	start := time.Now()
	
	cleaned := c.CleanupExpired()
	
	c.mu.Lock()
	currentSize := len(c.store)
	targetSize := int(float64(c.maxSize) * 0.8)
	
	if currentSize > targetSize {
		evicted := 0
		for key, entry := range c.store {
			if evicted >= (currentSize - targetSize) {
				break
			}
			
			if time.Since(entry.AccessedAt) > time.Hour && entry.AccessCount < 5 {
				delete(c.store, key)
				evicted++
			}
		}
		
		if evicted > 0 {
			c.stats.mu.Lock()
			c.stats.Evictions += int64(evicted)
			c.stats.TotalEntries -= int64(evicted)
			c.stats.mu.Unlock()
		}
	}
	c.mu.Unlock()

	c.logger.Info("Cache optimization completed",
		zap.Int("cleaned_expired", cleaned),
		zap.Duration("duration", time.Since(start)))
}

func (c *Cache) Export() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	export := make(map[string]interface{})
	
	for key, entry := range c.store {
		if !c.isExpired(entry) {
			export[key] = map[string]interface{}{
				"value": entry.Value,
				"ttl": entry.TTL,
				"created_at": entry.CreatedAt,
				"expires_at": entry.ExpiresAt,
				"access_count": entry.AccessCount,
			}
		}
	}

	return export
}

func (c *Cache) Import(data map[string]interface{}) error {
	if len(data) == 0 {
		return nil
	}

	imported := 0
	failed := 0

	for key, value := range data {
		entryData, ok := value.(map[string]interface{})
		if !ok {
			failed++
			continue
		}

		decision, ok := entryData["value"].(*policy.PolicyDecision)
		if !ok {
			failed++
			continue
		}

		ttl := c.defaultTTL
		if ttlValue, exists := entryData["ttl"]; exists {
			if duration, ok := ttlValue.(time.Duration); ok {
				ttl = duration
			}
		}

		if err := c.Set(key, decision, ttl); err != nil {
			failed++
		} else {
			imported++
		}
	}

	c.logger.Info("Cache import completed",
		zap.Int("imported", imported),
		zap.Int("failed", failed))

	return nil
}

func (c *Cache) Close() error {
	c.logger.Info("Shutting down cache")
	
	if c.janitor != nil {
		c.janitor.Stop()
	}

	c.Clear()
	
	c.logger.Info("Cache shutdown completed")
	return nil
}
