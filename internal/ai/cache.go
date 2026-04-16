package ai

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// cacheDirName is the subdirectory under ~/.drogonsec for AI response cache.
	cacheDirName = "ai-cache"
	// defaultTTLHours is the default cache entry time-to-live in hours (7 days).
	defaultTTLHours = 168
)

// cacheEntry represents a single cached AI response on disk.
type cacheEntry struct {
	Provider string `json:"provider"`
	Created  string `json:"created"`
	TTLHours int    `json:"ttl_hours"`
	Response string `json:"response"`
}

// cacheKey builds a deterministic cache key from the given components.
// It returns the first 16 hex characters of the SHA-256 hash.
func cacheKey(provider, model, ruleID, severity, code string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s", provider, model, ruleID, severity, code)
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// cacheDir returns the absolute path to the cache directory.
func cacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".drogonsec", cacheDirName)
}

// getCached looks up a cached AI response for the given finding.
// Returns the cached response and true on hit, or empty string and false on miss.
func (c *Client) getCached(key string) (string, bool) {
	dir := cacheDir()
	if dir == "" {
		return "", false
	}

	path := filepath.Join(dir, key+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		// Corrupted entry — silently remove and treat as miss.
		os.Remove(path)
		return "", false
	}

	// Check TTL expiration.
	created, err := time.Parse(time.RFC3339, entry.Created)
	if err != nil {
		os.Remove(path)
		return "", false
	}

	ttl := time.Duration(entry.TTLHours) * time.Hour
	if time.Since(created) > ttl {
		os.Remove(path)
		return "", false
	}

	return entry.Response, true
}

// setCache stores an AI response in the file-based cache.
// Errors are silently ignored so cache failures never break the scan.
func (c *Client) setCache(key, response string) {
	dir := cacheDir()
	if dir == "" {
		return
	}

	// Lazy-create the cache directory on first write.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}

	providerLabel := c.cfg.Provider
	if c.cfg.Model != "" {
		providerLabel += ":" + c.cfg.Model
	}

	entry := cacheEntry{
		Provider: providerLabel,
		Created:  time.Now().UTC().Format(time.RFC3339),
		TTLHours: defaultTTLHours,
		Response: response,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return
	}

	_ = os.WriteFile(filepath.Join(dir, key+".json"), data, 0o644)
}
