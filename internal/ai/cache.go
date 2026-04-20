package ai

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	// integrityKeyFile holds the per-user HMAC key (0o600) used to tag
	// cached entries. If the key file is missing or the HMAC on an entry
	// does not match, the entry is discarded — this defends against
	// cache poisoning on multi-tenant filesystems where an attacker with
	// write (but not read) access could inject malicious "remediation"
	// text into a future scan output.
	integrityKeyFile = "cache.key"
)

// cacheEntry represents a single cached AI response on disk.
type cacheEntry struct {
	Provider  string `json:"provider"`
	Created   string `json:"created"`
	TTLHours  int    `json:"ttl_hours"`
	Response  string `json:"response"`
	Integrity string `json:"integrity,omitempty"` // hex HMAC-SHA256 of Response
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

// loadOrCreateIntegrityKey returns the per-user HMAC key used to sign
// cache entries. A fresh 32-byte random key is generated on first use
// and stored with mode 0o600. Returns nil on failure — callers treat
// nil as "integrity disabled" (entries are still written but without
// a tag, and unsigned entries are accepted).
func loadOrCreateIntegrityKey() []byte {
	dir := cacheDir()
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, integrityKeyFile)
	if data, err := os.ReadFile(path); err == nil && len(data) >= 32 {
		return data[:32]
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil
	}
	return key
}

func computeIntegrity(key []byte, response string) string {
	if key == nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(response))
	return hex.EncodeToString(mac.Sum(nil))
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

	// Verify HMAC integrity when the stored entry carries a tag AND the
	// current user's key loads successfully. A tag with a mismatching
	// HMAC means the entry was tampered with (or came from a different
	// user's key) and must be discarded.
	if entry.Integrity != "" {
		if ikey := loadOrCreateIntegrityKey(); ikey != nil {
			if !hmac.Equal([]byte(computeIntegrity(ikey, entry.Response)), []byte(entry.Integrity)) {
				os.Remove(path)
				return "", false
			}
		}
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

	// Lazy-create the cache directory on first write with user-only perms.
	// Cached entries contain the vulnerable source snippet plus the AI
	// response; on shared workstations that should not be world-readable.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}

	providerLabel := c.cfg.Provider
	if c.cfg.Model != "" {
		providerLabel += ":" + c.cfg.Model
	}

	entry := cacheEntry{
		Provider:  providerLabel,
		Created:   time.Now().UTC().Format(time.RFC3339),
		TTLHours:  defaultTTLHours,
		Response:  response,
		Integrity: computeIntegrity(loadOrCreateIntegrityKey(), response),
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return
	}

	_ = os.WriteFile(filepath.Join(dir, key+".json"), data, 0o600)
}
