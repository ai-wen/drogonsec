package monitor

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const githubAPIBase = "https://api.github.com"

type githubClient struct {
	repo   string
	token  string
	secret string
	http   *http.Client
}

func newGitHubClient(repo, token, secret string) *githubClient {
	return &githubClient{
		repo:   repo,
		token:  token,
		secret: secret,
		http: &http.Client{
			Timeout: 15 * time.Second,
			// Never follow redirects: a 301/302 could redirect a credentialed
			// request to an attacker-controlled host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("refusing HTTP redirect (credential protection)")
			},
		},
	}
}

func (c *githubClient) GetBranchSHA(branch string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/branches/%s", githubAPIBase, c.repo, branch)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// Use Bearer token — never embed in URL to avoid server-log exposure.
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "drogonsec-monitor/0.1")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("GitHub token rejected (401) — check GITHUB_TOKEN scope (needs repo:read)")
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("branch %q not found in %s (404)", branch, c.repo)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API error: %s", resp.Status)
	}

	var result struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return "", fmt.Errorf("unexpected GitHub API response: %w", err)
	}
	if result.Commit.SHA == "" {
		return "", fmt.Errorf("GitHub API returned empty SHA")
	}
	return result.Commit.SHA, nil
}

func (c *githubClient) CloneURL() string {
	// Token embedded in HTTPS URL — only used for go-git's in-process clone,
	// never written to disk or printed.
	return fmt.Sprintf("https://oauth2:%s@github.com/%s.git", c.token, c.repo)
}

// ValidateWebhookSignature verifies the X-Hub-Signature-256 header using
// HMAC-SHA256 with constant-time comparison to prevent timing attacks.
func (c *githubClient) ValidateWebhookSignature(payload []byte, signature string) error {
	if c.secret == "" {
		return fmt.Errorf("webhook secret not configured (set WEBHOOK_SECRET)")
	}
	if !strings.HasPrefix(signature, "sha256=") {
		return fmt.Errorf("missing or malformed X-Hub-Signature-256 header")
	}
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	mac := hmac.New(sha256.New, []byte(c.secret))
	mac.Write(payload)
	expected := mac.Sum(nil)
	// ConstantTimeCompare prevents timing oracles that could reveal the secret.
	if subtle.ConstantTimeCompare(sigBytes, expected) != 1 {
		return fmt.Errorf("webhook signature mismatch — possible payload tampering")
	}
	return nil
}

type githubPushPayload struct {
	Ref string `json:"ref"` // "refs/heads/main"
}

func (c *githubClient) ParsePushBranch(payload []byte) (string, error) {
	var p githubPushPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return "", fmt.Errorf("invalid JSON payload: %w", err)
	}
	if !strings.HasPrefix(p.Ref, "refs/heads/") {
		return "", fmt.Errorf("not a branch push event (ref: %q)", p.Ref)
	}
	branch := strings.TrimPrefix(p.Ref, "refs/heads/")
	// Validate the extracted branch name to prevent downstream injection.
	if err := ValidateBranchName(branch); err != nil {
		return "", fmt.Errorf("webhook payload contains invalid branch name: %w", err)
	}
	return branch, nil
}
