package monitor

import (
	"time"

	"github.com/filipi86/drogonsec/internal/config"
)

// Platform identifies the Git hosting provider.
type Platform string

const (
	PlatformGitHub Platform = "github"
	PlatformGitLab Platform = "gitlab"
)

// Mode controls how DrogonSec receives change notifications.
type Mode string

const (
	// ModeWebhook starts an HTTP server and reacts to push events in real time.
	ModeWebhook Mode = "webhook"
	// ModePoll periodically queries the API and scans when the branch HEAD changes.
	ModePoll Mode = "poll"
)

// Config holds all settings for a monitoring session.
// Sensitive values (Token, WebhookSecret) must be sourced from environment
// variables by the caller — never from CLI flags.
type Config struct {
	Platform Platform
	Repo     string // "owner/repo"
	Branch   string // branch name to watch

	// Credentials — populated from env, never flags.
	Token         string // GITHUB_TOKEN or GITLAB_TOKEN
	WebhookSecret string // WEBHOOK_SECRET (HMAC key for GitHub; shared token for GitLab)

	Mode Mode

	// Webhook mode.
	ListenAddr  string // e.g. ":8080"
	TLSCertFile string
	TLSKeyFile  string

	// Poll mode.
	Interval time.Duration

	// Scan settings forwarded to the analyzer on each trigger.
	ScanConfig *config.ScanConfig
}
