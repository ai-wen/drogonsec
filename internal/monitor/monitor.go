package monitor

import (
	"context"
	"fmt"
)

// Run is the package entry point. It validates the config, constructs the
// appropriate platform client, and starts either a webhook server or a
// polling loop depending on cfg.Mode.
func Run(ctx context.Context, cfg *Config) error {
	if err := ValidateBranchName(cfg.Branch); err != nil {
		return err
	}
	if err := ValidateRepoSlug(cfg.Repo); err != nil {
		return err
	}

	client, err := newClient(cfg)
	if err != nil {
		return err
	}

	// Verify the branch exists and credentials work before entering the loop.
	if _, err := client.GetBranchSHA(cfg.Branch); err != nil {
		return fmt.Errorf("pre-flight check failed: %w", err)
	}

	scanFn := func(branch string) error {
		return cloneAndScan(cfg, client, branch)
	}

	switch cfg.Mode {
	case ModeWebhook:
		srv := newWebhookServer(cfg, client, scanFn)
		return srv.Start(ctx)
	case ModePoll:
		p := newPoller(cfg, client, scanFn)
		return p.Run(ctx)
	default:
		return fmt.Errorf("unknown mode %q — must be 'webhook' or 'poll'", cfg.Mode)
	}
}

// newClient constructs a PlatformClient for the given platform.
func newClient(cfg *Config) (PlatformClient, error) {
	switch cfg.Platform {
	case PlatformGitHub:
		return newGitHubClient(cfg.Repo, cfg.Token, cfg.WebhookSecret), nil
	case PlatformGitLab:
		return newGitLabClient(cfg.Repo, cfg.Token, cfg.WebhookSecret), nil
	default:
		return nil, fmt.Errorf("unsupported platform %q — must be 'github' or 'gitlab'", cfg.Platform)
	}
}
