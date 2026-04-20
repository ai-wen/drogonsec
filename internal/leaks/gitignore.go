package leaks

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// GitignoreMatcher resolves whether a file path is covered by the repo's
// .gitignore. Used to downgrade leak findings on intentionally ignored
// files (e.g. .env, .env.local) from CRITICAL/HIGH to INFO severity —
// keeping visibility of committed-by-accident leaks without generating
// noise on files the developer already excluded from VCS.
//
// See Issue #17 for the motivating false-positive pattern.
type GitignoreMatcher struct {
	root    string
	matcher gitignore.Matcher
}

// NewGitignoreMatcher parses <repoRoot>/.gitignore and returns a matcher.
// If no .gitignore is present or it cannot be read, a no-op matcher is
// returned (all IsIgnored calls yield false) — this is not an error.
func NewGitignoreMatcher(repoRoot string) *GitignoreMatcher {
	gm := &GitignoreMatcher{root: repoRoot}

	f, err := os.Open(filepath.Join(repoRoot, ".gitignore"))
	if err != nil {
		return gm // silently no-op on missing / unreadable
	}
	defer f.Close()

	var patterns []gitignore.Pattern
	scanner := bufio.NewScanner(f)
	// Cap .gitignore parsing to avoid OOM on malicious/huge files.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20) // 1 MiB per line max
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, gitignore.ParsePattern(line, nil))
	}
	if len(patterns) == 0 {
		return gm
	}
	gm.matcher = gitignore.NewMatcher(patterns)
	return gm
}

// IsIgnored returns true if absPath is covered by a rule in .gitignore.
// Paths outside repoRoot always return false.
func (gm *GitignoreMatcher) IsIgnored(absPath string) bool {
	if gm == nil || gm.matcher == nil {
		return false
	}
	rel, err := filepath.Rel(gm.root, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return false
	}
	// go-git gitignore Matcher expects path split on "/"; normalize
	// Windows separators to forward slash.
	parts := strings.Split(filepath.ToSlash(rel), "/")
	return gm.matcher.Match(parts, false)
}
