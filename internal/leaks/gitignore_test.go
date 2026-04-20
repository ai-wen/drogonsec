package leaks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitignoreMatcher_IsIgnored(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".gitignore"), []byte(`
# secrets
.env
.env.*
!.env.example
config/secrets/
`), 0o644); err != nil {
		t.Fatal(err)
	}

	gm := NewGitignoreMatcher(tmp)

	cases := []struct {
		rel  string
		want bool
	}{
		{".env", true},
		{".env.local", true},
		{".env.production", true},
		{".env.example", false}, // negated pattern
		{"config/secrets/keys.yaml", true},
		{"src/app.go", false},
		{"README.md", false},
	}
	for _, tc := range cases {
		got := gm.IsIgnored(filepath.Join(tmp, tc.rel))
		if got != tc.want {
			t.Errorf("IsIgnored(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}

func TestGitignoreMatcher_NoFile(t *testing.T) {
	tmp := t.TempDir()
	gm := NewGitignoreMatcher(tmp)
	if gm.IsIgnored(filepath.Join(tmp, "anything")) {
		t.Error("expected no-op matcher to return false when .gitignore is absent")
	}
}

func TestGitignoreMatcher_NilSafe(t *testing.T) {
	var gm *GitignoreMatcher
	if gm.IsIgnored("/tmp/x") {
		t.Error("nil matcher must return false")
	}
}
