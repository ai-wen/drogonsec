# Security Hardening

---

## Overview

Drogonsec implements several internal security controls to protect users and their data when running scans and generating reports.

---

## XSS Prevention in HTML Reports

All user-controlled data written to HTML reports is escaped using Go's standard `html.EscapeString()` before insertion into the template.

Affected fields across SAST, Leaks, and SCA findings:

| Engine | Escaped fields |
|--------|---------------|
| SAST | Title, File, RuleID, OWASP, CWE, Description, Remediation, AI Remediation |
| Leaks | Type, File, RuleID, Match, Description, AI Remediation |
| SCA | PackageName, PackageVersion, CVE, ManifestFile, FixedVersion, Ecosystem, Description, Advisory |

This prevents a malicious file path, variable name, or secret value in the scanned codebase from injecting scripts into the generated report when opened in a browser.

---

## HTTPS Enforcement for AI Endpoints

When a custom AI endpoint is configured (e.g. a self-hosted model or proxy), Drogonsec enforces HTTPS to prevent API key exfiltration over unencrypted connections.

**Allowed endpoints:**

```
https://         — any HTTPS endpoint
http://localhost — local development only
http://127.0.0.1 — local development only
```

Any other `http://` endpoint is silently replaced with the default Anthropic endpoint. This prevents accidental misconfiguration from sending API keys in plaintext over the network.

Configuration example (`.drogonsec.yaml`):

```yaml
ai:
  enabled: true
  endpoint: "https://your-proxy.internal/v1"  # must be HTTPS
  api_key: "sk-..."
```

---

## ReDoS Protection in Leak Detection

The secret detection engine applies a 10,000-byte line length limit before running regex patterns against source code lines.

```
if len(line) > 10,000 bytes → skip line
```

This prevents **ReDoS (Regular Expression Denial of Service)** — a class of attack where crafted input causes catastrophic backtracking in complex regex patterns, leading to CPU exhaustion and scanner hangs.

Both file scanning and Git history scanning are protected:

- `ScanFile()` — per-line guard before pattern matching
- `ScanGitHistory()` — per-line guard before pattern matching

The 10,000-byte limit is well above any realistic source code line and has no impact on normal scans.

---

## Supply Chain Security in CI

Drogonsec's own CI pipeline applies two layers of supply chain protection on every build:

### go mod verify

Validates that all downloaded modules match the checksums in `go.sum`. Detects if a dependency was tampered with or substituted after the lockfile was committed.

### govulncheck

Scans direct and transitive dependencies against the [Go Vulnerability Database](https://vuln.go.dev). Only reports vulnerabilities that are reachable in the actual call graph — eliminating noise from unused code paths.

Both checks run before compilation and block the build if they detect an issue.

See [CI/CD Pipelines](ci-cd.md) for the full pipeline details.
