# 🤖 AI-Powered Remediation

DrogonSec includes a built-in AI remediation engine that enriches security findings with context-aware, actionable fix suggestions. It supports local inference via **Ollama** (free, no data leaves your machine) and cloud providers such as **Anthropic**, **OpenAI**, and **Azure**.

---

## How It Works

When `--enable-ai` is passed, DrogonSec runs its full scan first and then sends qualifying findings to the configured AI provider for remediation enrichment.

```
scan findings
      │
      ▼
 filter: only HIGH + CRITICAL SAST
         + up to 5 Leak findings
      │
      ▼
 check local cache (~/.drogonsec/ai-cache/)
      │
  ┌───┴──────────────┐
cached?             not cached
  │                     │
  ▼                     ▼
return ⚡          call AI provider
                        │
                        ▼
                 store in cache (7-day TTL)
                        │
                        ▼
              enrich Finding.AIRemediation
                        │
                        ▼
               render in report output
```

AI remediation is **non-blocking** — if the AI provider is unavailable or times out, the scan completes normally with un-enriched findings.

---

## Quick Start

### Option 1 — Ollama (local, free, no API key)

```bash
# 1. Install Ollama
brew install ollama          # macOS
# or visit https://ollama.com for Linux/Windows

# 2. Pull a model (deepseek-coder is the default)
ollama pull deepseek-coder

# 3. Run Ollama in the background
ollama serve

# 4. Scan with AI remediation — DrogonSec auto-detects Ollama
drogonsec scan . --enable-ai
```

### Option 2 — Anthropic Claude (cloud)

```bash
export AI_API_KEY="sk-ant-..."
drogonsec scan . --enable-ai --ai-provider anthropic
```

### Option 3 — OpenAI (cloud)

```bash
export AI_API_KEY="sk-..."
drogonsec scan . --enable-ai --ai-provider openai --ai-endpoint https://api.openai.com/v1/messages
```

---

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-ai` | `false` | Enable AI-powered remediation |
| `--ai-provider` | `anthropic` | Provider: `ollama` \| `anthropic` \| `openai` \| `azure` \| `custom` |
| `--ai-model` | *(provider default)* | Override model name |
| `--ai-endpoint` | *(provider default)* | Custom API endpoint URL |
| `--ai-key` | *(env var)* | API key (overrides `AI_API_KEY`) |
| `--ai-timeout` | `30` (cloud) / `120` (Ollama) | Request timeout in seconds |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AI_API_KEY` | Primary API key for cloud providers |
| `ANTHROPIC_API_KEY` | Fallback key (Anthropic-specific) |

**Resolution priority:** `--ai-key` flag → `AI_API_KEY` → `ANTHROPIC_API_KEY`

---

## Supported Providers

### Ollama — Recommended for Open-Source Use

| Property | Value |
|----------|-------|
| Cost | Free |
| Privacy | 100% local — no data leaves your machine |
| Default model | `deepseek-coder` |
| Default endpoint | `http://127.0.0.1:11434/api/generate` |
| Timeout | 120 seconds |
| API key | Not required |

DrogonSec automatically detects a running Ollama instance when `--enable-ai` is set and no API key is provided. If Ollama is not running, it falls back to an error prompting for credentials.

```bash
# Use a different local model
drogonsec scan . --enable-ai --ai-provider ollama --ai-model codellama
```

### Anthropic

| Property | Value |
|----------|-------|
| Default model | `claude-sonnet-4-6` |
| Default endpoint | `https://api.anthropic.com/v1/messages` |
| Timeout | 30 seconds |
| Auth header | `x-api-key` |

```bash
AI_API_KEY="sk-ant-..." drogonsec scan . --enable-ai --ai-provider anthropic
```

### OpenAI / Azure / Custom

All three use `Authorization: Bearer <key>` authentication. Provide a custom endpoint for Azure or self-hosted deployments.

```bash
# OpenAI
AI_API_KEY="sk-..." drogonsec scan . \
  --enable-ai \
  --ai-provider openai \
  --ai-endpoint https://api.openai.com/v1/messages \
  --ai-model gpt-4o

# Azure OpenAI
AI_API_KEY="..." drogonsec scan . \
  --enable-ai \
  --ai-provider azure \
  --ai-endpoint https://<resource>.openai.azure.com/... \
  --ai-model gpt-4o

# Self-hosted / compatible endpoint
AI_API_KEY="..." drogonsec scan . \
  --enable-ai \
  --ai-provider custom \
  --ai-endpoint https://my-llm.internal/v1/messages
```

---

## What Gets Enriched

AI remediation is **selective by design** to minimize API costs and latency:

| Finding type | Enriched? | Condition |
|---|---|---|
| SAST — CRITICAL | ✅ | Always |
| SAST — HIGH | ✅ | Always |
| SAST — MEDIUM / LOW | ❌ | Skipped |
| Leak findings | ✅ | First 5 only |
| SCA (CVEs) | ❌ | Use CVE advisories directly |

To enrich only high-severity findings in config:

```yaml
# .drogonsec.yaml
ai:
  enabled: false          # use --enable-ai flag at runtime
  high_severity_only: true
```

---

## Output

### Text format

```
  #1 [CRITICAL] SQL Injection via string formatting
  File     : src/users.py:42
  Rule     : PY-001
  OWASP    : A05:2025 - Injection
  CWE      : CWE-89  CVSS: 9.8
  Fix      : Use parameterized queries instead of string formatting.

  🤖 AI Remediation:
  This vulnerability allows an attacker to manipulate the SQL query structure,
  potentially exposing or corrupting all data in the database.

  Corrected code:
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

  Additional controls:
  - Enable query logging to detect injection attempts
  - Use an ORM layer (SQLAlchemy) for additional abstraction
```

### HTML report

AI remediation sections appear as purple cards beneath each finding, clearly separated from the static rule-based fix.

### JSON

```json
{
  "sast_findings": [
    {
      "rule_id": "PY-001",
      "severity": "CRITICAL",
      "ai_remediation": "This vulnerability allows an attacker..."
    }
  ]
}
```

### Progress output during scan

```
  🤖 Running AI remediation (12 findings)...

  → [1/12] SQL Injection via string formatting...     ⚡ cached
  → [2/12] XSS vulnerability in template...           0.8s
  → [3/12] Exposed AWS Key in config.py...            1.2s
  → [4/12] Insecure deserialization...                ✗ error
  ...
  ✓ AI enrichment complete (3 cached, 8 new, 1 error) — 12.4s total
```

Status indicators:
- `⚡ cached` — served from local disk cache (< 100 ms)
- `1.2s` — fresh API call
- `✗ error` — provider unreachable or timed out (finding kept without AI section)

---

## Caching

DrogonSec caches AI responses locally to avoid redundant API calls across repeated scans.

| Property | Value |
|----------|-------|
| Cache location | `~/.drogonsec/ai-cache/` |
| Directory permission | `0700` (user-only) |
| File permission | `0600` (user-only) |
| TTL | 7 days |
| Cache key | `SHA256(provider + model + ruleID + severity + code_snippet)` |
| Integrity tag | `HMAC-SHA256(response)` — per-user key in `~/.drogonsec/ai-cache/cache.key` (0600) |
| Scope | Per provider + model combination |

Cache hits are shown in scan progress with the `⚡` symbol. Expired entries are removed automatically on the next read.

### Integrity guarantee

Every cached entry is HMAC-tagged on write and verified on read. If an entry is tampered with on disk (e.g., on a shared CI filesystem), the mismatching HMAC causes the entry to be discarded and a fresh call is made — DrogonSec will never display un-verified remediation text as if it came from the AI provider.

---

## Privacy & Security

### No HTTP redirects followed

The AI HTTP client refuses to follow HTTP 3xx redirects. Go's default client preserves the `x-api-key` header across redirects — a hostile or misconfigured endpoint responding with `302 Location: https://evil.example.com/` would otherwise leak the API key to a third-party host. DrogonSec fails loudly with an explicit error instead of silently leaking credentials.

### Endpoint validation

DrogonSec rejects plaintext HTTP endpoints unless the host resolves to a loopback address (`127.x.x.x`, `::1`). This prevents accidental transmission of source code and API keys over unencrypted connections.

```
# Rejected (plaintext, non-local):
--ai-endpoint http://my-llm.company.com/v1

# Accepted (HTTPS):
--ai-endpoint https://my-llm.company.com/v1

# Accepted (local plaintext — Ollama default):
--ai-endpoint http://127.0.0.1:11434/api/generate
```

### Data sent to the model

For each finding, DrogonSec sends:
- The vulnerable code snippet
- File path and line number
- Rule ID, OWASP category, CWE, CVSS score
- Severity level and language

**No other files or tokens from your repository are sent.**

### Using Ollama for full data isolation

With Ollama running locally, all inference happens on your machine. No source code, credentials, or finding details leave your environment. This is the recommended configuration for proprietary or regulated codebases.

---

## Configuration via `.drogonsec.yaml`

```yaml
ai:
  enabled: false           # enable via --enable-ai flag at runtime
  provider: "ollama"       # ollama | anthropic | openai | azure | custom
  model: ""                # leave empty for provider default
  endpoint: ""             # leave empty for provider default
  api_key: ""              # prefer AI_API_KEY env var
  timeout: 0               # 0 = auto (30s cloud, 120s Ollama)
  high_severity_only: true # skip MEDIUM/LOW findings
```

---

## Troubleshooting

### Ollama not detected

```
AI unavailable: no API key provided and Ollama not reachable at http://127.0.0.1:11434
```

Ensure Ollama is running before scanning:

```bash
ollama serve &
drogonsec scan . --enable-ai
```

### Timeout on large codebases

Increase the timeout for local models that need more inference time:

```bash
drogonsec scan . --enable-ai --ai-provider ollama --ai-timeout 300
```

### Cache not reducing API calls

The cache key includes the code snippet. If the file changed between scans, a new API call is made. To force cache reuse across minor changes, use `--ai-model` to pin the exact model version alongside the provider.

### Scan fails with HTTPS endpoint error

```
endpoint must use HTTPS (got http://...)
```

Switch to HTTPS or use a loopback address for local inference:

```bash
# Force Ollama over loopback (default — works as-is)
drogonsec scan . --enable-ai --ai-provider ollama

# External endpoint must use TLS
drogonsec scan . --enable-ai --ai-endpoint https://secure-endpoint.com/v1
```

---

## CI/CD Integration

### GitHub Actions with Ollama (no secrets needed)

```yaml
- name: Install Ollama
  run: |
    curl -fsSL https://ollama.com/install.sh | sh
    ollama serve &
    sleep 5
    ollama pull deepseek-coder

- name: Scan with AI remediation
  run: drogonsec scan . --enable-ai --format sarif --output results.sarif
```

### GitHub Actions with Anthropic

```yaml
- name: Scan with AI remediation
  env:
    AI_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    drogonsec scan . \
      --enable-ai \
      --ai-provider anthropic \
      --format sarif \
      --output results.sarif
```

---

## Related Pages

- [Usage](usage.md) — all CLI flags and output formats
- [Modules](modules.md) — SAST, SCA, and Leaks engine details
- [CI/CD Pipelines](ci-cd.md) — full pipeline examples with security gates
