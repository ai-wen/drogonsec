package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── Client construction tests ────────────────────────────────────────────────

func TestNewClient_OllamaDefaults(t *testing.T) {
	c := New(ClientConfig{Provider: "ollama"})

	if c.cfg.Model != defaultOllamaModel {
		t.Errorf("expected model %q, got %q", defaultOllamaModel, c.cfg.Model)
	}
	if c.cfg.Endpoint != defaultOllamaEndpoint {
		t.Errorf("expected endpoint %q, got %q", defaultOllamaEndpoint, c.cfg.Endpoint)
	}
	if c.httpClient.Timeout != defaultOllamaTimeout {
		t.Errorf("expected timeout %v, got %v", defaultOllamaTimeout, c.httpClient.Timeout)
	}
}

func TestNewClient_AnthropicDefaults(t *testing.T) {
	c := New(ClientConfig{})

	if c.cfg.Provider != defaultProvider {
		t.Errorf("expected provider %q, got %q", defaultProvider, c.cfg.Provider)
	}
	if c.cfg.Model != defaultModel {
		t.Errorf("expected model %q, got %q", defaultModel, c.cfg.Model)
	}
	if c.cfg.Endpoint != defaultEndpoint {
		t.Errorf("expected endpoint %q, got %q", defaultEndpoint, c.cfg.Endpoint)
	}
	if c.httpClient.Timeout != defaultCloudTimeout {
		t.Errorf("expected timeout %v, got %v", defaultCloudTimeout, c.httpClient.Timeout)
	}
}

func TestNewClient_CustomTimeout(t *testing.T) {
	custom := 45 * time.Second
	c := New(ClientConfig{Provider: "ollama", Timeout: custom})

	if c.httpClient.Timeout != custom {
		t.Errorf("expected timeout %v, got %v", custom, c.httpClient.Timeout)
	}
}

func TestNewClient_OllamaCustomModel(t *testing.T) {
	c := New(ClientConfig{Provider: "ollama", Model: "codellama"})

	if c.cfg.Model != "codellama" {
		t.Errorf("expected model %q, got %q", "codellama", c.cfg.Model)
	}
}

// ── Endpoint safety tests ────────────────────────────────────────────────────

func TestIsEndpointSafe_HTTPS(t *testing.T) {
	if !isEndpointSafe("https://api.openai.com/v1") {
		t.Error("HTTPS should always be safe")
	}
}

func TestIsEndpointSafe_Loopback(t *testing.T) {
	if !isEndpointSafe("http://127.0.0.1:11434/api/generate") {
		t.Error("HTTP loopback should be safe")
	}
}

func TestIsEndpointSafe_IPv6Loopback(t *testing.T) {
	if !isEndpointSafe("http://[::1]:11434/api/generate") {
		t.Error("IPv6 loopback should be safe")
	}
}

func TestIsEndpointSafe_ExternalHTTPReject(t *testing.T) {
	if isEndpointSafe("http://192.168.1.50:11434") {
		t.Error("external HTTP should be rejected")
	}
}

func TestIsEndpointSafe_LocalhostStringReject(t *testing.T) {
	// "localhost" is a hostname, not an IP — could resolve to anything
	if isEndpointSafe("http://localhost:11434") {
		t.Error("http://localhost should be rejected (not a loopback IP)")
	}
}

func TestIsEndpointSafe_EvilDomainReject(t *testing.T) {
	if isEndpointSafe("http://localhost.evil.com:11434") {
		t.Error("spoofed localhost domain should be rejected")
	}
}

// ── Ollama call tests ────────────────────────────────────────────────────────

func TestCallOllama_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var req ollamaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}

		if req.Model != "deepseek-coder" {
			t.Errorf("expected model deepseek-coder, got %s", req.Model)
		}
		if req.Stream {
			t.Error("expected stream=false")
		}

		json.NewEncoder(w).Encode(ollamaResponse{
			Response: "Use parameterized queries to prevent SQL injection.",
			Done:     true,
		})
	}))
	defer srv.Close()

	c := New(ClientConfig{
		Provider: "ollama",
		Endpoint: srv.URL,
	})

	result, err := c.callOllama("fix SQL injection", "You are a security expert.", 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "parameterized queries") {
		t.Errorf("unexpected response: %s", result)
	}
}

func TestCallOllama_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(ollamaResponse{
			Error: "model 'nonexistent' not found",
		})
	}))
	defer srv.Close()

	c := New(ClientConfig{
		Provider: "ollama",
		Endpoint: srv.URL,
	})

	_, err := c.callOllama("test", "system", 1024)
	if err == nil {
		t.Fatal("expected error for ollama error response")
	}
	if !strings.Contains(err.Error(), "model") {
		t.Errorf("error should mention model: %v", err)
	}
}

func TestCallOllama_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(ollamaResponse{
			Response: "",
			Done:     true,
		})
	}))
	defer srv.Close()

	c := New(ClientConfig{
		Provider: "ollama",
		Endpoint: srv.URL,
	})

	_, err := c.callOllama("test", "system", 1024)
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

func TestCallOllama_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer srv.Close()

	c := New(ClientConfig{
		Provider: "ollama",
		Endpoint: srv.URL,
	})

	_, err := c.callOllama("test", "system", 1024)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should contain status code: %v", err)
	}
}

// ── Cloud call tests ─────────────────────────────────────────────────────────

func TestCallCloud_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header
		if r.Header.Get("x-api-key") != "test-key" {
			t.Errorf("expected x-api-key header")
		}

		json.NewEncoder(w).Encode(aiResponse{
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{
				{Type: "text", Text: "Sanitize user input to prevent XSS."},
			},
		})
	}))
	defer srv.Close()

	c := New(ClientConfig{
		APIKey:   "test-key",
		Provider: "anthropic",
		Endpoint: srv.URL,
	})

	result, err := c.callCloud("fix XSS", "You are a security expert.", 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Sanitize") {
		t.Errorf("unexpected response: %s", result)
	}
}

func TestCallCloud_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(aiResponse{
			Error: &struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			}{
				Type:    "invalid_api_key",
				Message: "Invalid API key provided",
			},
		})
	}))
	defer srv.Close()

	c := New(ClientConfig{
		APIKey:   "bad-key",
		Provider: "anthropic",
		Endpoint: srv.URL,
	})

	_, err := c.callCloud("test", "system", 1024)
	if err == nil {
		t.Fatal("expected error for API error response")
	}
	if !strings.Contains(err.Error(), "invalid_api_key") {
		t.Errorf("error should contain error type: %v", err)
	}
}

// ── Health check tests ───────────────────────────────────────────────────────

func TestCheckHealth_OllamaUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Errorf("expected /api/tags, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"models":[]}`))
	}))
	defer srv.Close()

	c := New(ClientConfig{
		Provider: "ollama",
		Endpoint: srv.URL + "/api/generate",
	})

	if err := c.CheckHealth(); err != nil {
		t.Errorf("expected healthy, got error: %v", err)
	}
}

func TestCheckHealth_OllamaDown(t *testing.T) {
	c := New(ClientConfig{
		Provider: "ollama",
		Endpoint: "http://127.0.0.1:19999/api/generate", // no server on this port
	})

	if err := c.CheckHealth(); err == nil {
		t.Error("expected error for unreachable ollama")
	}
}

func TestCheckHealth_CloudNoOp(t *testing.T) {
	c := New(ClientConfig{Provider: "anthropic"})

	if err := c.CheckHealth(); err != nil {
		t.Errorf("cloud health check should be no-op, got: %v", err)
	}
}

// ── Auth header tests ────────────────────────────────────────────────────────

func TestSetAuthHeaders_Ollama(t *testing.T) {
	c := New(ClientConfig{Provider: "ollama"})
	req, _ := http.NewRequest("POST", "http://127.0.0.1:11434/api/generate", nil)
	c.setAuthHeaders(req)

	if req.Header.Get("x-api-key") != "" {
		t.Error("ollama should not set x-api-key")
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("ollama should not set Authorization")
	}
}

func TestSetAuthHeaders_Anthropic(t *testing.T) {
	c := New(ClientConfig{Provider: "anthropic", APIKey: "sk-ant-test"})
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	c.setAuthHeaders(req)

	if req.Header.Get("x-api-key") != "sk-ant-test" {
		t.Error("anthropic should set x-api-key")
	}
	if req.Header.Get("anthropic-version") == "" {
		t.Error("anthropic should set anthropic-version")
	}
}

func TestSetAuthHeaders_OpenAI(t *testing.T) {
	c := New(ClientConfig{Provider: "openai", APIKey: "sk-test"})
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat", nil)
	c.setAuthHeaders(req)

	if req.Header.Get("Authorization") != "Bearer sk-test" {
		t.Error("openai should set Bearer token")
	}
}

// ── isOllama tests ───────────────────────────────────────────────────────────

func TestIsOllama(t *testing.T) {
	tests := []struct {
		provider string
		want     bool
	}{
		{"ollama", true},
		{"Ollama", true},
		{"OLLAMA", true},
		{"anthropic", false},
		{"openai", false},
		{"", false},
	}

	for _, tt := range tests {
		c := &Client{cfg: ClientConfig{Provider: tt.provider}}
		if got := c.isOllama(); got != tt.want {
			t.Errorf("isOllama(%q) = %v, want %v", tt.provider, got, tt.want)
		}
	}
}

// ── call dispatch tests ──────────────────────────────────────────────────────

func TestCall_DispatchesToOllama(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's an Ollama-format request (has "prompt" field, not "messages")
		var raw map[string]interface{}
		json.NewDecoder(r.Body).Decode(&raw)

		if _, ok := raw["prompt"]; !ok {
			t.Error("ollama request should have 'prompt' field")
		}
		if _, ok := raw["messages"]; ok {
			t.Error("ollama request should NOT have 'messages' field")
		}

		json.NewEncoder(w).Encode(ollamaResponse{
			Response: "fixed",
			Done:     true,
		})
	}))
	defer srv.Close()

	c := New(ClientConfig{
		Provider: "ollama",
		Endpoint: srv.URL,
	})

	result, err := c.call("test prompt", "test system", 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "fixed" {
		t.Errorf("expected 'fixed', got %q", result)
	}
}

func TestCall_DispatchesToCloud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a cloud-format request (has "messages" field)
		var raw map[string]interface{}
		json.NewDecoder(r.Body).Decode(&raw)

		if _, ok := raw["messages"]; !ok {
			t.Error("cloud request should have 'messages' field")
		}

		json.NewEncoder(w).Encode(aiResponse{
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{
				{Type: "text", Text: "cloud response"},
			},
		})
	}))
	defer srv.Close()

	c := New(ClientConfig{
		Provider: "anthropic",
		APIKey:   "test",
		Endpoint: srv.URL,
	})

	result, err := c.call("test", "system", 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "cloud response" {
		t.Errorf("expected 'cloud response', got %q", result)
	}
}

// ── Response size limit test ─────────────────────────────────────────────────

func TestCallOllama_ResponseSizeLimit(t *testing.T) {
	// Generate a response larger than maxResponseBytes
	largeResponse := strings.Repeat("A", maxResponseBytes+1000)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Write raw JSON with oversized response field
		w.Write([]byte(`{"response":"` + largeResponse + `","done":true}`))
	}))
	defer srv.Close()

	c := New(ClientConfig{
		Provider: "ollama",
		Endpoint: srv.URL,
	})

	// Should fail because the truncated JSON won't parse correctly
	_, err := c.callOllama("test", "system", 1024)
	if err == nil {
		t.Error("expected error for oversized response")
	}
}

// TestClient_RefusesRedirects verifies that the AI HTTP client refuses to
// follow redirects so that credentials (x-api-key) are never leaked to
// third-party hosts.
func TestClient_RefusesRedirects(t *testing.T) {
	// Server A returns 302 to server B.
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If we ever get here, the redirect was followed — test fails.
		t.Errorf("redirect was followed; API key would have leaked to %s", r.Host)
		w.WriteHeader(http.StatusOK)
	}))
	defer serverB.Close()

	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, serverB.URL, http.StatusFound)
	}))
	defer serverA.Close()

	c := New(ClientConfig{
		APIKey:   "sk-ant-secret",
		Provider: "anthropic",
		Endpoint: serverA.URL,
	})

	_, err := c.callCloud("prompt", "system", 1024)
	if err == nil {
		t.Fatal("expected error from refused redirect, got nil")
	}
	if !strings.Contains(err.Error(), "refusing redirect") {
		t.Errorf("expected 'refusing redirect' in error, got: %v", err)
	}
}
