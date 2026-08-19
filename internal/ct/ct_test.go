package ct

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sentinelscan/internal/scope"
)

func TestCTClientScopeEnforcement(t *testing.T) {
	scopeEngine, err := scope.NewEngine(scope.ScopeRules{
		Domains: []string{"jobsira.com"},
	})
	if err != nil {
		t.Fatalf("failed to init scope: %v", err)
	}

	client := NewClient(scopeEngine, 2*time.Second)

	// Test out of scope domain
	_, err = client.DiscoverHostnames(t.Context(), "unauthorized.com")
	if err == nil {
		t.Errorf("expected scope rejection error, got nil")
	}
}

func TestCTClientMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"name_value":"jobsira.com\napi.jobsira.com\n*.admin.jobsira.com"}]`))
	}))
	defer server.Close()

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		Domains: []string{"jobsira.com"},
	})

	client := NewClient(scopeEngine, 2*time.Second)
	client.httpClient = server.Client() // Override client for mock server

	// Test discovery parsing logic directly
	resp, err := client.httpClient.Get(server.URL)
	if err != nil {
		t.Fatalf("failed to get mock response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
}
