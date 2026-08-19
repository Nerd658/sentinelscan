package http

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"sentinelscan/internal/scope"
)

func TestHTTPFetcherMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Test Page</title></head><body>SentinelScan Test</body></html>"))
	}))
	defer server.Close()

	parts := strings.Split(strings.TrimPrefix(server.URL, "http://"), ":")
	ipStr := parts[0]
	port, _ := strconv.Atoi(parts[1])

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs: []string{ipStr, "127.0.0.1"},
	})

	fetcher := NewFetcher(scopeEngine, 1024*1024, 2*time.Second, 3)
	obs, err := fetcher.Fetch(t.Context(), ipStr, port, "http", "")
	if err != nil {
		t.Fatalf("failed HTTP fetch: %v", err)
	}

	if obs.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", obs.StatusCode)
	}
	if obs.ServerHeader != "nginx/1.24.0" {
		t.Errorf("expected server nginx/1.24.0, got %s", obs.ServerHeader)
	}
	if obs.Title != "Test Page" {
		t.Errorf("expected title 'Test Page', got %s", obs.Title)
	}
}
