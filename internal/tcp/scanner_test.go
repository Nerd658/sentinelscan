package tcp

import (
	"net"
	"testing"
	"time"

	"sentinelscan/internal/scope"
)

func TestTCPScannerScopeEnforcement(t *testing.T) {
	scopeEngine, err := scope.NewEngine(scope.ScopeRules{
		IPs: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("failed to init scope: %v", err)
	}

	scanner := NewScanner(scopeEngine, 100*time.Millisecond, 5)

	// Test out-of-scope IP rejected
	_, err = scanner.ScanIP(t.Context(), "8.8.8.8", []int{80})
	if err == nil {
		t.Errorf("expected scope rejection error for 8.8.8.8, got nil")
	}

	// Test in-scope IP allowed
	results, err := scanner.ScanIP(t.Context(), "127.0.0.1", []int{12345})
	if err != nil {
		t.Fatalf("expected successful scan execution, got %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestTCPScannerProbeMock(t *testing.T) {
	// Start local TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open test listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	port := addr.Port

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs: []string{"127.0.0.1"},
	})

	scanner := NewScanner(scopeEngine, 500*time.Millisecond, 2)
	results, err := scanner.ScanIP(t.Context(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("unexpected error scanning open port: %v", err)
	}

	if len(results) != 1 || results[0].State != StateOpen {
		t.Errorf("expected open port state for %d, got %+v", port, results)
	}
}
