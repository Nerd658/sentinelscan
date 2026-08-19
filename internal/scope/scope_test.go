package scope

import (
	"net"
	"os"
	"testing"
)

func TestScopeEngineIPAndCIDR(t *testing.T) {
	rules := ScopeRules{
		IPs:   []string{"164.68.126.101", "10.0.0.1"},
		CIDRs: []string{"192.168.1.0/24"},
	}

	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatalf("failed to create scope engine: %v", err)
	}

	// Test Allowed IP
	if !engine.IsAllowedIP(net.ParseIP("164.68.126.101")) {
		t.Errorf("expected 164.68.126.101 to be allowed")
	}

	// Test Allowed CIDR match
	if !engine.IsAllowedIP(net.ParseIP("192.168.1.50")) {
		t.Errorf("expected 192.168.1.50 to be allowed by CIDR")
	}

	// Test Disallowed IP
	if engine.IsAllowedIP(net.ParseIP("8.8.8.8")) {
		t.Errorf("expected 8.8.8.8 to be rejected")
	}
}

func TestScopeEngineDomain(t *testing.T) {
	rules := ScopeRules{
		Domains: []string{"jobsira.com", "*.internal.net"},
	}

	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatalf("failed to create scope engine: %v", err)
	}

	// Exact domain match
	if !engine.IsAllowedDomain("jobsira.com") {
		t.Errorf("expected jobsira.com to be allowed")
	}

	// Subdomain match on wildcard
	if !engine.IsAllowedDomain("api.internal.net") {
		t.Errorf("expected api.internal.net to be allowed by wildcard")
	}

	// Disallowed domain
	if engine.IsAllowedDomain("google.com") {
		t.Errorf("expected google.com to be rejected")
	}
}

func TestScopeKillSwitch(t *testing.T) {
	rules := ScopeRules{
		IPs: []string{"1.1.1.1"},
	}

	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatalf("failed to create scope engine: %v", err)
	}

	if !engine.IsAllowedIP(net.ParseIP("1.1.1.1")) {
		t.Fatalf("expected IP allowed prior to killswitch")
	}

	engine.ActivateKillSwitch()
	if engine.IsAllowedIP(net.ParseIP("1.1.1.1")) {
		t.Errorf("expected IP rejected while killswitch is active")
	}

	engine.DeactivateKillSwitch()
	if !engine.IsAllowedIP(net.ParseIP("1.1.1.1")) {
		t.Errorf("expected IP allowed after killswitch deactivated")
	}
}

func TestAuditLogCreation(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "audit_*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	rules := ScopeRules{
		IPs:       []string{"127.0.0.1"},
		AuditFile: tmpFile.Name(),
	}

	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	engine.IsAllowedIP(net.ParseIP("127.0.0.1"))
	engine.IsAllowedIP(net.ParseIP("10.0.0.1"))
	engine.Close()

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}

	if len(content) == 0 {
		t.Errorf("expected non-empty audit log")
	}
}
