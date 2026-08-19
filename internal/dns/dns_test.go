package dns

import (
	"testing"

	"sentinelscan/internal/scope"
)

func TestDNSHistoryTrackerChangeDetection(t *testing.T) {
	tracker := NewTracker()
	domain := "jobsira.com"

	// 1. Initial observation
	oldRecords := []DNSRecord{
		{Domain: domain, RecordType: TypeA, Value: "104.21.5.10"},
		{Domain: domain, RecordType: TypeA, Value: "172.67.18.20"},
		{Domain: domain, RecordType: TypeCNAME, Value: "old-cname.cdn.net"},
		{Domain: domain, RecordType: TypeNS, Value: "ns1.oldhost.com"},
		{Domain: domain, RecordType: TypeNS, Value: "ns2.oldhost.com"},
	}

	// 2. New observation: 172.67.18.20 removed, 164.68.126.101 added, CNAME changed, NS changed
	newRecords := []DNSRecord{
		{Domain: domain, RecordType: TypeA, Value: "104.21.5.10"},
		{Domain: domain, RecordType: TypeA, Value: "164.68.126.101"},
		{Domain: domain, RecordType: TypeCNAME, Value: "new-cname.cdn.net"},
		{Domain: domain, RecordType: TypeNS, Value: "ns1.newhost.com"},
		{Domain: domain, RecordType: TypeNS, Value: "ns2.newhost.com"},
	}

	events := tracker.DetectChanges(domain, oldRecords, newRecords)

	if len(events) == 0 {
		t.Fatalf("expected DNS change events, got none")
	}

	eventMap := make(map[EventType]DNSEvent)
	for _, ev := range events {
		eventMap[ev.EventType] = ev
	}

	// Check IP_ADDED
	if ev, exists := eventMap[EventIPAdded]; !exists || ev.NewValue != "164.68.126.101" {
		t.Errorf("expected IP_ADDED for 164.68.126.101, got %+v", ev)
	}

	// Check IP_REMOVED
	if ev, exists := eventMap[EventIPRemoved]; !exists || ev.OldValue != "172.67.18.20" {
		t.Errorf("expected IP_REMOVED for 172.67.18.20, got %+v", ev)
	}

	// Check CNAME_CHANGED
	if ev, exists := eventMap[EventCNAMEChanged]; !exists || ev.NewValue != "new-cname.cdn.net" {
		t.Errorf("expected CNAME_CHANGED, got %+v", ev)
	}

	// Check NS_CHANGED
	if _, exists := eventMap[EventNSChanged]; !exists {
		t.Errorf("expected NS_CHANGED, got none")
	}
}

func TestDNSResolverScopeCheck(t *testing.T) {
	scopeEngine, err := scope.NewEngine(scope.ScopeRules{
		Domains: []string{"jobsira.com"},
	})
	if err != nil {
		t.Fatalf("failed to init scope engine: %v", err)
	}

	resolver := NewResolver(scopeEngine)

	// Test out-of-scope domain resolution attempt
	_, err = resolver.Resolve(t.Context(), "unauthorized-domain.com")
	if err == nil {
		t.Errorf("expected error resolving out-of-scope domain, got nil")
	}
}
