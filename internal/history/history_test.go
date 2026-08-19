package history

import (
	"testing"
)

func TestHistoryTrackerPortComparison(t *testing.T) {
	tracker := NewTracker()
	events := tracker.ComparePorts("164.68.126.101", []int{80, 443}, []int{443, 8443})

	if len(events) != 2 {
		t.Fatalf("expected 2 port change events (1 closed, 1 opened), got %d", len(events))
	}

	foundOpened := false
	foundClosed := false

	for _, ev := range events {
		if ev.ChangeType == PortOpened {
			foundOpened = true
		}
		if ev.ChangeType == PortClosed {
			foundClosed = true
		}
	}

	if !foundOpened || !foundClosed {
		t.Errorf("expected both PortOpened and PortClosed events, got %+v", events)
	}
}
