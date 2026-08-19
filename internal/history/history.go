package history

import (
	"time"
)

type ChangeType string

const (
	HostAdded           ChangeType = "HOST_ADDED"
	HostRemoved         ChangeType = "HOST_REMOVED"
	PortOpened          ChangeType = "PORT_OPENED"
	PortClosed          ChangeType = "PORT_CLOSED"
	ServiceChanged      ChangeType = "SERVICE_CHANGED"
	CertificateChanged  ChangeType = "CERTIFICATE_CHANGED"
	CertificateExpired  ChangeType = "CERTIFICATE_EXPIRED"
	TechnologyAdded     ChangeType = "TECHNOLOGY_ADDED"
	TechnologyRemoved   ChangeType = "TECHNOLOGY_REMOVED"
)

type HistoryEvent struct {
	EntityID   string     `json:"entity_id"`
	EntityType string     `json:"entity_type"` // host, port, certificate, technology
	ChangeType ChangeType `json:"change_type"`
	OldValue   string     `json:"old_value"`
	NewValue   string     `json:"new_value"`
	Timestamp  time.Time  `json:"timestamp"`
}

type Tracker struct{}

func NewTracker() *Tracker {
	return &Tracker{}
}

func (t *Tracker) ComparePorts(hostIP string, oldPorts, newPorts []int) []HistoryEvent {
	events := make([]HistoryEvent, 0)
	now := time.Now()

	oldMap := make(map[int]bool)
	newMap := make(map[int]bool)

	for _, p := range oldPorts {
		oldMap[p] = true
	}
	for _, p := range newPorts {
		newMap[p] = true
	}

	for p := range newMap {
		if !oldMap[p] {
			events = append(events, HistoryEvent{
				EntityID:   hostIP,
				EntityType: "port",
				ChangeType: PortOpened,
				OldValue:   "",
				NewValue:   string(rune(p)),
				Timestamp:  now,
			})
		}
	}

	for p := range oldMap {
		if !newMap[p] {
			events = append(events, HistoryEvent{
				EntityID:   hostIP,
				EntityType: "port",
				ChangeType: PortClosed,
				OldValue:   string(rune(p)),
				NewValue:   "",
				Timestamp:  now,
			})
		}
	}

	return events
}
