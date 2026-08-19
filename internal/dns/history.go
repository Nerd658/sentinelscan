package dns

import (
	"sort"
	"strings"
	"time"
)

type Tracker struct{}

func NewTracker() *Tracker {
	return &Tracker{}
}

func (t *Tracker) DetectChanges(domain string, oldRecords, newRecords []DNSRecord) []DNSEvent {
	events := make([]DNSEvent, 0)
	now := time.Now()

	// Categorize old and new records by type
	oldMap := groupRecordsByType(oldRecords)
	newMap := groupRecordsByType(newRecords)

	// 1. IP_ADDED & IP_REMOVED (A & AAAA records)
	oldIPs := extractValues(oldMap[TypeA], oldMap[TypeAAAA])
	newIPs := extractValues(newMap[TypeA], newMap[TypeAAAA])

	for ip := range newIPs {
		if !oldIPs[ip] {
			events = append(events, DNSEvent{
				Domain:    domain,
				EventType: EventIPAdded,
				OldValue:  "",
				NewValue:  ip,
				Timestamp: now,
			})
		}
	}

	for ip := range oldIPs {
		if !newIPs[ip] {
			events = append(events, DNSEvent{
				Domain:    domain,
				EventType: EventIPRemoved,
				OldValue:  ip,
				NewValue:  "",
				Timestamp: now,
			})
		}
	}

	// 2. CNAME_CHANGED
	oldCNAME := getFirstValue(oldMap[TypeCNAME])
	newCNAME := getFirstValue(newMap[TypeCNAME])

	if oldCNAME != "" && newCNAME != "" && oldCNAME != newCNAME {
		events = append(events, DNSEvent{
			Domain:    domain,
			EventType: EventCNAMEChanged,
			OldValue:  oldCNAME,
			NewValue:  newCNAME,
			Timestamp: now,
		})
	}

	// 3. NS_CHANGED
	oldNSJoined := joinValuesSorted(oldMap[TypeNS])
	newNSJoined := joinValuesSorted(newMap[TypeNS])

	if oldNSJoined != "" && newNSJoined != "" && oldNSJoined != newNSJoined {
		events = append(events, DNSEvent{
			Domain:    domain,
			EventType: EventNSChanged,
			OldValue:  oldNSJoined,
			NewValue:  newNSJoined,
			Timestamp: now,
		})
	}

	return events
}

func groupRecordsByType(records []DNSRecord) map[RecordType][]DNSRecord {
	m := make(map[RecordType][]DNSRecord)
	for _, rec := range records {
		m[rec.RecordType] = append(m[rec.RecordType], rec)
	}
	return m
}

func extractValues(recordGroups ...[]DNSRecord) map[string]bool {
	vals := make(map[string]bool)
	for _, group := range recordGroups {
		for _, rec := range group {
			vals[rec.Value] = true
		}
	}
	return vals
}

func getFirstValue(records []DNSRecord) string {
	if len(records) > 0 {
		return records[0].Value
	}
	return ""
}

func joinValuesSorted(records []DNSRecord) string {
	if len(records) == 0 {
		return ""
	}
	vals := make([]string, 0, len(records))
	for _, rec := range records {
		vals = append(vals, rec.Value)
	}
	sort.Strings(vals)
	return strings.Join(vals, ",")
}
