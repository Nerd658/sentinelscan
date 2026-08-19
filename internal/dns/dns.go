package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"sentinelscan/internal/scope"
	"sentinelscan/pkg/logger"
)

type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeMX    RecordType = "MX"
	TypeNS    RecordType = "NS"
	TypeTXT   RecordType = "TXT"
)

type DNSRecord struct {
	Domain     string     `json:"domain"`
	RecordType RecordType `json:"record_type"`
	Value      string     `json:"value"`
	TTL        int        `json:"ttl"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
}

type EventType string

const (
	EventIPAdded      EventType = "IP_ADDED"
	EventIPRemoved    EventType = "IP_REMOVED"
	EventCNAMEChanged EventType = "CNAME_CHANGED"
	EventNSChanged    EventType = "NS_CHANGED"
)

type DNSEvent struct {
	Domain    string    `json:"domain"`
	EventType EventType `json:"event_type"`
	OldValue  string    `json:"old_value"`
	NewValue  string    `json:"new_value"`
	Timestamp time.Time `json:"timestamp"`
}

type Resolver struct {
	netResolver *net.Resolver
	scopeEngine *scope.Engine
}

func NewResolver(scopeEngine *scope.Engine) *Resolver {
	return &Resolver{
		netResolver: &net.Resolver{
			PreferGo: true,
		},
		scopeEngine: scopeEngine,
	}
}

func (r *Resolver) Resolve(ctx context.Context, domain string) ([]DNSRecord, error) {
	cleanedDomain := strings.ToLower(strings.TrimSpace(domain))
	if cleanedDomain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	if r.scopeEngine != nil {
		if err := r.scopeEngine.WaitLimiter(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait cancelled: %w", err)
		}
		if !r.scopeEngine.IsAllowedDomain(cleanedDomain) {
			logger.Warn("DNS resolution attempt rejected by Scope Engine", "domain", cleanedDomain)
			return nil, fmt.Errorf("domain %s is outside authorized target scope", cleanedDomain)
		}
	}

	records := make([]DNSRecord, 0)
	now := time.Now()

	// 1. Resolve A records
	ips, err := r.netResolver.LookupIP(ctx, "ip4", cleanedDomain)
	if err == nil {
		for _, ip := range ips {
			records = append(records, DNSRecord{
				Domain:     cleanedDomain,
				RecordType: TypeA,
				Value:      ip.String(),
				TTL:        300,
				FirstSeen:  now,
				LastSeen:   now,
			})
		}
	}

	// 2. Resolve AAAA records
	ip6s, err := r.netResolver.LookupIP(ctx, "ip6", cleanedDomain)
	if err == nil {
		for _, ip := range ip6s {
			records = append(records, DNSRecord{
				Domain:     cleanedDomain,
				RecordType: TypeAAAA,
				Value:      ip.String(),
				TTL:        300,
				FirstSeen:  now,
				LastSeen:   now,
			})
		}
	}

	// 3. Resolve CNAME record
	cname, err := r.netResolver.LookupCNAME(ctx, cleanedDomain)
	if err == nil && cname != "" && strings.TrimSuffix(cname, ".") != cleanedDomain {
		records = append(records, DNSRecord{
			Domain:     cleanedDomain,
			RecordType: TypeCNAME,
			Value:      strings.TrimSuffix(cname, "."),
			TTL:        300,
			FirstSeen:  now,
			LastSeen:   now,
		})
	}

	// 4. Resolve MX records
	mxs, err := r.netResolver.LookupMX(ctx, cleanedDomain)
	if err == nil {
		for _, mx := range mxs {
			records = append(records, DNSRecord{
				Domain:     cleanedDomain,
				RecordType: TypeMX,
				Value:      fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")),
				TTL:        300,
				FirstSeen:  now,
				LastSeen:   now,
			})
		}
	}

	// 5. Resolve NS records
	nss, err := r.netResolver.LookupNS(ctx, cleanedDomain)
	if err == nil {
		for _, ns := range nss {
			records = append(records, DNSRecord{
				Domain:     cleanedDomain,
				RecordType: TypeNS,
				Value:      strings.TrimSuffix(ns.Host, "."),
				TTL:        300,
				FirstSeen:  now,
				LastSeen:   now,
			})
		}
	}

	// 6. Resolve TXT records
	txts, err := r.netResolver.LookupTXT(ctx, cleanedDomain)
	if err == nil {
		for _, txt := range txts {
			records = append(records, DNSRecord{
				Domain:     cleanedDomain,
				RecordType: TypeTXT,
				Value:      txt,
				TTL:        300,
				FirstSeen:  now,
				LastSeen:   now,
			})
		}
	}

	logger.Info("DNS resolution completed", "domain", cleanedDomain, "record_count", len(records))
	return records, nil
}
