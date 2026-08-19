package correlation

import (
	"fmt"
	"strings"

	"sentinelscan/internal/dns"
	"sentinelscan/internal/tls"
)

type RelationshipType string

const (
	RelResolvesTo          RelationshipType = "resolves_to"
	RelObservedOn          RelationshipType = "observed_on"
	RelCertificateContains RelationshipType = "certificate_contains"
	RelAssociatedWith      RelationshipType = "associated_with"
	RelRunsService         RelationshipType = "runs_service"
)

type CorrelationLink struct {
	SourceType   string           `json:"source_type"`   // domain, ip, certificate, host
	SourceID     string           `json:"source_id"`
	Relationship RelationshipType `json:"relationship"`
	TargetType   string           `json:"target_type"`
	TargetID     string           `json:"target_id"`
	Confidence   int              `json:"confidence"`
}

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) CorrelateDNS(domain string, records []dns.DNSRecord) []CorrelationLink {
	links := make([]CorrelationLink, 0)
	cleanedDomain := strings.ToLower(strings.TrimSpace(domain))

	for _, rec := range records {
		if rec.RecordType == dns.TypeA || rec.RecordType == dns.TypeAAAA {
			links = append(links, CorrelationLink{
				SourceType:   "domain",
				SourceID:     cleanedDomain,
				Relationship: RelResolvesTo,
				TargetType:   "ip",
				TargetID:     rec.Value,
				Confidence:   100,
			})
		}
	}
	return links
}

func (e *Engine) CorrelateTLS(ipStr string, tlsObs *tls.TLSObservation) []CorrelationLink {
	links := make([]CorrelationLink, 0)
	if tlsObs == nil {
		return links
	}

	if tlsObs.FingerprintSHA256 != "" {
		// Cert observed on IP
		links = append(links, CorrelationLink{
			SourceType:   "certificate",
			SourceID:     tlsObs.FingerprintSHA256,
			Relationship: RelObservedOn,
			TargetType:   "ip",
			TargetID:     fmt.Sprintf("%s:%d", ipStr, tlsObs.Port),
			Confidence:   100,
		})
	}

	if tlsObs.SubjectCN != "" {
		links = append(links, CorrelationLink{
			SourceType:   "ip",
			SourceID:     ipStr,
			Relationship: RelCertificateContains,
			TargetType:   "domain",
			TargetID:     tlsObs.SubjectCN,
			Confidence:   90,
		})
	}

	for _, san := range tlsObs.SAN {
		if san != tlsObs.SubjectCN && san != "" {
			links = append(links, CorrelationLink{
				SourceType:   "ip",
				SourceID:     ipStr,
				Relationship: RelAssociatedWith,
				TargetType:   "domain",
				TargetID:     san,
				Confidence:   85,
			})
		}
	}

	return links
}
