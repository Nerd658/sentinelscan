package correlation

import (
	"testing"

	"sentinelscan/internal/dns"
	"sentinelscan/internal/tls"
)

func TestCorrelationEngineDNSAndTLS(t *testing.T) {
	engine := NewEngine()

	// Test DNS correlation
	dnsRecords := []dns.DNSRecord{
		{Domain: "jobsira.com", RecordType: dns.TypeA, Value: "104.21.5.10"},
	}
	dnsLinks := engine.CorrelateDNS("jobsira.com", dnsRecords)
	if len(dnsLinks) != 1 || dnsLinks[0].Relationship != RelResolvesTo {
		t.Errorf("expected 1 resolves_to link, got %+v", dnsLinks)
	}

	// Test TLS correlation
	tlsObs := &tls.TLSObservation{
		Port:              443,
		FingerprintSHA256: "abc123sha256",
		SubjectCN:         "jobsira.com",
		SAN:               []string{"jobsira.com", "api.jobsira.com"},
	}
	tlsLinks := engine.CorrelateTLS("164.68.126.101", tlsObs)
	if len(tlsLinks) != 3 {
		t.Errorf("expected 3 TLS correlation links, got %d", len(tlsLinks))
	}
}
