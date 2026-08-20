package origin

import (
	"context"
	"testing"
	"time"

	"sentinelscan/internal/http"
	"sentinelscan/internal/scope"
	"sentinelscan/internal/tcp"
	"sentinelscan/internal/tls"
)

func TestClassifierCDNIPRange(t *testing.T) {
	classifier := NewClassifier()

	// Cloudflare IP: 172.67.213.80 (in 172.64.0.0/13)
	res := classifier.Classify("172.67.213.80", nil, nil)
	if !res.IsCDN || res.Role != RoleEdgeProxy || res.Provider != "Cloudflare" {
		t.Errorf("expected 172.67.213.80 to be classified as Cloudflare EdgeProxy, got: %+v", res)
	}

	// Cloudflare IP: 104.21.86.4 (in 104.16.0.0/13)
	res2 := classifier.Classify("104.21.86.4", nil, nil)
	if !res2.IsCDN || res2.Role != RoleEdgeProxy {
		t.Errorf("expected 104.21.86.4 to be classified as CDN, got: %+v", res2)
	}

	// Direct VPS IP: 164.68.126.101 (Contabo)
	res3 := classifier.Classify("164.68.126.101", nil, nil)
	if res3.IsCDN || res3.Role != RoleOriginCandidate {
		t.Errorf("expected 164.68.126.101 to be classified as OriginCandidate, got: %+v", res3)
	}
}

func TestClassifierHTTPHeaders(t *testing.T) {
	classifier := NewClassifier()

	httpObsCF := &http.HTTPObservation{
		ServerHeader: "cloudflare",
		Headers: map[string]string{
			"CF-Ray": "8b3f495038ab-CDG",
		},
	}
	resCF := classifier.Classify("192.0.2.1", httpObsCF, nil)
	if !resCF.IsCDN || resCF.Role != RoleEdgeProxy || resCF.Provider != "Cloudflare" {
		t.Errorf("expected HTTP Cloudflare headers to classify as EdgeProxy, got: %+v", resCF)
	}

	httpObsOrigin := &http.HTTPObservation{
		ServerHeader: "nginx/1.24.0 (Ubuntu)",
		Headers: map[string]string{
			"Server": "nginx/1.24.0 (Ubuntu)",
		},
	}
	resOrigin := classifier.Classify("192.0.2.2", httpObsOrigin, nil)
	if resOrigin.IsCDN || resOrigin.Role != RoleOriginCandidate {
		t.Errorf("expected direct Nginx server to classify as OriginCandidate, got: %+v", resOrigin)
	}
}

func TestOriginEngineCDNExclusionAndCandidateVerification(t *testing.T) {
	engine := NewEngine()

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		Domains: []string{"jobsira.test"},
		IPs:     []string{"127.0.0.1", "172.67.213.80"},
	})

	tcpScanner := tcp.NewScanner(scopeEngine, 1*time.Second, 5)
	httpFetcher := http.NewFetcher(scopeEngine, 1024*1024, 1*time.Second, 2)
	tlsInspector := tls.NewInspector(scopeEngine, 1*time.Second)

	// Scenario 1: Only CDN IP in DNS -> Origin not discovered
	verdict1 := engine.EvaluateTarget(
		context.Background(),
		"jobsira.test",
		[]string{"172.67.213.80"}, // Cloudflare IP
		[]string{},
		tcpScanner,
		httpFetcher,
		tlsInspector,
	)

	if verdict1.Status != "NOT_DISCOVERED" && verdict1.Status != "UNCONFIRMED" {
		t.Errorf("expected CDN-only target to NOT confirm origin, got status: %s", verdict1.Status)
	}
	if !verdict1.EdgeDetected {
		t.Errorf("expected EdgeDetected to be true for Cloudflare IP")
	}
}
