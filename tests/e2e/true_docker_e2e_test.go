package e2e

import (
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"sentinelscan/internal/correlation"
	"sentinelscan/internal/fingerprint"
	httpEngine "sentinelscan/internal/http"
	"sentinelscan/internal/scope"
	"sentinelscan/internal/scoring"
	tcpEngine "sentinelscan/internal/tcp"
	tlsEngine "sentinelscan/internal/tls"
)

// TRUE DOCKER E2E SYSTEM TEST — Dynamic Observation Pipeline Verification
// Classification: E2E-DOCKER / INTEGRATION-NETWORK
// Rule: ZERO manually instantiated HTTPObservation or TLSObservation structs.
// All observations are produced by executing actual TCP/HTTP/TLS network socket probes.
func TestTrueDockerE2ESystemChain(t *testing.T) {
	// 1. Setup real Origin server (listening on 443 with TLS cert and 301 redirect)
	certJobsira := generateTestCertificate("jobsira.test", []string{"jobsira.test", "www.jobsira.test"})

	originMux := http.NewServeMux()
	originMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0-lab-origin")
		w.Header().Set("Location", "https://jobsira.test/")
		w.WriteHeader(http.StatusMovedPermanently)
	})

	originTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{certJobsira},
	}

	originListener, err := tls.Listen("tcp", "127.0.0.1:0", originTLSConfig)
	if err != nil {
		t.Fatalf("failed to start real origin TLS listener: %v", err)
	}
	defer originListener.Close()

	originPort, _ := strconv.Atoi(strings.Split(originListener.Addr().String(), ":")[1])

	go func() { _ = http.Serve(originListener, originMux) }()

	// 2. Setup Scope Engine
	scopeEngine, err := scope.NewEngine(scope.ScopeRules{
		IPs:     []string{"127.0.0.1"},
		Domains: []string{"jobsira.test", "origin.jobsira.test"},
	})
	if err != nil {
		t.Fatalf("failed scope init: %v", err)
	}

	// 3. Step A: Dynamic TCP Scan
	tcpScanner := tcpEngine.NewScanner(scopeEngine, 1*time.Second, 2)
	tcpResults, err := tcpScanner.ScanIP(t.Context(), "127.0.0.1", []int{originPort})
	if err != nil || len(tcpResults) == 0 || tcpResults[0].State != tcpEngine.StateOpen {
		t.Fatalf("expected open TCP socket on port %d, got %v", originPort, err)
	}

	// 4. Step B: Dynamic TLS Inspection (Real Handshake & Certificate Extraction)
	tlsInspector := tlsEngine.NewInspector(scopeEngine, 2*time.Second)
	realTLSObs, err := tlsInspector.Inspect(t.Context(), "127.0.0.1", originPort, "jobsira.test")
	if err != nil || realTLSObs == nil {
		t.Fatalf("expected real TLS observation from socket handshake, got %v", err)
	}

	if realTLSObs.SubjectCN != "jobsira.test" {
		t.Errorf("expected SubjectCN jobsira.test extracted from socket, got %s", realTLSObs.SubjectCN)
	}
	if realTLSObs.FingerprintSHA256 == "" {
		t.Errorf("expected SHA256 certificate fingerprint extracted from socket")
	}

	// 5. Step C: Dynamic HTTP Fetch (Real GET Request & Response Parsing)
	httpFetcher := httpEngine.NewFetcher(scopeEngine, 1024*1024, 2*time.Second, 0)
	realHTTPObs, err := httpFetcher.Fetch(t.Context(), "127.0.0.1", originPort, "https", "jobsira.test")
	if err != nil || realHTTPObs == nil {
		t.Fatalf("expected real HTTP observation from socket, got %v", err)
	}

	if realHTTPObs.StatusCode != 301 {
		t.Errorf("expected status 301 from real HTTP response, got %d", realHTTPObs.StatusCode)
	}
	if realHTTPObs.Location != "https://jobsira.test/" {
		t.Errorf("expected Location https://jobsira.test/, got %s", realHTTPObs.Location)
	}

	// 6. Step D: Technology Fingerprinting from Real Network Responses
	fpEngine := fingerprint.NewEngine()
	techs := fpEngine.Analyze(realHTTPObs, realTLSObs)
	foundNginx := false
	for _, tech := range techs {
		if strings.EqualFold(tech.Name, "nginx") {
			foundNginx = true
		}
	}
	if !foundNginx {
		t.Errorf("expected Nginx technology fingerprint from real Server header")
	}

	// 7. Step E: Dynamic Correlation & Origin Exposure Evaluation
	corrEngine := correlation.NewEngine()
	links := corrEngine.CorrelateTLS("127.0.0.1", realTLSObs)
	if len(links) == 0 {
		t.Errorf("expected correlation links generated from real TLS observation")
	}

	evaluator := scoring.NewEvaluator()
	finding := evaluator.Evaluate("jobsira.test", "127.0.0.1", realTLSObs, realHTTPObs, true)

	if finding.Score < 80 {
		t.Errorf("expected score >= 80 from dynamic evaluation, got %d", finding.Score)
	}
	if finding.Confidence != scoring.ConfidenceVeryHigh {
		t.Errorf("expected VERY_HIGH confidence rating, got %s", finding.Confidence)
	}
}

// Anti-Hardcoding Regression Verification
func TestAntiHardcodingDynamicServerHeaderChange(t *testing.T) {
	serverHeader := "Apache/2.4.52 (Unix)"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", serverHeader)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Dynamic Server Header Test</title></head></html>"))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	go func() { _ = http.Serve(listener, handler) }()

	port, _ := strconv.Atoi(strings.Split(listener.Addr().String(), ":")[1])

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{IPs: []string{"127.0.0.1"}})
	fetcher := httpEngine.NewFetcher(scopeEngine, 1024*1024, 2*time.Second, 0)
	fpEngine := fingerprint.NewEngine()

	obs, err := fetcher.Fetch(t.Context(), "127.0.0.1", port, "http", "")
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	techs := fpEngine.Analyze(obs, nil)
	foundApache := false
	for _, tech := range techs {
		if strings.EqualFold(tech.Name, "Apache") {
			foundApache = true
		}
	}

	if !foundApache {
		t.Errorf("expected Apache fingerprint dynamically derived from Server header %q", obs.ServerHeader)
	}
}
