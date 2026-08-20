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

// Real Network Socket Probing Test (Phase 2 & 4)
func TestRealSocketProbingAndServices(t *testing.T) {
	// Start real TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start real TCP listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	scopeEngine, err := scope.NewEngine(scope.ScopeRules{
		IPs: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("failed scope init: %v", err)
	}

	scanner := tcpEngine.NewScanner(scopeEngine, 1*time.Second, 2)
	results, err := scanner.ScanIP(t.Context(), "127.0.0.1", []int{port, 9999})
	if err != nil {
		t.Fatalf("real TCP scan failed: %v", err)
	}

	resMap := make(map[int]tcpEngine.PortResult)
	for _, r := range results {
		resMap[r.Port] = r
	}

	if resMap[port].State != tcpEngine.StateOpen {
		t.Errorf("expected port %d to be OPEN via real TCP socket", port)
	}
	if resMap[9999].State == tcpEngine.StateOpen {
		t.Errorf("expected closed port 9999 NOT to be OPEN")
	}
}

// Real Virtual Hosting Inspection (Phase 5)
func TestRealVirtualHostingInspection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "jobsira.test":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><head><title>Jobsira Homepage</title></head></html>"))
		case "api.jobsira.test":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"service":"jobsira-api","version":"1.0"}`))
		case "admin.jobsira.test":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><head><title>Jobsira Admin</title></head></html>"))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	server := &http.Server{
		Addr:    "127.0.0.1:0",
		Handler: mux,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start vhost listener: %v", err)
	}
	defer listener.Close()

	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	port, _ := strconv.Atoi(strings.Split(listener.Addr().String(), ":")[1])

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs:     []string{"127.0.0.1"},
		Domains: []string{"jobsira.test", "api.jobsira.test", "admin.jobsira.test"},
	})
	fetcher := httpEngine.NewFetcher(scopeEngine, 1024*1024, 2*time.Second, 0)

	// Host 1: jobsira.test
	obs1, err := fetcher.Fetch(t.Context(), "127.0.0.1", port, "http", "jobsira.test")
	if err != nil || obs1.Title != "Jobsira Homepage" {
		t.Errorf("expected Jobsira Homepage title, got %v (title: %s)", err, obs1.Title)
	}

	// Host 2: api.jobsira.test
	obs2, err := fetcher.Fetch(t.Context(), "127.0.0.1", port, "http", "api.jobsira.test")
	if err != nil || obs2.StatusCode != 200 {
		t.Errorf("expected 200 OK for API host, got err=%v status=%d", err, obs2.StatusCode)
	}

	// Host 3: admin.jobsira.test
	obs3, err := fetcher.Fetch(t.Context(), "127.0.0.1", port, "http", "admin.jobsira.test")
	if err != nil || obs3.Title != "Jobsira Admin" {
		t.Errorf("expected Jobsira Admin title, got %s", obs3.Title)
	}
}

// Real TLS & SNI Certificate Selection (Phase 6)
func TestRealSNICertificateHandshake(t *testing.T) {
	certJobsira := generateTestCertificate("jobsira.test", []string{"jobsira.test"})
	certAPI := generateTestCertificate("api.jobsira.test", []string{"api.jobsira.test"})

	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if info.ServerName == "api.jobsira.test" {
				return &certAPI, nil
			}
			return &certJobsira, nil
		},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed tls listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tlsConn := c.(*tls.Conn)
				_ = tlsConn.Handshake()
				_ = tlsConn.Close()
			}(conn)
		}
	}()

	port, _ := strconv.Atoi(strings.Split(listener.Addr().String(), ":")[1])

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs:     []string{"127.0.0.1"},
		Domains: []string{"jobsira.test", "api.jobsira.test"},
	})
	inspector := tlsEngine.NewInspector(scopeEngine, 2*time.Second)

	// Probe with SNI = jobsira.test
	obs1, err := inspector.Inspect(t.Context(), "127.0.0.1", port, "jobsira.test")
	if err != nil || obs1.SubjectCN != "jobsira.test" {
		t.Errorf("expected SubjectCN jobsira.test, got %v (%s)", err, obs1.SubjectCN)
	}

	// Probe with SNI = api.jobsira.test
	obs2, err := inspector.Inspect(t.Context(), "127.0.0.1", port, "api.jobsira.test")
	if err != nil || obs2.SubjectCN != "api.jobsira.test" {
		t.Errorf("expected SubjectCN api.jobsira.test, got %v (%s)", err, obs2.SubjectCN)
	}
}

// Real Origin Exposure Pipeline & Scoring (Phase 7)
func TestRealOriginExposureScoringPipeline(t *testing.T) {
	evaluator := scoring.NewEvaluator()
	fpEngine := fingerprint.NewEngine()
	corrEngine := correlation.NewEngine()

	tlsObs := &tlsEngine.TLSObservation{
		IP:                "172.20.0.40",
		Port:              443,
		SubjectCN:         "jobsira.test",
		SAN:               []string{"jobsira.test", "www.jobsira.test"},
		Issuer:            "SentinelScan Lab CA",
		FingerprintSHA256: "sha256labcertfingerprint",
	}

	httpObs := &httpEngine.HTTPObservation{
		IP:           "172.20.0.40",
		Port:         443,
		HostHeader:   "jobsira.test",
		StatusCode:   301,
		Location:     "https://jobsira.test/",
		ServerHeader: "nginx",
	}

	// 1. Tech fingerprint
	techs := fpEngine.Analyze(httpObs, tlsObs)
	foundNginx := false
	for _, tech := range techs {
		if strings.EqualFold(tech.Name, "nginx") {
			foundNginx = true
		}
	}
	if !foundNginx {
		t.Errorf("expected nginx technology match")
	}

	// 2. Correlation
	links := corrEngine.CorrelateTLS("172.20.0.40", tlsObs)
	if len(links) == 0 {
		t.Errorf("expected correlation links")
	}

	// 3. Dynamic Origin Exposure Scoring
	result := evaluator.Evaluate("jobsira.test", "172.20.0.40", tlsObs, httpObs, true)
	if result.Score < 80 {
		t.Errorf("expected score >= 80, got %d", result.Score)
	}
	if result.Confidence != scoring.ConfidenceVeryHigh {
		t.Errorf("expected VERY_HIGH confidence, got %s", result.Confidence)
	}

	if len(result.Evidence) < 4 {
		t.Errorf("expected at least 4 evidence points, got %d", len(result.Evidence))
	}
}
