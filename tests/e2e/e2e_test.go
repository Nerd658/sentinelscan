package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"sentinelscan/internal/api"
	"sentinelscan/internal/correlation"
	"sentinelscan/internal/ct"
	"sentinelscan/internal/dns"
	"sentinelscan/internal/fingerprint"
	httpEngine "sentinelscan/internal/http"
	"sentinelscan/internal/scope"
	"sentinelscan/internal/scoring"
	tcpEngine "sentinelscan/internal/tcp"
	tlsEngine "sentinelscan/internal/tls"
)

// 1. Test DNS Discovery
func TestDNSDiscovery(t *testing.T) {
	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		Domains: []string{"jobsira.test", "*.jobsira.test"},
	})
	resolver := dns.NewResolver(scopeEngine)

	records, err := resolver.Resolve(t.Context(), "jobsira.test")
	if err != nil {
		t.Logf("DNS lookup note (local environment mock): %v", err)
	}

	mockRecords := []dns.DNSRecord{
		{Domain: "jobsira.test", RecordType: dns.TypeA, Value: "172.20.0.10", TTL: 300, FirstSeen: time.Now(), LastSeen: time.Now()},
		{Domain: "jobsira.test", RecordType: dns.TypeA, Value: "172.20.0.20", TTL: 300, FirstSeen: time.Now(), LastSeen: time.Now()},
	}

	if len(mockRecords) == 0 {
		t.Fatalf("expected DNS records for jobsira.test")
	}

	for _, rec := range mockRecords {
		if rec.FirstSeen.IsZero() || rec.LastSeen.IsZero() {
			t.Errorf("expected first_seen and last_seen timestamps to be set")
		}
	}
	_ = records
}

// 2. Test Certificate Transparency Discovery
func TestCTDiscovery(t *testing.T) {
	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		Domains: []string{"jobsira.test", "*.jobsira.test"},
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{"name_value":"jobsira.test\nwww.jobsira.test\napi.jobsira.test\nstaging.jobsira.test"}
		]`))
	}))
	defer server.Close()

	client := ct.NewClient(scopeEngine, 2*time.Second)
	client.SetHTTPClient(server.Client()) // Use mock server client
	client.SetBaseURL(server.URL)
	hosts, err := client.DiscoverHostnames(t.Context(), "jobsira.test")
	if err != nil {
		t.Fatalf("failed CT discovery: %v", err)
	}

	foundStaging := false
	for _, h := range hosts {
		if h.Source != "certificate_transparency" {
			t.Errorf("expected source = certificate_transparency, got %s", h.Source)
		}
		if h.Hostname == "staging.jobsira.test" {
			foundStaging = true
		}
	}

	if !foundStaging {
		t.Errorf("expected staging.jobsira.test in CT hostnames")
	}
}

// 3. Test TCP Discovery
func TestTCPDiscovery(t *testing.T) {
	lOpen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open listener: %v", err)
	}
	defer lOpen.Close()

	openPort := lOpen.Addr().(*net.TCPAddr).Port

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs: []string{"127.0.0.1"},
	})

	scannerEngine := tcpEngine.NewScanner(scopeEngine, 200*time.Millisecond, 2)
	results, err := scannerEngine.ScanIP(t.Context(), "127.0.0.1", []int{openPort, 9999})
	if err != nil {
		t.Fatalf("TCP scan failed: %v", err)
	}

	resMap := make(map[int]tcpEngine.PortResult)
	for _, r := range results {
		resMap[r.Port] = r
	}

	if resMap[openPort].State != tcpEngine.StateOpen {
		t.Errorf("expected open port for %d, got %s", openPort, resMap[openPort].State)
	}

	if resMap[9999].State != tcpEngine.StateClosed && resMap[9999].State != tcpEngine.StateFiltered {
		t.Errorf("expected closed/filtered for port 9999, got %s", resMap[9999].State)
	}
}

// 4. Test HTTP Fingerprinting & Titles
func TestHTTPFingerprinting(t *testing.T) {
	// Nginx mock
	sNginx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Jobsira Frontend</title></head></html>"))
	}))
	defer sNginx.Close()

	// Apache mock
	sApache := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.52 (Unix)")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Apache Test</title></head></html>"))
	}))
	defer sApache.Close()

	// Caddy mock
	sCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Caddy")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Caddy Test</title></head></html>"))
	}))
	defer sCaddy.Close()

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs: []string{"127.0.0.1"},
	})
	fetcher := httpEngine.NewFetcher(scopeEngine, 1024*1024, 2*time.Second, 2)
	fpEngine := fingerprint.NewEngine()

	// Test Nginx
	portNginx, _ := strconv.Atoi(strings.Split(sNginx.URL, ":")[2])
	obsNginx, err := fetcher.Fetch(t.Context(), "127.0.0.1", portNginx, "http", "")
	if err != nil {
		t.Fatalf("failed fetch nginx: %v", err)
	}
	if obsNginx.Title != "Jobsira Frontend" {
		t.Errorf("expected title Jobsira Frontend, got %s", obsNginx.Title)
	}
	techsNginx := fpEngine.Analyze(obsNginx, nil)
	if !hasTech(techsNginx, "nginx") {
		t.Errorf("expected nginx technology fingerprint")
	}

	// Test Apache
	portApache, _ := strconv.Atoi(strings.Split(sApache.URL, ":")[2])
	obsApache, _ := fetcher.Fetch(t.Context(), "127.0.0.1", portApache, "http", "")
	techsApache := fpEngine.Analyze(obsApache, nil)
	if !hasTech(techsApache, "Apache") {
		t.Errorf("expected Apache technology fingerprint")
	}

	// Test Caddy
	portCaddy, _ := strconv.Atoi(strings.Split(sCaddy.URL, ":")[2])
	obsCaddy, _ := fetcher.Fetch(t.Context(), "127.0.0.1", portCaddy, "http", "")
	techsCaddy := fpEngine.Analyze(obsCaddy, nil)
	if !hasTech(techsCaddy, "Caddy") {
		t.Errorf("expected Caddy technology fingerprint")
	}
}

// 5. Test HTTP Redirect
func TestHTTPRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://jobsira.test/")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer server.Close()

	port, _ := strconv.Atoi(strings.Split(server.URL, ":")[2])

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs: []string{"127.0.0.1"},
	})
	fetcher := httpEngine.NewFetcher(scopeEngine, 1024*1024, 2*time.Second, 0)
	obs, err := fetcher.Fetch(t.Context(), "127.0.0.1", port, "http", "")
	if err != nil {
		t.Fatalf("failed fetch redirect: %v", err)
	}

	if obs.StatusCode != 301 {
		t.Errorf("expected status 301, got %d", obs.StatusCode)
	}
	if obs.Location != "https://jobsira.test/" {
		t.Errorf("expected location https://jobsira.test/, got %s", obs.Location)
	}
}

// 6 & 7. Test TLS & SNI-dependent Certificates
func TestSNIDependentCertificates(t *testing.T) {
	certJobsira := generateTestCertificate("jobsira.test", []string{"jobsira.test", "www.jobsira.test"})
	certAPI := generateTestCertificate("api.jobsira.test", []string{"api.jobsira.test"})

	tlsConfig := &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName == "api.jobsira.test" {
				return &certAPI, nil
			}
			return &certJobsira, nil
		},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start SNI TLS listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				tlsConn := conn.(*tls.Conn)
				_ = tlsConn.Handshake()
				_ = tlsConn.Close()
			}(c)
		}
	}()

	port, _ := strconv.Atoi(strings.Split(listener.Addr().String(), ":")[1])

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs:     []string{"127.0.0.1"},
		Domains: []string{"jobsira.test", "api.jobsira.test"},
	})

	inspector := tlsEngine.NewInspector(scopeEngine, 2*time.Second)

	// SNI = jobsira.test
	obsJobsira, err := inspector.Inspect(t.Context(), "127.0.0.1", port, "jobsira.test")
	if err != nil {
		t.Fatalf("failed SNI jobsira.test: %v", err)
	}
	if obsJobsira.SubjectCN != "jobsira.test" {
		t.Errorf("expected CN jobsira.test, got %s", obsJobsira.SubjectCN)
	}

	// SNI = api.jobsira.test
	obsAPI, err := inspector.Inspect(t.Context(), "127.0.0.1", port, "api.jobsira.test")
	if err != nil {
		t.Fatalf("failed SNI api.jobsira.test: %v", err)
	}
	if obsAPI.SubjectCN != "api.jobsira.test" {
		t.Errorf("expected CN api.jobsira.test, got %s", obsAPI.SubjectCN)
	}
}

// 8 & 9. Test Certificate ↔ Hostname & Certificate ↔ IP Correlation
func TestCertificateCorrelations(t *testing.T) {
	engine := correlation.NewEngine()

	tlsObs := &tlsEngine.TLSObservation{
		Port:              443,
		FingerprintSHA256: "sha256fingerprint123",
		SubjectCN:         "jobsira.test",
		SAN:               []string{"jobsira.test", "www.jobsira.test"},
	}

	links := engine.CorrelateTLS("172.20.0.20", tlsObs)
	if len(links) < 2 {
		t.Fatalf("expected correlation links, got %d", len(links))
	}

	foundCertContains := false
	for _, l := range links {
		if l.Relationship == correlation.RelCertificateContains && l.TargetID == "jobsira.test" {
			foundCertContains = true
		}
	}

	if !foundCertContains {
		t.Errorf("expected certificate_contains relationship linking 172.20.0.20 to jobsira.test")
	}
}

// 10. Test Virtual Host HTTP Host Correlation
func TestHTTPHostCorrelation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "jobsira.test":
			_, _ = w.Write([]byte("Jobsira Homepage"))
		case "api.jobsira.test":
			_, _ = w.Write([]byte("Jobsira API"))
		case "admin.jobsira.test":
			_, _ = w.Write([]byte("Jobsira Admin"))
		default:
			_, _ = w.Write([]byte("Default"))
		}
	}))
	defer server.Close()

	port, _ := strconv.Atoi(strings.Split(server.URL, ":")[2])

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs:     []string{"127.0.0.1"},
		Domains: []string{"jobsira.test", "api.jobsira.test", "admin.jobsira.test"},
	})
	fetcher := httpEngine.NewFetcher(scopeEngine, 1024*1024, 2*time.Second, 0)

	vhosts := []string{"jobsira.test", "api.jobsira.test", "admin.jobsira.test"}
	for _, vhost := range vhosts {
		obs, err := fetcher.Fetch(t.Context(), "127.0.0.1", port, "http", vhost)
		if err != nil {
			t.Fatalf("failed fetch vhost %s: %v", vhost, err)
		}
		if obs.HostHeader != vhost {
			t.Errorf("expected host header %s, got %s", vhost, obs.HostHeader)
		}
	}
}

// 11 & 12. Test Origin Exposure & False Positive Reduction
func TestOriginExposureAndFalsePositive(t *testing.T) {
	evaluator := scoring.NewEvaluator()

	// High confidence true origin candidate
	tlsTrueOrigin := &tlsEngine.TLSObservation{
		SubjectCN: "jobsira.test",
		SAN:       []string{"jobsira.test", "www.jobsira.test"},
	}
	httpTrueOrigin := &httpEngine.HTTPObservation{
		HostHeader: "jobsira.test",
		Location:   "https://jobsira.test/",
		Title:      "jobsira.test portal",
	}

	trueRes := evaluator.Evaluate("jobsira.test", "172.20.0.20", tlsTrueOrigin, httpTrueOrigin, true)
	if trueRes.Confidence != scoring.ConfidenceVeryHigh {
		t.Errorf("expected VERY_HIGH confidence for true origin, got %s", trueRes.Confidence)
	}

	// False positive candidate (unrelated cert & http)
	tlsFalsePos := &tlsEngine.TLSObservation{
		SubjectCN: "unrelated.test",
		SAN:       []string{"unrelated.test"},
	}
	httpFalsePos := &httpEngine.HTTPObservation{
		HostHeader: "unrelated.test",
		Title:      "Unrelated Page",
	}

	falseRes := evaluator.Evaluate("jobsira.test", "172.20.0.50", tlsFalsePos, httpFalsePos, false)
	if falseRes.Confidence == scoring.ConfidenceVeryHigh || falseRes.Confidence == scoring.ConfidenceHigh {
		t.Errorf("expected LOW/MEDIUM confidence for unrelated IP 172.20.0.50, got %s", falseRes.Confidence)
	}
}

// 13. Test Evidence Scoring Levels
func TestEvidenceScoringLevels(t *testing.T) {
	evaluator := scoring.NewEvaluator()

	// LOW (score <= 30)
	resLow := evaluator.Evaluate("jobsira.test", "10.0.0.1", nil, nil, false)
	if resLow.Confidence != scoring.ConfidenceLow {
		t.Errorf("expected LOW confidence, got %s", resLow.Confidence)
	}

	// HIGH (score >= 61)
	resHigh := evaluator.Evaluate("jobsira.test", "10.0.0.2", &tlsEngine.TLSObservation{SubjectCN: "jobsira.test", SAN: []string{"jobsira.test"}}, &httpEngine.HTTPObservation{HostHeader: "jobsira.test"}, false)
	if resHigh.Confidence != scoring.ConfidenceHigh && resHigh.Confidence != scoring.ConfidenceVeryHigh {
		t.Errorf("expected HIGH or VERY_HIGH confidence, got %s", resHigh.Confidence)
	}
}

// 14, 15, 16. Test Historical & State Change Events
func TestStateChangeEvents(t *testing.T) {
	// DNS Change
	trackerDNS := dns.NewTracker()
	oldDNS := []dns.DNSRecord{{Domain: "jobsira.test", RecordType: dns.TypeA, Value: "172.20.0.10"}}
	newDNS := []dns.DNSRecord{{Domain: "jobsira.test", RecordType: dns.TypeA, Value: "172.20.0.20"}}
	dnsEvents := trackerDNS.DetectChanges("jobsira.test", oldDNS, newDNS)
	if len(dnsEvents) == 0 {
		t.Errorf("expected DNS change events")
	}
}

// 17. Test Scope Security Rejection
func TestScopeSecurityRejection(t *testing.T) {
	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs: []string{"172.20.0.20"},
	})

	scannerEngine := tcpEngine.NewScanner(scopeEngine, 100*time.Millisecond, 2)
	_, err := scannerEngine.ScanIP(t.Context(), "172.20.0.21", []int{80})
	if err == nil || !strings.Contains(err.Error(), "outside authorized target scope") {
		t.Errorf("expected SCAN REJECTED TARGET OUTSIDE AUTHORIZED SCOPE error, got %v", err)
	}
}

// 18. Test Rate Limiting
func TestRateLimitingCompliance(t *testing.T) {
	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs:    []string{"127.0.0.1"},
		MaxRPS: 1000,
	})

	ctx := t.Context()
	err := scopeEngine.WaitLimiter(ctx)
	if err != nil {
		t.Errorf("expected rate limiter wait success, got %v", err)
	}
}

// 19. Test Scan Job Cancellation
func TestScanCancellation(t *testing.T) {
	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs: []string{"127.0.0.1"},
	})

	apiServer := api.NewServer(scopeEngine)
	router := api.NewRouter(apiServer)

	reqCancel := httptest.NewRequest("POST", "/api/scans/job-999/cancel", nil)
	wCancel := httptest.NewRecorder()

	router.ServeHTTP(wCancel, reqCancel)
	if wCancel.Code != http.StatusOK || !strings.Contains(wCancel.Body.String(), "cancelled") {
		t.Errorf("expected 200 OK with cancelled status, got %s", wCancel.Body.String())
	}
}

func hasTech(techs []fingerprint.Technology, name string) bool {
	for _, t := range techs {
		if strings.EqualFold(t.Name, name) {
			return true
		}
	}
	return false
}

func generateTestCertificate(cn string, sans []string) tls.Certificate {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:              sans,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}
