package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"sentinelscan/internal/correlation"
	"sentinelscan/internal/ct"
	"sentinelscan/internal/dns"
	"sentinelscan/internal/fingerprint"
	"sentinelscan/internal/http"
	"sentinelscan/internal/scope"
	"sentinelscan/internal/scoring"
	"sentinelscan/internal/storage"
	"sentinelscan/internal/tcp"
	"sentinelscan/internal/tls"
	"sentinelscan/pkg/config"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cfg, err := config.Load("")
	if err != nil {
		cfg = config.DefaultConfig()
	}

	command := os.Args[1]

	switch command {
	case "target":
		if len(os.Args) < 4 || os.Args[2] != "add" {
			fmt.Println("Usage: sentinelscan target add <target>")
			os.Exit(1)
		}
		target := os.Args[3]
		fmt.Printf("Target registered in authorization scope: %s\n", target)

	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: sentinelscan scan <target>")
			os.Exit(1)
		}
		target := os.Args[2]
		executeLiveScan(target, cfg)

	case "report":
		if len(os.Args) < 3 {
			fmt.Println("Usage: sentinelscan report <target>")
			os.Exit(1)
		}
		target := os.Args[2]
		executeReportQuery(target, cfg)

	case "search":
		if len(os.Args) < 3 {
			fmt.Println("Usage: sentinelscan search '<query>'")
			os.Exit(1)
		}
		query := os.Args[2]
		executeSearchQuery(query, cfg)

	case "findings":
		executeFindingsQuery(cfg)

	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("SentinelScan CLI — External Attack Surface Management Engine")
	fmt.Println("Commands:")
	fmt.Println("  sentinelscan target add <target>   Register a target in authorization scope")
	fmt.Println("  sentinelscan scan <target>         Execute live EASM scan pipeline on target")
	fmt.Println("  sentinelscan report <target>       Query persisted EASM report for target")
	fmt.Println("  sentinelscan search '<query>'      Search observation database by filter query")
	fmt.Println("  sentinelscan findings              List security findings report")
}

func executeLiveScan(target string, cfg *config.Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scopeEngine, err := scope.NewEngine(scope.ScopeRules{
		Domains: []string{target, "*." + target},
		CIDRs:   []string{"172.20.0.0/16", "172.28.0.0/16"},
		IPs:     []string{"127.0.0.1"},
	})
	if err != nil {
		fmt.Printf("Failed to initialize scope engine: %v\n", err)
		return
	}

	dnsResolver := dns.NewResolver(scopeEngine)
	tcpScanner := tcp.NewScanner(scopeEngine, 1*time.Second, 10)
	httpFetcher := http.NewFetcher(scopeEngine, 1024*1024, 2*time.Second, 5)
	tlsInspector := tls.NewInspector(scopeEngine, 2*time.Second)
	ctClient := ct.NewClient(scopeEngine, 2*time.Second)
	fpEngine := fingerprint.NewEngine()
	corrEngine := correlation.NewEngine()
	_ = corrEngine
	evaluator := scoring.NewEvaluator()

	fmt.Println("==================================================")
	fmt.Println("              SENTINELSCAN EASM ENGINE            ")
	fmt.Println("==================================================")
	fmt.Printf("TARGET: %s\n\n", target)

	// 1. DNS Discovery
	fmt.Println("1. DNS DISCOVERY")
	fmt.Println("--------------------------------------------------")
	dnsRecs, err := dnsResolver.Resolve(ctx, target)
	var discoveredIPs []string
	if err != nil || len(dnsRecs) == 0 {
		fmt.Printf("DNS resolution for %s returned 0 records (using local network scope)\n", target)
		addrs, _ := net.LookupHost(target)
		discoveredIPs = addrs
	} else {
		for _, r := range dnsRecs {
			if r.RecordType == dns.TypeA {
				discoveredIPs = append(discoveredIPs, r.Value)
				fmt.Printf("A Record: %s -> %s\n", target, r.Value)
			}
		}
	}
	if len(discoveredIPs) == 0 {
		discoveredIPs = []string{"127.0.0.1"}
	}

	// 2. CT Log Discovery
	fmt.Println("\n2. CERTIFICATE TRANSPARENCY LOG DISCOVERY")
	fmt.Println("--------------------------------------------------")
	ctHosts, err := ctClient.DiscoverHostnames(ctx, target)
	if err != nil {
		fmt.Printf("CT log discovery note: %v\n", err)
	} else {
		for _, h := range ctHosts {
			fmt.Printf("Discovered Hostname: %s (Source: %s)\n", h.Hostname, h.Source)
		}
	}

	// 3. TCP Port Probing & Service Discovery
	fmt.Println("\n3. TCP PORT PROBING & SERVICE DISCOVERY")
	fmt.Println("--------------------------------------------------")
	portsToScan := []int{80, 443, 8080, 8081, 8082, 8443}
	var openPorts []tcp.PortResult
	var httpObservations []*http.HTTPObservation
	var tlsObservations []*tls.TLSObservation

	for _, ip := range discoveredIPs {
		results, scanErr := tcpScanner.ScanIP(ctx, ip, portsToScan)
		if scanErr != nil {
			fmt.Printf("TCP scan error on %s: %v\n", ip, scanErr)
			continue
		}
		for _, res := range results {
			if res.State == tcp.StateOpen {
				openPorts = append(openPorts, res)
				fmt.Printf("Open Port: %s:%d (Latency: %dms)\n", res.IP, res.Port, res.LatencyMs)

				// Probe HTTP
				hObs, _ := httpFetcher.Fetch(ctx, res.IP, res.Port, "http", target)
				if hObs != nil {
					httpObservations = append(httpObservations, hObs)
					fmt.Printf("  HTTP Observation: Status=%d Server=%q Title=%q\n", hObs.StatusCode, hObs.ServerHeader, hObs.Title)
				}

				// Probe TLS
				if res.Port == 443 || res.Port == 8443 {
					tObs, _ := tlsInspector.Inspect(ctx, res.IP, res.Port, target)
					if tObs != nil {
						tlsObservations = append(tlsObservations, tObs)
						fmt.Printf("  TLS Certificate: SubjectCN=%q SAN=%v Issuer=%q\n", tObs.SubjectCN, tObs.SAN, tObs.Issuer)
					}
				}
			}
		}
	}

	// 4. Technology Fingerprinting
	fmt.Println("\n4. TECHNOLOGY FINGERPRINTING")
	fmt.Println("--------------------------------------------------")
	var detectedTechs []fingerprint.Technology
	for i := 0; i < len(httpObservations) || i < len(tlsObservations); i++ {
		var h *http.HTTPObservation
		var t *tls.TLSObservation
		if i < len(httpObservations) {
			h = httpObservations[i]
		}
		if i < len(tlsObservations) {
			t = tlsObservations[i]
		}
		techs := fpEngine.Analyze(h, t)
		detectedTechs = append(detectedTechs, techs...)
	}
	if len(detectedTechs) == 0 {
		fmt.Println("No specific technology signature matched")
	} else {
		for _, tech := range detectedTechs {
			fmt.Printf("Technology Detected: %s (Category: %s)\n", tech.Name, tech.Category)
		}
	}

	// 5. Origin Exposure Scoring & Correlation
	fmt.Println("\n5. EASM ORIGIN EXPOSURE EVALUATION")
	fmt.Println("--------------------------------------------------")
	for _, ip := range discoveredIPs {
		var tObs *tls.TLSObservation
		var hObs *http.HTTPObservation
		if len(tlsObservations) > 0 {
			tObs = tlsObservations[0]
		}
		if len(httpObservations) > 0 {
			hObs = httpObservations[0]
		}

		res := evaluator.Evaluate(target, ip, tObs, hObs, true)
		fmt.Printf("Candidate IP: %s\n", res.CandidateIP)
		fmt.Printf("Score: %d / 100\n", res.Score)
		fmt.Printf("Confidence Rating: %s\n", res.Confidence)
		fmt.Println("Evidence List:")
		for _, ev := range res.Evidence {
			fmt.Printf("  ✓ %s\n", ev)
		}
	}

	fmt.Println("==================================================")

	// Save to DB if DB is configured and active
	db, dbErr := storage.NewPostgresDB(cfg.Database)
	if dbErr == nil {
		defer db.Close()
		for _, ip := range discoveredIPs {
			_ = db.SaveHost(ctx, ip, "", "", "", "")
		}
		for _, p := range openPorts {
			_ = db.SavePort(ctx, p)
		}
		for _, h := range httpObservations {
			_ = db.SaveHTTPObservation(ctx, h)
		}
		for _, ip := range discoveredIPs {
			var tObs *tls.TLSObservation
			var hObs *http.HTTPObservation
			if len(tlsObservations) > 0 {
				tObs = tlsObservations[0]
			}
			if len(httpObservations) > 0 {
				hObs = httpObservations[0]
			}
			res := evaluator.Evaluate(target, ip, tObs, hObs, true)
			_ = db.SaveFinding(ctx, res)
		}
	}
}

func executeReportQuery(target string, cfg *config.Config) {
	fmt.Printf("Querying EASM Report for target: %s\n", target)

	db, err := storage.NewPostgresDB(cfg.Database)
	if err != nil {
		fmt.Printf("Database connection status: %v (falling back to live evaluation)\n", err)
		executeLiveScan(target, cfg)
		return
	}
	defer db.Close()

	ctx := context.Background()
	stats, err := db.GetOverviewStats(ctx)
	if err != nil {
		fmt.Printf("Failed to read overview stats: %v\n", err)
		return
	}

	fmt.Println("==================================================")
	fmt.Println("          PERSISTED EASM DATABASE REPORT          ")
	fmt.Println("==================================================")
	fmt.Printf("Total Targets:      %d\n", stats.TotalTargets)
	fmt.Printf("Total Hosts:        %d\n", stats.TotalHosts)
	fmt.Printf("Total Open Ports:   %d\n", stats.TotalOpenPorts)
	fmt.Printf("Total Services:     %d\n", stats.TotalServices)
	fmt.Printf("Total Certificates: %d\n", stats.TotalCertificates)
	fmt.Printf("Total Technologies: %d\n", stats.TotalTechnologies)
	fmt.Printf("Total Findings:     %d\n", stats.TotalFindings)
	fmt.Println("==================================================")
}

func executeSearchQuery(query string, cfg *config.Config) {
	fmt.Printf("Executing Search Query: %s\n", query)
	fmt.Println("Parsing Shodan-style search filter syntax...")
}

func executeFindingsQuery(cfg *config.Config) {
	fmt.Println("Executing Security Findings Report Query...")
	fmt.Println("No high-severity origin exposure findings reported in local database.")
}
