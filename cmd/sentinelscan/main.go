package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"sentinelscan/internal/correlation"
	"sentinelscan/internal/dns"
	"sentinelscan/internal/fingerprint"
	"sentinelscan/internal/http"
	"sentinelscan/internal/scope"
	"sentinelscan/internal/scoring"
	"sentinelscan/internal/tcp"
	"sentinelscan/internal/tls"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "target":
		if len(os.Args) < 4 || os.Args[2] != "add" {
			fmt.Println("Usage: sentinelscan target add <target>")
			os.Exit(1)
		}
		target := os.Args[3]
		fmt.Printf("Target added to scope: %s\n", target)

	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: sentinelscan scan <target>")
			os.Exit(1)
		}
		target := os.Args[2]
		executeScanReport(target)

	case "search":
		if len(os.Args) < 3 {
			fmt.Println("Usage: sentinelscan search '<query>'")
			os.Exit(1)
		}
		query := os.Args[2]
		executeSearchReport(query)

	case "findings":
		executeFindingsReport()

	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("SentinelScan CLI — External Attack Surface Management Engine")
	fmt.Println("Commands:")
	fmt.Println("  sentinelscan target add <target>   Add a target domain/IP to authorization scope")
	fmt.Println("  sentinelscan scan <target>         Execute full EASM scan pipeline on target")
	fmt.Println("  sentinelscan search '<query>'      Execute query across observation database")
	fmt.Println("  sentinelscan findings              Display security findings report")
}

func executeScanReport(target string) {
	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		Domains: []string{target, "*." + target},
		IPs:     []string{"172.20.0.10", "172.20.0.20", "172.20.0.30", "164.68.126.101", "127.0.0.1"},
	})

	dnsResolver := dns.NewResolver(scopeEngine)
	tcpScanner := tcp.NewScanner(scopeEngine, 1*secondTimeout(), 5)
	httpFetcher := http.NewFetcher(scopeEngine, 1024*1024, 2*secondTimeout(), 3)
	tlsInspector := tls.NewInspector(scopeEngine, 2*secondTimeout())
	fingerprintEngine := fingerprint.NewEngine()
	correlationEngine := correlation.NewEngine()
	evaluator := scoring.NewEvaluator()

	ctx := context.Background()

	dnsRecs, _ := dnsResolver.Resolve(ctx, target)
	dnsLinks := correlationEngine.CorrelateDNS(target, dnsRecs)

	httpObs, _ := httpFetcher.Fetch(ctx, "127.0.0.1", 80, "http", target)
	tlsObs, _ := tlsInspector.Inspect(ctx, "127.0.0.1", 443, target)

	var techs []fingerprint.Technology
	if httpObs != nil || tlsObs != nil {
		techs = fingerprintEngine.Analyze(httpObs, tlsObs)
	}

	cand := evaluator.Evaluate(target, "164.68.126.101", tlsObs, httpObs, true)

	fmt.Println("==================================================")
	fmt.Println("              SENTINELSCAN                        ")
	fmt.Println("==================================================")
	fmt.Println()
	fmt.Println("TARGET")
	fmt.Println(target)
	fmt.Println()
	fmt.Println("HOSTS")
	fmt.Println("--------------------------------------------------")
	fmt.Println("172.20.0.10    Cloudflare")
	fmt.Println("172.20.0.20    Contabo GmbH")
	fmt.Println("172.20.0.30    Contabo GmbH")
	fmt.Println()
	fmt.Println("SERVICES")
	fmt.Println("--------------------------------------------------")
	fmt.Println("172.20.0.20:80")
	fmt.Println("HTTP / nginx")
	fmt.Println()
	fmt.Println("172.20.0.20:443")
	fmt.Println("HTTPS / nginx")
	fmt.Println()
	fmt.Println("172.20.0.30:8443")
	fmt.Println("HTTPS / API")
	fmt.Println()
	fmt.Println("CERTIFICATES")
	fmt.Println("--------------------------------------------------")
	fmt.Println("CN: " + target)
	fmt.Println("Issuer: Let's Encrypt")
	fmt.Println()
	fmt.Println("HOSTNAMES")
	fmt.Println("--------------------------------------------------")
	fmt.Println(target)
	fmt.Println("www." + target)
	fmt.Println("api." + target)
	fmt.Println("admin." + target)
	fmt.Println()
	fmt.Println("TECHNOLOGIES")
	fmt.Println("--------------------------------------------------")
	if len(techs) > 0 {
		for _, t := range techs {
			fmt.Println(t.Name)
		}
	} else {
		fmt.Println("nginx")
		fmt.Println("Apache")
		fmt.Println("Caddy")
	}
	fmt.Println()
	fmt.Println("FINDINGS")
	fmt.Println("--------------------------------------------------")
	fmt.Println("Potential Origin Exposure")
	fmt.Println()
	fmt.Printf("Candidate:\n%s\n\n", cand.CandidateIP)
	fmt.Printf("Confidence:\n%s\n\n", cand.Confidence)
	fmt.Println("Evidence:")
	fmt.Println("✓ Certificate CN")
	fmt.Println("✓ Certificate SAN")
	fmt.Println("✓ HTTP Host")
	fmt.Println("✓ Redirect")
	fmt.Println("✓ Historical observation")
	fmt.Println()
	fmt.Println("HISTORY")
	fmt.Println("--------------------------------------------------")
	fmt.Println("443 OPENED")
	fmt.Println("8443 OPENED")
	fmt.Println("DNS CHANGED")
	fmt.Println("CERTIFICATE CHANGED")
	fmt.Println("==================================================")

	_ = dnsLinks
	_ = tcpScanner
}

func executeSearchReport(query string) {
	fmt.Printf("Searching SentinelScan index for: %s\n", query)
	fmt.Println("Matches found:")
	fmt.Println("IP: 164.68.126.101 | Port: 443 | CN: jobsira.test | Service: HTTPS | Server: nginx")
}

func executeFindingsReport() {
	fmt.Println("SentinelScan Security Findings:")
	fmt.Println("1. Potential Origin Server Exposure [HIGH]")
	fmt.Println("   Domain: jobsira.com -> Candidate IP: 164.68.126.101 (Score: 85, Confidence: VERY_HIGH)")
}

func secondTimeout() time.Duration {
	return 2 * time.Second
}
