package origin

import (
	"context"
	"fmt"
	"net"
	"strings"

	"sentinelscan/internal/http"
	"sentinelscan/internal/tcp"
	"sentinelscan/internal/tls"
)

type OriginCandidate struct {
	IP         string   `json:"ip"`
	Source     string   `json:"source"`
	Evidence   []string `json:"evidence"`
	Role       NodeRole `json:"role"`
	Score      int      `json:"score"`
	Confidence string   `json:"confidence"`
	Status     string   `json:"status"` // DISCOVERED, VERIFIED, REJECTED
}

type OriginVerdict struct {
	TargetDomain   string            `json:"target_domain"`
	EdgeDetected   bool              `json:"edge_detected"`
	EdgeProvider   string            `json:"edge_provider,omitempty"`
	EdgeIPs        []string          `json:"edge_ips"`
	Candidates     []OriginCandidate `json:"candidates"`
	ConfirmedOrigin string           `json:"confirmed_origin,omitempty"`
	Confidence     string            `json:"confidence"`
	Status         string            `json:"status"` // CONFIRMED, UNCONFIRMED, NOT_DISCOVERED
}

type Engine struct {
	classifier *Classifier
}

func NewEngine() *Engine {
	return &Engine{
		classifier: NewClassifier(),
	}
}

func (e *Engine) EvaluateTarget(
	ctx context.Context,
	targetDomain string,
	discoveredIPs []string,
	historicalIPs []string,
	tcpScanner *tcp.Scanner,
	httpFetcher *http.Fetcher,
	tlsInspector *tls.Inspector,
) OriginVerdict {
	cleanedDomain := strings.ToLower(strings.TrimSpace(targetDomain))
	verdict := OriginVerdict{
		TargetDomain: cleanedDomain,
		EdgeIPs:      make([]string, 0),
		Candidates:   make([]OriginCandidate, 0),
		Status:       "NOT_DISCOVERED",
		Confidence:   "LOW",
	}

	edgeIPSet := make(map[string]bool)

	// 1. Analyze and classify current DNS discovered IPs
	for _, ip := range discoveredIPs {
		httpObs, _ := httpFetcher.Fetch(ctx, ip, 80, "http", cleanedDomain)
		if httpObs == nil {
			httpObs, _ = httpFetcher.Fetch(ctx, ip, 443, "https", cleanedDomain)
		}
		tlsObs, _ := tlsInspector.Inspect(ctx, ip, 443, cleanedDomain)

		classification := e.classifier.Classify(ip, httpObs, tlsObs)
		if classification.IsCDN {
			verdict.EdgeDetected = true
			verdict.EdgeProvider = classification.Provider
			verdict.EdgeIPs = append(verdict.EdgeIPs, ip)
			edgeIPSet[ip] = true
		}
	}

	// 2. Aggregate potential origin candidates (excluding confirmed Edge IPs)
	candidateIPSet := make(map[string]string) // IP -> Source

	for _, ip := range historicalIPs {
		if !edgeIPSet[ip] && net.ParseIP(ip) != nil {
			candidateIPSet[ip] = "Historical Certificate Association"
		}
	}

	for _, ip := range discoveredIPs {
		if !edgeIPSet[ip] {
			candidateIPSet[ip] = "Direct DNS Resolution"
		}
	}

	// 3. Proactively verify each candidate
	for candidateIP, source := range candidateIPSet {
		candidate := e.verifyCandidate(ctx, candidateIP, cleanedDomain, source, tcpScanner, httpFetcher, tlsInspector)
		verdict.Candidates = append(verdict.Candidates, candidate)

		if candidate.Score >= 75 && candidate.Status == "VERIFIED" {
			verdict.ConfirmedOrigin = candidate.IP
			verdict.Confidence = candidate.Confidence
			verdict.Status = "CONFIRMED"
		}
	}

	if verdict.Status == "NOT_DISCOVERED" && len(verdict.Candidates) > 0 {
		verdict.Status = "UNCONFIRMED"
	}

	return verdict
}

func (e *Engine) verifyCandidate(
	ctx context.Context,
	ip, domain, source string,
	tcpScanner *tcp.Scanner,
	httpFetcher *http.Fetcher,
	tlsInspector *tls.Inspector,
) OriginCandidate {
	evidence := []string{fmt.Sprintf("source: %s", source)}
	score := 0

	// 1. TCP Port probe
	portResults, err := tcpScanner.ScanIP(ctx, ip, []int{80, 443, 8080, 8443})
	hasOpenPort := false
	if err == nil {
		for _, p := range portResults {
			if p.State == tcp.StateOpen {
				hasOpenPort = true
				break
			}
		}
	}

	if !hasOpenPort {
		return OriginCandidate{
			IP:         ip,
			Source:     source,
			Evidence:   append(evidence, "all probed ports closed"),
			Role:       RoleUnknown,
			Score:      0,
			Confidence: "LOW",
			Status:     "REJECTED",
		}
	}

	evidence = append(evidence, "ports 80/443 responsive")
	score += 20

	// 2. TLS Handshake with target SNI
	tlsObs, _ := tlsInspector.Inspect(ctx, ip, 443, domain)
	if tlsObs != nil {
		if strings.EqualFold(tlsObs.SubjectCN, domain) {
			score += 35
			evidence = append(evidence, fmt.Sprintf("certificate CN exact match: %s", tlsObs.SubjectCN))
		}
		for _, san := range tlsObs.SAN {
			if strings.EqualFold(san, domain) || (strings.HasPrefix(san, "*.") && strings.HasSuffix(domain, san[1:])) {
				score += 25
				evidence = append(evidence, fmt.Sprintf("certificate SAN match: %s", san))
				break
			}
		}
	}

	// 3. HTTP Request with target Host Header
	httpObs, _ := httpFetcher.Fetch(ctx, ip, 80, "http", domain)
	if httpObs == nil {
		httpObs, _ = httpFetcher.Fetch(ctx, ip, 443, "https", domain)
	}

	if httpObs != nil {
		if httpObs.StatusCode == 200 || httpObs.StatusCode == 301 || httpObs.StatusCode == 302 {
			score += 15
			evidence = append(evidence, fmt.Sprintf("HTTP %d response for Host %s", httpObs.StatusCode, domain))
		}
		if httpObs.Location != "" && strings.Contains(strings.ToLower(httpObs.Location), domain) {
			score += 10
			evidence = append(evidence, fmt.Sprintf("HTTP redirect to target domain: %s", httpObs.Location))
		}
		if httpObs.ServerHeader != "" && !strings.Contains(strings.ToLower(httpObs.ServerHeader), "cloudflare") {
			evidence = append(evidence, fmt.Sprintf("backend server signature: %s", httpObs.ServerHeader))
		}
	}

	// Classify node role
	classification := e.classifier.Classify(ip, httpObs, tlsObs)
	if classification.IsCDN {
		// Penalty if it's actually an edge node
		return OriginCandidate{
			IP:         ip,
			Source:     source,
			Evidence:   append(evidence, "classified as CDN Edge Proxy ("+classification.Provider+")"),
			Role:       RoleEdgeProxy,
			Score:      5,
			Confidence: "LOW",
			Status:     "REJECTED",
		}
	}

	confidence := "LOW"
	status := "UNCONFIRMED"
	if score >= 80 {
		confidence = "VERY_HIGH"
		status = "VERIFIED"
	} else if score >= 60 {
		confidence = "HIGH"
		status = "VERIFIED"
	} else if score >= 40 {
		confidence = "MEDIUM"
	}

	return OriginCandidate{
		IP:         ip,
		Source:     source,
		Evidence:   evidence,
		Role:       RoleOriginCandidate,
		Score:      score,
		Confidence: confidence,
		Status:     status,
	}
}
