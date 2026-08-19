package scoring

import (
	"strings"

	"sentinelscan/internal/http"
	"sentinelscan/internal/tls"
)

type ConfidenceLevel string

const (
	ConfidenceLow      ConfidenceLevel = "LOW"
	ConfidenceMedium   ConfidenceLevel = "MEDIUM"
	ConfidenceHigh     ConfidenceLevel = "HIGH"
	ConfidenceVeryHigh ConfidenceLevel = "VERY_HIGH"
)

type OriginCandidateResult struct {
	CandidateIP string          `json:"candidate_ip"`
	Domain      string          `json:"domain"`
	Score       int             `json:"score"`
	Confidence  ConfidenceLevel `json:"confidence"`
	Evidence    []string        `json:"evidence"`
}

type Evaluator struct{}

func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

func (e *Evaluator) Evaluate(domain, candidateIP string, tlsObs *tls.TLSObservation, httpObs *http.HTTPObservation, hasHistory bool) OriginCandidateResult {
	cleanedDomain := strings.ToLower(strings.TrimSpace(domain))
	score := 0
	evidence := make([]string, 0)

	if tlsObs != nil {
		// 1. Certificate CN match (+30)
		if strings.EqualFold(tlsObs.SubjectCN, cleanedDomain) {
			score += 30
			evidence = append(evidence, "certificate_cn_match")
		}

		// 2. Certificate SAN match (+25)
		for _, san := range tlsObs.SAN {
			if strings.EqualFold(san, cleanedDomain) || (strings.HasPrefix(san, "*.") && strings.HasSuffix(cleanedDomain, san[1:])) {
				score += 25
				evidence = append(evidence, "certificate_san_match")
				break
			}
		}
	}

	if httpObs != nil {
		// 3. HTTP Host match (+20)
		if strings.EqualFold(httpObs.HostHeader, cleanedDomain) {
			score += 20
			evidence = append(evidence, "http_host_match")
		}

		// 4. HTTP Redirect match (+10)
		if httpObs.Location != "" && strings.Contains(strings.ToLower(httpObs.Location), cleanedDomain) {
			score += 10
			evidence = append(evidence, "http_redirect_match")
		}

		// 5. Title similarity (+5)
		if httpObs.Title != "" && strings.Contains(strings.ToLower(httpObs.Title), cleanedDomain) {
			score += 5
			evidence = append(evidence, "title_match")
		}
	}

	// 6. Historical evidence (+10)
	if hasHistory {
		score += 10
		evidence = append(evidence, "historical_observation")
	}

	var confidence ConfidenceLevel
	switch {
	case score >= 81:
		confidence = ConfidenceVeryHigh
	case score >= 61:
		confidence = ConfidenceHigh
	case score >= 31:
		confidence = ConfidenceMedium
	default:
		confidence = ConfidenceLow
	}

	return OriginCandidateResult{
		CandidateIP: candidateIP,
		Domain:      cleanedDomain,
		Score:       score,
		Confidence:  confidence,
		Evidence:    evidence,
	}
}
