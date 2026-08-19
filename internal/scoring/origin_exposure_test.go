package scoring

import (
	"testing"

	"sentinelscan/internal/http"
	"sentinelscan/internal/tls"
)

func TestOriginExposureEvaluatorScoreCalculation(t *testing.T) {
	evaluator := NewEvaluator()

	domain := "jobsira.com"
	candidateIP := "164.68.126.101"

	tlsObs := &tls.TLSObservation{
		SubjectCN: "jobsira.com",
		SAN:       []string{"jobsira.com", "www.jobsira.com"},
	}

	httpObs := &http.HTTPObservation{
		HostHeader: "jobsira.com",
		Location:   "https://jobsira.com/",
		Title:      "jobsira.com portal",
	}

	res := evaluator.Evaluate(domain, candidateIP, tlsObs, httpObs, true)

	// CN (+30) + SAN (+25) + Host (+20) + Redirect (+10) + Title (+5) + History (+10) = 100
	if res.Score != 100 {
		t.Errorf("expected score 100, got %d", res.Score)
	}

	if res.Confidence != ConfidenceVeryHigh {
		t.Errorf("expected VERY_HIGH confidence, got %s", res.Confidence)
	}

	if len(res.Evidence) != 6 {
		t.Errorf("expected 6 evidence signals, got %d", len(res.Evidence))
	}
}
