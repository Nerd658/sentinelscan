package fingerprint

import (
	"testing"

	"sentinelscan/internal/http"
	"sentinelscan/internal/tls"
)

func TestFingerprintEngine(t *testing.T) {
	engine := NewEngine()

	httpObs := &http.HTTPObservation{
		ServerHeader: "nginx/1.24.0",
		Title:        "My Application",
		Headers: map[string]string{
			"CF-Ray": "89347891238",
		},
	}

	tlsObs := &tls.TLSObservation{
		Issuer:    "Let's Encrypt Authority X3",
		SubjectCN: "jobsira.com",
	}

	techs := engine.Analyze(httpObs, tlsObs)

	if len(techs) == 0 {
		t.Fatalf("expected fingerprint technology matches, got none")
	}

	foundNginx := false
	foundCloudflare := false
	foundLetsEncrypt := false

	for _, tech := range techs {
		if tech.Name == "nginx" {
			foundNginx = true
		}
		if tech.Name == "Cloudflare" {
			foundCloudflare = true
		}
		if tech.Name == "Let's Encrypt" {
			foundLetsEncrypt = true
		}
	}

	if !foundNginx {
		t.Errorf("expected nginx detection")
	}
	if !foundCloudflare {
		t.Errorf("expected Cloudflare detection")
	}
	if !foundLetsEncrypt {
		t.Errorf("expected Let's Encrypt detection")
	}
}
