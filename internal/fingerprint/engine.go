package fingerprint

import (
	"strings"

	"sentinelscan/internal/http"
	"sentinelscan/internal/tls"
)

type Technology struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"` // Web Server, CDN, Framework, CMS, SSL Provider
	Confidence  int      `json:"confidence"` // 0 - 100
	Evidence    []string `json:"evidence"`
}

type Rule struct {
	Name            string
	Category        string
	HeaderContains  map[string]string
	ServerContains  string
	TitleContains   string
	BodyContains    string
	CertCNContains  string
	CertIssuerMatch string
}

var defaultRules = []Rule{
	{
		Name:           "nginx",
		Category:       "Web Server",
		ServerContains: "nginx",
	},
	{
		Name:           "Apache",
		Category:       "Web Server",
		ServerContains: "apache",
	},
	{
		Name:           "Caddy",
		Category:       "Web Server",
		ServerContains: "caddy",
	},
	{
		Name:           "Traefik",
		Category:       "Web Server",
		ServerContains: "traefik",
	},
	{
		Name:           "Cloudflare",
		Category:       "CDN / Proxy",
		ServerContains: "cloudflare",
		HeaderContains: map[string]string{
			"CF-Ray": "",
		},
	},
	{
		Name:         "Next.js",
		Category:     "Framework",
		BodyContains: "__NEXT_DATA__",
		HeaderContains: map[string]string{
			"X-Nextjs-Redirect": "",
		},
	},
	{
		Name:         "WordPress",
		Category:     "CMS",
		BodyContains: "wp-content",
	},
	{
		Name:            "Let's Encrypt",
		Category:        "SSL Provider",
		CertIssuerMatch: "Let's Encrypt",
	},
}

type Engine struct {
	rules []Rule
}

func NewEngine() *Engine {
	return &Engine{
		rules: defaultRules,
	}
}

func (e *Engine) Analyze(httpObs *http.HTTPObservation, tlsObs *tls.TLSObservation) []Technology {
	detected := make([]Technology, 0)

	for _, rule := range e.rules {
		evidence := make([]string, 0)
		score := 0

		if httpObs != nil {
			if rule.ServerContains != "" && strings.Contains(strings.ToLower(httpObs.ServerHeader), strings.ToLower(rule.ServerContains)) {
				score += 50
				evidence = append(evidence, "server_header_match: "+httpObs.ServerHeader)
			}

			if rule.TitleContains != "" && strings.Contains(strings.ToLower(httpObs.Title), strings.ToLower(rule.TitleContains)) {
				score += 30
				evidence = append(evidence, "title_match: "+httpObs.Title)
			}

			for hKey, hVal := range rule.HeaderContains {
				for k, v := range httpObs.Headers {
					if strings.EqualFold(k, hKey) {
						if hVal == "" || strings.Contains(strings.ToLower(v), strings.ToLower(hVal)) {
							score += 40
							evidence = append(evidence, "header_match: "+k)
						}
					}
				}
			}
		}

		if tlsObs != nil {
			if rule.CertIssuerMatch != "" && strings.Contains(strings.ToLower(tlsObs.Issuer), strings.ToLower(rule.CertIssuerMatch)) {
				score += 60
				evidence = append(evidence, "cert_issuer_match: "+tlsObs.Issuer)
			}
			if rule.CertCNContains != "" && strings.Contains(strings.ToLower(tlsObs.SubjectCN), strings.ToLower(rule.CertCNContains)) {
				score += 40
				evidence = append(evidence, "cert_cn_match: "+tlsObs.SubjectCN)
			}
		}

		if score > 0 {
			confidence := score
			if confidence > 100 {
				confidence = 100
			}
			detected = append(detected, Technology{
				Name:       rule.Name,
				Category:   rule.Category,
				Confidence: confidence,
				Evidence:   evidence,
			})
		}
	}

	return detected
}
