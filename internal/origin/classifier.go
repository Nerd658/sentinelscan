package origin

import (
	"net"
	"strings"

	"sentinelscan/internal/http"
	"sentinelscan/internal/tls"
)

type NodeRole string

const (
	RoleEdgeProxy       NodeRole = "EDGE_PROXY"
	RoleOriginCandidate NodeRole = "ORIGIN_CANDIDATE"
	RoleDirectHost      NodeRole = "DIRECT_HOST"
	RoleUnknown         NodeRole = "UNKNOWN"
)

type ClassificationResult struct {
	Role       NodeRole `json:"role"`
	Provider   string   `json:"provider,omitempty"`
	IsCDN      bool     `json:"is_cdn"`
	Confidence string   `json:"confidence"`
	Reason     string   `json:"reason"`
}

var knownCDNCIDRs = []string{
	// Cloudflare IPv4
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

type Classifier struct {
	cdnIPNets []*net.IPNet
}

func NewClassifier() *Classifier {
	nets := make([]*net.IPNet, 0, len(knownCDNCIDRs))
	for _, cidr := range knownCDNCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}
	return &Classifier{cdnIPNets: nets}
}

func (c *Classifier) Classify(ipStr string, httpObs *http.HTTPObservation, tlsObs *tls.TLSObservation) ClassificationResult {
	parsedIP := net.ParseIP(ipStr)

	// 1. Check known CDN IP CIDR ranges
	if parsedIP != nil {
		for _, ipNet := range c.cdnIPNets {
			if ipNet.Contains(parsedIP) {
				return ClassificationResult{
					Role:       RoleEdgeProxy,
					Provider:   "Cloudflare",
					IsCDN:      true,
					Confidence: "VERY_HIGH",
					Reason:     "IP belongs to known Cloudflare CDN CIDR range",
				}
			}
		}
	}

	// 2. Check HTTP Response Headers for CDN signatures
	if httpObs != nil {
		server := strings.ToLower(httpObs.ServerHeader)
		if strings.Contains(server, "cloudflare") {
			return ClassificationResult{
				Role:       RoleEdgeProxy,
				Provider:   "Cloudflare",
				IsCDN:      true,
				Confidence: "VERY_HIGH",
				Reason:     "HTTP Server header indicates Cloudflare Edge",
			}
		}
		if strings.Contains(server, "cloudfront") {
			return ClassificationResult{
				Role:       RoleEdgeProxy,
				Provider:   "Amazon CloudFront",
				IsCDN:      true,
				Confidence: "VERY_HIGH",
				Reason:     "HTTP Server header indicates Amazon CloudFront",
			}
		}
		if strings.Contains(server, "cdn-edge-proxy") || strings.Contains(server, "fastly") || strings.Contains(server, "akamai") {
			return ClassificationResult{
				Role:       RoleEdgeProxy,
				Provider:   "CDN / Edge Proxy",
				IsCDN:      true,
				Confidence: "HIGH",
				Reason:     "HTTP Server header indicates Edge Proxy infrastructure",
			}
		}

		// Check specific CDN headers
		for hKey := range httpObs.Headers {
			lowerK := strings.ToLower(hKey)
			if lowerK == "cf-ray" || lowerK == "cf-cache-status" {
				return ClassificationResult{
					Role:       RoleEdgeProxy,
					Provider:   "Cloudflare",
					IsCDN:      true,
					Confidence: "VERY_HIGH",
					Reason:     "Cloudflare proprietary header detected (" + hKey + ")",
				}
			}
			if lowerK == "x-amz-cf-id" {
				return ClassificationResult{
					Role:       RoleEdgeProxy,
					Provider:   "Amazon CloudFront",
					IsCDN:      true,
					Confidence: "VERY_HIGH",
					Reason:     "CloudFront proprietary header detected (" + hKey + ")",
				}
			}
			if lowerK == "x-fastly-request-id" {
				return ClassificationResult{
					Role:       RoleEdgeProxy,
					Provider:   "Fastly",
					IsCDN:      true,
					Confidence: "VERY_HIGH",
					Reason:     "Fastly proprietary header detected (" + hKey + ")",
				}
			}
			if lowerK == "x-cdn-edge" {
				return ClassificationResult{
					Role:       RoleEdgeProxy,
					Provider:   "Generic CDN Simulator",
					IsCDN:      true,
					Confidence: "HIGH",
					Reason:     "Edge proxy header detected (" + hKey + ")",
				}
			}
		}
	}

	// 3. Check TLS Certificate Issuer for Managed CDN Certs
	if tlsObs != nil {
		issuer := strings.ToLower(tlsObs.Issuer)
		if strings.Contains(issuer, "cloudflare") || strings.Contains(issuer, "ye1") {
			if httpObs != nil && (strings.Contains(strings.ToLower(httpObs.ServerHeader), "cloudflare") || len(httpObs.Headers) == 0) {
				return ClassificationResult{
					Role:       RoleEdgeProxy,
					Provider:   "Cloudflare Managed SSL",
					IsCDN:      true,
					Confidence: "HIGH",
					Reason:     "TLS certificate issuer matches Cloudflare Managed CA",
				}
			}
		}
	}

	// Default to potential origin candidate or direct host if not an edge proxy
	return ClassificationResult{
		Role:       RoleOriginCandidate,
		Provider:   "Direct / Hosting Infrastructure",
		IsCDN:      false,
		Confidence: "MEDIUM",
		Reason:     "No CDN or Edge Proxy signatures detected",
	}
}
