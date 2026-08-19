package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"sentinelscan/internal/scope"
	"sentinelscan/pkg/logger"
)

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

type HTTPObservation struct {
	IP           string            `json:"ip"`
	Port         int               `json:"port"`
	Scheme       string            `json:"scheme"`
	HostHeader   string            `json:"host_header"`
	StatusCode   int               `json:"status_code"`
	ServerHeader string            `json:"server_header"`
	Location     string            `json:"location"`
	ContentType  string            `json:"content_type"`
	Title        string            `json:"title"`
	FaviconHash  string            `json:"favicon_hash"`
	Headers      map[string]string `json:"headers"`
	BodySize     int64             `json:"body_size"`
	Timestamp    time.Time         `json:"timestamp"`
}

type Fetcher struct {
	scopeEngine  *scope.Engine
	maxBodySize  int64
	timeout      time.Duration
	maxRedirects int
}

func NewFetcher(scopeEngine *scope.Engine, maxBodySize int64, timeout time.Duration, maxRedirects int) *Fetcher {
	if maxBodySize <= 0 {
		maxBodySize = 1048576 // 1MB default
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if maxRedirects < 0 {
		maxRedirects = 5
	}
	return &Fetcher{
		scopeEngine:  scopeEngine,
		maxBodySize:  maxBodySize,
		timeout:      timeout,
		maxRedirects: maxRedirects,
	}
}

func (f *Fetcher) Fetch(ctx context.Context, ipStr string, port int, scheme, hostHeader string) (*HTTPObservation, error) {
	if scheme == "" {
		if port == 443 || port == 8443 {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	target := ipStr
	if hostHeader != "" {
		target = hostHeader
	}

	if f.scopeEngine != nil {
		if err := f.scopeEngine.WaitLimiter(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait cancelled: %w", err)
		}
		if !f.scopeEngine.IsAllowedTarget(target) {
			logger.Warn("HTTP fetch attempt rejected by Scope Engine", "target", target)
			return nil, fmt.Errorf("target %s is outside authorized scan scope", target)
		}
	}

	client := &http.Client{
		Timeout: f.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         hostHeader,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: f.timeout}
				return dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ipStr, port))
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= f.maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, ipStr, port)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP request: %w", err)
	}

	if hostHeader != "" {
		req.Host = hostHeader
	}
	req.Header.Set("User-Agent", "SentinelScan/1.0 (EASM Scanner Engine)")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed to %s: %w", url, err)
	}
	defer resp.Body.Close()

	bodyReader := io.LimitReader(resp.Body, f.maxBodySize)
	bodyBytes, err := io.ReadAll(bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed reading HTTP body: %w", err)
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	title := extractTitle(string(bodyBytes))
	server := resp.Header.Get("Server")
	location := resp.Header.Get("Location")
	contentType := resp.Header.Get("Content-Type")

	obs := &HTTPObservation{
		IP:           ipStr,
		Port:         port,
		Scheme:       scheme,
		HostHeader:   hostHeader,
		StatusCode:   resp.StatusCode,
		ServerHeader: server,
		Location:     location,
		ContentType:  contentType,
		Title:        title,
		FaviconHash:  "", // Optional favicon hash
		Headers:      headers,
		BodySize:     int64(len(bodyBytes)),
		Timestamp:    start,
	}

	logger.Info("HTTP observation captured", "ip", ipStr, "port", port, "status", resp.StatusCode, "server", server, "title", title)
	return obs, nil
}

func extractTitle(body string) string {
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
