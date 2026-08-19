package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sentinelscan/internal/scope"
	"sentinelscan/pkg/logger"
)

type CTHostname struct {
	Hostname  string    `json:"hostname"`
	Domain    string    `json:"domain"`
	Source    string    `json:"source"` // certificate_transparency
	FirstSeen time.Time `json:"first_seen"`
}

type Client struct {
	scopeEngine *scope.Engine
	httpClient  *http.Client
}

func NewClient(scopeEngine *scope.Engine, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		scopeEngine: scopeEngine,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

func (c *Client) DiscoverHostnames(ctx context.Context, domain string) ([]CTHostname, error) {
	cleanedDomain := strings.ToLower(strings.TrimSpace(domain))
	if cleanedDomain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	if c.scopeEngine != nil {
		if err := c.scopeEngine.WaitLimiter(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait cancelled: %w", err)
		}
		if !c.scopeEngine.IsAllowedDomain(cleanedDomain) {
			logger.Warn("CT discovery rejected by Scope Engine", "domain", cleanedDomain)
			return nil, fmt.Errorf("domain %s is outside authorized scan scope", cleanedDomain)
		}
	}

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", cleanedDomain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build crt.sh request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status code %d", resp.StatusCode)
	}

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode crt.sh JSON response: %w", err)
	}

	seen := make(map[string]bool)
	hostnames := make([]CTHostname, 0)
	now := time.Now()

	for _, entry := range entries {
		lines := strings.Split(entry.NameValue, "\n")
		for _, line := range lines {
			h := strings.ToLower(strings.TrimSpace(line))
			h = strings.TrimPrefix(h, "*.")
			if h != "" && !seen[h] {
				seen[h] = true
				hostnames = append(hostnames, CTHostname{
					Hostname:  h,
					Domain:    cleanedDomain,
					Source:    "certificate_transparency",
					FirstSeen: now,
				})
			}
		}
	}

	logger.Info("CT hostname discovery completed", "domain", cleanedDomain, "discovered_count", len(hostnames))
	return hostnames, nil
}
