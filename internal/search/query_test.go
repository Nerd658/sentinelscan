package search

import (
	"testing"
)

func TestParseQuery(t *testing.T) {
	qStr := `ssl.cert.subject.cn:"jobsira.com" port:443 nginx`
	parsed := ParseQuery(qStr)

	if len(parsed.Filters) != 2 {
		t.Fatalf("expected 2 filters, got %d", len(parsed.Filters))
	}

	if parsed.Filters[0].Field != "ssl.cert.subject.cn" || parsed.Filters[0].Value != "jobsira.com" {
		t.Errorf("unexpected filter 0: %+v", parsed.Filters[0])
	}

	if parsed.Filters[1].Field != "port" || parsed.Filters[1].Value != "443" {
		t.Errorf("unexpected filter 1: %+v", parsed.Filters[1])
	}

	if parsed.FreeText != "nginx" {
		t.Errorf("expected free text 'nginx', got %s", parsed.FreeText)
	}
}
