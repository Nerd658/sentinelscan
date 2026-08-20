package scope

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Target    string    `json:"target"`
	TargetType string   `json:"target_type"`
	Allowed   bool      `json:"allowed"`
	Reason    string    `json:"reason"`
}

type Engine struct {
	mu             sync.RWMutex
	allowedIPs     map[string]bool
	allowedCIDRs   []*net.IPNet
	allowedDomains []string

	limiter    *rate.Limiter
	killSwitch uint32 // 0: inactive, 1: active
	auditLog   *os.File
}

type ScopeRules struct {
	IPs      []string `yaml:"ips"`
	CIDRs    []string `yaml:"cidrs"`
	Domains  []string `yaml:"domains"`
	MaxRPS   int      `yaml:"max_rps"`
	AuditFile string   `yaml:"audit_file"`
}

func NewEngine(rules ScopeRules) (*Engine, error) {
	e := &Engine{
		allowedIPs:     make(map[string]bool),
		allowedCIDRs:   make([]*net.IPNet, 0),
		allowedDomains: make([]string, 0),
	}

	for _, ipStr := range rules.IPs {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			return nil, fmt.Errorf("invalid IP in scope rules: %s", ipStr)
		}
		e.allowedIPs[ip.String()] = true
	}

	for _, cidrStr := range rules.CIDRs {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidrStr))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR in scope rules %s: %w", cidrStr, err)
		}
		e.allowedCIDRs = append(e.allowedCIDRs, ipNet)
	}

	for _, domain := range rules.Domains {
		cleaned := strings.ToLower(strings.TrimSpace(domain))
		if cleaned != "" {
			e.allowedDomains = append(e.allowedDomains, cleaned)
		}
	}

	rps := rules.MaxRPS
	if rps <= 0 {
		rps = 100
	}
	e.limiter = rate.NewLimiter(rate.Limit(rps), rps)

	if rules.AuditFile != "" {
		f, err := os.OpenFile(rules.AuditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			e.auditLog = f
		}
	}

	return e, nil
}

func (e *Engine) ActivateKillSwitch() {
	atomic.StoreUint32(&e.killSwitch, 1)
}

func (e *Engine) DeactivateKillSwitch() {
	atomic.StoreUint32(&e.killSwitch, 0)
}

func (e *Engine) IsKillSwitchActive() bool {
	return atomic.LoadUint32(&e.killSwitch) == 1
}

func (e *Engine) AddAllowedIP(ipStr string) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.allowedIPs[ip.String()] = true
}

func (e *Engine) IsAllowedIP(ip net.IP) bool {
	if e.IsKillSwitchActive() {
		e.logAudit(ip.String(), "ip", false, "kill switch active")
		return false
	}

	if ip == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	ipStr := ip.String()
	if e.allowedIPs[ipStr] {
		e.logAudit(ipStr, "ip", true, "explicit ip match")
		return true
	}

	for _, cidr := range e.allowedCIDRs {
		if cidr.Contains(ip) {
			e.logAudit(ipStr, "ip", true, fmt.Sprintf("cidr match %s", cidr.String()))
			return true
		}
	}

	e.logAudit(ipStr, "ip", false, "no ip/cidr match")
	return false
}

func (e *Engine) IsAllowedDomain(domain string) bool {
	if e.IsKillSwitchActive() {
		e.logAudit(domain, "domain", false, "kill switch active")
		return false
	}

	cleaned := strings.ToLower(strings.TrimSpace(domain))
	if cleaned == "" {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, allowed := range e.allowedDomains {
		if allowed == cleaned {
			e.logAudit(cleaned, "domain", true, "exact domain match")
			return true
		}
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:] // e.g. ".jobsira.com"
			if strings.HasSuffix(cleaned, suffix) {
				e.logAudit(cleaned, "domain", true, fmt.Sprintf("wildcard domain match %s", allowed))
				return true
			}
		}
	}

	e.logAudit(cleaned, "domain", false, "no domain match")
	return false
}

func (e *Engine) IsAllowedCIDR(cidrStr string) bool {
	if e.IsKillSwitchActive() {
		return false
	}

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, allowed := range e.allowedCIDRs {
		if allowed.String() == ipNet.String() {
			return true
		}
	}

	return false
}

func (e *Engine) IsAllowedTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}

	ip := net.ParseIP(target)
	if ip != nil {
		return e.IsAllowedIP(ip)
	}

	return e.IsAllowedDomain(target)
}

func (e *Engine) WaitLimiter(ctx context.Context) error {
	if e.limiter == nil {
		return nil
	}
	return e.limiter.Wait(ctx)
}

func (e *Engine) logAudit(target, targetType string, allowed bool, reason string) {
	if e.auditLog == nil {
		return
	}

	entry := fmt.Sprintf("[%s] TYPE=%s TARGET=%s ALLOWED=%t REASON=%s\n",
		time.Now().Format(time.RFC3339), targetType, target, allowed, reason)
	_, _ = e.auditLog.WriteString(entry)
}

func (e *Engine) Close() error {
	if e.auditLog != nil {
		return e.auditLog.Close()
	}
	return nil
}
