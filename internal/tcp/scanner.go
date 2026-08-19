package tcp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"sentinelscan/internal/scope"
	"sentinelscan/pkg/logger"
)

var DefaultPorts = []int{
	22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443,
}

type PortState string

const (
	StateOpen     PortState = "open"
	StateClosed   PortState = "closed"
	StateFiltered PortState = "filtered"
)

type PortResult struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	State     PortState `json:"state"`
	LatencyMs int64     `json:"latency_ms"`
	Timestamp time.Time `json:"timestamp"`
}

type Scanner struct {
	scopeEngine *scope.Engine
	timeout     time.Duration
	workers     int
}

func NewScanner(scopeEngine *scope.Engine, timeout time.Duration, workers int) *Scanner {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if workers <= 0 {
		workers = 20
	}
	return &Scanner{
		scopeEngine: scopeEngine,
		timeout:     timeout,
		workers:     workers,
	}
}

func (s *Scanner) ScanIP(ctx context.Context, ipStr string, ports []int) ([]PortResult, error) {
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	if s.scopeEngine != nil {
		if err := s.scopeEngine.WaitLimiter(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait cancelled: %w", err)
		}
		if !s.scopeEngine.IsAllowedIP(parsedIP) {
			logger.Warn("TCP scan attempt rejected by Scope Engine", "ip", ipStr)
			return nil, fmt.Errorf("IP %s is outside authorized target scope", ipStr)
		}
	}

	if len(ports) == 0 {
		ports = DefaultPorts
	}

	type portTask struct {
		port int
	}

	tasks := make(chan portTask, len(ports))
	resultsChan := make(chan PortResult, len(ports))

	for _, p := range ports {
		tasks <- portTask{port: p}
	}
	close(tasks)

	var wg sync.WaitGroup
	workerCount := s.workers
	if workerCount > len(ports) {
		workerCount = len(ports)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
					res := s.probePort(ctx, ipStr, task.port)
					resultsChan <- res
				}
			}
		}()
	}

	wg.Wait()
	close(resultsChan)

	results := make([]PortResult, 0)
	for res := range resultsChan {
		results = append(results, res)
	}

	logger.Info("TCP port scan completed", "ip", ipStr, "ports_scanned", len(ports), "open_ports", countOpenPorts(results))
	return results, nil
}

func (s *Scanner) probePort(ctx context.Context, ipStr string, port int) PortResult {
	targetAddr := fmt.Sprintf("%s:%d", ipStr, port)
	start := time.Now()

	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", targetAddr)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return PortResult{
				IP:        ipStr,
				Port:      port,
				Protocol:  "tcp",
				State:     StateFiltered,
				LatencyMs: latency,
				Timestamp: time.Now(),
			}
		}
		return PortResult{
			IP:        ipStr,
			Port:      port,
			Protocol:  "tcp",
			State:     StateClosed,
			LatencyMs: latency,
			Timestamp: time.Now(),
		}
	}
	_ = conn.Close()

	return PortResult{
		IP:        ipStr,
		Port:      port,
		Protocol:  "tcp",
		State:     StateOpen,
		LatencyMs: latency,
		Timestamp: time.Now(),
	}
}

func countOpenPorts(results []PortResult) int {
	count := 0
	for _, r := range results {
		if r.State == StateOpen {
			count++
		}
	}
	return count
}
