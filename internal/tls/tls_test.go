package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	cryptoTLS "crypto/tls"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"sentinelscan/internal/scope"
)

func TestTLSInspectorMockServer(t *testing.T) {
	// Generate test cert
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "jobsira.test",
		},
		DNSNames:              []string{"jobsira.test", "api.jobsira.test"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	tlsCert := cryptoTLS.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	listener, err := cryptoTLS.Listen("tcp", "127.0.0.1:0", &cryptoTLS.Config{
		Certificates: []cryptoTLS.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tlsConn := c.(*cryptoTLS.Conn)
				_ = tlsConn.Handshake()
				_ = tlsConn.Close()
			}(conn)
		}
	}()

	addrParts := strings.Split(listener.Addr().String(), ":")
	ipStr := addrParts[0]
	port, _ := strconv.Atoi(addrParts[1])

	scopeEngine, _ := scope.NewEngine(scope.ScopeRules{
		IPs:     []string{ipStr},
		Domains: []string{"jobsira.test"},
	})

	inspector := NewInspector(scopeEngine, 2*time.Second)
	obs, err := inspector.Inspect(t.Context(), ipStr, port, "jobsira.test")
	if err != nil {
		t.Fatalf("failed TLS inspection: %v", err)
	}

	if obs.SubjectCN != "jobsira.test" {
		t.Errorf("expected SubjectCN jobsira.test, got %s", obs.SubjectCN)
	}
	if len(obs.SAN) != 2 {
		t.Errorf("expected 2 SAN entries, got %d", len(obs.SAN))
	}
}
