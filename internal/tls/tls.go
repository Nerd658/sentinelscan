package tls

import (
	"context"
	cryptoTLS "crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"sentinelscan/internal/scope"
	"sentinelscan/pkg/logger"
)

type TLSObservation struct {
	IP                 string    `json:"ip"`
	Port               int       `json:"port"`
	SNI                string    `json:"sni"`
	Version            string    `json:"version"`
	CipherSuite        string    `json:"cipher_suite"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	SubjectCN          string    `json:"subject_cn"`
	Issuer             string    `json:"issuer"`
	SAN                []string  `json:"san"`
	SerialNumber       string    `json:"serial_number"`
	ValidFrom          time.Time `json:"valid_from"`
	ValidUntil         time.Time `json:"valid_until"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	Timestamp          time.Time `json:"timestamp"`
}

type Inspector struct {
	scopeEngine *scope.Engine
	timeout     time.Duration
}

func NewInspector(scopeEngine *scope.Engine, timeout time.Duration) *Inspector {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Inspector{
		scopeEngine: scopeEngine,
		timeout:     timeout,
	}
}

func (i *Inspector) Inspect(ctx context.Context, ipStr string, port int, sni string) (*TLSObservation, error) {
	if port <= 0 {
		port = 443
	}

	target := ipStr
	if sni != "" {
		target = sni
	}

	if i.scopeEngine != nil {
		if err := i.scopeEngine.WaitLimiter(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait cancelled: %w", err)
		}
		if !i.scopeEngine.IsAllowedTarget(target) {
			logger.Warn("TLS inspection rejected by Scope Engine", "target", target)
			return nil, fmt.Errorf("target %s is outside authorized scan scope", target)
		}
	}

	dialer := &net.Dialer{Timeout: i.timeout}
	addr := fmt.Sprintf("%s:%d", ipStr, port)

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed TCP dial for TLS to %s: %w", addr, err)
	}
	defer conn.Close()

	tlsConfig := &cryptoTLS.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	}

	tlsConn := cryptoTLS.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake failed for %s: %w", addr, err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates returned by %s", addr)
	}

	cert := state.PeerCertificates[0]
	sans := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	fingerprint := fmt.Sprintf("%x", cert.Raw) // Raw bytes string representation
	versionStr := tlsVersionToString(state.Version)
	cipherStr := cryptoTLS.CipherSuiteName(state.CipherSuite)

	obs := &TLSObservation{
		IP:                 ipStr,
		Port:               port,
		SNI:                sni,
		Version:            versionStr,
		CipherSuite:        cipherStr,
		FingerprintSHA256:  fingerprint,
		SubjectCN:          cert.Subject.CommonName,
		Issuer:             cert.Issuer.CommonName,
		SAN:                sans,
		SerialNumber:       cert.SerialNumber.String(),
		ValidFrom:          cert.NotBefore,
		ValidUntil:         cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: publicKeyAlgorithmToString(cert.PublicKeyAlgorithm),
		Timestamp:          time.Now(),
	}

	logger.Info("TLS inspection completed", "ip", ipStr, "port", port, "cn", obs.SubjectCN, "issuer", obs.Issuer)
	return obs, nil
}

func tlsVersionToString(v uint16) string {
	switch v {
	case cryptoTLS.VersionTLS10:
		return "TLS 1.0"
	case cryptoTLS.VersionTLS11:
		return "TLS 1.1"
	case cryptoTLS.VersionTLS12:
		return "TLS 1.2"
	case cryptoTLS.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

func publicKeyAlgorithmToString(algo x509.PublicKeyAlgorithm) string {
	switch algo {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return strings.ToUpper(algo.String())
	}
}
