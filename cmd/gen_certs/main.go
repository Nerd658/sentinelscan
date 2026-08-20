package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	outDir := "tests/e2e/certs"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	_ = os.MkdirAll(outDir, 0755)

	createCert(outDir, "jobsira.test", []string{"jobsira.test", "www.jobsira.test", "admin.jobsira.test", "origin.jobsira.test"})
	createCert(outDir, "api.jobsira.test", []string{"api.jobsira.test"})
	createCert(outDir, "wildcard.jobsira.test", []string{"*.jobsira.test", "jobsira.test"})

	fmt.Println("Lab certificates generated successfully in", outDir)
}

func createCert(outDir, name string, sans []string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"SentinelScan Lab CA"},
		},
		DNSNames:              sans,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("172.20.0.20"), net.ParseIP("172.20.0.40")},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}

	certFile, _ := os.Create(filepath.Join(outDir, name+".crt"))
	_ = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	_ = certFile.Close()

	keyFile, _ := os.Create(filepath.Join(outDir, name+".key"))
	_ = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	_ = keyFile.Close()
}
