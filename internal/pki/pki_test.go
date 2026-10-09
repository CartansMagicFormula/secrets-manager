package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func newCA(t *testing.T) *CA {
	t.Helper()
	certPEM, keyDER, err := NewCA("Test CA", now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCA(certPEM, keyDER)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func csr(t *testing.T, tmpl *x509.CertificateRequest, key any) []byte {
	t.Helper()
	if key == nil {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func parse(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(p)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCA(t *testing.T) {
	ca := newCA(t)
	if !ca.Cert.IsCA || !ca.Cert.MaxPathLenZero || ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CA constraints missing")
	}
	if _, err := LoadCA(ca.CertPEM, []byte("garbage")); err == nil {
		t.Fatal("broken key accepted")
	}
}

func TestIssueServer(t *testing.T) {
	ca := newCA(t)
	allowed := []string{"postgres", "lumen-postgres-1", "127.0.0.1"}
	req := csr(t, &x509.CertificateRequest{DNSNames: []string{"postgres", "lumen-postgres-1"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, nil)
	issued, err := ca.Issue(Request{CSRPEM: req, Usage: "server", Allowed: allowed}, now)
	if err != nil {
		t.Fatal(err)
	}
	cert := parse(t, issued.CertPEM)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "postgres", Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("issued certificate does not verify: %v", err)
	}
	if cert.IsCA || !cert.NotAfter.Equal(now.Add(DefaultTTL).Truncate(time.Second)) || len(issued.Names) != 3 {
		t.Fatalf("unexpected certificate: ca=%v notAfter=%v names=%v", cert.IsCA, cert.NotAfter, issued.Names)
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "postgres", Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("server certificate usable as client certificate")
	}
}

func TestIssueRejects(t *testing.T) {
	ca := newCA(t)
	allowed := []string{"postgres", "lumen-app"}
	rsaSmall, _ := rsa.GenerateKey(rand.Reader, 1024)
	other := csr(t, &x509.CertificateRequest{DNSNames: []string{"postgres"}}, nil)
	tampered := strings.Replace(string(other), string(other[100:110]), "AAAAAAAAAA", 1)
	cases := map[string]Request{
		"name not allowed":     {CSRPEM: csr(t, &x509.CertificateRequest{DNSNames: []string{"postgres", "evil.example.com"}}, nil), Usage: "server", Allowed: allowed},
		"no names":             {CSRPEM: csr(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "postgres"}}, nil), Usage: "server", Allowed: allowed},
		"ip not allowed":       {CSRPEM: csr(t, &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}}, nil), Usage: "server", Allowed: allowed},
		"email SAN":            {CSRPEM: csr(t, &x509.CertificateRequest{DNSNames: []string{"postgres"}, EmailAddresses: []string{"a@b.c"}}, nil), Usage: "server", Allowed: allowed},
		"weak RSA":             {CSRPEM: csr(t, &x509.CertificateRequest{DNSNames: []string{"postgres"}}, rsaSmall), Usage: "server", Allowed: allowed},
		"ttl too long":         {CSRPEM: other, Usage: "server", Allowed: allowed, TTL: 365 * 24 * time.Hour},
		"ttl too short":        {CSRPEM: other, Usage: "server", Allowed: allowed, TTL: time.Minute},
		"unknown usage":        {CSRPEM: other, Usage: "ca", Allowed: allowed},
		"not PEM":              {CSRPEM: []byte("hello"), Usage: "server", Allowed: allowed},
		"tampered":             {CSRPEM: []byte(tampered), Usage: "server", Allowed: allowed},
		"client with DNS":      {CSRPEM: csr(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "lumen-app"}, DNSNames: []string{"postgres"}}, nil), Usage: "client", Allowed: allowed},
		"client cn disallowed": {CSRPEM: csr(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "postgres-superuser"}}, nil), Usage: "client", Allowed: allowed},
	}
	for name, r := range cases {
		if _, err := ca.Issue(r, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIssueClient(t *testing.T) {
	ca := newCA(t)
	issued, err := ca.Issue(Request{
		CSRPEM: csr(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "lumen-app"}}, nil),
		Usage:  "client", Allowed: []string{"lumen-app"}, TTL: 24 * time.Hour,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	cert := parse(t, issued.CertPEM)
	if cert.Subject.CommonName != "lumen-app" || len(cert.DNSNames) != 0 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("client certificate: %v %v %v", cert.Subject, cert.DNSNames, cert.ExtKeyUsage)
	}
}

func TestServerCertificateAndTLS(t *testing.T) {
	certPEM, keyDER, err := NewCA("Test CA", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCA(certPEM, keyDER)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.ServerCertificate([]string{"secrets-manager", "127.0.0.1"}, 7*24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "secrets-manager", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("client does not trust the vault certificate: %v", err)
	}
	conn.Close()

	sealed, err := SelfSigned([]string{"secrets-manager"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealed.Leaf.Verify(x509.VerifyOptions{DNSName: "secrets-manager", Roots: pool}); err == nil {
		t.Fatal("self-signed sealed certificate verifies against the CA")
	}
}
