// Package pki is the vault's internal certificate authority.
//
// No primitive is implemented here: ECDSA P-256 keys (crypto/ecdsa), X.509
// certificates and CSRs (crypto/x509), randomness (crypto/rand). The rules
// this package enforces: clients send a CSR (their private key never leaves
// them), every name in a certificate must be on the client's allow list,
// certificates are short-lived and carry exactly one usage (server or client).
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"time"
)

// Lifetimes.
const (
	CALifetime     = 10 * 365 * 24 * time.Hour
	DefaultTTL     = 30 * 24 * time.Hour
	MaxTTL         = 90 * 24 * time.Hour
	MinTTL         = time.Hour
	backdate       = 5 * time.Minute // tolerate small clock skew between containers
	usageServer    = "server"
	usageClient    = "client"
	maxNamesPerCSR = 20
)

// CA holds the parsed CA certificate and key.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// NewCA creates a self-signed root (ECDSA P-256). It returns the certificate
// (PEM) and the private key (PKCS#8 DER) for the encrypted state.
func NewCA(name string, now time.Time) (certPEM, keyDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(CALifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyDER, nil
}

// LoadCA parses the stored CA.
func LoadCA(certPEM, keyDER []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("invalid CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("invalid CA key")
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: signer}, nil
}

// Request for a certificate.
type Request struct {
	CSRPEM  []byte
	Usage   string        // server | client
	TTL     time.Duration // 0 = DefaultTTL
	Allowed []string      // names the client may put into certificates
}

// Issued certificate.
type Issued struct {
	CertPEM  []byte
	Serial   string
	Names    []string
	NotAfter time.Time
}

func checkKey(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return errors.New("ECDSA key must use P-256 or P-384")
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return errors.New("RSA key must have at least 2048 bits")
		}
	default:
		return errors.New("key must be ECDSA or RSA")
	}
	return nil
}

// Issue signs a CSR after checking every requested name against the allow list.
// Server certificates carry the DNS names / IPs of the CSR; client
// certificates carry only the common name (the identity, e.g. a DB user).
func (ca *CA) Issue(r Request, now time.Time) (*Issued, error) {
	block, _ := pem.Decode(r.CSRPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr: PEM certificate request required")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.New("csr: cannot parse")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("csr: invalid signature")
	}
	if err := checkKey(csr.PublicKey); err != nil {
		return nil, err
	}
	if len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return nil, errors.New("csr: only DNS names and IP addresses are allowed")
	}
	ttl := r.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < MinTTL || ttl > MaxTTL {
		return nil, fmt.Errorf("ttl must be between %s and %s", MinTTL, MaxTTL)
	}
	allowed := func(name string) bool { return slices.Contains(r.Allowed, name) }
	var names []string
	tmpl := &x509.Certificate{
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(ttl),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if _, isRSA := csr.PublicKey.(*rsa.PublicKey); isRSA {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	switch r.Usage {
	case usageServer:
		if len(csr.DNSNames)+len(csr.IPAddresses) == 0 || len(csr.DNSNames)+len(csr.IPAddresses) > maxNamesPerCSR {
			return nil, fmt.Errorf("csr: 1 to %d DNS names / IP addresses required", maxNamesPerCSR)
		}
		for _, n := range csr.DNSNames {
			if !allowed(n) {
				return nil, fmt.Errorf("name not allowed: %s", n)
			}
			names = append(names, n)
		}
		for _, ip := range csr.IPAddresses {
			if !allowed(ip.String()) {
				return nil, fmt.Errorf("address not allowed: %s", ip)
			}
			names = append(names, ip.String())
		}
		tmpl.DNSNames, tmpl.IPAddresses = csr.DNSNames, csr.IPAddresses
		tmpl.Subject = pkix.Name{CommonName: names[0]}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case usageClient:
		cn := csr.Subject.CommonName
		if cn == "" || !allowed(cn) || len(csr.DNSNames)+len(csr.IPAddresses) > 0 {
			return nil, errors.New("csr: client certificates carry only an allowed common name")
		}
		names = []string{cn}
		tmpl.Subject = pkix.Name{CommonName: cn}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, errors.New("usage must be server or client")
	}
	if tmpl.NotAfter.After(ca.Cert.NotAfter) {
		tmpl.NotAfter = ca.Cert.NotAfter
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = sn
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return &Issued{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:  sn.Text(16), Names: names, NotAfter: tmpl.NotAfter,
	}, nil
}

// ServerCertificate creates a key pair in memory and a server certificate for
// it (the vault's own TLS listener; the key is never written anywhere).
func (ca *CA) ServerCertificate(names []string, ttl time.Duration, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: dnsOnly(names), IPAddresses: ipsOnly(names)}, key)
	if err != nil {
		return nil, err
	}
	issued, err := ca.Issue(Request{
		CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		Usage:  usageServer, TTL: ttl, Allowed: names,
	}, now)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(issued.CertPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{block.Bytes, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// SelfSigned is a throwaway certificate for the sealed phase (no CA key in
// memory yet). Clients that verify against the CA reject it, as they should.
func SelfSigned(names []string, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{CommonName: "secrets-manager (sealed)"},
		NotBefore: now.Add(-backdate), NotAfter: now.Add(30 * 24 * time.Hour),
		DNSNames: dnsOnly(names), IPAddresses: ipsOnly(names),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func dnsOnly(names []string) []string {
	var out []string
	for _, n := range names {
		if net.ParseIP(n) == nil {
			out = append(out, n)
		}
	}
	return out
}

func ipsOnly(names []string) []net.IP {
	var out []net.IP
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
