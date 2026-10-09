package client_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"secrets-manager/internal/client"
	"secrets-manager/internal/pki"
	"secrets-manager/internal/testvault"
)

func TestClientOverTLS(t *testing.T) {
	v := testvault.Start(t)
	v.Admin("PUT", "/v1/admin/secrets/svc/api-key", `{"kind":"static","value":"value-1"}`)
	tokenFile := v.Client("svc", `{"name":"svc","policies":["svc"],"pki_names":["svc.internal"]}`)

	c, err := client.New(v.TS.URL, v.CAFile, tokenFile, "svc-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Get("svc/api-key", false); err != nil || got != "value-1" {
		t.Fatalf("get: %q %v", got, err)
	}
	if _, err := c.Get("svc/api-key", true); !errors.Is(err, client.ErrNoPrevious) {
		t.Fatalf("previous without rotation: %v", err)
	}
	if _, err := c.Get("other/key", false); err == nil {
		t.Fatal("read outside the policy")
	}

	// Certificate from a CSR
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"svc.internal"}}, key)
	cert, err := c.Issue(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), "server", 24*time.Hour)
	if err != nil || cert.Serial == "" || cert.NotAfter.Before(time.Now().Add(23*time.Hour)) {
		t.Fatalf("issue: %v %v", cert, err)
	}

	// Vault sealed and unsealed: the old access token is gone, the client logs in again
	v.Admin("POST", "/v1/sys/seal", "")
	if _, err := c.Get("svc/api-key", false); !errors.Is(err, client.ErrSealed) {
		t.Fatalf("sealed: %v", err)
	}
	if code, _ := v.Admin("POST", "/v1/sys/unseal", `{"master_key":"`+v.Master+`"}`); code != 200 {
		t.Fatal("unseal")
	}
	if got, err := c.Get("svc/api-key", false); err != nil || got != "value-1" {
		t.Fatalf("after unseal: %q %v", got, err)
	}
}

func TestClientRejectsForeignCA(t *testing.T) {
	v := testvault.Start(t)
	tokenFile := v.Client("svc", `{"name":"svc","policies":["svc"]}`)
	foreign, _, err := pki.NewCA("Someone else", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "foreign.crt")
	_ = os.WriteFile(caFile, foreign, 0o644)
	c, err := client.New(v.TS.URL, caFile, tokenFile, "svc-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get("svc/api-key", false); err == nil {
		t.Fatal("client trusted a vault certificate from a foreign CA")
	}
	if _, err := client.New(v.TS.URL, filepath.Join(t.TempDir(), "missing"), tokenFile, ""); err == nil {
		t.Fatal("missing CA file accepted")
	}
}
