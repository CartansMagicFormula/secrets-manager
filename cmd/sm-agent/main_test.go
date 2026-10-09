package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secrets-manager/internal/client"
	"secrets-manager/internal/testvault"
)

func TestAgentCertsAndSecrets(t *testing.T) {
	v := testvault.Start(t)
	v.Admin("PUT", "/v1/admin/secrets/lumen/db-password", `{"kind":"generated","length":32}`)
	tokenFile := v.Client("lumen-postgres", `{"name":"lumen-postgres","policies":["lumen/db-password"],"pki_names":["postgres","127.0.0.1"]}`)
	c, err := client.New(v.TS.URL, v.CAFile, tokenFile, "postgres-1")
	if err != nil {
		t.Fatal(err)
	}
	certDir, secretDir := t.TempDir(), t.TempDir()
	o, err := parse([]string{"-cert", "postgres,127.0.0.1", "-cert-dir", certDir, "-secret", "lumen/db-password=db_password", "-secret-dir", secretDir, "-once"})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if !run(logger, c, o) {
		t.Fatal("first run failed")
	}

	// Key 0600, usable key pair, chain verifies against the fleet CA
	info, err := os.Stat(filepath.Join(certDir, "tls.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", info, err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(certDir, "tls.crt"), filepath.Join(certDir, "tls.key"))
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	caPEM, _ := os.ReadFile(v.CAFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "postgres", Roots: pool}); err != nil {
		t.Fatalf("certificate does not verify: %v", err)
	}
	secret, err := os.ReadFile(filepath.Join(secretDir, "db_password"))
	if err != nil || len(secret) != 32 {
		t.Fatalf("secret file: %d %v", len(secret), err)
	}

	// Second run: nothing due, nothing rewritten
	before, _ := os.ReadFile(filepath.Join(certDir, "tls.crt"))
	run(logger, c, o)
	after, _ := os.ReadFile(filepath.Join(certDir, "tls.crt"))
	if string(before) != string(after) {
		t.Fatal("certificate renewed although not due")
	}

	// Rotation in the vault reaches the file
	v.Admin("POST", "/v1/admin/rotate/lumen/db-password", "")
	run(logger, c, o)
	rotated, _ := os.ReadFile(filepath.Join(secretDir, "db_password"))
	if string(rotated) == string(secret) {
		t.Fatal("rotated secret not written")
	}

	// A foreign name is refused and nothing is written
	bad, _ := parse([]string{"-cert", "keycloak", "-cert-dir", t.TempDir(), "-once"})
	if run(logger, c, bad) {
		t.Fatal("certificate for a foreign name")
	}
}

func TestEnroll(t *testing.T) {
	v := testvault.Start(t)
	v.Admin("PUT", "/v1/admin/secrets/svc/key", `{"kind":"static","value":"value-1"}`)
	_, created := v.Admin("POST", "/v1/admin/clients", `{"name":"svc","policies":["svc"]}`)
	id := created["client"].(map[string]any)["id"].(string)
	_, out := v.Admin("POST", "/v1/admin/clients/"+id+"/enroll", "")
	t.Setenv("SM_URL", v.TS.URL)
	t.Setenv("SM_CA_FILE", v.CAFile)
	tokenFile := filepath.Join(t.TempDir(), "svc")

	if err := enroll([]string{"-out", tokenFile}, strings.NewReader(out["code"].(string)+"\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(tokenFile)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("token file: %v %v", info, err)
	}
	c, err := client.New(v.TS.URL, v.CAFile, tokenFile, "svc-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Get("svc/key", false); err != nil || got != "value-1" {
		t.Fatalf("login with the enrolled token: %q %v", got, err)
	}
	// The code works once
	if err := enroll([]string{"-out", filepath.Join(t.TempDir(), "again")}, strings.NewReader(out["code"].(string))); err == nil {
		t.Fatal("code used twice")
	}
	if err := enroll([]string{"-out", tokenFile}, strings.NewReader("")); err == nil {
		t.Fatal("empty code accepted")
	}
	// -owner hands the file to the service's user (here: our own, no root in tests)
	_, out = v.Admin("POST", "/v1/admin/clients/"+id+"/enroll", "")
	owned := filepath.Join(t.TempDir(), "owned")
	owner := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	if err := enroll([]string{"-out", owned, "-owner", owner}, strings.NewReader(out["code"].(string)+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := enroll([]string{"-out", owned, "-owner", "postgres"}, strings.NewReader("x\n")); err == nil || !strings.Contains(err.Error(), "uid:gid") {
		t.Fatalf("bad owner: %v", err)
	}
}

func TestCertDue(t *testing.T) {
	block := func(notBefore, notAfter time.Time) string {
		dir := t.TempDir()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: notBefore, NotAfter: notAfter}
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "tls.crt")
		_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
		return path
	}
	now := time.Now()
	if certDue(block(now.Add(-time.Hour), now.Add(29*24*time.Hour)), now) {
		t.Fatal("fresh certificate due")
	}
	if !certDue(block(now.Add(-21*24*time.Hour), now.Add(9*24*time.Hour)), now) {
		t.Fatal("certificate past 2/3 not due")
	}
	if !certDue(filepath.Join(t.TempDir(), "missing"), now) {
		t.Fatal("missing certificate not due")
	}
}

func TestParse(t *testing.T) {
	bad := [][]string{
		{},
		{"-secret", "no-equals"},
		{"-secret", "a/b=../escape"},
		{"-cert", "x", "-usage", "ca"},
		{"-cert", "x", "-reload-signal", "KILL"},
		{"-cert", "x", "-interval", "1s"},
		{"-secret", "a/b=f", "--", "/service"}, // a command needs -once
	}
	for _, args := range bad {
		if _, err := parse(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
	o, err := parse([]string{"-once", "-secret", "a/b=f", "--", "/service", "-flag"})
	if err != nil || len(o.exec) != 2 || o.exec[0] != "/service" || o.exec[1] != "-flag" {
		t.Fatalf("command: %v %v", o.exec, err)
	}
}
